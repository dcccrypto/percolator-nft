//! Token-2022 TransferHook implementation.
//!
//! This module implements the SPL TransferHook interface. Token-2022 calls
//! our `Execute` handler on every NFT transfer. The hook:
//!
//! 1. Verifies position is not in liquidation zone
//! 2. Settles pending funding (seller gets accrued, buyer starts clean)
//! 3. Updates `owner` field in slab position → new wallet (via CPI)
//! 4. Rejects transfer if position is being liquidated
//!
//! Reference: Uniswap V3 NonfungiblePositionManager transfer logic.

extern crate alloc;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions as sysvar_instructions,
};

use crate::{
    cpi::{read_position, verify_slab_owner, PERCOLATOR_DEVNET, PERCOLATOR_MAINNET},
    error::NftError,
    state::{verify_pda_version, PositionNft, MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
    token2022,
};

// Maintenance margin bps offset within the engine block.
// Engine layout: +0 mark_price_e6(u64), +8 oracle_price_e6(u64), +16 last_funding_slot(u64),
//               ..., +96 maintenance_margin_bps(u64).
const ENGINE_MARK_PRICE_OFF: usize = 0;
const ENGINE_MAINT_MARGIN_OFF: usize = 96;

// ═══════════════════════════════════════════════════════════════
// SPL TransferHook interface constants
// ═══════════════════════════════════════════════════════════════

/// Discriminator for the TransferHook `Execute` instruction.
/// SHA256("spl-transfer-hook-interface:execute")[:8]
pub const EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

/// Instruction tag for the TransferOwnershipCpi handler in percolator-prog.
/// Tag 65 is TransferPositionOwnership (user-facing, 8-account flow).
/// Tag 69 is TransferOwnershipCpi (CPI-only, 3-account flow) — the correct hook target.
///
/// GH#1868 (PERC-8221): previous code sent tag 65, which expected 8 accounts and a user
/// signer — causing AccountBorrowFailed / missing-signer panic on every NFT transfer.
pub const TAG_TRANSFER_POSITION_OWNERSHIP: u8 = 69;

// ═══════════════════════════════════════════════════════════════
// Margin check — verify position has positive equity vs maintenance margin
// ═══════════════════════════════════════════════════════════════

/// Read a u64 from slab data at the given absolute offset.
fn read_u64_at(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[off..off + 8].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Check if a position has sufficient equity above maintenance margin.
///
/// Equity = collateral + unrealized_pnl + funding_delta.
/// Maintenance requirement = size * maintenance_margin_bps / 10_000.
///
/// PERC-9050: The funding delta (accrued but unsettled funding) is now
/// included in the equity calculation. Previously, equity was computed as
/// `collateral + unrealized_pnl` without funding, which meant a position
/// with large negative accrued funding could appear healthy and be
/// transferred — the buyer would inherit the funding debt.
///
/// This is a real margin check using the same formula as valuation.rs,
/// not just a mark_price > 0 guard. Liquidatable positions are rejected.
///
/// Parameters:
/// - `slab_data`: raw slab bytes
/// - `position_size`: absolute size in collateral micro-units
/// - `entry_price_e6`: position entry price (E6)
/// - `is_long`: 1 for long, 0 for short
/// - `collateral`: deposited collateral in micro-units
/// - `engine_off`: byte offset to engine block (from `read_position()`)
/// - `funding_delta_e18`: accrued funding since last settlement
///   (global_funding_index_e18 - last_funding_index_e18).
///   Positive = funding received, negative = funding owed.
///   Scaled by E18; must be normalized by position size and price.
///
/// Returns true if equity >= maintenance_margin (position is healthy).
fn is_position_healthy(
    slab_data: &[u8],
    position_size: u64,
    entry_price_e6: u64,
    is_long: u8,
    collateral: u64,
    engine_off: usize,
    funding_delta_e18: i128,
) -> Result<bool, ProgramError> {
    if position_size == 0 {
        // PERC-9061: A closed position (size=0) has zero exposure and cannot
        // be liquidated. Return healthy so the transfer hook proceeds —
        // the new holder may need to withdraw remaining collateral or burn
        // the NFT. The margin check below is meaningless when size=0
        // (maintenance requirement = size * bps / 10000 = 0).
        return Ok(true);
    }

    // PERC-9009: Reject if entry_price_e6 is zero — this would make PnL=0
    // regardless of mark price, potentially letting an unhealthy position
    // pass the margin check if collateral alone covers maintenance.
    if entry_price_e6 == 0 {
        return Ok(false);
    }

    // Read mark price from engine block.
    let mark_price_e6 = match read_u64_at(slab_data, engine_off + ENGINE_MARK_PRICE_OFF) {
        Some(p) if p > 0 => p,
        _ => return Ok(false), // Stale / zero price → reject.
    };

    // Read maintenance_margin_bps from engine block.
    // PERC-9010: Reject instead of defaulting to 500bps if the read fails.
    // An attacker could craft slab data truncated before offset 96 to force
    // a lenient 500bps default instead of the actual (possibly higher) value.
    let maint_margin_bps = read_u64_at(slab_data, engine_off + ENGINE_MAINT_MARGIN_OFF)
        .ok_or(NftError::SlabDataTooShort)?;

    // PERC-9009: Use checked arithmetic instead of saturating to detect
    // overflow. Saturating silently clamps to i128::MAX or 0, which can
    // make an unhealthy position appear healthy (or vice versa).
    let size = position_size as i128;
    let mark = mark_price_e6 as i128;
    let entry = entry_price_e6 as i128;

    let price_diff = if is_long == 1 {
        mark.checked_sub(entry).ok_or(ProgramError::ArithmeticOverflow)?
    } else {
        entry.checked_sub(mark).ok_or(ProgramError::ArithmeticOverflow)?
    };

    let unrealized_pnl = size
        .checked_mul(price_diff)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(entry)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // PERC-9050: Compute funding adjustment in collateral micro-units.
    // funding_delta_e18 is the index delta (E18-scaled, per unit of position).
    // Funding payment = position_size * funding_delta_e18 / 1e18.
    // Sign convention: positive delta = funding received (adds to equity),
    // negative delta = funding owed (subtracts from equity).
    // For shorts the funding direction is inverted: if the funding index
    // increases, longs pay shorts, so a short position receives funding
    // when delta > 0. We apply the sign flip based on direction.
    const E18: i128 = 1_000_000_000_000_000_000;
    let raw_funding = size
        .checked_mul(funding_delta_e18)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_div(E18)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    // For longs, positive funding_delta means longs pay → subtract.
    // For shorts, positive funding_delta means shorts receive → add.
    // Percolator convention: funding_delta > 0 means longs pay shorts.
    let funding_adjustment = if is_long == 1 {
        raw_funding.checked_neg().ok_or(ProgramError::ArithmeticOverflow)?
    } else {
        raw_funding
    };

    let net_equity = (collateral as i128)
        .checked_add(unrealized_pnl)
        .ok_or(ProgramError::ArithmeticOverflow)?
        .checked_add(funding_adjustment)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let maint_requirement = (position_size as i128)
        .checked_mul(maint_margin_bps as i128)
        .ok_or(ProgramError::ArithmeticOverflow)?
        / 10_000;

    // Healthy if equity >= maintenance margin.
    Ok(net_equity >= maint_requirement)
}

// ═══════════════════════════════════════════════════════════════
// Execute — called by Token-2022 on every NFT transfer
// ═══════════════════════════════════════════════════════════════

/// Process the TransferHook Execute instruction.
///
/// Accounts (per SPL TransferHook interface):
///   0. `[]`          Source token account
///   1. `[]`          Mint
///   2. `[]`          Destination token account
///   3. `[]`          Destination wallet (new owner)
///   4. `[]`          Extra account metas PDA (validation)
///
/// Extra accounts (appended by our ExtraAccountMetaList):
///   5. `[writable]`  PositionNft PDA
///   6. `[]`          Slab account
///   7. `[]`          Percolator program
///   8. `[]`          Mint authority PDA
///   9. `[]`          Instructions sysvar (for CPI caller verification)
///
/// Data: discriminator(8) + amount(8)
pub fn process_execute(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    // PERC-9036: Validate transfer amount is exactly 1.
    // This is an NFT (decimals=0, supply=1). Token-2022 enforces supply
    // constraints, but defense-in-depth: reject any amount != 1 to prevent
    // unexpected behavior if Token-2022 ever changes semantics or if the
    // hook is called directly (outside Token-2022 CPI).
    if amount != 1 {
        msg!("Transfer rejected: expected amount=1 for NFT, got {}", amount);
        return Err(ProgramError::InvalidInstructionData);
    }

    let accounts_iter = &mut accounts.iter();

    let source_ata = next_account_info(accounts_iter)?; // 0: source token account
    let mint = next_account_info(accounts_iter)?; // 1: NFT mint
    let dest_ata = next_account_info(accounts_iter)?; // 2: destination token account
    let dest_wallet = next_account_info(accounts_iter)?; // 3: new owner wallet
    let extra_metas = next_account_info(accounts_iter)?; // 4: ExtraAccountMetaList PDA

    // Extra accounts
    let nft_pda = next_account_info(accounts_iter)?; // 5: PositionNft PDA (writable)
    let slab = next_account_info(accounts_iter)?; // 6: Slab account
    let percolator_prog = next_account_info(accounts_iter)?; // 7: Percolator program
    let mint_auth = next_account_info(accounts_iter)?; // 8: Mint authority PDA
    let sysvar_ix = next_account_info(accounts_iter)?; // 9: Instructions sysvar

    // ════════════════════════════════════════════════════════════════════
    // SECURITY: Verify this Execute was invoked via CPI from Token-2022.
    //
    // Without this check, an attacker can call Execute directly with
    // crafted accounts, stealing position ownership without moving the
    // NFT token. We use the Instructions sysvar to introspect the call
    // stack and confirm the outer instruction is a Token-2022
    // Transfer/TransferChecked targeting our mint.
    // ════════════════════════════════════════════════════════════════════

    // 1. Verify the Instructions sysvar account key.
    if *sysvar_ix.key != sysvar_instructions::id() {
        msg!("Transfer rejected: account 9 is not the Instructions sysvar");
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    // 2. Validate the extra_metas PDA matches canonical derivation for this mint
    //    AND is owned by this program. The key derivation check alone is not
    //    sufficient — an attacker could compute the correct PDA address but pass
    //    an account at that address that is uninitialized (owned by System program).
    //    The owner check proves the PDA was actually created by this program
    //    during InitializeExtraAccountMetas, which only happens via the
    //    legitimate Token-2022 transfer hook setup flow.
    let (expected_extra_metas, _) = extra_account_metas_pda(mint.key, program_id);
    if *extra_metas.key != expected_extra_metas {
        msg!("Transfer rejected: extra_metas PDA does not match expected derivation");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }
    if extra_metas.owner != program_id {
        msg!("Transfer rejected: extra_metas PDA not owned by this program");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }

    // 3. Validate source token account (defense-in-depth).
    //    Even with the sysvar check, validating the source ATA ensures the
    //    account is a real Token-2022 token account for this mint with
    //    sufficient balance. Token-2022 passes pre-transfer state, so
    //    balance >= 1 proves the source genuinely holds the NFT.
    if *source_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("Transfer rejected: source token account not owned by Token-2022");
        return Err(NftError::InvalidTokenAccount.into());
    }
    {
        let src_data = source_ata.try_borrow_data()?;
        // Token-2022 account layout (same offsets as SPL Token):
        //   [0..32]  mint (Pubkey)
        //   [64..72] amount (u64 LE)
        //   [108]    state (u8: 0=uninit, 1=initialized, 2=frozen)
        if src_data.len() < 165 {
            msg!("Transfer rejected: source token account data too short");
            return Err(NftError::InvalidTokenAccount.into());
        }
        let src_mint = Pubkey::new_from_array(src_data[0..32].try_into().unwrap());
        let src_amount = u64::from_le_bytes(src_data[64..72].try_into().unwrap());
        let src_initialized =
            src_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
        if !src_initialized {
            msg!("Transfer rejected: source token account not initialized");
            return Err(NftError::InvalidTokenAccount.into());
        }
        if src_mint != *mint.key {
            msg!("Transfer rejected: source token account mint mismatch");
            return Err(NftError::InvalidTokenAccount.into());
        }
        if src_amount < amount {
            msg!("Transfer rejected: source balance insufficient");
            return Err(NftError::InvalidTokenAccount.into());
        }
    }

    // 4. Validate destination token account.
    if *dest_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("Transfer rejected: dest token account not owned by Token-2022");
        return Err(NftError::InvalidTokenAccount.into());
    }
    {
        let dst_data = dest_ata.try_borrow_data()?;
        if dst_data.len() < 165 {
            msg!("Transfer rejected: dest token account data too short");
            return Err(NftError::InvalidTokenAccount.into());
        }
        let dst_mint = Pubkey::new_from_array(dst_data[0..32].try_into().unwrap());
        let dst_initialized =
            dst_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
        if !dst_initialized {
            msg!("Transfer rejected: dest token account not initialized");
            return Err(NftError::InvalidTokenAccount.into());
        }
        if dst_mint != *mint.key {
            msg!("Transfer rejected: dest token account mint mismatch");
            return Err(NftError::InvalidTokenAccount.into());
        }
    }

    // 5. Use the Instructions sysvar to verify CPI caller is Token-2022.
    //    get_processed_sibling_instruction is not what we need — we need the
    //    *outer* (parent) instruction that CPI'd into us. On Solana, when
    //    Token-2022 calls our hook via CPI, the current instruction index
    //    points to Token-2022's Transfer/TransferChecked instruction in the
    //    transaction's top-level instruction list. We load that instruction
    //    and verify its program_id is Token-2022.
    verify_cpi_caller_is_token2022(sysvar_ix, mint.key)?;

    // ── GH#1687: Validate percolator_prog key against known constants ──
    // Prevents an attacker from supplying a malicious program as account[7].
    // Without this check the CPI target is attacker-controlled, allowing them
    // to complete the NFT transfer while leaving slab position ownership stale.
    if percolator_prog.key != &PERCOLATOR_DEVNET && percolator_prog.key != &PERCOLATOR_MAINNET {
        msg!(
            "Transfer rejected: percolator_prog key {} is not a known Percolator program",
            percolator_prog.key
        );
        return Err(NftError::InvalidPercolatorProgram.into());
    }

    // ── PERC-9006: Validate mint authority PDA ──
    // The mint_auth account is used as the CPI signer for TransferOwnershipCpi.
    // Without verification an attacker could pass a different PDA or keypair,
    // causing the CPI signature to fail (best case) or — if percolator-prog
    // doesn't re-derive the PDA — allowing an unauthorized ownership transfer.
    let (expected_mint_auth, _) = crate::state::mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("Transfer rejected: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Verify slab ownership (program ID check) ──
    verify_slab_owner(slab)?;

    // ── Read NFT PDA state and extract values ──
    // PERC-9001 / PERC-9002: We must drop ALL account data borrows (both
    // pda_data and slab_data) before the CPI invoke_signed call below.
    // Solana runtime checks for outstanding RefCell borrows on every
    // AccountInfo passed to a CPI. Holding a Ref/RefMut across invoke_signed
    // causes AccountBorrowFailed, permanently breaking NFT transfers.
    //
    // Strategy: read everything we need into local variables, drop borrows,
    // then perform the CPI and final PDA write in separate scopes.
    let (pda_user_idx, pda_slab_bytes, old_funding, new_funding, pda_entry_price_e6, pda_is_long);
    {
        // ── PERC-9003: Verify PDA is owned by this program ──
        // Without this an attacker can pass a crafted account with matching magic
        // bytes but owned by a different program, bypassing all state checks.
        if nft_pda.owner != program_id {
            msg!("Transfer rejected: PositionNft PDA not owned by this program");
            return Err(ProgramError::IllegalOwner);
        }

        let pda_data = nft_pda.try_borrow_data()?;
        if pda_data.len() < POSITION_NFT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_data[..POSITION_NFT_LEN]);
        if nft_state.magic != POSITION_NFT_MAGIC {
            return Err(ProgramError::InvalidAccountData);
        }
        verify_pda_version(nft_state)?;

        // ── GH#2: Verify slab key matches the NFT PDA's recorded slab ──
        if nft_state.slab != slab.key.to_bytes() {
            msg!("Transfer rejected: slab account does not match NFT PDA slab binding");
            return Err(ProgramError::InvalidAccountData);
        }

        // ── PERC-9006: Verify mint account matches the PDA's recorded mint ──
        // Without this check the hook could operate on a PDA that belongs to a
        // different mint, allowing cross-mint state confusion.
        if nft_state.nft_mint != mint.key.to_bytes() {
            msg!("Transfer rejected: mint does not match NFT PDA nft_mint binding");
            return Err(NftError::InvalidNftPda.into());
        }

        pda_user_idx = nft_state.user_idx;
        pda_slab_bytes = nft_state.slab;
        old_funding = nft_state.last_funding_index_e18;
        pda_entry_price_e6 = nft_state.entry_price_e6;
        pda_is_long = nft_state.is_long;

        // ── PERC-9056: Verify PDA address matches expected derivation ──
        // Consistency with Burn (PERC-9008). Without this, any program-owned
        // account with matching magic/slab/mint fields could be substituted.
        let (expected_pda, _) = crate::state::position_nft_pda(
            &Pubkey::new_from_array(nft_state.slab),
            pda_user_idx,
            program_id,
        );
        if *nft_pda.key != expected_pda {
            msg!("Transfer rejected: PDA address does not match expected derivation");
            return Err(NftError::InvalidNftPda.into());
        }


        // pda_data (immutable Ref) is dropped here at end of block
    }

    // ── Read position from slab (scoped borrow) ──
    let position = {
        let slab_data = slab.try_borrow_data()?;
        let pos = read_position(&slab_data, pda_user_idx)?;

        // ── PERC-9061: Closed-position fast path ──
        // When size==0 the position has been fully closed on Percolator.
        // Percolator zeroes entry_price_e6 on close, so the PERC-9060 snapshot
        // check below would always fail for legitimate closed positions. There is
        // also no margin to check, no funding to settle, and no slab owner to
        // update. Allow the transfer so the NFT can eventually be burned once
        // collateral is withdrawn.
        if pos.size == 0 {
            msg!(
                "Position closed (size=0) — transfer allowed: slab={}, idx={}, new_owner={}",
                Pubkey::new_from_array(pda_slab_bytes),
                pda_user_idx,
                dest_wallet.key
            );
            return Ok(());
        }

        // ── Verify account_id matches — slot reuse protection (primary) ──
        if pos.account_id != nft_state.account_id {
            msg!(
                "Transfer rejected: account_id mismatch (stored={}, current={})",
                nft_state.account_id,
                pos.account_id,
            );
            return Err(NftError::InvalidAccountId.into());
        }

        // ── PERC-9060: Verify slab slot still matches PDA snapshot ──
        // If the original position was closed and the slab slot reused for a
        // different position, entry_price_e6 and/or is_long will differ from
        // the values snapshotted at mint time. Without this check, the NFT
        // would silently operate on a completely different position.
        // (Only reached when size > 0 — closed positions use the fast path above.)
        if pda_entry_price_e6 != pos.entry_price_e6 || pda_is_long != pos.is_long {
            msg!(
                "Transfer rejected: slab slot reuse detected (PDA snapshot does not match live position)"
            );
            return Err(NftError::PositionMismatch.into());
        }

        // ── GH#1 / GH#11: Verify position equity >= maintenance margin ──
        // Uses real PnL calculation. Collateral is read from slab acct_off+32
        // (the deposited margin field), NOT position.size (which is notional trade
        // size and would inflate equity by the leverage factor).
        //
        // PERC-9050: Include unsettled funding delta in the health check.
        // The funding settlement (PDA update) happens AFTER this check, so we
        // must account for accrued funding here to prevent transferring positions
        // that are unhealthy once funding is settled.
        let funding_delta_e18 = pos.global_funding_index_e18
            .checked_sub(old_funding)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if !is_position_healthy(
            &slab_data,
            pos.size,
            pos.entry_price_e6,
            pos.is_long,
            pos.collateral,
            pos.engine_off,
            funding_delta_e18,
        )? {
            msg!("Transfer rejected: position is below maintenance margin (liquidatable)");
            return Err(NftError::PositionInLiquidation.into());
        }

        pos
        // slab_data (Ref) is dropped here at end of block
    };

    // ── 2. Settle funding — compute new index (write happens after CPI) ──
    new_funding = position.global_funding_index_e18;
    if old_funding != new_funding {
        msg!(
            "Funding settled on transfer: {} → {}",
            old_funding,
            new_funding
        );
    }

    // ── 3. Update position owner in slab via CPI ──
    // percolator-prog tag 69 (TransferOwnershipCpi):
    //   - Verifies caller is the NFT program's mint authority PDA
    //   - Changes account[user_idx].owner to the new wallet
    //
    // CPI data: tag(1) + user_idx(2) + new_owner(32)
    let (_, mint_auth_bump) = crate::state::mint_authority_pda(program_id);
    let cpi_data = {
        let mut d = Vec::with_capacity(35);
        d.push(TAG_TRANSFER_POSITION_OWNERSHIP);
        d.extend_from_slice(&pda_user_idx.to_le_bytes());
        d.extend_from_slice(dest_wallet.key.as_ref());
        d
    };

    // Accounts: [mint_authority(signer), slab(writable), nft_program(readonly)]
    let cpi_accounts = vec![
        solana_program::instruction::AccountMeta::new_readonly(*mint_auth.key, true),
        solana_program::instruction::AccountMeta::new(*slab.key, false),
        solana_program::instruction::AccountMeta::new_readonly(*program_id, false),
    ];

    let cpi_ix = solana_program::instruction::Instruction {
        program_id: *percolator_prog.key,
        accounts: cpi_accounts,
        data: cpi_data,
    };

    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];

    // All borrows (slab_data, pda_data) are now dropped — CPI is safe.
    invoke_signed(
        &cpi_ix,
        &[mint_auth.clone(), slab.clone()],
        &[mint_auth_seeds],
    )?;

    // ── 4. Write updated funding index to PDA (after CPI completes) ──
    {
        let mut pda_data = nft_pda.try_borrow_mut_data()?;
        let nft_state =
            bytemuck::from_bytes_mut::<PositionNft>(&mut pda_data[..POSITION_NFT_LEN]);
        nft_state.last_funding_index_e18 = new_funding;
    }

    msg!(
        "Position transferred: slab={}, idx={}, new_owner={}",
        Pubkey::new_from_array(pda_slab_bytes),
        pda_user_idx,
        dest_wallet.key
    );

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// CPI caller verification — ensure Execute is called via Token-2022
// ═══════════════════════════════════════════════════════════════

/// SPL Token Transfer instruction tag.
const TOKEN_IX_TRANSFER: u8 = 3;
/// SPL Token TransferChecked instruction tag.
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;

/// Verify that the current instruction was invoked via CPI from the Token-2022
/// program, and that the outer instruction is a Transfer or TransferChecked
/// targeting the expected mint.
///
/// This is the standard defense used by SPL TransferHook reference
/// implementations. It prevents direct invocation of the Execute handler.
///
/// How it works:
/// - On Solana, when program A CPI-calls program B, program B's instruction
///   still runs in the context of program A's top-level instruction index.
/// - We use `load_current_index_checked` to find which top-level instruction
///   is currently executing, then `load_instruction_at_checked` to read it.
/// - If we were invoked via CPI from Token-2022, the top-level instruction
///   will be Token-2022's Transfer/TransferChecked.
/// - If we were invoked directly (not via CPI), the top-level instruction
///   will be our own program — which we reject.
fn verify_cpi_caller_is_token2022(
    sysvar_ix: &AccountInfo,
    expected_mint: &Pubkey,
) -> Result<(), ProgramError> {
    // Load the index of the currently executing top-level instruction.
    let current_ix_idx = sysvar_instructions::load_current_index_checked(sysvar_ix)?;

    // Load the top-level instruction at that index.
    let current_ix =
        sysvar_instructions::load_instruction_at_checked(current_ix_idx as usize, sysvar_ix)?;

    // The outer instruction must be from Token-2022.
    if current_ix.program_id != token2022::TOKEN_2022_PROGRAM_ID {
        msg!(
            "Transfer rejected: outer instruction program {} is not Token-2022",
            current_ix.program_id
        );
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    // Verify the outer instruction is Transfer (tag 3) or TransferChecked (tag 12).
    // Both are valid Token-2022 instructions that trigger the transfer hook.
    if current_ix.data.is_empty() {
        msg!("Transfer rejected: Token-2022 instruction data is empty");
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    let ix_tag = current_ix.data[0];
    match ix_tag {
        TOKEN_IX_TRANSFER => {
            // Transfer: tag(1) + amount(8)
            // Accounts: [source, dest, authority]
            // The mint is not directly in the instruction data for Transfer,
            // but Token-2022 resolves it internally. We still validated that
            // the outer program is Token-2022 and the instruction is a Transfer,
            // which is sufficient — Token-2022 itself ensures the hook is only
            // called for the correct mint via the TransferHook extension.
            Ok(())
        }
        TOKEN_IX_TRANSFER_CHECKED => {
            // TransferChecked: tag(1) + amount(8) + decimals(1)
            // Accounts: [source, mint, dest, authority]
            // Verify the mint account in the instruction matches our expected mint.
            if current_ix.accounts.len() < 2 {
                msg!("Transfer rejected: TransferChecked has insufficient accounts");
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            let ix_mint = &current_ix.accounts[1].pubkey;
            if ix_mint != expected_mint {
                msg!(
                    "Transfer rejected: TransferChecked mint {} does not match expected {}",
                    ix_mint,
                    expected_mint
                );
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            Ok(())
        }
        _ => {
            msg!(
                "Transfer rejected: Token-2022 instruction tag {} is not Transfer or TransferChecked",
                ix_tag
            );
            Err(NftError::UnauthorizedDirectInvocation.into())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// ExtraAccountMetaList — tells Token-2022 which extra accounts
// to pass to our Execute handler
// ═══════════════════════════════════════════════════════════════

/// PDA seed for the ExtraAccountMetaList account.
pub const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";

/// Derive the ExtraAccountMetaList PDA for a given mint.
pub fn extra_account_metas_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EXTRA_METAS_SEED, mint.as_ref()], program_id)
}

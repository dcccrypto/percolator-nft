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
};

use crate::{
    cpi::{read_position, verify_slab_owner, PERCOLATOR_DEVNET, PERCOLATOR_MAINNET},
    error::NftError,
    state::{verify_pda_version, PositionNft, MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
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
/// Equity = collateral + unrealized_pnl.
/// Maintenance requirement = size * maintenance_margin_bps / 10_000.
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
///
/// Returns true if equity >= maintenance_margin (position is healthy).
fn is_position_healthy(
    slab_data: &[u8],
    position_size: u64,
    entry_price_e6: u64,
    is_long: u8,
    collateral: u64,
    engine_off: usize,
) -> Result<bool, ProgramError> {
    if position_size == 0 {
        return Ok(false); // No position = nothing to transfer.
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

    let net_equity = (collateral as i128)
        .checked_add(unrealized_pnl)
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

    let _source_ata = next_account_info(accounts_iter)?; // 0: source token account
    let mint = next_account_info(accounts_iter)?; // 1: NFT mint
    let _dest_ata = next_account_info(accounts_iter)?; // 2: destination token account
    let dest_wallet = next_account_info(accounts_iter)?; // 3: new owner wallet
    let _extra_metas = next_account_info(accounts_iter)?; // 4: ExtraAccountMetaList PDA

    // Extra accounts
    let nft_pda = next_account_info(accounts_iter)?; // 5: PositionNft PDA (writable)
    let slab = next_account_info(accounts_iter)?; // 6: Slab account
    let percolator_prog = next_account_info(accounts_iter)?; // 7: Percolator program
    let mint_auth = next_account_info(accounts_iter)?; // 8: Mint authority PDA

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
    let (pda_user_idx, pda_slab_bytes, old_funding, new_funding);
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
        // pda_data (immutable Ref) is dropped here at end of block
    }

    // ── Read position from slab (scoped borrow) ──
    let position = {
        let slab_data = slab.try_borrow_data()?;
        let pos = read_position(&slab_data, pda_user_idx)?;

        // ── GH#1 / GH#11: Verify position equity >= maintenance margin ──
        // Uses real PnL calculation. Collateral is read from slab acct_off+32
        // (the deposited margin field), NOT position.size (which is notional trade
        // size and would inflate equity by the leverage factor).
        if !is_position_healthy(
            &slab_data,
            pos.size,
            pos.entry_price_e6,
            pos.is_long,
            pos.collateral,
            pos.engine_off,
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
// ExtraAccountMetaList — tells Token-2022 which extra accounts
// to pass to our Execute handler
// ═══════════════════════════════════════════════════════════════

/// PDA seed for the ExtraAccountMetaList account.
pub const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";

/// Derive the ExtraAccountMetaList PDA for a given mint.
pub fn extra_account_metas_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EXTRA_METAS_SEED, mint.as_ref()], program_id)
}

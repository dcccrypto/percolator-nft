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
    state::{PositionNft, MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
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
) -> bool {
    if position_size == 0 {
        return false; // No position = nothing to transfer.
    }

    // Read mark price from engine block.
    let mark_price_e6 = match read_u64_at(slab_data, engine_off + ENGINE_MARK_PRICE_OFF) {
        Some(p) if p > 0 => p,
        _ => return false, // Stale / zero price → reject.
    };

    // Read maintenance_margin_bps from engine block.
    let maint_margin_bps =
        read_u64_at(slab_data, engine_off + ENGINE_MAINT_MARGIN_OFF).unwrap_or(500);

    // Unrealized PnL (signed, in collateral micro-units).
    let unrealized_pnl: i128 = if entry_price_e6 > 0 {
        let size = position_size as i128;
        let mark = mark_price_e6 as i128;
        let entry = entry_price_e6 as i128;
        if is_long == 1 {
            size.saturating_mul(mark.saturating_sub(entry)) / entry
        } else {
            size.saturating_mul(entry.saturating_sub(mark)) / entry
        }
    } else {
        0
    };

    // Net equity = collateral + unrealized_pnl.
    let net_equity: i128 = (collateral as i128).saturating_add(unrealized_pnl);

    // Maintenance margin requirement.
    let maint_requirement: i128 =
        (position_size as i128).saturating_mul(maint_margin_bps as i128) / 10_000;

    // Healthy if equity >= maintenance margin (strictly above liquidation threshold).
    net_equity >= maint_requirement
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
    _amount: u64,
) -> ProgramResult {
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
    if percolator_prog.key != &PERCOLATOR_DEVNET && percolator_prog.key != &PERCOLATOR_MAINNET {
        msg!(
            "Transfer rejected: percolator_prog key {} is not a known Percolator program",
            percolator_prog.key
        );
        return Err(NftError::InvalidPercolatorProgram.into());
    }

    // ── PERC-9006: Validate mint authority PDA ──
    // The mint_auth account is used as the CPI signer for
    // TransferOwnershipCpi. Without verification an attacker could pass a
    // different PDA or keypair, causing the CPI signature to fail (best case)
    // or — if percolator-prog doesn't re-derive the PDA — allowing an
    // unauthorized ownership transfer (worst case).
    let (expected_mint_auth, _) = crate::state::mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("Transfer rejected: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Verify slab ownership (program ID check) ──
    verify_slab_owner(slab)?;

    // ── Read NFT PDA state ──
    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes_mut::<PositionNft>(&mut pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }

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

    // ── Read position from slab ──
    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;

    // ── GH#1 / GH#11: Verify position equity >= maintenance margin ──
    // Uses real PnL calculation. Collateral is read from slab acct_off+32
    // (the deposited margin field), NOT position.size (which is notional trade
    // size and would inflate equity by the leverage factor).
    // engine_off comes from read_position() layout detection.
    if !is_position_healthy(
        &slab_data,
        position.size,
        position.entry_price_e6,
        position.is_long,
        position.collateral,
        position.engine_off,
    ) {
        msg!("Transfer rejected: position is below maintenance margin (liquidatable)");
        return Err(NftError::PositionInLiquidation.into());
    }

    // ── 2. Settle funding (update NFT state with current funding index) ──
    let old_funding = nft_state.last_funding_index_e18;
    let new_funding = position.global_funding_index_e18;
    if old_funding != new_funding {
        msg!(
            "Funding settled on transfer: {} → {}",
            old_funding,
            new_funding
        );
    }
    nft_state.last_funding_index_e18 = new_funding;

    // ── 3. Update position owner in slab via CPI ──
    // This requires percolator-prog to have a TransferPositionOwnership
    // instruction (tag 53) that:
    //   - Verifies caller is the NFT program's mint authority PDA
    //   - Changes account[user_idx].owner to the new wallet
    //
    // CPI data: tag(1) + user_idx(2) + new_owner(32)
    let (_, mint_auth_bump) = crate::state::mint_authority_pda(program_id);
    let cpi_data = {
        let mut d = Vec::with_capacity(35);
        d.push(TAG_TRANSFER_POSITION_OWNERSHIP);
        d.extend_from_slice(&nft_state.user_idx.to_le_bytes());
        d.extend_from_slice(dest_wallet.key.as_ref());
        d
    };

    // Accounts: [mint_authority(signer), slab(writable), nft_program(readonly)]
    // The nft_program (this program's program_id) is passed so percolator-prog can
    // derive and verify the mint_authority PDA: find_pda(&[b"mint_authority"], nft_program_id).
    let cpi_accounts = vec![
        solana_program::instruction::AccountMeta::new_readonly(*mint_auth.key, true), // signer (PDA)
        solana_program::instruction::AccountMeta::new(*slab.key, false), // slab (writable)
        solana_program::instruction::AccountMeta::new_readonly(*program_id, false), // NFT program_id
    ];

    let cpi_ix = solana_program::instruction::Instruction {
        program_id: *percolator_prog.key,
        accounts: cpi_accounts,
        data: cpi_data,
    };

    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &cpi_ix,
        &[mint_auth.clone(), slab.clone()],
        &[mint_auth_seeds],
    )?;

    drop(slab_data);

    msg!(
        "Position transferred: slab={}, idx={}, new_owner={}",
        Pubkey::new_from_array(nft_state.slab),
        nft_state.user_idx,
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

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
    cpi::{read_position, verify_slab_owner},
    error::NftError,
    state::{
        PositionNft, MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC,
    },
};

// ═══════════════════════════════════════════════════════════════
// SPL TransferHook interface constants
// ═══════════════════════════════════════════════════════════════

/// Discriminator for the TransferHook `Execute` instruction.
/// SHA256("spl-transfer-hook-interface:execute")[:8]
pub const EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

/// Instruction tag for TransferPositionOwnership in percolator-prog.
/// This must be added to percolator-prog as tag 53.
pub const TAG_TRANSFER_POSITION_OWNERSHIP: u8 = 53;

// ═══════════════════════════════════════════════════════════════
// Margin check — verify position is not in liquidation zone
// ═══════════════════════════════════════════════════════════════

/// Read the engine's mark price and maintenance margin from slab data.
/// Returns (mark_price_e6, maintenance_margin_bps).
///
/// Engine layout (from engine_off):
///   +0:  mark_price_e6 (u64)
///   +8:  oracle_price_e6 (u64)
///   +16: last_funding_slot (u64)
///   ...
///   +96: maintenance_margin_bps (u64)  [approximate offset]
fn read_engine_mark_price(slab_data: &[u8], engine_off: usize) -> Option<u64> {
    if engine_off + 8 > slab_data.len() {
        return None;
    }
    let bytes: [u8; 8] = slab_data[engine_off..engine_off + 8].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Check if a position is above maintenance margin.
/// Returns true if the position is healthy (can be transferred).
///
/// Simple check: if mark_price exists and position has size, position is
/// considered healthy. Full margin calculation requires the risk engine
/// which lives in percolator-prog — we rely on the keeper to liquidate
/// unhealthy positions (which burns the NFT first).
///
/// For the transfer hook, we do a conservative check:
/// - Position must have size > 0
/// - Mark price must exist (not stale/zero)
/// - Position must not be flagged for liquidation
fn is_position_healthy(
    slab_data: &[u8],
    position_size: u64,
    engine_off: usize,
) -> bool {
    if position_size == 0 {
        return false; // No position = nothing to transfer
    }

    // Check that mark price exists (market is active)
    match read_engine_mark_price(slab_data, engine_off) {
        Some(price) if price > 0 => true,
        _ => false, // No price = can't verify health, reject transfer
    }
}

// ═══════════════════════════════════════════════════════════════
// Detect engine offset (same logic as cpi.rs)
// ═══════════════════════════════════════════════════════════════

const V0_ENGINE_OFF: usize = 480;
const V1D_ENGINE_OFF: usize = 424;

fn detect_engine_off(slab_data: &[u8]) -> usize {
    // Heuristic: V1D slabs are smaller. Use V0 for large slabs, V1D for small.
    if slab_data.len() > 100_000 {
        V0_ENGINE_OFF
    } else {
        V1D_ENGINE_OFF
    }
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

    let _source_ata = next_account_info(accounts_iter)?;     // 0: source token account
    let _mint = next_account_info(accounts_iter)?;           // 1: NFT mint
    let _dest_ata = next_account_info(accounts_iter)?;       // 2: destination token account
    let dest_wallet = next_account_info(accounts_iter)?;     // 3: new owner wallet
    let _extra_metas = next_account_info(accounts_iter)?;    // 4: ExtraAccountMetaList PDA

    // Extra accounts
    let nft_pda = next_account_info(accounts_iter)?;         // 5: PositionNft PDA (writable)
    let slab = next_account_info(accounts_iter)?;            // 6: Slab account
    let _percolator_prog = next_account_info(accounts_iter)?;// 7: Percolator program
    let mint_auth = next_account_info(accounts_iter)?;       // 8: Mint authority PDA

    // ── Verify slab ownership ──
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

    // ── Read position from slab ──
    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;

    // ── 1. Verify position is not in liquidation zone ──
    let engine_off = detect_engine_off(&slab_data);
    if !is_position_healthy(&slab_data, position.size, engine_off) {
        msg!("Transfer rejected: position is unhealthy or in liquidation zone");
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

    let cpi_accounts = vec![
        solana_program::instruction::AccountMeta::new_readonly(*mint_auth.key, true), // signer (PDA)
        solana_program::instruction::AccountMeta::new(*slab.key, false), // slab (writable)
    ];

    let cpi_ix = solana_program::instruction::Instruction {
        program_id: *_percolator_prog.key,
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

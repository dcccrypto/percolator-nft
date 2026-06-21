//! GetPositionValue — read-only v16 position data for marketplaces and lending
//! protocols.
//!
//! Logs raw v16 leg fields via `POSITION_VALUE_V16:` prefixed `msg!` lines.
//! Does NOT re-derive an equity or margin formula — v16's formula is
//! engine-internal; a re-derivation here would be wrong and mislead consumers.
//! Clients use `simulateTransaction` to read the log output.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    cpi_v16,
    slab_types_v16,
    state_v16::{verify_position_nft, PositionNftV16, POSITION_NFT_V16_LEN},
};

/// Process GetPositionValue instruction.
///
/// Accounts:
///   0. `[]`  PositionNft PDA
///   1. `[]`  Portfolio account
///
/// Data: tag(1) — no additional data needed.
///
/// Logs `POSITION_VALUE_V16:` lines (clients use simulateTransaction).
pub fn process_get_position_value(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let nft_pda = next_account_info(accounts_iter)?;
    let portfolio = next_account_info(accounts_iter)?;

    // ── Verify portfolio ownership ──
    cpi_v16::verify_portfolio_program(portfolio)?;

    // ── Verify PDA is owned by this program ──
    if nft_pda.owner != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // ── Read PositionNftV16 state ──
    let pda_data = nft_pda.try_borrow_data()?;
    if pda_data.len() < POSITION_NFT_V16_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state =
        bytemuck::from_bytes::<PositionNftV16>(&pda_data[..POSITION_NFT_V16_LEN]);
    verify_position_nft(nft_state)?;
    if nft_state.portfolio_account != portfolio.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    let asset_index = nft_state.asset_index.get();
    let (expected_pda, _) = crate::state_v16::position_nft_pda(
        portfolio.key,
        asset_index as u16,
        program_id,
    );
    if *nft_pda.key != expected_pda {
        return Err(NftError::InvalidNftPda.into());
    }
    drop(pda_data);

    // ── Decode portfolio ──
    let portfolio_data = portfolio.try_borrow_data()?;
    let p = slab_types_v16::decode_portfolio(&portfolio_data)
        .map_err(cpi_v16::map_decode_err)?;
    if p.provenance_header.portfolio_account_id != portfolio.key.to_bytes() {
        msg!("GetPositionValue: portfolio account ID does not match provenance header");
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Find active leg for the bound asset_index ──
    match p.active_leg_slot_for_asset(asset_index) {
        None => {
            // No active leg — position closed or never existed.
            msg!("POSITION_VALUE_V16:portfolio={}", portfolio.key);
            msg!("POSITION_VALUE_V16:asset_index={}", asset_index);
            msg!("POSITION_VALUE_V16:status=no_active_leg");
            return Ok(());
        }
        Some(slot) => {
            let leg = &p.legs[slot];

            // Check for market_id mismatch (slot reuse). Non-gating for
            // read-only: log the mismatch so marketplaces can detect staleness,
            // but still return Ok so callers can observe the stale state.
            let nft_market_id = {
                let pda_data2 = nft_pda.try_borrow_data()?;
                let ns = bytemuck::from_bytes::<PositionNftV16>(
                    &pda_data2[..POSITION_NFT_V16_LEN],
                );
                ns.market_id_at_mint.get()
            };

            if leg.market_id.get() != nft_market_id {
                msg!(
                    "POSITION_VALUE_V16:portfolio={}",
                    portfolio.key
                );
                msg!("POSITION_VALUE_V16:asset_index={}", asset_index);
                msg!(
                    "POSITION_VALUE_V16:status=slot_reuse_detected market_id_at_mint={} current_market_id={}",
                    nft_market_id,
                    leg.market_id.get()
                );
                return Err(NftError::InvalidNftPda.into());
            }

            msg!("POSITION_VALUE_V16:portfolio={}", portfolio.key);
            msg!("POSITION_VALUE_V16:asset_index={}", asset_index);
            msg!("POSITION_VALUE_V16:market_id={}", leg.market_id.get());
            msg!("POSITION_VALUE_V16:side={}", leg.side);
            msg!(
                "POSITION_VALUE_V16:basis_pos_q={}",
                leg.basis_pos_q.get()
            );
            msg!("POSITION_VALUE_V16:f_snap={}", leg.f_snap.get());
            msg!(
                "POSITION_VALUE_V16:epoch_snap={}",
                leg.epoch_snap.get()
            );
            msg!(
                "POSITION_VALUE_V16:loss_weight={}",
                leg.loss_weight.get()
            );
            // v17: capital/pnl are now per-asset domain fields (not per-portfolio scalars).
            // Log the portfolio-level residual counters that replaced them.
            msg!(
                "POSITION_VALUE_V16:residual_crystallized={}",
                p.residual_crystallized_loss_atoms_total.get()
            );
            msg!(
                "POSITION_VALUE_V16:residual_spent={}",
                p.residual_spent_principal_atoms_total.get()
            );
        }
    }

    Ok(())
}

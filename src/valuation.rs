//! GetPositionValue — read-only v16 position data for marketplaces and lending
//! protocols.
//!
//! Emits raw v16 leg fields via `POSITION_VALUE_V16:` prefixed `msg!` lines.
//! Does NOT re-derive an equity or margin formula — v16's formula is
//! engine-internal; a re-derivation here would be wrong and mislead consumers.
//! Clients use `simulateTransaction` to read the log output.
//!
//! This instruction does NOT return a value via CPI (no `set_return_data`).
//!
//! It is fail-CLOSED. Every condition that makes the bound leg non-transferable
//! returns an error rather than `Ok(())`, so callers cannot silently observe
//! invalid state. The full set is the `LegTransferGate` variants plus
//! slot-reuse: `no_active_leg`, `leg_stale`, `portfolio_locked_or_stale`,
//! `resolved`, `close_in_progress`, `slot_reuse_detected`. Each emits
//! `POSITION_VALUE_V16:status=<reason>`; the healthy path emits `status=ok`.
//!
//! A blocked position still reports its economics, but under the separate
//! `POSITION_BLOCKED_V16:` prefix, so a consumer scanning for
//! `POSITION_VALUE_V16:` fields fails closed while one that deliberately wants
//! distressed pricing can opt in. Slot-reuse is the sole exception: its fields
//! would describe a different position instance entirely, so they are withheld.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    cpi_v16,
    error::NftError,
    slab_types_v16::{self, LegTransferGate},
    state_v16::{verify_position_nft, PositionNftV16, POSITION_NFT_V16_LEN},
};

/// Map a gate verdict to its `status=` string and the error the instruction
/// returns for it, if any.
///
/// Extracted and `pub(crate)` purely so it can be exhaustively unit-tested. The
/// status string is this instruction's real API — it returns nothing via CPI,
/// and the four blocked states deliberately share one error code, so the string
/// is the ONLY thing distinguishing them to a consumer. `msg!` output cannot be
/// captured off-chain on this `solana-program` pin (`solana-msg`'s non-BPF
/// `sol_log` is a bare `println!`, bypassing `program_stubs`), so testing the
/// mapping directly is what keeps the vocabulary from silently rotting.
pub(crate) fn gate_status(gate: LegTransferGate) -> (&'static str, Option<NftError>) {
    match gate {
        LegTransferGate::Transferable(_) => ("ok", None),
        LegTransferGate::LegStale => ("leg_stale", Some(NftError::TransferBlocked)),
        LegTransferGate::PortfolioLockedOrStale => {
            ("portfolio_locked_or_stale", Some(NftError::TransferBlocked))
        }
        LegTransferGate::Resolved => ("resolved", Some(NftError::TransferBlocked)),
        LegTransferGate::CloseInProgress => ("close_in_progress", Some(NftError::TransferBlocked)),
        LegTransferGate::NoActiveLeg => ("no_active_leg", Some(NftError::LegNotActive)),
    }
}

/// Emit the two identifying lines every response begins with. Each call site
/// then emits its own `status=` line, so the slot-reuse path can keep its extra
/// fields without duplicating these two.
fn emit_position_header(portfolio: &Pubkey, asset_index: u32) {
    msg!("POSITION_VALUE_V16:portfolio={}", portfolio);
    msg!("POSITION_VALUE_V16:asset_index={}", asset_index);
}

/// Process GetPositionValue instruction.
///
/// Emits raw leg/valuation fields via transaction logs; does NOT return a
/// value via CPI (no set_return_data). Clients use `simulateTransaction`.
///
/// Accounts:
///   0. `[]`  PositionNft PDA
///   1. `[]`  Portfolio account
///
/// Data: tag(1) — no additional data needed.
pub fn process_get_position_value(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
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
    let nft_state = bytemuck::from_bytes::<PositionNftV16>(&pda_data[..POSITION_NFT_V16_LEN]);
    verify_position_nft(nft_state)?;
    if nft_state.portfolio_account != portfolio.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    let asset_index = nft_state.asset_index.get();
    // #118/#119: Re-derive the canonical PDA using market_id_at_mint (u64),
    // NOT asset_index. market_id_at_mint is the correct second seed per #108.
    // Using asset_index here (as PR #122 did) is the critical bug: asset_index
    // is reused across positions, so it would produce the wrong PDA address.
    let market_id_at_mint = nft_state.market_id_at_mint.get();
    let (expected_pda, _) = crate::state_v16::position_nft_pda(
        portfolio.key,
        market_id_at_mint, // u64 — the correct seed per #108
        program_id,
    );
    if *nft_pda.key != expected_pda {
        msg!(
            "GetPositionValue: PDA does not match canonical derivation (market_id_at_mint={})",
            market_id_at_mint
        );
        return Err(NftError::InvalidNftPda.into());
    }
    drop(pda_data);

    // ── Decode portfolio ──
    let portfolio_data = portfolio.try_borrow_data()?;
    let p = slab_types_v16::decode_portfolio(&portfolio_data).map_err(cpi_v16::map_decode_err)?;

    cpi_v16::verify_portfolio_account_id(p, portfolio.key, "GetPositionValue")?;

    // ── Consolidated gate ──
    // Route through `leg_transfer_gate` — the same gate the transfer hook and
    // the wrapper's B-3 use — so this instruction cannot disagree with them
    // about whether a position is healthy. Previously only the no-active-leg
    // arm was checked, which left the documented fail-CLOSED-on-stale contract
    // untrue for the other four: a liquidation-locked, resolved, mid-close or
    // stale position was reported to marketplaces and lending protocols as a
    // healthy active leg, while the hook refused to move that same NFT.
    //
    // The gate decides the RESULT, not whether to answer — but a blocked
    // position's economics are emitted under a DIFFERENT prefix.
    //
    // `simulateTransaction` returns logs alongside `err`, so the data does
    // reach a caller either way. The prefix split is what makes that safe: an
    // existing integrator scanning for `POSITION_VALUE_V16:capital=` finds
    // nothing on a blocked position and fails closed, exactly as intended —
    // emitting the economics under the SAME prefix would let a parser that
    // ignores `err` keep reading a real number off a liquidation-locked
    // position, which is precisely the defect this fix exists to close.
    // A caller that wants distressed pricing opts in by reading
    // `POSITION_BLOCKED_V16:`, and can only do so deliberately.
    //
    // Withholding the numbers entirely would be worse than it sounds: the
    // engine sets `leg.b_stale` on any multi-chunk backing settlement, so
    // `LegStale` is ordinary crank-paced operation, not an exceptional state —
    // and `Resolved` is terminal and carries the position's final settled
    // value. The wrapper records the same principle for this same gate:
    // `UnwrapEscrowedPortfolio` is "deliberately NOT gated on active-leg /
    // resolved_payout_receipt / liquidation_lock / stale / close-progress"
    // because "gating on those would strand funds".
    let (status, blocked) = gate_status(p.leg_transfer_gate(asset_index));

    // #100/#118: no bound leg at all — there is no position to describe, so
    // emit only the identifying lines and fail closed.
    let slot = match p.active_leg_slot_for_asset(asset_index) {
        Some(slot) => slot,
        None => {
            emit_position_header(portfolio.key, asset_index);
            msg!("POSITION_VALUE_V16:status={}", status);
            return Err(blocked.unwrap_or(NftError::LegNotActive).into());
        }
    };
    let leg = &p.legs[slot];

    // #118: fail-CLOSED on slot-reuse (market_id mismatch). A different
    // market_id means the slot was closed and re-opened for a NEW position, so
    // the fields below would describe someone else's position entirely. This is
    // the one blocked case whose payload IS withheld — it would be actively
    // wrong rather than merely stale.
    let nft_market_id = {
        let pda_data2 = nft_pda.try_borrow_data()?;
        let ns = bytemuck::from_bytes::<PositionNftV16>(&pda_data2[..POSITION_NFT_V16_LEN]);
        ns.market_id_at_mint.get()
    };
    if leg.market_id.get() != nft_market_id {
        emit_position_header(portfolio.key, asset_index);
        // One key per line: packing extra `k=v` pairs onto the status line (as
        // this path previously did) makes `status` parse as a compound value.
        msg!("POSITION_VALUE_V16:status=slot_reuse_detected");
        msg!("POSITION_VALUE_V16:market_id_at_mint={}", nft_market_id);
        msg!(
            "POSITION_VALUE_V16:current_market_id={}",
            leg.market_id.get()
        );
        return Err(NftError::MarketIdMismatch.into());
    }

    // ── Emit the field block, then apply the gate's verdict ──
    // Healthy positions report under POSITION_VALUE_V16; blocked ones report
    // the same fields under POSITION_BLOCKED_V16 so no existing parser can
    // mistake distressed data for a quote. `status` is always emitted under the
    // well-known prefix so the reason is discoverable without opting in.
    emit_position_header(portfolio.key, asset_index);
    msg!("POSITION_VALUE_V16:status={}", status);
    if blocked.is_some() {
        msg!("POSITION_BLOCKED_V16:market_id={}", leg.market_id.get());
        msg!("POSITION_BLOCKED_V16:side={}", leg.side);
        msg!("POSITION_BLOCKED_V16:basis_pos_q={}", leg.basis_pos_q.get());
        msg!("POSITION_BLOCKED_V16:f_snap={}", leg.f_snap.get());
        msg!("POSITION_BLOCKED_V16:epoch_snap={}", leg.epoch_snap.get());
        msg!("POSITION_BLOCKED_V16:loss_weight={}", leg.loss_weight.get());
        msg!("POSITION_BLOCKED_V16:capital={}", p.capital.get());
        msg!("POSITION_BLOCKED_V16:pnl={}", p.pnl.get());
        msg!("POSITION_BLOCKED_V16:reserved_pnl={}", p.reserved_pnl.get());
        msg!(
            "POSITION_BLOCKED_V16:residual_crystallized={}",
            p.residual_crystallized_loss_atoms_total.get()
        );
        msg!(
            "POSITION_BLOCKED_V16:residual_spent={}",
            p.residual_spent_principal_atoms_total.get()
        );
        return Err(blocked.unwrap_or(NftError::TransferBlocked).into());
    }
    msg!("POSITION_VALUE_V16:market_id={}", leg.market_id.get());
    msg!("POSITION_VALUE_V16:side={}", leg.side);
    msg!("POSITION_VALUE_V16:basis_pos_q={}", leg.basis_pos_q.get());
    msg!("POSITION_VALUE_V16:f_snap={}", leg.f_snap.get());
    msg!("POSITION_VALUE_V16:epoch_snap={}", leg.epoch_snap.get());
    msg!("POSITION_VALUE_V16:loss_weight={}", leg.loss_weight.get());
    // #147: capital/pnl/reserved_pnl are RETAINED per-portfolio scalars in
    // v17 (NOT moved per-asset and NOT replaced — the residual_* counters
    // are additive and sit after them). Emit the retained scalars so a
    // consumer can read the actual position economics; logged RAW (no equity
    // re-derivation — see the module header). Units are atoms; `capital`/
    // `reserved_pnl` are unsigned, `pnl` is SIGNED (a loss prints with a
    // leading '-'). They are portfolio-level, which IS this position's P&L
    // since one NFT escrows the whole portfolio.
    msg!("POSITION_VALUE_V16:capital={}", p.capital.get());
    msg!("POSITION_VALUE_V16:pnl={}", p.pnl.get());
    msg!("POSITION_VALUE_V16:reserved_pnl={}", p.reserved_pnl.get());
    // Additive residual-loss accounting counters (portfolio-wide totals),
    // NOT the position's value.
    msg!(
        "POSITION_VALUE_V16:residual_crystallized={}",
        p.residual_crystallized_loss_atoms_total.get()
    );
    msg!(
        "POSITION_VALUE_V16:residual_spent={}",
        p.residual_spent_principal_atoms_total.get()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the `status=` vocabulary. These strings are the instruction's API:
    /// `GetPositionValue` returns nothing via CPI, and the four blocked states
    /// share error code 24, so a consumer distinguishes them by this string
    /// alone. A rename or copy-paste here is a breaking change for every
    /// integrator and must fail a test.
    #[test]
    fn gate_status_vocabulary_is_pinned() {
        let cases = [
            (LegTransferGate::Transferable(0), "ok", None),
            (
                LegTransferGate::LegStale,
                "leg_stale",
                Some(NftError::TransferBlocked),
            ),
            (
                LegTransferGate::PortfolioLockedOrStale,
                "portfolio_locked_or_stale",
                Some(NftError::TransferBlocked),
            ),
            (
                LegTransferGate::Resolved,
                "resolved",
                Some(NftError::TransferBlocked),
            ),
            (
                LegTransferGate::CloseInProgress,
                "close_in_progress",
                Some(NftError::TransferBlocked),
            ),
            (
                LegTransferGate::NoActiveLeg,
                "no_active_leg",
                Some(NftError::LegNotActive),
            ),
        ];
        for (gate, expected_status, expected_err) in cases {
            let (status, err) = gate_status(gate);
            assert_eq!(status, expected_status, "status for {gate:?}");
            assert_eq!(err, expected_err, "error for {gate:?}");
        }
    }

    /// Every status string must be distinct from every other, so a consumer can
    /// switch on it. (A copy-paste giving two states the same string would
    /// otherwise pass the mapping test above.)
    #[test]
    fn every_gate_status_string_is_distinct() {
        let all = [
            LegTransferGate::Transferable(0),
            LegTransferGate::LegStale,
            LegTransferGate::PortfolioLockedOrStale,
            LegTransferGate::Resolved,
            LegTransferGate::CloseInProgress,
            LegTransferGate::NoActiveLeg,
        ];
        let mut seen: Vec<&str> = all.iter().map(|g| gate_status(*g).0).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "duplicate status strings: {seen:?}");
    }

    /// Only `Transferable` yields Ok; everything else fails closed.
    #[test]
    fn only_transferable_is_not_an_error() {
        assert!(gate_status(LegTransferGate::Transferable(3)).1.is_none());
        for g in [
            LegTransferGate::LegStale,
            LegTransferGate::PortfolioLockedOrStale,
            LegTransferGate::Resolved,
            LegTransferGate::CloseInProgress,
            LegTransferGate::NoActiveLeg,
        ] {
            assert!(gate_status(g).1.is_some(), "{g:?} must fail closed");
        }
    }
}

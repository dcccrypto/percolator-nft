//! GetPositionValue — read-only valuation for marketplaces and lending protocols.
//!
//! Returns all data needed to value a position NFT:
//! - Net equity (Percolator spec §3.4 `Eq_maint_raw` on v12.17, mark-PnL on legacy layouts)
//! - Distance to liquidation (bps)
//! - Maintenance margin requirement
//! - Entry price (legacy layouts) / position_basis_q (v12.17), current size, direction, market
//!
//! All computed from existing on-chain slab state — no new data needed.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    cpi::{read_position, verify_slab_owner, POS_SCALE},
    error::NftError,
    state::{verify_pda_version, PositionNft, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
};

/// Read a u64 from slab data at offset (checked).
fn read_u64_checked(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[off..off + 8].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Position valuation data returned by GetPositionValue.
///
/// All values are also logged via `msg!` since Solana programs can't return
/// data directly. Clients read from transaction logs or simulate. The
/// struct is `pub` so unit tests (and downstream programs that call into
/// `compute_position_value` directly) can assert on every field without
/// re-parsing logs.
///
/// PERC-N2: v12.17 layouts (`layout_v12_17 = true`) populate `unrealized_pnl`,
/// `net_equity`, `pnl_q`, and `fee_debt_q` per Percolator spec §3.4
/// (`account_equity_maint_raw` in the upstream `percolator` crate):
///
/// ```text
///   equity_maint_raw = capital + pnl - fee_debt
///   fee_debt         = max(0, -fee_credits)
/// ```
///
/// On v12.17 the `unrealized_pnl` field carries `account.pnl` directly —
/// Percolator's authoritative running-PnL field, which folds funding
/// accruals and other realization adjustments into a single value. It is
/// NOT the legacy mark-vs-entry mark-to-market PnL; consumers must inspect
/// `layout_v12_17` and parse accordingly.
///
/// On legacy layouts (`layout_v12_17 = false`) `unrealized_pnl` is the
/// mark-vs-entry formula `size × (mark - entry) / entry` (long side), and
/// `net_equity = collateral + unrealized_pnl`. `pnl_q` and `fee_debt_q` are
/// 0 in this case.
#[derive(Debug, Clone, Copy)]
pub struct PositionValuation {
    /// Slab (market) address.
    pub slab: Pubkey,
    /// User index in slab.
    pub user_idx: u16,
    /// 1 = long, 0 = short.
    pub is_long: u8,
    /// Entry price (E6 fixed-point). 0 on v12.17 layouts (field removed).
    pub entry_price_e6: u64,
    /// Current position size — magnitude of `position_basis_q`. On legacy
    /// layouts this is in collateral micro-units; on v12.17 it is in
    /// basis-quote units scaled by `POS_SCALE` (= 1_000_000).
    pub size: u64,
    /// Current mark / oracle price (E6 fixed-point). On v12.17 this is
    /// `engine.last_oracle_price` (no separate mark field).
    pub mark_price_e6: u64,
    /// Unrealized PnL (legacy: mark-vs-entry formula in collateral micro-units).
    /// On v12.17: `account.pnl` — Percolator's authoritative persistent PnL.
    pub unrealized_pnl: i128,
    /// Collateral deposited — `account.capital` lo-word in micro-units.
    pub collateral: u64,
    /// Net equity. Legacy: `collateral + unrealized_pnl`. v12.17:
    /// `capital + pnl - fee_debt` (spec §3.4 `Eq_maint_raw_i`).
    pub net_equity: i128,
    /// Maintenance margin requirement (micro-units). Legacy: `size * bps / 10_000`.
    /// v12.17: `notional * bps / 10_000` where
    /// `notional = |position_basis_q| * mark_price_e6 / POS_SCALE`.
    pub maintenance_margin: u128,
    /// Distance to liquidation in basis points:
    /// `(net_equity - maintenance_margin) / net_equity * 10_000`.
    /// Negative ⇒ already below maintenance (immediately liquidatable).
    /// `-10_000` ⇒ `net_equity <= 0`.
    pub liquidation_distance_bps: i64,
    /// Funding index delta since NFT mint. Meaningful on legacy layouts
    /// with a single global funding index. 0 on v12.17 (per-side funding
    /// numerators are tracked in `f_long_num` / `f_short_num` instead and
    /// already accrue into `account.pnl`).
    pub funding_delta_e18: i128,
    /// `true` if the slab layout is v12.17 (no `Account.entry_price` field).
    /// Consumers MUST inspect this flag — `unrealized_pnl`, `net_equity`,
    /// and `maintenance_margin` use different formulas across the two layouts.
    pub layout_v12_17: bool,
    /// v12.17 only: raw `account.pnl` (= `unrealized_pnl` on v12.17).
    /// 0 on legacy layouts.
    pub pnl_q: i128,
    /// v12.17 only: `max(0, -fee_credits)` — Percolator's fee debt in micro-units.
    /// 0 on legacy layouts.
    pub fee_debt_q: u128,
    /// v12.17 only: notional position value in quote micro-units, computed
    /// with ceiling division for parity with upstream's `risk_notional_ceil`
    /// (`mul_div_ceil_u128(|basis_q|, mark, POS_SCALE)`). Exposed so
    /// consumers can replay `mm_req = floor(notional * bps / 10_000)`
    /// without re-multiplying. 0 on legacy layouts (the legacy
    /// `maintenance_margin` is computed straight from `size * bps / 10_000`
    /// and does not pass through a notional projection).
    pub notional_quote: u128,
}

// Engine field offsets are now layout-dependent — read from PositionData.
// V0:     mark_price=0,    maint_margin=96
// V1D:    mark_price=424,  maint_margin=80
// V12_1:  mark_price=928,  maint_margin=104 (engine at 616, params+maint_margin at 616+104)
// V12_17: mark_price=0 (last_oracle_price at engine+624), maint_margin=32 (params+0, ENGINE_OFF=504)

/// Percolator's `fee_debt_u128_checked` semantics (upstream
/// `percolator::wide_math`): a negative `fee_credits` represents debt of
/// magnitude `-fee_credits`; positive `fee_credits` is pre-paid credit.
/// `i128::MIN` is rejected by upstream as corrupt — we mirror that.
fn fee_debt_from_fee_credits(fee_credits: i128) -> Result<u128, ProgramError> {
    if fee_credits == i128::MIN {
        // Mirror upstream `fee_debt_u128_checked`: i128::MIN cannot be negated
        // without overflow; treat as corrupt slab data rather than silently
        // saturating to a finite (and therefore misleading) debt value.
        return Err(ProgramError::ArithmeticOverflow);
    }
    if fee_credits >= 0 {
        Ok(0)
    } else {
        Ok((-fee_credits) as u128)
    }
}

/// Pure computation of a position's valuation — no account validation,
/// no `msg!` logging, no CPIs. Takes `slab_data` and a pre-validated
/// `PositionNft` PDA snapshot. Used by `process_get_position_value` and
/// unit tests.
///
/// PERC-N2: Branches on `position.is_v12_17` to use Percolator spec §3.4
/// (`Eq_maint_raw = capital + pnl - fee_debt`) for v12.17 layouts, and the
/// legacy mark-vs-entry PnL formula for older layouts. Both code paths
/// share the slot-reuse / position-mismatch guards above and the
/// `liquidation_distance_bps` computation below.
pub fn compute_position_value(
    slab_data: &[u8],
    nft_state: &PositionNft,
) -> Result<PositionValuation, ProgramError> {
    let position = read_position(slab_data, nft_state.user_idx)?;

    // PERC-N1: v12.17 slot-reuse bypass fix — verify position owner has not changed.
    // On v12.17 slabs `account_id` is always 0; `account_id != stored` is always false.
    // `position_owner` is the live discriminator that changes across slot occupants.
    // MIGRATION GUARD: skip if position_owner == [0u8; 32] (pre-fix NFT). Tagged remove-after-devnet-wipe.
    if nft_state.position_owner != [0u8; 32]
        && position.owner.to_bytes() != nft_state.position_owner
    {
        return Err(NftError::SlotReused.into());
    }

    // ── PERC-9060: Verify slab slot still matches PDA snapshot ──
    // If the original position was closed and the slab slot reused for a
    // different position, entry_price_e6 and/or is_long will differ from
    // the values snapshotted at mint time. (On v12.17 both sides are 0 so
    // the check is vacuous; PERC-N1's owner check covers the slot-reuse
    // case for that layout.)
    if nft_state.entry_price_e6 != position.entry_price_e6
        || nft_state.is_long != position.is_long
    {
        return Err(NftError::PositionMismatch.into());
    }

    if position.size == 0 {
        return Err(NftError::PositionNotOpen.into());
    }

    let engine_off = position.engine_off;

    // PERC-9060: Read mark price, returning an error instead of silently
    // defaulting to 0. A zeroed mark price causes legacy unrealized_pnl to
    // compute as 0; on v12.17 it also breaks the notional/maint_margin math.
    let mark_price_e6 = read_u64_checked(slab_data, engine_off + position.engine_mark_price_off)
        .ok_or(ProgramError::from(NftError::SlabDataTooShort))?;

    let collateral = position.collateral;

    // PERC-9018: Read maintenance_margin_bps as u64 (consistent with transfer_hook.rs).
    // PERC-9060: Propagate error instead of silently defaulting to 0.
    let maint_margin_bps: u64 = read_u64_checked(slab_data, engine_off + position.engine_maint_margin_off)
        .ok_or(ProgramError::from(NftError::SlabDataTooShort))?;

    // PERC-N2: Branch on layout.
    let (unrealized_pnl, net_equity, maintenance_margin, pnl_q, fee_debt_q, notional_quote) = if position.is_v12_17 {
        // ── v12.17: Percolator spec §3.4 ──
        //
        // The Account struct dropped `entry_price` in v12.17 — the legacy
        // `size × (mark - entry) / entry` formula is undefined. Use
        // Percolator's authoritative equity formula instead:
        //
        //     Eq_maint_raw_i = capital + pnl - fee_debt
        //
        // Source of truth: `RiskEngine::account_equity_maint_raw` in the
        // `percolator` crate (`percolator-crate.rs:4899-4922`). The on-chain
        // engine uses this same expression in maintenance-margin and
        // liquidation gates.
        //
        // `position.pnl_q` is the raw `account.pnl: I128` field; on v12.17
        // this folds in funding accruals via the per-side funding mechanism
        // (`f_long_num` / `f_short_num`), so the value is a "running PnL"
        // — semantically distinct from the legacy mark-vs-entry "unrealized"
        // PnL. The struct exposes both forms via the `layout_v12_17` flag.
        let fee_debt = fee_debt_from_fee_credits(position.fee_credits_q)?;
        let equity = (collateral as i128)
            .checked_add(position.pnl_q)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .checked_sub(fee_debt as i128)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Maintenance margin on v12.17 must use the actual notional in
        // quote micro-units, not the basis-quote `size`. `size` here is
        // `|position_basis_q|` which is POS_SCALE-scaled; the legacy
        // `size × bps / 10_000` formula would under-report mm_req by a
        // factor of `mark_price_e6 / POS_SCALE`.
        //
        // PERC-N2 (review pass 2): notional uses CEILING division to match
        // upstream `wide_math::mul_div_ceil_u128(|basis_q|, mark, POS_SCALE)`
        // (see `risk_notional_ceil` at percolator-prog/src/percolator.rs:6721).
        // The mm_req step uses floor division to match upstream's
        // `mul_div_floor_u128` (see liquidation-buffer math at
        // percolator-prog.rs:7110-7120). Without the ceiling on notional,
        // a position 1 micro-unit above a clean POS_SCALE multiple would
        // report `liquidation_distance_bps` 1 unit above what the engine
        // itself computes — a lender gating on `>= 0` could extend credit
        // to a position that percolator-prog has already moved into the
        // liquidation queue.
        //
        //     notional = ceil(|position_basis_q| × mark_price / POS_SCALE)
        //     mm_req   = floor(notional × bps / 10_000)
        let num = (position.size as u128)
            .checked_mul(mark_price_e6 as u128)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        let notional = num
            .checked_add(POS_SCALE - 1)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / POS_SCALE;
        let mm_req = notional
            .checked_mul(maint_margin_bps as u128)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / 10_000;

        (position.pnl_q, equity, mm_req, position.pnl_q, fee_debt, notional)
    } else {
        // ── Legacy (V0, V1D, V12_1, V12_1_EP, V12_15): mark-vs-entry PnL ──
        //
        // PERC-9019: Compute PnL with checked arithmetic returning explicit
        // errors instead of silently producing 0 via unwrap_or(0). A
        // silently zeroed PnL can mislead lending protocols.
        let unrealized_pnl: i128 = if position.entry_price_e6 > 0 && mark_price_e6 > 0 {
            let size = position.size as i128;
            let mark = mark_price_e6 as i128;
            let entry = position.entry_price_e6 as i128;

            let price_diff = if position.is_long == 1 {
                mark.checked_sub(entry)
                    .ok_or(ProgramError::ArithmeticOverflow)?
            } else {
                entry.checked_sub(mark)
                    .ok_or(ProgramError::ArithmeticOverflow)?
            };
            size.checked_mul(price_diff)
                .ok_or(ProgramError::ArithmeticOverflow)?
                .checked_div(entry)
                .ok_or(ProgramError::ArithmeticOverflow)?
        } else {
            // Legacy layouts SHOULD have entry > 0 for any open position;
            // if not, the slab is in an anomalous state. Match historical
            // behaviour and surface unrealized_pnl=0 rather than erroring,
            // since the PERC-N1 / PERC-9060 guards above already cover the
            // "closed-and-reused" case.
            0
        };

        let net_equity = (collateral as i128)
            .checked_add(unrealized_pnl)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Legacy maint_margin: `size × bps / 10_000`. Here `size` is in
        // collateral micro-units (POS_SCALE-less) per the legacy convention.
        let mm_req = (position.size as u128)
            .checked_mul(maint_margin_bps as u128)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / 10_000;

        (unrealized_pnl, net_equity, mm_req, 0, 0, 0)
    };

    let liquidation_distance_bps: i64 = if net_equity > 0 {
        let distance = net_equity
            .checked_sub(maintenance_margin as i128)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        // PERC-9060: Use checked arithmetic and clamp before casting to prevent
        // silent truncation/wrapping that could flip the sign and make an
        // underwater position appear healthy to lending protocols.
        let bps_i128 = distance
            .checked_mul(10_000)
            .unwrap_or(if distance < 0 { i128::MIN } else { i128::MAX })
            / net_equity;
        bps_i128.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    } else {
        -10_000 // fully liquidatable
    };

    // PERC-9060 / PERC-N2: Funding-delta semantics.
    //
    // On legacy layouts: `funding_delta = global_funding - last_funding`
    // (snapshot-relative), propagated with checked arithmetic.
    //
    // On v12.17: `global_funding_index_e18` is always 0 because per-side
    // funding is tracked separately in `f_long_num` / `f_short_num` and
    // is already folded into `account.pnl`. If we naively compute
    // `0 - nft_state.last_funding_index_e18` for an NFT that was minted
    // on a LEGACY slab and is now being read against a v12.17 slab (e.g.
    // post-slab-upgrade), the PDA's stale legacy snapshot would surface
    // as a misleading negative delta. Force-zero on v12.17 — the field
    // is meaningless there and the new `pnl_q` / `fee_debt_q` lines carry
    // the actual current-state information.
    let funding_delta_e18 = if position.is_v12_17 {
        0
    } else {
        position
            .global_funding_index_e18
            .checked_sub(nft_state.last_funding_index_e18)
            .ok_or(ProgramError::ArithmeticOverflow)?
    };

    Ok(PositionValuation {
        slab: Pubkey::new_from_array(nft_state.slab),
        user_idx: nft_state.user_idx,
        is_long: position.is_long,
        entry_price_e6: position.entry_price_e6,
        size: position.size,
        mark_price_e6,
        unrealized_pnl,
        collateral,
        net_equity,
        maintenance_margin,
        liquidation_distance_bps,
        funding_delta_e18,
        layout_v12_17: position.is_v12_17,
        pnl_q,
        fee_debt_q,
        notional_quote,
    })
}

/// Process GetPositionValue instruction.
///
/// Accounts:
///   0. `[]`  PositionNft PDA
///   1. `[]`  Slab account
///
/// Data: tag(1) — no additional data needed.
///
/// Returns valuation via `msg!` logs (clients use simulateTransaction).
pub fn process_get_position_value(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let nft_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;

    // Verify slab ownership.
    verify_slab_owner(slab)?;

    // ── PERC-9003: Verify PDA is owned by this program ──
    if nft_pda.owner != _program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read NFT PDA + slab in a single scope so both borrows release before
    // the `msg!` block. `compute_position_value` takes `&PositionNft` so the
    // pda_data borrow must outlive the call; we copy the resulting struct
    // out of the scope (PositionValuation is `Copy`).
    let v = {
        let pda_data = nft_pda.try_borrow_data()?;
        if pda_data.len() < POSITION_NFT_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state =
            bytemuck::from_bytes::<PositionNft>(&pda_data[..POSITION_NFT_LEN]);
        if nft_state.magic != POSITION_NFT_MAGIC {
            return Err(ProgramError::InvalidAccountData);
        }
        verify_pda_version(nft_state)?;
        if nft_state.slab != slab.key.to_bytes() {
            return Err(ProgramError::InvalidAccountData);
        }
        let slab_data = slab.try_borrow_data()?;
        compute_position_value(&slab_data, nft_state)?
    };

    // Log valuation data (clients read via simulateTransaction).
    msg!("POSITION_VALUE:slab={}", v.slab);
    msg!("POSITION_VALUE:idx={}", v.user_idx);
    msg!(
        "POSITION_VALUE:direction={}",
        if v.is_long == 1 { "LONG" } else { "SHORT" }
    );
    // PERC-N2: tag the layout so consumers branch correctly. On v12.17 the
    // semantics of `unrealized_pnl` and `net_equity` differ — see struct doc.
    msg!(
        "POSITION_VALUE:layout={}",
        if v.layout_v12_17 { "v12_17" } else { "legacy" }
    );
    msg!("POSITION_VALUE:entry_price_e6={}", v.entry_price_e6);
    msg!("POSITION_VALUE:size={}", v.size);
    msg!("POSITION_VALUE:mark_price_e6={}", v.mark_price_e6);
    msg!("POSITION_VALUE:unrealized_pnl={}", v.unrealized_pnl);
    msg!("POSITION_VALUE:collateral={}", v.collateral);
    msg!("POSITION_VALUE:net_equity={}", v.net_equity);
    msg!("POSITION_VALUE:maintenance_margin={}", v.maintenance_margin);
    msg!(
        "POSITION_VALUE:liquidation_distance_bps={}",
        v.liquidation_distance_bps
    );
    msg!("POSITION_VALUE:funding_delta_e18={}", v.funding_delta_e18);
    if v.layout_v12_17 {
        // Expose the raw spec-§3.4 inputs so a consumer can replay
        // `equity = capital + pnl - fee_debt` directly without re-reading
        // the slab, plus the ceiling-rounded `notional_quote` that drives
        // `maintenance_margin = floor(notional_quote × bps / 10_000)`.
        msg!("POSITION_VALUE:pnl_q={}", v.pnl_q);
        msg!("POSITION_VALUE:fee_debt_q={}", v.fee_debt_q);
        msg!("POSITION_VALUE:notional_quote={}", v.notional_quote);
    }

    Ok(())
}

//! v16 portfolio read + per-handler decision logic (the testable core).
//!
//! Replaces the v12 `crate::cpi` layer (slab `detect_layout`/`read_position`).
//! v16 has ONE fixed layout, so the entire heuristic machinery collapses to
//! [`crate::slab_types_v16::decode_portfolio`]. This module adds:
//!   * [`verify_portfolio_program`] — fail-closed wrapper-program allowlist.
//!   * the pure per-handler decision functions (mint eligibility, bound-leg /
//!     slot-reuse verification, emergency-burn eligibility, transfer gate).
//!
//! The decision functions take an already-decoded `&PortfolioAccountV16Account`
//! (+ `&PositionNftV16` where relevant) so they are pure and exhaustively
//! unit-testable WITHOUT a Solana runtime. The on-chain handlers do account
//! plumbing + the (unchanged) Token-2022 CPIs around these functions; the
//! end-to-end path is verified by the A.5 LiteSVM suite.
//!
//! ## v16 position identity = `market_id` (slot-reuse anchor)
//!
//! v16 `market_id` is strictly monotonic and never reused (engine
//! `next_market_id` only ever `checked_add(1)`). It uniquely identifies a
//! position INSTANCE and is invariant across the NFT's life — it does NOT
//! change on a legitimate ownership transfer or as the position is traded.
//! It is therefore the ONLY correct slot-reuse anchor:
//!   * `provenance.owner` changes on a legit B-3 transfer → useless as a reuse
//!     gate (would false-positive on every transferred NFT).
//!   * `leg.epoch_snap` advances with funding → useless as a reuse gate
//!     (would false-positive on normal funding accrual).
//!   * `leg.basis_pos_q` changes as the position is traded → not an identity.
//!
//! So the reuse check is `market_id`-only (design-correction (b), §16.2). The
//! mint-time `epoch_snap`/`position_owner` snapshots are kept informational.

use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

// ═══════════════════════════════════════════════════════════════
// NFT registry PDA (SHARED SEED CONTRACT with percolator-prog)
// ═══════════════════════════════════════════════════════════════

/// Per-market NFT registry PDA seed. SHARED CONTRACT with percolator-prog
/// `constants::NFT_REGISTRY_SEED` / `state::derive_nft_registry`. The wrapper's
/// B-3 re-derives the SAME per-market registry PDA and validates the passed
/// account against it. The registry PDA is owned by the WRAPPER program (the
/// program that owns the portfolio account), so it is derived under
/// `wrapper_program_id` (= `portfolio.owner`), NOT the NFT program id.
pub const NFT_REGISTRY_SEED: &[u8] = b"nft_registry";

/// Derive the per-market NFT registry PDA. The PDA is owned by
/// `wrapper_program_id` (the Percolator wrapper that owns portfolio accounts)
/// and is keyed by `market_group` so each market group has its own registry.
///
/// SHARED CONTRACT: the wrapper's B-3 `TransferPortfolioOwnership` handler
/// derives the same PDA from the same seeds under the same program and validates
/// the account passed to it. Any drift between this derivation and the wrapper's
/// breaks the CPI.
pub fn derive_nft_registry(wrapper_program_id: &Pubkey, market_group: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[NFT_REGISTRY_SEED, market_group.as_ref()],
        wrapper_program_id,
    )
}

use crate::error::NftError;
use crate::slab_types_v16::{
    LegTransferGate, PortfolioAccountV16Account, PortfolioDecodeError,
};
use crate::state_v16::PositionNftV16;

// ═══════════════════════════════════════════════════════════════
// Wrapper-program allowlist (fail-closed)
// ═══════════════════════════════════════════════════════════════

/// Known Percolator wrapper program IDs. The mainnet ID is the live wrapper
/// (`ESa89R5…`, unchanged at v16 cutover per hard constraint #5).
pub const PERCOLATOR_DEVNET: Pubkey =
    solana_program::pubkey!("FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD");
pub const PERCOLATOR_MAINNET: Pubkey =
    solana_program::pubkey!("ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv");

/// Verify the portfolio account is owned by a known Percolator wrapper program.
/// Fail-closed: anything not on the allowlist is rejected. (v16 analog of v12
/// `verify_slab_owner`.)
pub fn verify_portfolio_program(portfolio_ai: &AccountInfo) -> Result<(), ProgramError> {
    if portfolio_ai.owner != &PERCOLATOR_DEVNET && portfolio_ai.owner != &PERCOLATOR_MAINNET {
        return Err(NftError::InvalidPortfolioOwner.into());
    }
    Ok(())
}

/// Map a layout-decode failure to the NFT error space, logging the specific
/// cause for diagnostics.
pub fn map_decode_err(e: PortfolioDecodeError) -> ProgramError {
    solana_program::msg!("portfolio decode failed: {:?}", e);
    NftError::PortfolioDecodeFailed.into()
}

// ═══════════════════════════════════════════════════════════════
// Per-handler decision logic (pure — unit-tested below)
// ═══════════════════════════════════════════════════════════════

/// MintPositionNft eligibility. Returns the leg array slot to snapshot.
///
/// Caller must be the portfolio owner; the requested `asset_index` must have an
/// active leg. (No LP/User `kind` gate — v16 portfolios are trading accounts;
/// LP vaults are a separate program surface.)
///
/// `asset_index` is the asset *identifier* (matched against `legs[].asset_index`,
/// engine `v16.rs` `active_leg_slot_for_asset`), NOT the `legs` array slot. Its
/// valid domain is the market-group asset registry size (`config.max_market_slots`,
/// a `u32` — engine `v16.rs:2606`), which is independent of, and `>=`,
/// `WRAPPER_MAX_PORTFOLIO_ASSETS` (the per-portfolio *active-leg count* cap;
/// engine asserts `max_portfolio_assets <= max_market_slots`, `v16.rs:1975`).
/// Earlier code rejected any `asset_index >= WRAPPER_MAX_PORTFOLIO_ASSETS (14)`,
/// which wrongly rejected legitimate positions on asset identifiers `>= 14` in
/// market groups with more than 14 assets (#94). The leg scan below is the
/// correct and sufficient gate: it succeeds iff an active leg genuinely trades
/// the requested asset, returning `LegNotActive` otherwise — identical to every
/// other handler (burn / settle / transfer-gate). No upper bound is needed; the
/// instruction decode already constrains `asset_index` to `u16`.
pub fn mint_leg_slot(
    portfolio: &PortfolioAccountV16Account,
    caller_owner: &[u8; 32],
    asset_index: u32,
) -> Result<usize, NftError> {
    if &portfolio.owner() != caller_owner {
        return Err(NftError::NotNftHolder);
    }
    portfolio
        .active_leg_slot_for_asset(asset_index)
        .ok_or(NftError::LegNotActive)
}

/// Verify the leg this NFT was minted against is still the SAME position
/// instance (used by Burn / SettleFunding). Returns the leg slot.
///
/// Slot-reuse is detected solely via `market_id` (see module docs): a reused
/// slot necessarily carries a different, higher market_id. This does NOT
/// false-positive on a legit ownership transfer (market_id is invariant) — that
/// is exactly why `provenance.owner` is NOT part of the check.
pub fn verify_bound_leg(
    portfolio: &PortfolioAccountV16Account,
    nft: &PositionNftV16,
) -> Result<usize, NftError> {
    let asset_index = nft.asset_index.get();
    let slot = portfolio
        .active_leg_slot_for_asset(asset_index)
        .ok_or(NftError::LegNotActive)?;
    if portfolio.legs[slot].market_id.get() != nft.market_id_at_mint.get() {
        return Err(NftError::MarketIdMismatch);
    }
    Ok(slot)
}

/// EmergencyBurn eligibility — the escape hatch to recover the NFT wrapper
/// (and its rent) when the NFT's BOUND position no longer exists. Burning only
/// destroys the NFT/PDA/ATA; it never touches the portfolio, so it is always
/// safe once the bound position is gone.
///
/// Eligibility is keyed on the NFT's `market_id` (the position identity), NOT
/// merely the asset_index — otherwise a holder is stranded when their position
/// closed and the asset slot was REUSED by a newer position: normal Burn would
/// reject (`MarketIdMismatch`) and an asset_index-only emergency check would
/// also reject (`PositionNotClosed`), leaving the dead NFT unburnable.
///
/// Eligible iff: no active leg for the asset (bound position closed), OR the
/// active leg's `market_id` differs from the mint snapshot (bound position
/// closed and the slot was reused), OR the bound leg is flat (`basis_pos_q == 0`).
/// Rejected only when the bound position (same market_id) is still open — then
/// the holder must use normal Burn.
pub fn emergency_burn_ok(
    portfolio: &PortfolioAccountV16Account,
    nft: &PositionNftV16,
) -> Result<(), NftError> {
    let asset_index = nft.asset_index.get();
    match portfolio.active_leg_slot_for_asset(asset_index) {
        None => Ok(()), // no active leg → bound position closed/gone
        Some(slot) => {
            let leg = &portfolio.legs[slot];
            // Eligible if the bound position is gone (slot reused with a newer
            // market_id) OR the bound leg is flat (liquidated / fully reduced).
            if leg.market_id.get() != nft.market_id_at_mint.get()
                || leg.basis_pos_q.get() == 0
            {
                Ok(())
            } else {
                Err(NftError::PositionNotClosed) // bound position still open → use normal Burn
            }
        }
    }
}

/// Transfer gate (used by ExecuteTransferHook and wrapper B-3). Maps
/// [`LegTransferGate`] to a Result. `Ok(slot)` only when the leg is active and
/// no close/resolve/stale/lock gate is engaged (original NFT bug #3).
pub fn transfer_gate_check(
    portfolio: &PortfolioAccountV16Account,
    asset_index: u32,
) -> Result<usize, NftError> {
    match portfolio.leg_transfer_gate(asset_index) {
        LegTransferGate::Transferable(slot) => Ok(slot),
        LegTransferGate::NoActiveLeg => Err(NftError::LegNotActive),
        _ => Err(NftError::TransferBlocked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slab_types_v16::{V16PodI128, V16PodU32, V16PodU64, WRAPPER_MAX_PORTFOLIO_ASSETS};
    use crate::state_v16::{PositionNftV16, POSITION_NFT_V16_MAGIC, POSITION_NFT_V16_VERSION};
    use bytemuck::Zeroable;

    // ── derive_nft_registry unit tests ──────────────────────────────────

    #[test]
    fn nft_registry_pda_is_per_market() {
        let wrapper = Pubkey::new_unique();
        let group_a = Pubkey::new_unique();
        let group_b = Pubkey::new_unique();
        let (pda_a, _) = derive_nft_registry(&wrapper, &group_a);
        let (pda_b, _) = derive_nft_registry(&wrapper, &group_b);
        // Two different market groups under the same wrapper yield different PDAs
        // (per-market correctness — each market group has its own registry).
        assert_ne!(pda_a, pda_b, "distinct market_groups must produce distinct registry PDAs");
    }

    #[test]
    fn nft_registry_pda_is_deterministic() {
        let wrapper = Pubkey::new_unique();
        let group = Pubkey::new_unique();
        let (pda1, bump1) = derive_nft_registry(&wrapper, &group);
        let (pda2, bump2) = derive_nft_registry(&wrapper, &group);
        assert_eq!(pda1, pda2, "same inputs must yield the same registry PDA");
        assert_eq!(bump1, bump2, "same inputs must yield the same bump");
    }

    fn portfolio_with_leg(owner: [u8; 32], asset_index: u32, market_id: u64, basis: i128)
        -> PortfolioAccountV16Account
    {
        let mut acct: PortfolioAccountV16Account = Zeroable::zeroed();
        acct.owner = owner;
        acct.provenance_header.owner = owner;
        acct.legs[4].active = 1;
        acct.legs[4].asset_index = V16PodU32::new(asset_index);
        acct.legs[4].market_id = V16PodU64::new(market_id);
        acct.legs[4].basis_pos_q = V16PodI128::new(basis);
        acct
    }

    fn nft_for(asset_index: u32, market_id: u64, owner: [u8; 32]) -> PositionNftV16 {
        let mut n: PositionNftV16 = Zeroable::zeroed();
        n.magic = V16PodU64::new(POSITION_NFT_V16_MAGIC);
        n.version = POSITION_NFT_V16_VERSION;
        n.asset_index = V16PodU32::new(asset_index);
        n.market_id_at_mint = V16PodU64::new(market_id);
        n.position_owner_at_mint = owner;
        n
    }

    #[test]
    fn mint_eligibility() {
        let owner = [1u8; 32];
        let p = portfolio_with_leg(owner, 9, 100, 500);
        // happy
        assert_eq!(mint_leg_slot(&p, &owner, 9), Ok(4));
        // wrong owner
        assert_eq!(mint_leg_slot(&p, &[2u8; 32], 9), Err(NftError::NotNftHolder));
        // no active leg for that asset
        assert_eq!(mint_leg_slot(&p, &owner, 10), Err(NftError::LegNotActive));
    }

    /// Regression for #94: an `asset_index >= WRAPPER_MAX_PORTFOLIO_ASSETS (14)`
    /// is a legitimate asset identifier in a market group with more than 14
    /// assets (the engine validates `asset_index < config.max_market_slots`, a
    /// `u32` — NOT against the per-portfolio active-leg count). The old code
    /// rejected any such index before scanning, stranding valid positions; mint
    /// must now succeed when an active leg genuinely trades that asset.
    #[test]
    fn mint_eligibility_high_asset_index_regression() {
        let owner = [1u8; 32];

        // A single active leg trading asset identifier 20 (>= 14): the engine
        // allows this whenever the market group configures >= 21 assets.
        let p = portfolio_with_leg(owner, 20, 100, 500);
        assert_eq!(
            mint_leg_slot(&p, &owner, 20),
            Ok(4),
            "asset_index 20 must mint (was wrongly rejected pre-#94)"
        );

        // Just above the old cap: still valid when an active leg trades it.
        let p14 = portfolio_with_leg(owner, 14, 100, 500);
        assert_eq!(mint_leg_slot(&p14, &owner, 14), Ok(4));

        // And the eligibility decision still rests on a real active leg: a high
        // asset_index with NO matching active leg correctly returns LegNotActive
        // (not a blanket range rejection).
        assert_eq!(mint_leg_slot(&p, &owner, 21), Err(NftError::LegNotActive));
        // Ownership is still enforced for high indices.
        assert_eq!(
            mint_leg_slot(&p, &[2u8; 32], 20),
            Err(NftError::NotNftHolder)
        );
        // The constant itself remains the per-portfolio active-leg cap, not an
        // asset-id domain bound (referenced to keep this invariant explicit).
        assert!(WRAPPER_MAX_PORTFOLIO_ASSETS == 14);
    }

    #[test]
    fn slot_reuse_regression_via_market_id() {
        let owner = [1u8; 32];
        let nft = nft_for(9, 100, owner);

        // same market_id -> bound leg verified (the position instance is intact)
        let p_ok = portfolio_with_leg(owner, 9, 100, 500);
        assert_eq!(verify_bound_leg(&p_ok, &nft), Ok(4));

        // legit ownership transfer: owner changed, market_id SAME -> still OK
        // (proves market_id-only does NOT false-positive on transfer).
        let mut p_transferred = portfolio_with_leg([7u8; 32], 9, 100, 500);
        p_transferred.provenance_header.owner = [7u8; 32];
        assert_eq!(verify_bound_leg(&p_transferred, &nft), Ok(4));

        // slot reused by a NEW position: same asset_index, DIFFERENT market_id
        // (higher, never-reused) -> MarketIdMismatch.
        let p_reused = portfolio_with_leg(owner, 9, 101, 500);
        assert_eq!(
            verify_bound_leg(&p_reused, &nft),
            Err(NftError::MarketIdMismatch)
        );

        // position closed (no active leg) -> LegNotActive (holder uses EmergencyBurn).
        let p_closed: PortfolioAccountV16Account = Zeroable::zeroed();
        assert_eq!(verify_bound_leg(&p_closed, &nft), Err(NftError::LegNotActive));
    }

    #[test]
    fn emergency_burn_eligibility() {
        let owner = [1u8; 32];
        let nft = nft_for(9, 100, owner); // bound to asset 9, market_id 100

        // no active leg -> eligible (bound position closed)
        let p_closed: PortfolioAccountV16Account = Zeroable::zeroed();
        assert_eq!(emergency_burn_ok(&p_closed, &nft), Ok(()));

        // bound leg present (same market_id) but flat (basis 0) -> eligible
        let p_flat = portfolio_with_leg(owner, 9, 100, 0);
        assert_eq!(emergency_burn_ok(&p_flat, &nft), Ok(()));

        // bound leg present (same market_id) and open -> NOT eligible (use normal Burn)
        let p_open = portfolio_with_leg(owner, 9, 100, 500);
        assert_eq!(
            emergency_burn_ok(&p_open, &nft),
            Err(NftError::PositionNotClosed)
        );

        // ESCAPE HATCH: asset slot reused by a NEWER open position (different
        // market_id) -> eligible. Without market_id-awareness this would strand
        // the holder (normal Burn rejects MarketIdMismatch; an asset-only
        // emergency check would reject PositionNotClosed).
        let p_reused = portfolio_with_leg(owner, 9, 205, 9999);
        assert_eq!(emergency_burn_ok(&p_reused, &nft), Ok(()));
        // and normal Burn on the same reused slab is correctly blocked:
        assert_eq!(
            verify_bound_leg(&p_reused, &nft),
            Err(NftError::MarketIdMismatch)
        );
    }

    #[test]
    fn handler_decision_lifecycle() {
        // Walk the per-handler decision functions across an NFT's life on one
        // portfolio: mint -> (transfer gate) -> settle/burn while open ->
        // close -> burn blocked / emergency-burn allowed.
        let owner = [1u8; 32];
        let p_open = portfolio_with_leg(owner, 9, 100, 500);

        // Mint: eligible, returns the leg slot.
        let slot = mint_leg_slot(&p_open, &owner, 9).expect("mint");
        let nft = nft_for(9, 100, owner);

        // Transfer gate (hook/B-3): clean -> transferable on the same slot.
        assert_eq!(transfer_gate_check(&p_open, 9), Ok(slot));
        // Burn / Settle: position intact -> bound leg verified on the same slot.
        assert_eq!(verify_bound_leg(&p_open, &nft), Ok(slot));
        // EmergencyBurn while open -> rejected (use normal Burn).
        assert_eq!(emergency_burn_ok(&p_open, &nft), Err(NftError::PositionNotClosed));

        // Position closed (leg gone): Burn/Settle -> LegNotActive; transfer
        // gate -> LegNotActive; EmergencyBurn -> allowed (recover rent).
        let p_closed: PortfolioAccountV16Account = Zeroable::zeroed();
        assert_eq!(verify_bound_leg(&p_closed, &nft), Err(NftError::LegNotActive));
        assert_eq!(transfer_gate_check(&p_closed, 9), Err(NftError::LegNotActive));
        assert_eq!(emergency_burn_ok(&p_closed, &nft), Ok(()));
    }

    #[test]
    fn transfer_gate_maps_reasons() {
        let owner = [1u8; 32];
        // transferable
        let p = portfolio_with_leg(owner, 9, 100, 500);
        assert_eq!(transfer_gate_check(&p, 9), Ok(4));
        // no active leg
        assert_eq!(transfer_gate_check(&p, 10), Err(NftError::LegNotActive));
        // blocked by lock
        let mut p_locked = portfolio_with_leg(owner, 9, 100, 500);
        p_locked.liquidation_lock = 1;
        assert_eq!(transfer_gate_check(&p_locked, 9), Err(NftError::TransferBlocked));
        // blocked by close-in-progress
        let mut p_closing = portfolio_with_leg(owner, 9, 100, 500);
        p_closing.close_progress.active = 1;
        p_closing.close_progress.asset_index = V16PodU32::new(9);
        assert_eq!(transfer_gate_check(&p_closing, 9), Err(NftError::TransferBlocked));
    }
}

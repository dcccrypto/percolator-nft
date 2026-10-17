//! v2.2 full audit 2026-10-17, workstream K: the NFT program had NO Kani harness at its head.
//! Real production fns only (`mint_leg_slot`, `verify_bound_leg`, `emergency_burn_ok`,
//! `transfer_gate_check`, `verify_portfolio_account_id`) over a portfolio whose every gate-relevant
//! byte is symbolic: owner, all 16 legs (active, asset_index, market_id, basis, stale flags), the
//! locks, the close ledger and the resolved receipt. cfg(kani) only.
use super::*;
use crate::slab_types_v16::{PortfolioAccountV16Account, V16PodI128, V16PodU32, V16PodU64, V16_MAX_PORTFOLIO_ASSETS_N};
use crate::state_v16::{PositionNftV16, POSITION_NFT_V16_MAGIC};
use bytemuck::Zeroable;

fn sym_portfolio() -> PortfolioAccountV16Account {
    let mut p: PortfolioAccountV16Account = Zeroable::zeroed();
    p.owner = kani::any();
    let mut i = 0;
    while i < V16_MAX_PORTFOLIO_ASSETS_N {
        p.legs[i].active = kani::any();
        p.legs[i].asset_index = V16PodU32::new(kani::any());
        p.legs[i].market_id = V16PodU64::new(kani::any());
        p.legs[i].basis_pos_q = V16PodI128::new(kani::any());
        p.legs[i].b_stale = kani::any();
        p.legs[i].stale = kani::any();
        i += 1;
    }
    p.stale_state = kani::any();
    p.b_stale_state = kani::any();
    p.liquidation_lock = kani::any();
    p.close_progress.active = kani::any();
    p.close_progress.asset_index = V16PodU32::new(kani::any());
    p.resolved_payout_receipt.present = kani::any();
    p
}

fn sym_nft() -> PositionNftV16 {
    let mut n: PositionNftV16 = Zeroable::zeroed();
    n.magic = V16PodU64::new(POSITION_NFT_V16_MAGIC);
    n.asset_index = V16PodU32::new(kani::any());
    n.market_id_at_mint = V16PodU64::new(kani::any());
    n
}

/// K-N1: `mint_leg_slot` is owner-gated and returns the FIRST active leg of the asset; it errors
/// exactly with `NotNftHolder` (wrong caller) or `LegNotActive` (no such active leg).
#[kani::proof]
#[kani::unwind(34)]
fn kani_audit1017_n1_mint_requires_owner_and_active_leg() {
    let p = sym_portfolio();
    let caller: [u8; 32] = kani::any();
    let asset: u32 = kani::any();
    let r = mint_leg_slot(&p, &caller, asset);
    match r {
        Ok(slot) => {
            assert!(caller == p.owner);
            assert!(slot < V16_MAX_PORTFOLIO_ASSETS_N);
            assert!(p.legs[slot].active != 0 && p.legs[slot].asset_index.get() == asset);
            let mut j = 0;
            while j < slot {
                assert!(!(p.legs[j].active != 0 && p.legs[j].asset_index.get() == asset));
                j += 1;
            }
            kani::cover!(slot > 0, "a non-first slot is selected");
        }
        Err(NftError::NotNftHolder) => {
            assert!(caller != p.owner);
            kani::cover!(true, "non-owner refused");
        }
        Err(NftError::LegNotActive) => {
            assert!(caller == p.owner);
            let mut j = 0;
            while j < V16_MAX_PORTFOLIO_ASSETS_N {
                assert!(!(p.legs[j].active != 0 && p.legs[j].asset_index.get() == asset));
                j += 1;
            }
            kani::cover!(true, "owner but no active leg");
        }
        Err(_) => assert!(false, "no other error"),
    }
}

/// K-N2: `verify_bound_leg` accepts only the SAME position instance (market_id equals the mint snapshot).
#[kani::proof]
#[kani::unwind(18)]
fn kani_audit1017_n2_bound_leg_is_same_position_instance() {
    let p = sym_portfolio();
    let nft = sym_nft();
    match verify_bound_leg(&p, &nft) {
        Ok(slot) => {
            let l = &p.legs[slot];
            assert!(l.active != 0);
            assert!(l.asset_index.get() == nft.asset_index.get());
            assert!(l.market_id.get() == nft.market_id_at_mint.get());
            kani::cover!(true, "bound leg accepted");
        }
        Err(NftError::MarketIdMismatch) => {
            let s = p.active_leg_slot_for_asset(nft.asset_index.get());
            assert!(s.is_some_and(|s| p.legs[s].market_id.get() != nft.market_id_at_mint.get()));
            kani::cover!(true, "reused slot refused");
        }
        Err(NftError::LegNotActive) => {
            assert!(p.active_leg_slot_for_asset(nft.asset_index.get()).is_none());
            kani::cover!(true, "no active leg refused");
        }
        Err(_) => assert!(false, "no other error"),
    }
}

/// K-N3: EmergencyBurn is refused ONLY while the bound position is still open, and in exactly that
/// state normal Burn is available: no state strands the holder (burn or emergency burn always works).
#[kani::proof]
#[kani::unwind(18)]
fn kani_audit1017_n3_emergency_burn_only_when_position_gone_and_never_stranded() {
    let p = sym_portfolio();
    let nft = sym_nft();
    let e = emergency_burn_ok(&p, &nft);
    let b = verify_bound_leg(&p, &nft);
    if e.is_err() {
        // refused => the bound leg is active, same market_id, non-zero basis, AND normal burn accepts it
        assert!(e == Err(NftError::PositionNotClosed));
        let s = p.active_leg_slot_for_asset(nft.asset_index.get());
        assert!(s.is_some_and(|s| p.legs[s].market_id.get() == nft.market_id_at_mint.get() && p.legs[s].basis_pos_q.get() != 0));
        assert!(b.is_ok());
        kani::cover!(true, "position open: emergency burn refused, normal burn open");
    } else {
        kani::cover!(b.is_err(), "emergency burn is the only way out (slot reused / closed)");
        kani::cover!(b.is_ok(), "both paths open (flat leg)");
    }
    // never stranded
    assert!(e.is_ok() || b.is_ok());
}

/// K-N4: the transfer gate returns a slot ONLY when every blocker is clear.
#[kani::proof]
#[kani::unwind(18)]
fn kani_audit1017_n4_transfer_gate_safety() {
    let p = sym_portfolio();
    let asset: u32 = kani::any();
    match transfer_gate_check(&p, asset) {
        Ok(slot) => {
            let l = &p.legs[slot];
            assert!(l.active != 0 && l.asset_index.get() == asset);
            assert!(p.liquidation_lock == 0 && p.stale_state == 0 && p.b_stale_state == 0);
            assert!(p.resolved_payout_receipt.present == 0);
            assert!(!(p.close_progress.active != 0 && p.close_progress.asset_index.get() == asset));
            assert!(l.b_stale == 0 && l.stale == 0);
            kani::cover!(true, "transferable");
        }
        Err(NftError::LegNotActive) => {
            assert!(p.active_leg_slot_for_asset(asset).is_none());
            kani::cover!(true, "no active leg");
        }
        Err(NftError::TransferBlocked) => {
            let s = p.active_leg_slot_for_asset(asset);
            assert!(s.is_some());
            let l = &p.legs[s.unwrap()];
            assert!(
                p.liquidation_lock != 0
                    || p.stale_state != 0
                    || p.b_stale_state != 0
                    || p.resolved_payout_receipt.present != 0
                    || (p.close_progress.active != 0 && p.close_progress.asset_index.get() == asset)
                    || l.b_stale != 0
                    || l.stale != 0
            );
            kani::cover!(p.liquidation_lock != 0, "blocked by liquidation lock");
            kani::cover!(p.resolved_payout_receipt.present != 0, "blocked by resolved receipt");
            kani::cover!(l.stale != 0 && p.liquidation_lock == 0 && p.stale_state == 0, "blocked by leg stale only");
        }
        Err(_) => assert!(false, "no other error"),
    }
}

/// K-N5: a decoded portfolio is trusted only if its provenance id IS the passed account key.
#[kani::proof]
#[kani::unwind(34)]
fn kani_audit1017_n5_portfolio_id_binds_to_key() {
    let mut p: PortfolioAccountV16Account = Zeroable::zeroed();
    p.provenance_header.portfolio_account_id = kani::any();
    let key_bytes: [u8; 32] = kani::any();
    let key = Pubkey::new_from_array(key_bytes);
    let r = verify_portfolio_account_id(&p, &key, "k");
    assert!(r.is_ok() == (p.provenance_header.portfolio_account_id == key_bytes));
    kani::cover!(r.is_ok(), "match");
    kani::cover!(r.is_err(), "mismatch");
}

//! v17 portfolio layout — vendored Percolator v17 type definitions (NFT side).
//!
//! ## What this file is
//!
//! Re-vendored against the converged v17 engine (`percolator/src/v16.rs` at tag
//! `v17-phase2-engine`). Replaces the v16-sync version (revision 3, 2907-byte
//! `PortfolioAccountV16Account`) with the v17 layout:
//!
//! * `PortfolioAccountV16Account` now embeds a fixed sparse
//!   `source_domains: [PortfolioSourceDomainV16Account; 32]` array (32 × 196 B =
//!   6272 B) between `legs` and `health_cert`, growing the fixed head from 2907 B
//!   to 9227 B — and then to **9419 B** at engine layout 18 (see below).
//! * **Layout 18 (N-1, engine `2c38570a`; introduced by `bf2fda46`, adopting
//!   upstream `92ed4a1a`)**: `PortfolioLegV16Account` gains `kf_epoch_snap`
//!   (144 → 152 B, +128 B over 16 legs) and the portfolio gains four
//!   `funding_*_atoms_total` counters (+64 B), for 9227 → 9419 B.
//!   `V16_LAYOUT_DISCRIMINATOR` moves 16 → 18 with it, and the wrapper's own
//!   header `VERSION` moves 17 → 18 (percolator-prog `fix/W-19`). All three
//!   constants are one flag day.
//! * `capital`, `pnl`, `reserved_pnl` are RETAINED from v16 (each 16 B, total
//!   48 B); they precede the `residual_*_atoms_total` counters.
//! * Additionally three `residual_*_atoms_total` counters are present, adding
//!   48 B to the v16 layout (v17 gain).
//! * `PORTFOLIO_SOURCE_DOMAIN_CAP` is `cfg(not(kani))=32` / `cfg(kani)=4`
//!   (mirroring the engine); the NFT program never runs under kani, so production
//!   always uses 32 and the vendored constant hard-codes that value.
//!
//! In v17, ONE `PortfolioAccountV16Account` is its own Solana account (no
//! 2N dynamic tail — source-domains are now an inline fixed array). The wrapper
//! stores it as:
//!
//! ```text
//!   [ 16-byte wrapper header ][ PortfolioAccountV16Account (9419 B) ][ inline matcher cfg tail ]
//!     MAGIC u64 @0                fixed head                           104 B, ignored by NFT
//!     VERSION u16 @8              starts at HEADER_LEN=16
//!     kind   u8  @10
//! ```
//!
//! (percolator-prog `PORTFOLIO_ACCOUNT_LEN` = 16 + 9419 + 104 = 9539 at layout 18.)
//!
//! [`decode_portfolio`] reads `HEADER_LEN .. HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE`
//! (16 .. 9435) and bytemuck-casts it — field access by name removes all hand-computed offsets.
//!
//! ## BPF / host byte-identity
//!
//! Every multi-byte scalar uses a `#[repr(C)]` byte-array wrapper (align 1).
//! The whole struct is packed with zero padding, byte-identical on host and SBF.
//!
//! ## Compile-time guards
//!
//! `const_assert!` on every sub-struct size + key field offsets verify internal
//! consistency of the mirror struct. They do NOT verify alignment with the live
//! engine's layout — that requires runtime validation against real on-chain data.

#![allow(dead_code)] // wired into cpi.rs / processor.rs

use core::mem::{align_of, offset_of, size_of};

// ════════════════════════════════════════════════════════════════════════════
// LAYOUT REVISION
// ════════════════════════════════════════════════════════════════════════════

/// Bump whenever assertions are intentionally re-vendored against a new engine
/// layout. Stamped into every minted NFT so re-vendoring invalidates older NFTs
/// rather than silently decoding with wrong offsets.
///
/// Revision 5: v17 layout — 9227-byte fixed `PortfolioAccountV16Account` with
/// inline `source_domains` array + retained `capital`/`pnl`/`reserved_pnl` +
/// residual counters. Corrects revision 4 which incorrectly dropped those 48 B,
/// shifting legs array 48 bytes early and causing Custom(22) LegNotActive at
/// runtime in the transfer hook. Supersedes revision 4.
///
/// Revision 6 (N-1): **engine layout 18** — 9419-byte
/// `PortfolioAccountV16Account`, 152-byte `PortfolioLegV16Account`,
/// `V16_LAYOUT_DISCRIMINATOR` 18. Engine `bf2fda46` (adopting upstream
/// `92ed4a1a`) inserted `PortfolioLegV16::kf_epoch_snap` (+8 B per leg, +128 B)
/// and four `funding_*_atoms_total` counters (+64 B) — the revision-5 mirror is
/// 192 B short and every offset from `fee_credits` onward is wrong, `legs` and
/// the `stale_state`/`liquidation_lock` transfer gates included. It did not
/// misread in practice only because the discriminator check fails closed first.
/// Ships in the same flag day as percolator-prog `fix/W-19` and the full
/// devnet re-seed.
pub const LAYOUT_REVISION: u32 = 6;

// ════════════════════════════════════════════════════════════════════════════
// WRAPPER ACCOUNT HEADER — percolator-prog/src/v16_program.rs constants
// ════════════════════════════════════════════════════════════════════════════

/// `"PERCV16\0"` little-endian. Byte 0..8 of every wrapper account.
pub const MAGIC: u64 = 0x5045_5243_5631_3600;
/// Wrapper account-format version. Byte 8..10.
///
/// Bumped 16 -> 17 to accept the protocol-fee/taker-only wrapper layout
/// change (~/v17/PROTOCOL-FEE-DESIGN.md): `WrapperConfigV16` grows 432 -> 496
/// bytes and `percolator-prog::v16_program::state::VERSION` bumps in lockstep
/// (`v16_program.rs`, `state` mod). This is the WRAPPER account's header
/// version (bytes 8..10 of every wrapper-owned account, portfolio included)
/// -- distinct from the NFT's OWN account version (`POSITION_NFT_V16_VERSION`
/// in `state_v16.rs`, currently 2, unaffected by this change).
///
/// N-1 / percolator-prog W-19: bumped 17 -> 18 IN LOCKSTEP with
/// `percolator-prog` `fix/W-19` (`src/v16_program.rs:50`, `1734196f`), which
/// raises the wrapper's own `VERSION` to 18 so that `check_header`
/// (`v16_program.rs:1546`) fail-closed rejects every account stamped under the
/// pre-layout-18 engine instead of misparsing it. The wrapper stamps this byte
/// at `write_header` (`v16_program.rs:1530`) for all seven account kinds, and
/// `decode_portfolio` below compares it for EXACT equality, so the two
/// constants are one flag day: a wrapper at 18 and an NFT at 17 makes every
/// NFT entry point that touches a portfolio return `BadVersion`.
///
/// This is a CROSS-PROGRAM constant. `percolator-prog/scripts/parity-check.sh`
/// row `nft.header_version` compares it against the wrapper's `VERSION` for
/// both the DEPLOYED and the CANDIDATE pair, and an unlisted divergence is
/// `exit 1` (`tests/KNOWN_PARITY_DIVERGENCE.txt` records the P5 deploy that
/// shipped this axis diverged and killed every nft portfolio path on devnet).
pub const VERSION: u16 = 18;
/// Account-kind discriminant for a portfolio. Byte 10.
pub const KIND_PORTFOLIO: u8 = 2;
/// Bytes consumed by the wrapper header before the engine POD begins.
pub const HEADER_LEN: usize = 16;

// ════════════════════════════════════════════════════════════════════════════
// ENGINE CONSTANTS — percolator/src/v16.rs
// ════════════════════════════════════════════════════════════════════════════

/// `ProvenanceHeaderV16.layout_discriminator` must equal this (v16/v17 guard).
///
/// N-1: 16 -> 18. The engine raised it in `bf2fda46` ("Adopt upstream 92ed4a1a:
/// track K/F settlement cohorts by generation (layout 18)"), the same commit
/// that inserted `PortfolioLegV16::kf_epoch_snap`. `decode_portfolio` compares
/// this for EXACT equality, so it is the SECOND gate — after [`VERSION`] — that
/// a layout-18 portfolio must clear. Bumping `VERSION` alone leaves the NFT
/// rejecting every real portfolio with `BadLayoutDiscriminator`.
pub const V16_LAYOUT_DISCRIMINATOR: u16 = 18;
/// `ProvenanceHeaderV16.version` must equal this.
pub const V16_ACCOUNT_VERSION: u16 = 1;
/// Number of leg slots in a portfolio's `legs` array (V16_MAX_PORTFOLIO_ASSETS_N).
pub const V16_MAX_PORTFOLIO_ASSETS_N: usize = 16;
/// `ceil(V16_MAX_PORTFOLIO_ASSETS_N / 64)` = 1.
///
/// M-1 (#160): DERIVED from the asset count, not hardcoded. The engine writes
/// the same quantity as `(V16_MAX_PORTFOLIO_ASSETS_N + 63) / 64` (`v16.rs`);
/// `div_ceil` is that value expressed the way clippy requires here. Both
/// evaluate to 1 today.
///
/// The value was previously written as a literal `1` with the formula only in
/// this comment. That is precisely the drift this module's `const_assert!`s
/// cannot catch: they compare the mirror against itself, so raising the asset
/// count past 64 would grow the engine's bitmap to two words while a literal
/// `1` stayed put — silently shifting `legs` and every field after it,
/// including the `stale_state` / `b_stale_state` / `liquidation_lock` flags the
/// transfer gate reads. The size assertion would not save us either: whoever
/// bumped the count would update `EXPECTED_PORTFOLIO_ACCOUNT_SIZE` to whatever
/// the (wrong) struct computed, and the assertion would pass.
///
/// `PORTFOLIO_SOURCE_DOMAIN_CAP` below was already derived; this closes the
/// asymmetry.
pub const V16_ACTIVE_BITMAP_WORDS: usize = V16_MAX_PORTFOLIO_ASSETS_N.div_ceil(64);
/// Largest active-leg *count* the wrapper permits per portfolio (CU envelope).
/// This is NOT a bound on the asset *identifier* (`legs[].asset_index`): an
/// NFT's `asset_index` is matched against the engine's market-group asset
/// registry, whose domain is `config.max_market_slots` (a `u32`, always
/// `>= max_portfolio_assets`; engine `v16.rs:1975`). A position may legitimately
/// trade an asset identifier `>= WRAPPER_MAX_PORTFOLIO_ASSETS` (#94). Eligibility
/// is therefore decided by `active_leg_slot_for_asset` (a scan for a matching
/// active leg), never by comparing `asset_index` to this count.
pub const WRAPPER_MAX_PORTFOLIO_ASSETS: u16 = 14;

/// v17: source-domains are now a fixed inline sparse array of this capacity.
/// Production: 2 * V16_MAX_PORTFOLIO_ASSETS_N = 32.
/// (kani uses 4 for tractability; the NFT program never runs kani.)
pub const PORTFOLIO_SOURCE_DOMAIN_CAP: usize = 2 * V16_MAX_PORTFOLIO_ASSETS_N; // = 32

// M-1 (#160): the array-length constants must stay DERIVED from
// V16_MAX_PORTFOLIO_ASSETS_N, matching the engine's own expressions. These are
// const assertions rather than #[test]s so every build checks them — including
// `cargo build-sbf`, and any environment where the dev-dependency graph cannot
// be built.
//
// This is the one drift vector the size assertions below cannot catch. They
// compare the mirror against itself, so a literal that stops tracking the
// engine's formula still yields a self-consistent struct: whoever raised the
// asset count would update EXPECTED_PORTFOLIO_ACCOUNT_SIZE to whatever the
// wrong layout computed, and every assertion would pass while `legs` and the
// gate flags after it read from shifted bytes.
const _: () = assert!(V16_ACTIVE_BITMAP_WORDS == V16_MAX_PORTFOLIO_ASSETS_N.div_ceil(64));
const _: () = assert!(PORTFOLIO_SOURCE_DOMAIN_CAP == 2 * V16_MAX_PORTFOLIO_ASSETS_N);
// The property the formula exists to guarantee, asserted independently of it:
// the bitmap must be able to address every leg slot.
const _: () = assert!(V16_ACTIVE_BITMAP_WORDS * 64 >= V16_MAX_PORTFOLIO_ASSETS_N);

// ════════════════════════════════════════════════════════════════════════════
// EXPECTED SIZES — empirically verified against the v17 engine crate
// ════════════════════════════════════════════════════════════════════════════

pub const EXPECTED_PROVENANCE_HEADER_SIZE: usize = 100;
/// N-1: 144 -> 152. Layout 18 inserted `kf_epoch_snap: u64` at offset 78.
pub const EXPECTED_PORTFOLIO_LEG_SIZE: usize = 152;
pub const EXPECTED_SOURCE_DOMAIN_SIZE: usize = 196;
pub const EXPECTED_HEALTH_CERT_SIZE: usize = 121;
pub const EXPECTED_CLOSE_PROGRESS_SIZE: usize = 184;
pub const EXPECTED_RESOLVED_PAYOUT_RECEIPT_SIZE: usize = 66;
/// N-1: 9227 -> 9419. +192 B = the four `funding_*_atoms_total` counters
/// (4 x 16 B) plus `kf_epoch_snap` in all 16 legs (16 x 8 B).
pub const EXPECTED_PORTFOLIO_ACCOUNT_SIZE: usize = 9419;

// ════════════════════════════════════════════════════════════════════════════
// POD SCALAR WRAPPERS — byte arrays, align 1 (percolator/src/v16.rs:3181-3255)
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodU16 {
    pub bytes: [u8; 2],
}
impl V16PodU16 {
    pub fn new(value: u16) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> u16 {
        u16::from_le_bytes(self.bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodU32 {
    pub bytes: [u8; 4],
}
impl V16PodU32 {
    pub fn new(value: u32) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> u32 {
        u32::from_le_bytes(self.bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodU64 {
    pub bytes: [u8; 8],
}
impl V16PodU64 {
    pub fn new(value: u64) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> u64 {
        u64::from_le_bytes(self.bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodU128 {
    pub bytes: [u8; 16],
}
impl V16PodU128 {
    pub fn new(value: u128) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> u128 {
        u128::from_le_bytes(self.bytes)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodI128 {
    pub bytes: [u8; 16],
}
impl V16PodI128 {
    pub fn new(value: i128) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> i128 {
        i128::from_le_bytes(self.bytes)
    }
}

/// Signed 64-bit, align-1 byte array. Used by the NFT's own `PositionNftV16`
/// state (e.g. `minted_at`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct V16PodI64 {
    pub bytes: [u8; 8],
}
impl V16PodI64 {
    pub fn new(value: i64) -> Self {
        Self {
            bytes: value.to_le_bytes(),
        }
    }
    pub fn get(self) -> i64 {
        i64::from_le_bytes(self.bytes)
    }
}

const _: () = assert!(size_of::<V16PodU16>() == 2 && align_of::<V16PodU16>() == 1);
const _: () = assert!(size_of::<V16PodI64>() == 8 && align_of::<V16PodI64>() == 1);
const _: () = assert!(size_of::<V16PodU32>() == 4 && align_of::<V16PodU32>() == 1);
const _: () = assert!(size_of::<V16PodU64>() == 8 && align_of::<V16PodU64>() == 1);
const _: () = assert!(size_of::<V16PodU128>() == 16 && align_of::<V16PodU128>() == 1);
const _: () = assert!(size_of::<V16PodI128>() == 16 && align_of::<V16PodI128>() == 1);

// ════════════════════════════════════════════════════════════════════════════
// ProvenanceHeaderV16Account — percolator/src/v16.rs:3937
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct ProvenanceHeaderV16Account {
    pub market_group_id: [u8; 32],
    pub portfolio_account_id: [u8; 32],
    pub owner: [u8; 32],
    pub version: V16PodU16,
    pub layout_discriminator: V16PodU16,
}

const _: () = assert!(size_of::<ProvenanceHeaderV16Account>() == EXPECTED_PROVENANCE_HEADER_SIZE);
const _: () = assert!(align_of::<ProvenanceHeaderV16Account>() == 1);
const _: () = assert!(offset_of!(ProvenanceHeaderV16Account, market_group_id) == 0);
const _: () = assert!(offset_of!(ProvenanceHeaderV16Account, portfolio_account_id) == 32);
const _: () = assert!(offset_of!(ProvenanceHeaderV16Account, owner) == 64);
const _: () = assert!(offset_of!(ProvenanceHeaderV16Account, version) == 96);
const _: () = assert!(offset_of!(ProvenanceHeaderV16Account, layout_discriminator) == 98);

// ════════════════════════════════════════════════════════════════════════════
// PortfolioLegV16Account — percolator/src/v16.rs:14571
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct PortfolioLegV16Account {
    pub active: u8,
    pub asset_index: V16PodU32,
    pub market_id: V16PodU64,
    pub side: u8,
    pub basis_pos_q: V16PodI128,
    pub a_basis: V16PodU128,
    pub k_snap: V16PodI128,
    pub f_snap: V16PodI128,
    /// Layout 18 (engine `bf2fda46`, upstream `92ed4a1a`): the K/F settlement
    /// cohort generation this leg's `k_snap`/`f_snap` were taken in. INSERTED
    /// before `epoch_snap`, so it shifts `epoch_snap` and every field after it
    /// by +8 B. The NFT does not read it; it is vendored because the offsets
    /// after it ARE read.
    pub kf_epoch_snap: V16PodU64,
    pub epoch_snap: V16PodU64,
    pub loss_weight: V16PodU128,
    pub b_snap: V16PodU128,
    pub b_rem: V16PodU128,
    pub b_epoch_snap: V16PodU64,
    pub b_stale: u8,
    pub stale: u8,
}

const _: () = assert!(size_of::<PortfolioLegV16Account>() == EXPECTED_PORTFOLIO_LEG_SIZE);
const _: () = assert!(align_of::<PortfolioLegV16Account>() == 1);
const _: () = assert!(offset_of!(PortfolioLegV16Account, active) == 0);
const _: () = assert!(offset_of!(PortfolioLegV16Account, asset_index) == 1);
const _: () = assert!(offset_of!(PortfolioLegV16Account, market_id) == 5);
const _: () = assert!(offset_of!(PortfolioLegV16Account, side) == 13);
const _: () = assert!(offset_of!(PortfolioLegV16Account, basis_pos_q) == 14);
// N-1 / layout 18: kf_epoch_snap took offset 78; epoch_snap moved 78 -> 86 and
// b_stale / stale moved 142/143 -> 150/151.
const _: () = assert!(offset_of!(PortfolioLegV16Account, kf_epoch_snap) == 78);
const _: () = assert!(offset_of!(PortfolioLegV16Account, epoch_snap) == 86);
const _: () = assert!(offset_of!(PortfolioLegV16Account, b_stale) == 150);
const _: () = assert!(offset_of!(PortfolioLegV16Account, stale) == 151);

// ════════════════════════════════════════════════════════════════════════════
// PortfolioSourceDomainV16Account — percolator/src/v16.rs:14842
// NEW in v17: fixed inline sparse array replaces the 2N dynamic tail.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct PortfolioSourceDomainV16Account {
    pub domain: V16PodU32,
    pub source_claim_market_id: V16PodU64,
    pub source_claim_bound_num: V16PodU128,
    pub source_claim_liened_num: V16PodU128,
    pub source_claim_counterparty_liened_num: V16PodU128,
    pub source_claim_insurance_liened_num: V16PodU128,
    pub source_lien_effective_reserved: V16PodU128,
    pub source_lien_counterparty_backing_num: V16PodU128,
    pub source_lien_insurance_backing_num: V16PodU128,
    pub source_lien_fee_last_slot: V16PodU64,
    pub source_claim_impaired_num: V16PodU128,
    pub source_lien_impaired_effective_reserved: V16PodU128,
    pub source_lien_capital_at_risk_fee_revenue: V16PodU128,
    pub source_lien_impaired_capital_at_risk_fee_revenue: V16PodU128,
}

const _: () = assert!(size_of::<PortfolioSourceDomainV16Account>() == EXPECTED_SOURCE_DOMAIN_SIZE);
const _: () = assert!(align_of::<PortfolioSourceDomainV16Account>() == 1);
// Field offset spot-checks (against engine v17):
const _: () = assert!(offset_of!(PortfolioSourceDomainV16Account, domain) == 0);
const _: () = assert!(offset_of!(PortfolioSourceDomainV16Account, source_claim_market_id) == 4);
const _: () = assert!(offset_of!(PortfolioSourceDomainV16Account, source_claim_bound_num) == 12);

// ════════════════════════════════════════════════════════════════════════════
// HealthCertV16Account — percolator/src/v16.rs:14639
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct HealthCertV16Account {
    pub certified_equity: V16PodI128,
    pub certified_initial_req: V16PodU128,
    pub certified_maintenance_req: V16PodU128,
    pub certified_liq_deficit: V16PodU128,
    pub certified_worst_case_loss: V16PodU128,
    pub cert_oracle_epoch: V16PodU64,
    pub cert_funding_epoch: V16PodU64,
    pub cert_risk_epoch: V16PodU64,
    pub cert_asset_set_epoch: V16PodU64,
    pub active_bitmap_at_cert: [V16PodU64; V16_ACTIVE_BITMAP_WORDS],
    pub valid: u8,
}

const _: () = assert!(size_of::<HealthCertV16Account>() == EXPECTED_HEALTH_CERT_SIZE);
const _: () = assert!(align_of::<HealthCertV16Account>() == 1);

// ════════════════════════════════════════════════════════════════════════════
// CloseProgressLedgerV16Account — percolator/src/v16.rs:14691
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct CloseProgressLedgerV16Account {
    pub active: u8,
    pub finalized: u8,
    pub canceled: u8,
    pub close_id: V16PodU64,
    pub asset_index: V16PodU32,
    pub market_id: V16PodU64,
    pub domain_side: u8,
    pub gross_loss_at_close_start: V16PodU128,
    pub drift_reference_slot: V16PodU64,
    pub max_close_slot: V16PodU64,
    pub support_consumed: V16PodU128,
    pub junior_face_burned: V16PodU128,
    pub insurance_spent: V16PodU128,
    pub b_loss_booked: V16PodU128,
    pub explicit_loss_assigned: V16PodU128,
    pub quantity_adl_applied_q: V16PodU128,
    pub drift_consumed: V16PodU128,
    pub residual_remaining: V16PodU128,
}

const _: () = assert!(size_of::<CloseProgressLedgerV16Account>() == EXPECTED_CLOSE_PROGRESS_SIZE);
const _: () = assert!(align_of::<CloseProgressLedgerV16Account>() == 1);
const _: () = assert!(offset_of!(CloseProgressLedgerV16Account, active) == 0);
const _: () = assert!(offset_of!(CloseProgressLedgerV16Account, asset_index) == 11);

// ════════════════════════════════════════════════════════════════════════════
// ResolvedPayoutReceiptV16Account — percolator/src/v16.rs:14807
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct ResolvedPayoutReceiptV16Account {
    pub prior_bound_contribution_num: V16PodU128,
    pub live_released_face_at_receipt: V16PodU128,
    pub terminal_positive_claim_face: V16PodU128,
    pub paid_effective: V16PodU128,
    pub present: u8,
    pub finalized: u8,
}

const _: () =
    assert!(size_of::<ResolvedPayoutReceiptV16Account>() == EXPECTED_RESOLVED_PAYOUT_RECEIPT_SIZE);
const _: () = assert!(align_of::<ResolvedPayoutReceiptV16Account>() == 1);
const _: () = assert!(offset_of!(ResolvedPayoutReceiptV16Account, present) == 64);
const _: () = assert!(offset_of!(ResolvedPayoutReceiptV16Account, finalized) == 65);

// ════════════════════════════════════════════════════════════════════════════
// PortfolioAccountV16Account — percolator/src/v16.rs:14898 (v17 layout)
//
// v17 changes vs v16:
//   * `capital/pnl/reserved_pnl` are RETAINED (48 B, offsets 132/148/164); the
//     `residual_crystallized_loss_atoms_total`, `residual_spent_principal_atoms_total`,
//     `residual_received_atoms_total` counters are ADDED after them (offset 180+),
//     NOT replacements. (The revision-4 vendor wrongly dropped the 48 B, shifting legs.)
//   * `source_domains: [PortfolioSourceDomainV16Account; 32]` INSERTED between
//     `legs` and `health_cert` (+6272 B). This is the dominant layout change.
//   * The NFT reads: provenance_header, owner, legs, liquidation_lock,
//     stale_state, b_stale_state, resolved_payout_receipt, close_progress.
//     All are still present; health_cert / stale / lock / close_progress /
//     resolved_payout_receipt shifted by +6272 B from prior offsets.
//
// LAYOUT 18 (N-1, engine 2c38570a) on top of that:
//   * four `funding_*_atoms_total` counters INSERTED before `fee_credits`
//     (+64 B): everything from `fee_credits` onward moves +64.
//   * `PortfolioLegV16Account` grows 144 -> 152 (`kf_epoch_snap`): everything
//     from `source_domains` onward moves a further +128.
//   * Net 9227 -> 9419. `legs` 276 -> 340, `stale_state` 8973 -> 9165,
//     `liquidation_lock` 8976 -> 9168 — i.e. EVERY field the transfer gate
//     reads moved. `V16_LAYOUT_DISCRIMINATOR` 16 -> 18 is what made the stale
//     mirror fail closed instead of misreading these bytes.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Zeroable, bytemuck::Pod)]
pub struct PortfolioAccountV16Account {
    pub provenance_header: ProvenanceHeaderV16Account,
    pub owner: [u8; 32],
    // v16 legacy margin-accounting fields — RETAINED in v17 (NOT dropped).
    // These 48 B precede the residual counters; the revision-4 vendor
    // incorrectly omitted them, shifting legs by -48 B.
    pub capital: V16PodU128,
    pub pnl: V16PodI128,
    pub reserved_pnl: V16PodU128,
    // v17 residual-farming counters (additive; sit after capital/pnl/reserved_pnl).
    pub residual_crystallized_loss_atoms_total: V16PodU128,
    pub residual_spent_principal_atoms_total: V16PodU128,
    pub residual_received_atoms_total: V16PodU128,
    // Layout 18: four funding-flow counters INSERTED between the residual
    // counters and `fee_credits` (+64 B). Monotonic reward accounting only —
    // the NFT reads none of them — but every field after them shifts.
    pub funding_long_paid_atoms_total: V16PodU128,
    pub funding_long_received_atoms_total: V16PodU128,
    pub funding_short_paid_atoms_total: V16PodU128,
    pub funding_short_received_atoms_total: V16PodU128,
    pub fee_credits: V16PodI128,
    pub cancel_deposit_escrow: V16PodU128,
    pub last_fee_slot: V16PodU64,
    pub active_bitmap: [V16PodU64; V16_ACTIVE_BITMAP_WORDS],
    pub legs: [PortfolioLegV16Account; V16_MAX_PORTFOLIO_ASSETS_N],
    // v17 NEW: fixed inline sparse source-domain array (was a dynamic 2N tail).
    pub source_domains: [PortfolioSourceDomainV16Account; PORTFOLIO_SOURCE_DOMAIN_CAP],
    pub health_cert: HealthCertV16Account,
    pub stale_state: u8,
    pub b_stale_state: u8,
    pub rebalance_lock: u8,
    pub liquidation_lock: u8,
    pub close_progress: CloseProgressLedgerV16Account,
    pub resolved_payout_receipt: ResolvedPayoutReceiptV16Account,
}

const _: () = assert!(size_of::<PortfolioAccountV16Account>() == EXPECTED_PORTFOLIO_ACCOUNT_SIZE);
const _: () = assert!(align_of::<PortfolioAccountV16Account>() == 1);
// Spot-check offsets — byte-exact match against percolator/src/v16.rs:14898.
const _: () = assert!(offset_of!(PortfolioAccountV16Account, provenance_header) == 0);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, owner) == 100);
// capital/pnl/reserved_pnl at 132/148/164 (retained from v16 — NOT dropped)
const _: () = assert!(offset_of!(PortfolioAccountV16Account, capital) == 132);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, pnl) == 148);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, reserved_pnl) == 164);
// residual counters start at 180 (after capital/pnl/reserved_pnl)
const _: () = assert!(
    offset_of!(
        PortfolioAccountV16Account,
        residual_crystallized_loss_atoms_total
    ) == 180
);
// N-1 / layout 18: the four funding_* counters occupy 228..292, so fee_credits
// and everything after it moved +64 B; legs grew 144 -> 152 each, so everything
// after `legs` moved a further +128 B.
const _: () = assert!(offset_of!(PortfolioAccountV16Account, funding_long_paid_atoms_total) == 228);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, fee_credits) == 292);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, last_fee_slot) == 324);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, active_bitmap) == 332);
// legs at 340 (was 276 before the funding_* insertion)
const _: () = assert!(offset_of!(PortfolioAccountV16Account, legs) == 340);
// source_domains: 340 + 152*16 = 340 + 2432 = 2772
const _: () = assert!(offset_of!(PortfolioAccountV16Account, source_domains) == 2772);
// health_cert: 2772 + 196*32 = 2772 + 6272 = 9044
const _: () = assert!(offset_of!(PortfolioAccountV16Account, health_cert) == 9044);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, stale_state) == 9165);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, b_stale_state) == 9166);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, rebalance_lock) == 9167);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, liquidation_lock) == 9168);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, close_progress) == 9169);
const _: () = assert!(offset_of!(PortfolioAccountV16Account, resolved_payout_receipt) == 9353);

// ════════════════════════════════════════════════════════════════════════════
// DECODE — mirrors percolator-prog `portfolio_wire`
// ════════════════════════════════════════════════════════════════════════════

/// Why a portfolio account failed to decode. Each variant maps to an
/// NFT-program error so the on-chain handler can reject precisely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortfolioDecodeError {
    /// Account data shorter than `HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE`.
    TooShort,
    /// Wrapper header MAGIC mismatch — not a percolator-v16/v17 account.
    BadMagic,
    /// Wrapper header VERSION mismatch.
    BadVersion,
    /// Account kind is not `KIND_PORTFOLIO`.
    BadKind,
    /// `bytemuck` cast failed (should be impossible after the length check).
    Cast,
    /// `provenance_header.layout_discriminator != V16_LAYOUT_DISCRIMINATOR`.
    BadLayoutDiscriminator,
    /// `provenance_header.version != V16_ACCOUNT_VERSION`.
    BadAccountVersion,
    /// Engine invariant `owner == provenance_header.owner` violated.
    OwnerMismatch,
}

/// Decode a wrapper-owned portfolio account's raw data into the vendored fixed
/// head. Validates the wrapper header, the v16/v17 provenance guard, and the
/// engine's `owner == provenance_header.owner` invariant. Any bytes beyond the
/// fixed head (e.g. inline matcher-config tail) are ignored.
///
/// SECURITY: this is the only place the NFT interprets portfolio bytes. The
/// body offset is the constant [`HEADER_LEN`] and field access is by name; no
/// offset is ever hand-computed (closes the v12 layout-offset bug class).
pub fn decode_portfolio(data: &[u8]) -> Result<&PortfolioAccountV16Account, PortfolioDecodeError> {
    if data.len() < HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE {
        return Err(PortfolioDecodeError::TooShort);
    }
    let magic = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    if magic != MAGIC {
        return Err(PortfolioDecodeError::BadMagic);
    }
    let version = u16::from_le_bytes([data[8], data[9]]);
    if version != VERSION {
        return Err(PortfolioDecodeError::BadVersion);
    }
    if data[10] != KIND_PORTFOLIO {
        return Err(PortfolioDecodeError::BadKind);
    }
    let body = &data[HEADER_LEN..HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE];
    let account: &PortfolioAccountV16Account =
        bytemuck::try_from_bytes(body).map_err(|_| PortfolioDecodeError::Cast)?;
    if account.provenance_header.layout_discriminator.get() != V16_LAYOUT_DISCRIMINATOR {
        return Err(PortfolioDecodeError::BadLayoutDiscriminator);
    }
    if account.provenance_header.version.get() != V16_ACCOUNT_VERSION {
        return Err(PortfolioDecodeError::BadAccountVersion);
    }
    if account.owner != account.provenance_header.owner {
        return Err(PortfolioDecodeError::OwnerMismatch);
    }
    Ok(account)
}

impl PortfolioAccountV16Account {
    /// Authoritative owner. (`owner == provenance_header.owner` is enforced by
    /// [`decode_portfolio`] and by the engine's `validate`.)
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }

    /// Find the leg slot whose leg is active and trades `asset_index`. Mirrors
    /// the engine's `active_leg_slot_for_asset` (`v16.rs:~14932`). `asset_index`
    /// is the asset identifier — NOT the array slot — so this scans the array.
    /// Returns `None` if no active leg trades that asset.
    pub fn active_leg_slot_for_asset(&self, asset_index: u32) -> Option<usize> {
        self.legs
            .iter()
            .position(|leg| leg.active != 0 && leg.asset_index.get() == asset_index)
    }

    /// True if a close is in progress for `asset_index` (transfer must reject).
    pub fn close_in_progress_for_asset(&self, asset_index: u32) -> bool {
        self.close_progress.active != 0 && self.close_progress.asset_index.get() == asset_index
    }

    /// True if the portfolio has a terminal payout receipt present.
    pub fn has_resolved_receipt(&self) -> bool {
        self.resolved_payout_receipt.present != 0
    }

    /// True if any portfolio-level lock/stale gate blocks free transfer.
    pub fn portfolio_locked_or_stale(&self) -> bool {
        self.liquidation_lock != 0 || self.stale_state != 0 || self.b_stale_state != 0
    }

    /// Decide whether the leg trading `asset_index` may have its ownership /
    /// NFT freely transferred RIGHT NOW. Single consolidated gate for both
    /// the transfer-hook and the wrapper's B-3 `TransferPortfolioOwnership`.
    ///
    /// Returns `Transferable(slot)` only when an active leg for the asset
    /// exists AND no close/resolve/stale/lock gate is engaged; otherwise the
    /// precise blocking reason.
    pub fn leg_transfer_gate(&self, asset_index: u32) -> LegTransferGate {
        let slot = match self.active_leg_slot_for_asset(asset_index) {
            Some(s) => s,
            None => return LegTransferGate::NoActiveLeg,
        };
        if self.portfolio_locked_or_stale() {
            return LegTransferGate::PortfolioLockedOrStale;
        }
        if self.has_resolved_receipt() {
            return LegTransferGate::Resolved;
        }
        if self.close_in_progress_for_asset(asset_index) {
            return LegTransferGate::CloseInProgress;
        }
        let leg = &self.legs[slot];
        if leg.b_stale != 0 || leg.stale != 0 {
            return LegTransferGate::LegStale;
        }
        LegTransferGate::Transferable(slot)
    }
}

/// Result of [`PortfolioAccountV16Account::leg_transfer_gate`]. Each non-OK
/// variant is a distinct reason the position is not freely transferable, so a
/// caller can return a precise error or route to EmergencyBurn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegTransferGate {
    /// The bound leg is active and unencumbered; transfer permitted. Carries
    /// the leg array slot.
    Transferable(usize),
    /// No active leg trades this asset (closed / never existed) — use EmergencyBurn.
    NoActiveLeg,
    /// A close is in progress for this asset's leg.
    CloseInProgress,
    /// The portfolio has a terminal resolved-payout receipt.
    Resolved,
    /// Portfolio-level liquidation lock or stale state engaged.
    PortfolioLockedOrStale,
    /// The bound leg itself is marked stale / b_stale.
    LegStale,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_account() -> PortfolioAccountV16Account {
        bytemuck::Zeroable::zeroed()
    }

    /// Build a minimal valid wrapper-framed portfolio buffer for an owner with a
    /// single active leg. Mirrors the wrapper's `[header][POD][tail]` framing.
    /// Layout 18: the POD is 9419 B; the tail (inline matcher cfg) is ignored by NFT.
    fn framed(owner: [u8; 32], asset_index: u32, market_id: u64) -> Vec<u8> {
        let mut acct = empty_account();
        acct.provenance_header.owner = owner;
        acct.provenance_header.version = V16PodU16::new(V16_ACCOUNT_VERSION);
        acct.provenance_header.layout_discriminator = V16PodU16::new(V16_LAYOUT_DISCRIMINATOR);
        acct.owner = owner;
        acct.legs[3].active = 1;
        acct.legs[3].asset_index = V16PodU32::new(asset_index);
        acct.legs[3].market_id = V16PodU64::new(market_id);

        // Allocate enough for header + POD + small tail (simulate the matcher cfg tail).
        let mut buf = vec![0u8; HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE + 104];
        buf[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        buf[8..10].copy_from_slice(&VERSION.to_le_bytes());
        buf[10] = KIND_PORTFOLIO;
        let body = bytemuck::bytes_of(&acct);
        buf[HEADER_LEN..HEADER_LEN + body.len()].copy_from_slice(body);
        buf
    }

    #[test]
    fn sizes_match_engine_ground_truth() {
        // These values must match the v17 engine's actual struct sizes.
        // N-1: layout 18 (engine 2c38570a) — 9227 -> 9419, leg 144 -> 152.
        assert_eq!(size_of::<PortfolioAccountV16Account>(), 9419);
        assert_eq!(size_of::<ProvenanceHeaderV16Account>(), 100);
        assert_eq!(size_of::<PortfolioLegV16Account>(), 152);
        assert_eq!(size_of::<PortfolioSourceDomainV16Account>(), 196);
        assert_eq!(size_of::<CloseProgressLedgerV16Account>(), 184);
        assert_eq!(size_of::<HealthCertV16Account>(), 121);
        assert_eq!(size_of::<ResolvedPayoutReceiptV16Account>(), 66);
        // Derived totals:
        assert_eq!(
            PORTFOLIO_SOURCE_DOMAIN_CAP * size_of::<PortfolioSourceDomainV16Account>(),
            32 * 196,
        );
    }

    /// #184 (5.1) — LAYOUT_REVISION now tracks the layout it names.
    ///
    /// This test used to read `assert_eq!(LAYOUT_REVISION, 5)`: a constant asserted
    /// against its own literal, which cannot fail and therefore guarded nothing.
    /// The audit called the constant "declared and never used"; the truth was
    /// narrower and worse — it WAS used, by a test that could not fail.
    ///
    /// Bound to a fingerprint of the sizes the revision describes, so changing any
    /// of them without bumping LAYOUT_REVISION breaks the build. That is the only
    /// property a layout-revision marker is for.
    #[test]
    fn layout_revision_tracks_the_layout_it_names() {
        // Revision 6 == this exact set of sizes. Change a size, bump the revision,
        // and update this fingerprint — deliberately three edits, so it cannot
        // happen by accident.
        let fingerprint = [
            size_of::<PortfolioAccountV16Account>(),
            size_of::<ProvenanceHeaderV16Account>(),
            size_of::<PortfolioLegV16Account>(),
            size_of::<PortfolioSourceDomainV16Account>(),
            size_of::<CloseProgressLedgerV16Account>(),
            size_of::<HealthCertV16Account>(),
            size_of::<ResolvedPayoutReceiptV16Account>(),
        ];
        let expected_for_revision_6 = [9419usize, 100, 152, 196, 184, 121, 66];
        assert_eq!(
            (LAYOUT_REVISION, fingerprint),
            (6, expected_for_revision_6),
            "the v17 layout changed without LAYOUT_REVISION being bumped (or vice versa)",
        );
    }

    #[test]
    fn decode_happy_path() {
        let owner = [7u8; 32];
        let buf = framed(owner, 9, 42);
        let acct = decode_portfolio(&buf).expect("decode");
        assert_eq!(acct.owner(), owner);
        let slot = acct.active_leg_slot_for_asset(9).expect("leg");
        assert_eq!(slot, 3);
        assert_eq!(acct.legs[slot].market_id.get(), 42);
        assert!(acct.active_leg_slot_for_asset(10).is_none());
    }

    #[test]
    fn decode_rejects_bad_header() {
        let owner = [1u8; 32];
        let mut buf = framed(owner, 1, 1);
        buf[0] ^= 0xFF;
        assert_eq!(decode_portfolio(&buf), Err(PortfolioDecodeError::BadMagic));

        let mut buf = framed(owner, 1, 1);
        buf[10] = KIND_PORTFOLIO + 1;
        assert_eq!(decode_portfolio(&buf), Err(PortfolioDecodeError::BadKind));

        let short = vec![0u8; HEADER_LEN + 10];
        assert_eq!(
            decode_portfolio(&short),
            Err(PortfolioDecodeError::TooShort)
        );
    }

    #[test]
    fn decode_rejects_owner_mismatch() {
        let mut acct = empty_account();
        acct.provenance_header.owner = [1u8; 32];
        acct.provenance_header.version = V16PodU16::new(V16_ACCOUNT_VERSION);
        acct.provenance_header.layout_discriminator = V16PodU16::new(V16_LAYOUT_DISCRIMINATOR);
        acct.owner = [2u8; 32]; // diverges from provenance owner
        let mut buf = vec![0u8; HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE];
        buf[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        buf[8..10].copy_from_slice(&VERSION.to_le_bytes());
        buf[10] = KIND_PORTFOLIO;
        buf[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&acct));
        assert_eq!(
            decode_portfolio(&buf),
            Err(PortfolioDecodeError::OwnerMismatch)
        );
    }

    #[test]
    fn decode_rejects_bad_provenance() {
        let owner = [3u8; 32];
        let mut acct = empty_account();
        acct.provenance_header.owner = owner;
        acct.owner = owner;
        acct.provenance_header.version = V16PodU16::new(V16_ACCOUNT_VERSION);
        acct.provenance_header.layout_discriminator = V16PodU16::new(99); // wrong
        let mut buf = vec![0u8; HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE];
        buf[0..8].copy_from_slice(&MAGIC.to_le_bytes());
        buf[8..10].copy_from_slice(&VERSION.to_le_bytes());
        buf[10] = KIND_PORTFOLIO;
        buf[HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&acct));
        assert_eq!(
            decode_portfolio(&buf),
            Err(PortfolioDecodeError::BadLayoutDiscriminator)
        );
    }

    #[test]
    fn leg_transfer_gate_variants() {
        // No active leg for asset 7 -> NoActiveLeg.
        let mut acct = empty_account();
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::NoActiveLeg);

        // Active leg, nothing engaged -> Transferable(slot).
        acct.legs[2].active = 1;
        acct.legs[2].asset_index = V16PodU32::new(7);
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::Transferable(2));

        // Portfolio lock blocks.
        acct.liquidation_lock = 1;
        assert_eq!(
            acct.leg_transfer_gate(7),
            LegTransferGate::PortfolioLockedOrStale
        );
        acct.liquidation_lock = 0;

        // Resolved receipt blocks.
        acct.resolved_payout_receipt.present = 1;
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::Resolved);
        acct.resolved_payout_receipt.present = 0;

        // Close-in-progress for this asset blocks.
        acct.close_progress.active = 1;
        acct.close_progress.asset_index = V16PodU32::new(7);
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::CloseInProgress);
        acct.close_progress.active = 0;

        // Per-leg stale blocks.
        acct.legs[2].stale = 1;
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::LegStale);
        acct.legs[2].stale = 0;
        acct.legs[2].b_stale = 1;
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::LegStale);
        acct.legs[2].b_stale = 0;

        // Back to clean -> Transferable.
        assert_eq!(acct.leg_transfer_gate(7), LegTransferGate::Transferable(2));
    }

    #[test]
    fn close_and_resolve_gates() {
        let mut acct = empty_account();
        acct.legs[0].active = 1;
        acct.legs[0].asset_index = V16PodU32::new(5);
        assert!(!acct.close_in_progress_for_asset(5));
        acct.close_progress.active = 1;
        acct.close_progress.asset_index = V16PodU32::new(5);
        assert!(acct.close_in_progress_for_asset(5));
        assert!(!acct.close_in_progress_for_asset(6));

        assert!(!acct.has_resolved_receipt());
        acct.resolved_payout_receipt.present = 1;
        assert!(acct.has_resolved_receipt());

        assert!(!acct.portfolio_locked_or_stale());
        acct.liquidation_lock = 1;
        assert!(acct.portfolio_locked_or_stale());
    }

    #[test]
    fn source_domain_cap_is_correct() {
        // Confirm that the production cap (2 * V16_MAX_PORTFOLIO_ASSETS_N) is
        // what we compiled with, not the kani-only 4-slot value.
        assert_eq!(PORTFOLIO_SOURCE_DOMAIN_CAP, 32);
        assert_eq!(
            size_of::<PortfolioAccountV16Account>(),
            // provenance_header (100) + owner (32) +
            // capital (16) + pnl (16) + reserved_pnl (16) [retained from v16] +
            // residuals (3*16=48) + funding_* (4*16=64) [layout 18] +
            // fee_credits (16) + cancel_escrow (16) +
            // last_fee_slot (8) + bitmap (8) +
            // legs (152*16=2432) [layout 18] + source_domains (196*32=6272) +
            // health_cert (121) + 4 lock/stale bytes + close_progress (184) +
            // resolved_receipt (66)
            100 + 32 + 16 + 16 + 16 + 48 + 64 + 16 + 16 + 8 + 8 + 2432 + 6272 + 121 + 4 + 184 + 66
        );
    }
}

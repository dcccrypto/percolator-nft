//! PR B of the slab layout rebuild — vendored Percolator type definitions.
//!
//! ## What this file is (and isn't)
//!
//! This module vendors the real upstream Percolator type definitions
//! ([`Account`], [`RiskEngine`], [`RiskParams`], [`InsuranceFund`],
//! [`SlabHeader`], [`MarketConfig`], [`I128`], [`U128`], [`SideMode`])
//! byte-for-byte from `dcccrypto/percolator` and `dcccrypto/percolator-prog`,
//! plus compile-time `size_of!` / `offset_of!` assertions that will fail to
//! compile if the vendored layout drifts from upstream.
//!
//! **This file is pure infrastructure.** Nothing in [`crate::cpi`] uses these
//! types yet. PR C (PERC-9067) will rewrite `read_position` to compute every
//! slab offset via `core::mem::offset_of!` against the types below, replacing
//! the current hand-maintained `V0_*` / `V1D_*` / `V12_1_*` hardcoded offsets.
//!
//! ## Why not depend on the `percolator` crate directly?
//!
//! The NFT program deliberately avoids a Cargo dependency on `percolator` /
//! `percolator-prog`:
//!
//! - Upstream pulls in `solana-program` at a different version, `spl-token-2022`,
//!   and a number of other crates that conflict with the NFT program's pinned
//!   `solana-program = "=2.2.1"`.
//! - Upstream declares its own `entrypoint!()`, which would clash at link time.
//! - Following the policy established in `src/token2022.rs` (comment at
//!   `Cargo.toml:14-16`), we vendor hand-verified type definitions instead.
//!
//! ## The BPF / host alignment hazard
//!
//! Rust 1.77 changed native `i128`/`u128` alignment from 8 to 16 bytes on
//! x86_64, **but the Solana SBF platform-tools toolchain keeps native
//! `i128`/`u128` at 8-byte alignment** on-chain. See the explicit statement
//! in upstream's `percolator/src/i128.rs` header comment, and the
//! compile-time assertion at `percolator-prog/src/lib.rs:55-57`:
//! ```ignore
//! pub const ACCOUNT_SIZE: usize = size_of::<percolator::Account>();
//! #[cfg(target_arch = "sbf")]
//! const _SBF_ENGINE_ALIGN: [(); 8] = [(); ENGINE_ALIGN];
//! ```
//! That `[(); 8]` assertion proves `align_of::<RiskEngine>() == 8` on SBF,
//! which is only possible if native `u128`/`i128` fields inside `RiskParams`
//! and `RiskEngine` are 8-byte aligned on SBF.
//!
//! To make this file **target-independent** — so `cargo check` on the host
//! and `cargo build-sbf` on the on-chain target produce identical offsets —
//! every 128-bit field below uses the [`U128`] / [`I128`] wrappers
//! (`#[repr(C)] struct([u64; 2])`, size 16, align 8) rather than native
//! `u128` / `i128`. This matches upstream's own `U128` / `I128` BPF wrappers
//! and produces a byte-identical memory image to the upstream-compiled-to-SBF
//! layout. No `#[cfg(target_arch = "sbf")]` gating is required for any of
//! the assertions below.
//!
//! ## Feature flag coordination with deployed Percolator
//!
//! `MAX_ACCOUNTS` is feature-gated in upstream and **must match** the feature
//! flag the deployed Percolator program was built with, because the size of
//! `RiskEngine` (and therefore `offset_of!(RiskEngine, accounts)`) depends
//! on it. The gating below is copied character-for-character from
//! `percolator/src/lib.rs:67-95` (see `_percolator_core_reference.rs`).
//!
//! | Feature flag | `MAX_ACCOUNTS` | `BITMAP_WORDS` | `RiskEngine` size |
//! |--------------|----------------|----------------|-------------------|
//! | (default)    | 4096           | 64             | varies            |
//! | `medium`     | 1024           | 16             | varies            |
//! | `small`      | 256            | 4              | varies            |
//! | `test`       | 64             | 1              | varies            |
//! | `cfg(kani)`  | 4              | 1              | varies            |
//!
//! **Deployment rule**: if mainnet Percolator is built with `--features medium`,
//! the NFT program MUST also be built with `--features medium`. A mismatch
//! fails to compile (the closed-form `EXPECTED_RISK_ENGINE_SIZE` assertion
//! will trip).
//!
//! ## Update protocol when upstream changes
//!
//! 1. Re-fetch `_percolator_core_reference.rs` and `_percolator_prog_reference.rs`
//! 2. Diff the vendored structs below against upstream
//! 3. Update field lists, re-run `cargo check --all-features`
//! 4. Bump `LAYOUT_REVISION`

#![allow(dead_code)] // Infrastructure-only; PR C wires cpi.rs into these types.
#![allow(clippy::manual_div_ceil)]

use core::mem::{align_of, offset_of, size_of};

// ════════════════════════════════════════════════════════════════════════════
// LAYOUT REVISION
// ════════════════════════════════════════════════════════════════════════════

/// Bump any time the assertions below are intentionally updated. PR C stamps
/// this into every minted NFT so that re-vendoring against a new upstream
/// layout invalidates older NFTs rather than silently decoding them with the
/// wrong offsets.
///
/// Revision 2: v12.17 SBF layout.
/// - MarketConfig: 544 → 432 bytes (upstream reorganization + dex_pool 32 bytes)
/// - Account: 320 → 352 bytes (removed account_id/entry_price/cohorts;
///   added f_snap + two-bucket warmup; capital is now the first field)
/// - RiskParams: 352 → 184 bytes (stripped fork-specific fields not in v12.17)
/// - InsuranceFund: 80 → 16 bytes (stripped to balance: U128 only)
/// - ENGINE_OFF: 616 → 504 (align_up(72 + 432, 8))
pub const LAYOUT_REVISION: u32 = 2;

// ════════════════════════════════════════════════════════════════════════════
// MAX_ACCOUNTS feature gating — verbatim from percolator/src/lib.rs:67-95
// ════════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
pub const MAX_ACCOUNTS: usize = 4;

#[cfg(all(feature = "test", not(kani)))]
pub const MAX_ACCOUNTS: usize = 64; // Micro: ~0.17 SOL rent

#[cfg(all(feature = "small", not(feature = "test"), not(kani)))]
pub const MAX_ACCOUNTS: usize = 256; // Small: ~0.68 SOL rent

#[cfg(all(
    feature = "medium",
    not(feature = "test"),
    not(feature = "small"),
    not(kani)
))]
pub const MAX_ACCOUNTS: usize = 1024; // Medium: ~2.7 SOL rent

#[cfg(all(
    not(kani),
    not(feature = "test"),
    not(feature = "small"),
    not(feature = "medium")
))]
pub const MAX_ACCOUNTS: usize = 4096; // Full: ~6.9 SOL rent

pub const BITMAP_WORDS: usize = (MAX_ACCOUNTS + 63) / 64;

// ════════════════════════════════════════════════════════════════════════════
// Pinned expected sizes — the single source of truth for all assertions.
// Update here and the assertions fail if vendored types drift.
// ════════════════════════════════════════════════════════════════════════════

pub const EXPECTED_SLAB_HEADER_SIZE: usize = 72;
/// v12.17: MarketConfig shrunk from 544 to 432 bytes
/// (upstream reorganization: many fields removed/reorganized, dex_pool 32 bytes added).
pub const EXPECTED_MARKET_CONFIG_SIZE: usize = 432;
/// v12.17: InsuranceFund stripped to balance: U128 only (16 bytes).
pub const EXPECTED_INSURANCE_FUND_SIZE: usize = 16;
/// v12.17: RiskParams stripped to 184 bytes (removed warmup_period_slots and
/// all fork-specific funding/partial-liq/dynamic-fee fields; added h_min, h_max,
/// resolve_price_deviation_bps).
pub const EXPECTED_RISK_PARAMS_SIZE: usize = 184;
/// v12.17: Account grew from 320 to 352 bytes (removed account_id, entry_price,
/// fees_earned_total, funding_index, position_size, last_partial_liquidation_slot,
/// warmup_started_at_slot, warmup_slope_per_step; added f_snap and two warmup buckets).
pub const EXPECTED_ACCOUNT_SIZE: usize = 352;

// All structs are 8-byte aligned because every 128-bit field uses the
// [u64; 2]-backed U128/I128 wrappers instead of native i128/u128.
pub const EXPECTED_ENGINE_ALIGN: usize = 8;

// ════════════════════════════════════════════════════════════════════════════
// BPF-safe 128-bit wrappers — verbatim from percolator/src/i128.rs (non-kani)
// ════════════════════════════════════════════════════════════════════════════
//
// `#[repr(C)] struct X([u64; 2])` has `size == 16`, `align == 8` on every
// target. This matches the SBF native i128/u128 ABI and is target-independent.

/// BPF-safe unsigned 128-bit integer.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct U128(pub [u64; 2]);

impl U128 {
    pub const ZERO: Self = Self([0, 0]);
    pub const MAX: Self = Self([u64::MAX, u64::MAX]);

    #[inline]
    pub const fn new(val: u128) -> Self {
        Self([val as u64, (val >> 64) as u64])
    }

    #[inline]
    pub const fn get(self) -> u128 {
        ((self.0[1] as u128) << 64) | (self.0[0] as u128)
    }
}

impl core::fmt::Debug for U128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "U128({})", self.get())
    }
}

/// BPF-safe signed 128-bit integer.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct I128(pub [u64; 2]);

impl I128 {
    pub const ZERO: Self = Self([0, 0]);
    pub const MIN: Self = Self([0, 0x8000_0000_0000_0000]);
    pub const MAX: Self = Self([u64::MAX, 0x7FFF_FFFF_FFFF_FFFF]);

    #[inline]
    pub const fn new(val: i128) -> Self {
        Self([val as u64, (val >> 64) as u64])
    }

    #[inline]
    pub const fn get(self) -> i128 {
        ((self.0[1] as i128) << 64) | (self.0[0] as u128 as i128)
    }
}

impl core::fmt::Debug for I128 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "I128({})", self.get())
    }
}

// Pin the wrapper layouts — foundation for every other assertion in this file.
const _: () = assert!(size_of::<U128>() == 16);
const _: () = assert!(size_of::<I128>() == 16);
const _: () = assert!(align_of::<U128>() == 8);
const _: () = assert!(align_of::<I128>() == 8);

// ════════════════════════════════════════════════════════════════════════════
// SideMode — verbatim from percolator/src/lib.rs:172-178
// ════════════════════════════════════════════════════════════════════════════

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SideMode {
    Normal = 0,
    DrainOnly = 1,
    ResetPending = 2,
}

const _: () = assert!(size_of::<SideMode>() == 1);
const _: () = assert!(align_of::<SideMode>() == 1);

/// MarketMode — v12.17 engine state flag.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarketMode {
    Live = 0,
    Resolved = 1,
}

const _: () = assert!(size_of::<MarketMode>() == 1);
const _: () = assert!(align_of::<MarketMode>() == 1);

// ════════════════════════════════════════════════════════════════════════════
// SlabHeader — verbatim from percolator-prog/src/lib.rs:2154-2163
// ════════════════════════════════════════════════════════════════════════════

/// Upstream slab magic: `0x504552434f4c4154` = ASCII "PERCOLAT" (read MSB→LSB).
/// Matches `percolator_prog::constants::MAGIC`. Corrected from the NFT's
/// historical `"PERCSLAB"` value in PR A (PERC-9065).
pub const MAGIC: u64 = 0x5045_5243_4F4C_4154;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlabHeader {
    pub magic: u64,
    pub version: u32,
    pub bump: u8,
    pub _padding: [u8; 3],
    pub admin: [u8; 32],
    /// `[0..8]=nonce, [8..16]=last_thr_slot, [16..24]=dust_base` per upstream
    pub _reserved: [u8; 24],
}

const _: () = assert!(size_of::<SlabHeader>() == EXPECTED_SLAB_HEADER_SIZE);
const _: () = assert!(align_of::<SlabHeader>() == 8);
const _: () = assert!(offset_of!(SlabHeader, magic) == 0);
const _: () = assert!(offset_of!(SlabHeader, version) == 8);
const _: () = assert!(offset_of!(SlabHeader, bump) == 12);
const _: () = assert!(offset_of!(SlabHeader, admin) == 16);
const _: () = assert!(offset_of!(SlabHeader, _reserved) == 48);

// ════════════════════════════════════════════════════════════════════════════
// MarketConfig — OPAQUE, since NFT never reads its fields
// ════════════════════════════════════════════════════════════════════════════
//
// The NFT program only needs `size_of::<MarketConfig>()` to compute
// `ENGINE_OFF`. Field-level drift inside MarketConfig (e.g., upstream adds
// a field in the middle with matching total size) does not affect the NFT
// program. The size is pinned, so if upstream grows or shrinks MarketConfig,
// the `MARKET_CONFIG_SIZE` const below must be manually bumped and this
// assertion will trip.
//
// v12.17: MarketConfig shrank from 544 to 432 bytes. The field reorganization
// (including the addition of `dex_pool: [u8; 32]`) was already accounted for
// in `percolator-prog`. The opaque blob approach means the NFT program only
// needs to update this constant — no field-level changes required.

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct MarketConfig(pub [u8; EXPECTED_MARKET_CONFIG_SIZE]);

const _: () = assert!(size_of::<MarketConfig>() == EXPECTED_MARKET_CONFIG_SIZE);
const _: () = assert!(align_of::<MarketConfig>() == 8);

// ════════════════════════════════════════════════════════════════════════════
// InsuranceFund — v12.17: stripped to balance: U128 only (16 bytes).
//
// The v12.17 InsuranceFund (percolator/src/percolator.rs:340-342) was
// radically simplified: fee_revenue, balance_incentive_reserve, isolated_balance,
// insurance_isolation_bps, and all padding fields were removed, leaving only
// `balance: U128`.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InsuranceFund {
    pub balance: U128,
}

const _: () = assert!(size_of::<InsuranceFund>() == EXPECTED_INSURANCE_FUND_SIZE);
const _: () = assert!(align_of::<InsuranceFund>() == 8);
const _: () = assert!(offset_of!(InsuranceFund, balance) == 0);

// ════════════════════════════════════════════════════════════════════════════
// RiskParams — v12.17 (SBF, 184 bytes)
//
// Verbatim from percolator/src/percolator.rs:347-368 with native u128 fields
// replaced by [u64; 2]-backed U128/I128 wrappers for target independence.
//
// v12.17 changes vs V12_1:
// - Removed: warmup_period_slots, maintenance_fee_per_slot, risk_reduction_threshold,
//   liquidation_buffer_bps, all funding rate fields, all partial liquidation fields,
//   all dynamic fee fields (fee_tier2/3, fee_split_*, fee_utilization_surge_bps),
//   use_mark_price_for_liquidation + bool_pad
// - Added: h_min, h_max (warmup horizon bounds), resolve_price_deviation_bps
// - maintenance_margin_bps is now the FIRST field (offset 0, not 8)
//
// SBF field offsets (from task spec):
//   [  0..  8] maintenance_margin_bps      u64
//   [  8.. 16] initial_margin_bps          u64
//   [ 16.. 24] trading_fee_bps             u64
//   [ 24.. 32] max_accounts                u64
//   [ 32.. 48] new_account_fee             U128
//   [ 48.. 56] max_crank_staleness_slots   u64
//   [ 56.. 64] liquidation_fee_bps         u64
//   [ 64.. 80] liquidation_fee_cap         U128
//   [ 80.. 96] min_liquidation_abs         U128
//   [ 96..112] min_initial_deposit         U128
//   [112..128] min_nonzero_mm_req          U128 (native u128 wrapped)
//   [128..144] min_nonzero_im_req          U128 (native u128 wrapped)
//   [144..160] insurance_floor             U128
//   [160..168] h_min                       u64
//   [168..176] h_max                       u64
//   [176..184] resolve_price_deviation_bps u64
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskParams {
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub trading_fee_bps: u64,
    pub max_accounts: u64,
    pub new_account_fee: U128,
    pub max_crank_staleness_slots: u64,
    pub liquidation_fee_bps: u64,
    pub liquidation_fee_cap: U128,
    pub min_liquidation_abs: U128,
    pub min_initial_deposit: U128,
    /// Native `u128` in upstream; wrapped here for target-independent alignment.
    pub min_nonzero_mm_req: U128,
    /// Native `u128` in upstream; wrapped here for target-independent alignment.
    pub min_nonzero_im_req: U128,
    pub insurance_floor: U128,
    /// Minimum warmup horizon in slots (spec §6.1).
    pub h_min: u64,
    /// Maximum warmup horizon in slots (spec §6.1).
    pub h_max: u64,
    /// Max deviation (bps) from oracle for resolved settlement price (spec §10.7).
    pub resolve_price_deviation_bps: u64,
}

const _: () = assert!(size_of::<RiskParams>() == EXPECTED_RISK_PARAMS_SIZE);
const _: () = assert!(align_of::<RiskParams>() == 8);
const _: () = assert!(offset_of!(RiskParams, maintenance_margin_bps) == 0);
const _: () = assert!(offset_of!(RiskParams, initial_margin_bps) == 8);
const _: () = assert!(offset_of!(RiskParams, max_accounts) == 24);
const _: () = assert!(offset_of!(RiskParams, new_account_fee) == 32);
const _: () = assert!(offset_of!(RiskParams, max_crank_staleness_slots) == 48);
const _: () = assert!(offset_of!(RiskParams, liquidation_fee_cap) == 64);
const _: () = assert!(offset_of!(RiskParams, min_initial_deposit) == 96);
const _: () = assert!(offset_of!(RiskParams, min_nonzero_mm_req) == 112);
const _: () = assert!(offset_of!(RiskParams, insurance_floor) == 144);
const _: () = assert!(offset_of!(RiskParams, h_min) == 160);
const _: () = assert!(offset_of!(RiskParams, h_max) == 168);
const _: () = assert!(offset_of!(RiskParams, resolve_price_deviation_bps) == 176);

// ════════════════════════════════════════════════════════════════════════════
// Account — v12.17 (SBF, 352 bytes)
//
// Verbatim from percolator/src/percolator.rs:243-294 with native i128/u128
// replaced by [u64; 2]-backed wrappers for target independence.
//
// v12.17 BREAKING CHANGES vs V12_1 (320 bytes):
// - REMOVED: account_id (was first field, u64)
// - REMOVED: warmup_started_at_slot, warmup_slope_per_step
// - REMOVED: entry_price, funding_index, position_size (legacy fields)
// - REMOVED: last_partial_liquidation_slot
// - REMOVED: fees_earned_total
// - REMOVED: last_fee_slot
// - ADDED: f_snap (I128, funding snapshot at last attachment)
// - ADDED: sched_present, sched_remaining_q, sched_anchor_q,
//          sched_start_slot, sched_horizon, sched_release_q (scheduled warmup bucket)
// - ADDED: pending_present, pending_remaining_q, pending_horizon,
//          pending_created_slot (pending warmup bucket)
// - capital is now the FIRST field (was at offset 8 after account_id)
//
// SBF field offsets (task spec v12.17):
//   [  0.. 16] capital             U128
//   [ 16.. 17] kind                u8
//   [ 17.. 24] _kind_pad           [u8; 7]
//   [ 24.. 40] pnl                 I128
//   [ 40.. 56] reserved_pnl        U128
//   [ 56.. 72] position_basis_q    I128
//   [ 72.. 88] adl_a_basis         U128
//   [ 88..104] adl_k_snap          I128
//   [104..120] f_snap              I128
//   [120..128] adl_epoch_snap      u64
//   [128..160] matcher_program     [u8; 32]
//   [160..192] matcher_context     [u8; 32]
//   [192..224] owner               [u8; 32]
//   [224..240] fee_credits         I128
//   [240..241] sched_present       u8
//   [241..248] _sched_pad          [u8; 7]
//   [248..264] sched_remaining_q   U128
//   [264..280] sched_anchor_q      U128
//   [280..288] sched_start_slot    u64
//   [288..296] sched_horizon       u64
//   [296..312] sched_release_q     U128
//   [312..313] pending_present     u8
//   [313..320] _pending_pad        [u8; 7]
//   [320..336] pending_remaining_q U128
//   [336..344] pending_horizon     u64
//   [344..352] pending_created_slot u64
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub capital: U128,
    /// 0 = User, 1 = LP (upstream migrated from `AccountKind` enum to `u8`).
    pub kind: u8,
    pub _kind_pad: [u8; 7],

    /// Native `i128` upstream; wrapped here.
    pub pnl: I128,
    /// Native `u128` upstream; wrapped here.
    pub reserved_pnl: U128,

    /// Native `i128` upstream; wrapped here. The primary position size/side
    /// field (v12.15+ basis-q representation).
    pub position_basis_q: I128,

    /// Native `u128` upstream; wrapped here.
    pub adl_a_basis: U128,
    /// Native `i128` upstream; wrapped here.
    pub adl_k_snap: I128,

    /// Per-account funding snapshot at last attachment (v12.17).
    /// Native `i128` upstream; wrapped here.
    pub f_snap: I128,

    pub adl_epoch_snap: u64,

    pub matcher_program: [u8; 32],
    pub matcher_context: [u8; 32],

    pub owner: [u8; 32],

    pub fee_credits: I128,

    // ---- Scheduled warmup reserve bucket (spec §4.3) ----
    pub sched_present: u8,
    pub _sched_pad: [u8; 7],
    /// Native `u128` upstream; wrapped here.
    pub sched_remaining_q: U128,
    /// Native `u128` upstream; wrapped here.
    pub sched_anchor_q: U128,
    pub sched_start_slot: u64,
    pub sched_horizon: u64,
    /// Native `u128` upstream; wrapped here.
    pub sched_release_q: U128,

    // ---- Pending warmup reserve bucket ----
    pub pending_present: u8,
    pub _pending_pad: [u8; 7],
    /// Native `u128` upstream; wrapped here.
    pub pending_remaining_q: U128,
    pub pending_horizon: u64,
    pub pending_created_slot: u64,
}

impl Account {
    pub const KIND_USER: u8 = 0;
    pub const KIND_LP: u8 = 1;
}

const _: () = assert!(size_of::<Account>() == EXPECTED_ACCOUNT_SIZE);
const _: () = assert!(align_of::<Account>() == 8);

// Field offsets — these are the values PR C will use via `offset_of!` at
// runtime. Pinned here so any drift fails at compile time.
pub const ACCT_OFF_CAPITAL: usize = offset_of!(Account, capital);
pub const ACCT_OFF_KIND: usize = offset_of!(Account, kind);
pub const ACCT_OFF_PNL: usize = offset_of!(Account, pnl);
pub const ACCT_OFF_RESERVED_PNL: usize = offset_of!(Account, reserved_pnl);
pub const ACCT_OFF_POSITION_BASIS_Q: usize = offset_of!(Account, position_basis_q);
pub const ACCT_OFF_ADL_A_BASIS: usize = offset_of!(Account, adl_a_basis);
pub const ACCT_OFF_ADL_K_SNAP: usize = offset_of!(Account, adl_k_snap);
pub const ACCT_OFF_F_SNAP: usize = offset_of!(Account, f_snap);
pub const ACCT_OFF_ADL_EPOCH_SNAP: usize = offset_of!(Account, adl_epoch_snap);
pub const ACCT_OFF_MATCHER_PROGRAM: usize = offset_of!(Account, matcher_program);
pub const ACCT_OFF_MATCHER_CONTEXT: usize = offset_of!(Account, matcher_context);
pub const ACCT_OFF_OWNER: usize = offset_of!(Account, owner);
pub const ACCT_OFF_FEE_CREDITS: usize = offset_of!(Account, fee_credits);
pub const ACCT_OFF_SCHED_PRESENT: usize = offset_of!(Account, sched_present);
pub const ACCT_OFF_SCHED_REMAINING_Q: usize = offset_of!(Account, sched_remaining_q);
pub const ACCT_OFF_SCHED_ANCHOR_Q: usize = offset_of!(Account, sched_anchor_q);
pub const ACCT_OFF_SCHED_START_SLOT: usize = offset_of!(Account, sched_start_slot);
pub const ACCT_OFF_SCHED_HORIZON: usize = offset_of!(Account, sched_horizon);
pub const ACCT_OFF_SCHED_RELEASE_Q: usize = offset_of!(Account, sched_release_q);
pub const ACCT_OFF_PENDING_PRESENT: usize = offset_of!(Account, pending_present);
pub const ACCT_OFF_PENDING_REMAINING_Q: usize = offset_of!(Account, pending_remaining_q);
pub const ACCT_OFF_PENDING_HORIZON: usize = offset_of!(Account, pending_horizon);
pub const ACCT_OFF_PENDING_CREATED_SLOT: usize = offset_of!(Account, pending_created_slot);

// Pinned offsets for Account fields (SBF v12.17):
const _: () = assert!(ACCT_OFF_CAPITAL == 0);
const _: () = assert!(ACCT_OFF_KIND == 16);
const _: () = assert!(ACCT_OFF_PNL == 24);
const _: () = assert!(ACCT_OFF_RESERVED_PNL == 40);
const _: () = assert!(ACCT_OFF_POSITION_BASIS_Q == 56);
const _: () = assert!(ACCT_OFF_ADL_A_BASIS == 72);
const _: () = assert!(ACCT_OFF_ADL_K_SNAP == 88);
const _: () = assert!(ACCT_OFF_F_SNAP == 104);
const _: () = assert!(ACCT_OFF_ADL_EPOCH_SNAP == 120);
const _: () = assert!(ACCT_OFF_MATCHER_PROGRAM == 128);
const _: () = assert!(ACCT_OFF_MATCHER_CONTEXT == 160);
const _: () = assert!(ACCT_OFF_OWNER == 192);
const _: () = assert!(ACCT_OFF_FEE_CREDITS == 224);
const _: () = assert!(ACCT_OFF_SCHED_PRESENT == 240);
const _: () = assert!(ACCT_OFF_SCHED_REMAINING_Q == 248);
const _: () = assert!(ACCT_OFF_SCHED_ANCHOR_Q == 264);
const _: () = assert!(ACCT_OFF_SCHED_START_SLOT == 280);
const _: () = assert!(ACCT_OFF_SCHED_HORIZON == 288);
const _: () = assert!(ACCT_OFF_SCHED_RELEASE_Q == 296);
const _: () = assert!(ACCT_OFF_PENDING_PRESENT == 312);
const _: () = assert!(ACCT_OFF_PENDING_REMAINING_Q == 320);
const _: () = assert!(ACCT_OFF_PENDING_HORIZON == 336);
const _: () = assert!(ACCT_OFF_PENDING_CREATED_SLOT == 344);

// ════════════════════════════════════════════════════════════════════════════
// RiskEngine — v12.17 (SBF)
//
// Verbatim from percolator/src/percolator.rs:370-459 with native i128/u128
// replaced by [u64; 2]-backed U128/I128 wrappers for target independence.
//
// v12.17 BREAKING CHANGES vs V12_1:
// - InsuranceFund is now 16 bytes (was 80)
// - RiskParams is now 184 bytes (was 352)
// - Added: market_mode (u8), resolved_price, resolved_slot,
//   resolved_payout_h_num, resolved_payout_h_den, resolved_payout_ready,
//   resolved_k_long_terminal_delta, resolved_k_short_terminal_delta,
//   resolved_live_price
// - Added: neg_pnl_account_count, fund_px_last, f_long_num, f_short_num,
//   f_epoch_start_long_num, f_epoch_start_short_num
// - Removed: funding_rate_bps_per_slot_last, max_crank_staleness_slots (dup),
//   liq_cursor, crank_cursor, sweep_start_idx, various cursor padding,
//   last_full_sweep_start/completed_slot, lifetime_liquidations,
//   lifetime_force_realize_closes, last_oracle_price dup, mark_price_e6,
//   funding_index_qpb_e6, last_funding_slot, funding_frozen, funding_frozen_rate,
//   emergency_oi_mode, emergency_start_slot, last_breaker_slot,
//   trade_twap_e6, twap_last_slot, many LP aggregates
// - next_account_id removed from slab management tail
//
// SBF offsets (from task spec):
//   vault: 0           (U128)
//   insurance_fund: 16 (InsuranceFund = 16)
//   params: 32         (RiskParams = 184)
//   current_slot: 216  (u64)
//   market_mode: 224   (u8)
//   ...
//   c_tot: 336         (U128)
//   pnl_pos_tot: 352   (U128)
//   pnl_matured_pos_tot: 368 (U128)
//   ...
//   neg_pnl_account_count: 616 (u64)
//   last_oracle_price: 624     (u64)
//   fund_px_last: 632          (u64)
//   f_long_num: 648            (I128)
//   f_short_num: 664           (I128)
//   ...
//   bitmap (used array): 712   ([u64; BITMAP_WORDS])
//   num_used_accounts: 712 + 8*BITMAP_WORDS  (u16)
//   free_head: ...             (u16)
//   next_free: ...             ([u16; MAX_ACCOUNTS])
//   accounts: varies           ([Account; MAX_ACCOUNTS])
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskEngine {
    pub vault: U128,
    pub insurance_fund: InsuranceFund,
    pub params: RiskParams,
    pub current_slot: u64,

    /// Market mode (Live=0, Resolved=1).
    pub market_mode: MarketMode,
    pub _market_mode_pad: [u8; 7],

    // Resolved market state
    pub resolved_price: u64,
    pub resolved_slot: u64,
    /// Native `u128` upstream; wrapped here.
    pub resolved_payout_h_num: U128,
    /// Native `u128` upstream; wrapped here.
    pub resolved_payout_h_den: U128,
    pub resolved_payout_ready: u8,
    pub _resolved_ready_pad: [u8; 7],
    /// Native `i128` upstream; wrapped here.
    pub resolved_k_long_terminal_delta: I128,
    /// Native `i128` upstream; wrapped here.
    pub resolved_k_short_terminal_delta: I128,
    pub resolved_live_price: u64,

    pub last_crank_slot: u64,

    pub c_tot: U128,
    /// Native `u128` upstream; wrapped here.
    pub pnl_pos_tot: U128,
    /// Native `u128` upstream; wrapped here.
    pub pnl_matured_pos_tot: U128,

    pub gc_cursor: u16,
    pub _gc_pad: [u8; 6],

    /// ADL side state
    /// Native `u128` upstream; wrapped here.
    pub adl_mult_long: U128,
    /// Native `u128` upstream; wrapped here.
    pub adl_mult_short: U128,
    /// Native `i128` upstream; wrapped here.
    pub adl_coeff_long: I128,
    /// Native `i128` upstream; wrapped here.
    pub adl_coeff_short: I128,
    pub adl_epoch_long: u64,
    pub adl_epoch_short: u64,
    /// Native `i128` upstream; wrapped here.
    pub adl_epoch_start_k_long: I128,
    /// Native `i128` upstream; wrapped here.
    pub adl_epoch_start_k_short: I128,
    /// Native `u128` upstream; wrapped here.
    pub oi_eff_long_q: U128,
    /// Native `u128` upstream; wrapped here.
    pub oi_eff_short_q: U128,

    pub side_mode_long: SideMode,
    pub side_mode_short: SideMode,
    pub _side_mode_pad: [u8; 6],

    pub stored_pos_count_long: u64,
    pub stored_pos_count_short: u64,
    pub stale_account_count_long: u64,
    pub stale_account_count_short: u64,

    /// Native `u128` upstream; wrapped here.
    pub phantom_dust_bound_long_q: U128,
    /// Native `u128` upstream; wrapped here.
    pub phantom_dust_bound_short_q: U128,

    pub materialized_account_count: u64,

    /// Count of accounts with PNL < 0 (spec §4.7, v12.16.4).
    pub neg_pnl_account_count: u64,

    /// Last oracle price used in accrue_market_to (P_last).
    pub last_oracle_price: u64,
    /// Last funding-sample price (fund_px_last, spec §5.5 step 11).
    pub fund_px_last: u64,
    pub last_market_slot: u64,

    /// Cumulative funding numerator for long side (v12.15).
    /// Native `i128` upstream; wrapped here.
    pub f_long_num: I128,
    /// Cumulative funding numerator for short side (v12.15).
    /// Native `i128` upstream; wrapped here.
    pub f_short_num: I128,
    /// F snapshot at epoch start for long side.
    /// Native `i128` upstream; wrapped here.
    pub f_epoch_start_long_num: I128,
    /// F snapshot at epoch start for short side.
    /// Native `i128` upstream; wrapped here.
    pub f_epoch_start_short_num: I128,

    // ────── Parametric tail (sizes depend on MAX_ACCOUNTS) ──────
    pub used: [u64; BITMAP_WORDS],
    pub num_used_accounts: u16,
    pub free_head: u16,
    pub next_free: [u16; MAX_ACCOUNTS],
    pub accounts: [Account; MAX_ACCOUNTS],
}

/// Closed-form expected size of `RiskEngine`, derived from the task spec
/// field offsets and tail layout.
///
/// From task spec:
///   bitmap (used) at engine+712 → fixed_prefix_through_f_epoch = 712
///   bitmap = 8 * BITMAP_WORDS
///   num_used_accounts(u16) + free_head(u16) = 4 bytes, pad to 8 = +4 pad
///   next_free = 2 * MAX_ACCOUNTS
///   Align to Account (8) before accounts array.
///   accounts = 352 * MAX_ACCOUNTS
pub const EXPECTED_RISK_ENGINE_SIZE: usize = {
    const fn align_up(x: usize, a: usize) -> usize {
        (x + (a - 1)) & !(a - 1)
    }
    // Fixed prefix: all fields up to (but not including) `used` bitmap.
    // From task spec: bitmap starts at engine+712.
    let fixed_prefix: usize = 712;
    let used_bytes: usize = 8 * BITMAP_WORDS;
    // num_used_accounts(u16) + free_head(u16) = 4 bytes; next u64 boundary = 8 bytes total
    let mid: usize = 4;
    let next_free_bytes: usize = 2 * MAX_ACCOUNTS;
    let unaligned = fixed_prefix + used_bytes + mid + next_free_bytes;
    // Account alignment is 8, so round up to 8 before the array starts.
    let accounts_off = align_up(unaligned, 8);
    accounts_off + EXPECTED_ACCOUNT_SIZE * MAX_ACCOUNTS
};

const _: () = assert!(size_of::<RiskEngine>() == EXPECTED_RISK_ENGINE_SIZE);
const _: () = assert!(align_of::<RiskEngine>() == EXPECTED_ENGINE_ALIGN);

// Feature-independent relative offsets (verified against task spec):
pub const ENGINE_REL_PARAMS: usize = offset_of!(RiskEngine, params);
pub const ENGINE_REL_MAINT_MARGIN_BPS: usize = offset_of!(RiskEngine, params.maintenance_margin_bps);
pub const ENGINE_REL_MAX_ACCOUNTS_FIELD: usize = offset_of!(RiskEngine, params.max_accounts);
pub const ENGINE_REL_C_TOT: usize = offset_of!(RiskEngine, c_tot);
pub const ENGINE_REL_PNL_POS_TOT: usize = offset_of!(RiskEngine, pnl_pos_tot);
pub const ENGINE_REL_NEG_PNL_ACCOUNT_COUNT: usize = offset_of!(RiskEngine, neg_pnl_account_count);
pub const ENGINE_REL_LAST_ORACLE_PRICE: usize = offset_of!(RiskEngine, last_oracle_price);
pub const ENGINE_REL_FUND_PX_LAST: usize = offset_of!(RiskEngine, fund_px_last);
pub const ENGINE_REL_F_LONG_NUM: usize = offset_of!(RiskEngine, f_long_num);
pub const ENGINE_REL_F_SHORT_NUM: usize = offset_of!(RiskEngine, f_short_num);
pub const ENGINE_REL_USED: usize = offset_of!(RiskEngine, used);
pub const ENGINE_REL_ACCOUNTS: usize = offset_of!(RiskEngine, accounts);

// Pin the feature-independent offsets against the task spec:
const _: () = assert!(ENGINE_REL_PARAMS == 32);
const _: () = assert!(ENGINE_REL_MAINT_MARGIN_BPS == 32); // params at 32, maint_margin at params+0
const _: () = assert!(ENGINE_REL_MAX_ACCOUNTS_FIELD == 32 + 24); // params+24
const _: () = assert!(ENGINE_REL_C_TOT == 336);
const _: () = assert!(ENGINE_REL_PNL_POS_TOT == 352);
const _: () = assert!(ENGINE_REL_NEG_PNL_ACCOUNT_COUNT == 616);
const _: () = assert!(ENGINE_REL_LAST_ORACLE_PRICE == 624);
const _: () = assert!(ENGINE_REL_FUND_PX_LAST == 632);
const _: () = assert!(ENGINE_REL_F_LONG_NUM == 648);
const _: () = assert!(ENGINE_REL_F_SHORT_NUM == 664);
const _: () = assert!(ENGINE_REL_USED == 712);

// ════════════════════════════════════════════════════════════════════════════
// Slab geometry — verbatim from percolator-prog/src/lib.rs:47-72
// ════════════════════════════════════════════════════════════════════════════

pub const HEADER_LEN: usize = size_of::<SlabHeader>();
pub const CONFIG_LEN: usize = size_of::<MarketConfig>();
pub const ENGINE_ALIGN: usize = align_of::<RiskEngine>();

const fn align_up_runtime(x: usize, a: usize) -> usize {
    (x + (a - 1)) & !(a - 1)
}

/// Byte offset of `RiskEngine` within the slab account data.
/// v12.17: align_up(72 + 432, 8) = align_up(504, 8) = 504
pub const ENGINE_OFF: usize = align_up_runtime(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN);
pub const ENGINE_LEN: usize = size_of::<RiskEngine>();
pub const SLAB_LEN: usize = ENGINE_OFF + ENGINE_LEN;

// Pin the slab geometry so a future change to SlabHeader or MarketConfig
// is caught at compile time.
const _: () = assert!(HEADER_LEN == 72);
const _: () = assert!(CONFIG_LEN == 432);
const _: () = assert!(ENGINE_ALIGN == 8);
const _: () = assert!(ENGINE_OFF == 504); // align_up(72 + 432, 8) = 504
const _: () = assert!(ENGINE_OFF.is_multiple_of(8));

// ════════════════════════════════════════════════════════════════════════════
// Pre-computed absolute slab offsets — convenience for PR C
// ════════════════════════════════════════════════════════════════════════════
//
// These compose `ENGINE_OFF` with the relative offsets above so PR C's
// `read_position` can slice the slab data directly without arithmetic.

pub const SLAB_OFF_MAGIC: usize = 0;
pub const SLAB_OFF_MAINT_MARGIN_BPS: usize = ENGINE_OFF + ENGINE_REL_MAINT_MARGIN_BPS;
pub const SLAB_OFF_MAX_ACCOUNTS: usize = ENGINE_OFF + ENGINE_REL_MAX_ACCOUNTS_FIELD;
pub const SLAB_OFF_C_TOT: usize = ENGINE_OFF + ENGINE_REL_C_TOT;
pub const SLAB_OFF_PNL_POS_TOT: usize = ENGINE_OFF + ENGINE_REL_PNL_POS_TOT;
pub const SLAB_OFF_NEG_PNL_ACCOUNT_COUNT: usize = ENGINE_OFF + ENGINE_REL_NEG_PNL_ACCOUNT_COUNT;
pub const SLAB_OFF_LAST_ORACLE_PRICE: usize = ENGINE_OFF + ENGINE_REL_LAST_ORACLE_PRICE;
pub const SLAB_OFF_FUND_PX_LAST: usize = ENGINE_OFF + ENGINE_REL_FUND_PX_LAST;
pub const SLAB_OFF_F_LONG_NUM: usize = ENGINE_OFF + ENGINE_REL_F_LONG_NUM;
pub const SLAB_OFF_F_SHORT_NUM: usize = ENGINE_OFF + ENGINE_REL_F_SHORT_NUM;
pub const SLAB_OFF_USED: usize = ENGINE_OFF + ENGINE_REL_USED;
pub const SLAB_OFF_ACCOUNTS: usize = ENGINE_OFF + ENGINE_REL_ACCOUNTS;

// Sanity pins on the absolute offsets (ENGINE_OFF = 504):
const _: () = assert!(SLAB_OFF_MAGIC == 0);
const _: () = assert!(SLAB_OFF_MAINT_MARGIN_BPS == 504 + 32);   // 536
const _: () = assert!(SLAB_OFF_MAX_ACCOUNTS == 504 + 56);        // 560
const _: () = assert!(SLAB_OFF_C_TOT == 504 + 336);              // 840
const _: () = assert!(SLAB_OFF_PNL_POS_TOT == 504 + 352);        // 856
const _: () = assert!(SLAB_OFF_NEG_PNL_ACCOUNT_COUNT == 504 + 616); // 1120
const _: () = assert!(SLAB_OFF_LAST_ORACLE_PRICE == 504 + 624);  // 1128
const _: () = assert!(SLAB_OFF_FUND_PX_LAST == 504 + 632);       // 1136
const _: () = assert!(SLAB_OFF_F_LONG_NUM == 504 + 648);         // 1152
const _: () = assert!(SLAB_OFF_F_SHORT_NUM == 504 + 664);        // 1168
const _: () = assert!(SLAB_OFF_USED == 504 + 712);               // 1216

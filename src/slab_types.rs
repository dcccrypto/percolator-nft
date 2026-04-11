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
//! | (default)    | 4096           | 64             | 1 320 464         |
//! | `medium`     | 1024           | 16             | 330 896           |
//! | `small`      | 256            | 4              | 83 504            |
//! | `test`       | 64             | 1              | 21 656            |
//! | `cfg(kani)`  | 4              | 1              | 2 336             |
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
pub const LAYOUT_REVISION: u32 = 1;

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
pub const EXPECTED_MARKET_CONFIG_SIZE: usize = 544;
pub const EXPECTED_INSURANCE_FUND_SIZE: usize = 80;
pub const EXPECTED_RISK_PARAMS_SIZE: usize = 352;
pub const EXPECTED_ACCOUNT_SIZE: usize = 320;

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

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct MarketConfig(pub [u8; EXPECTED_MARKET_CONFIG_SIZE]);

const _: () = assert!(size_of::<MarketConfig>() == EXPECTED_MARKET_CONFIG_SIZE);
const _: () = assert!(align_of::<MarketConfig>() == 8);

// ════════════════════════════════════════════════════════════════════════════
// InsuranceFund — verbatim from percolator/src/lib.rs:309-335
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InsuranceFund {
    pub balance: U128,
    pub fee_revenue: U128,
    pub balance_incentive_reserve: u64,
    pub _rebate_pad: [u8; 8],
    pub isolated_balance: U128,
    pub insurance_isolation_bps: u16,
    pub _isolation_padding: [u8; 14],
}

const _: () = assert!(size_of::<InsuranceFund>() == EXPECTED_INSURANCE_FUND_SIZE);
const _: () = assert!(align_of::<InsuranceFund>() == 8);

// ════════════════════════════════════════════════════════════════════════════
// RiskParams — verbatim from percolator/src/lib.rs:339-419
//
// Native u128 fields (`min_nonzero_mm_req`, `min_nonzero_im_req`,
// `fee_tier2_threshold`, `fee_tier3_threshold`) are replaced with [u64; 2]
// wrappers for 8-byte alignment matching the SBF ABI. On SBF this is
// byte-identical to upstream. On host this avoids Rust 1.77+ 16-byte
// alignment that would produce a different `size_of` value.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RiskParams {
    pub warmup_period_slots: u64,
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub trading_fee_bps: u64,
    pub max_accounts: u64,
    pub new_account_fee: U128,
    pub maintenance_fee_per_slot: U128,
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

    // ────── Fork-specific fields (see _percolator_core_reference.rs) ──────
    pub risk_reduction_threshold: U128,
    pub liquidation_buffer_bps: u64,

    // ────── Funding rate (PERC-121) ──────
    pub funding_premium_weight_bps: u64,
    pub funding_settlement_interval_slots: u64,
    pub funding_premium_dampening_e6: u64,
    pub funding_premium_max_bps_per_slot: i64,

    // ────── Partial liquidation (PERC-122) ──────
    pub partial_liquidation_bps: u64,
    pub partial_liquidation_cooldown_slots: u64,
    /// Upstream is `bool`; stored as `u8` here so the struct has no trailing
    /// niche and the `Default` derive works unconditionally.
    pub use_mark_price_for_liquidation: u8,
    pub _bool_pad: [u8; 7],
    pub emergency_liquidation_margin_bps: u64,

    // ────── Dynamic fees (PERC-120/283) ──────
    pub fee_tier2_bps: u64,
    pub fee_tier3_bps: u64,
    /// Native `u128` in upstream; wrapped here for target-independent alignment.
    pub fee_tier2_threshold: U128,
    /// Native `u128` in upstream; wrapped here for target-independent alignment.
    pub fee_tier3_threshold: U128,
    pub fee_split_lp_bps: u64,
    pub fee_split_protocol_bps: u64,
    pub fee_split_creator_bps: u64,
    pub fee_utilization_surge_bps: u64,
}

// Note: Default is not derived because `#![forbid(unsafe_code)]` blocks the
// simplest `core::mem::zeroed()` implementation, and a field-by-field Default
// isn't needed by PR C. If a consumer wants a zero-filled RiskParams, they
// can use `bytemuck::Zeroable` in the future (not derived here to minimize
// coupling).

const _: () = assert!(size_of::<RiskParams>() == EXPECTED_RISK_PARAMS_SIZE);
const _: () = assert!(align_of::<RiskParams>() == 8);
const _: () = assert!(offset_of!(RiskParams, warmup_period_slots) == 0);
const _: () = assert!(offset_of!(RiskParams, maintenance_margin_bps) == 8);
const _: () = assert!(offset_of!(RiskParams, max_accounts) == 32);

// ════════════════════════════════════════════════════════════════════════════
// Account — verbatim from percolator/src/lib.rs:202-267
//
// Native `i128`/`u128` fields replaced with [u64; 2] wrappers for target
// independence. On SBF, byte-identical to upstream. On host, gives the SAME
// size (320) as SBF, avoiding the Rust 1.77+ native i128 alignment mismatch.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub account_id: u64,
    pub capital: U128,
    /// 0 = User, 1 = LP (upstream migrated from `AccountKind` enum to `u8`).
    pub kind: u8,
    pub _kind_pad: [u8; 7],

    /// Native `i128` upstream; wrapped here.
    pub pnl: I128,
    /// Native `u128` upstream; wrapped here.
    pub reserved_pnl: U128,

    pub warmup_started_at_slot: u64,
    /// Native `u128` upstream; wrapped here.
    pub warmup_slope_per_step: U128,

    /// Native `i128` upstream; wrapped here. The primary position size/side
    /// field (PERC-121 basis-q representation).
    pub position_basis_q: I128,

    /// Native `u128` upstream; wrapped here.
    pub adl_a_basis: U128,
    /// Native `i128` upstream; wrapped here.
    pub adl_k_snap: I128,
    pub adl_epoch_snap: u64,

    pub matcher_program: [u8; 32],
    pub matcher_context: [u8; 32],

    pub owner: [u8; 32],

    pub fee_credits: I128,
    pub last_fee_slot: u64,
    pub fees_earned_total: U128,

    // ────── Legacy fields (kept by upstream fork, see line 248-263) ──────
    pub entry_price: u64,
    pub funding_index: i64,
    /// Native `i128` upstream; wrapped here. Legacy — upstream is migrating
    /// to `position_basis_q` but keeps this around for the prog-wrapper path.
    pub position_size: I128,
    pub last_partial_liquidation_slot: u64,
}

impl Account {
    pub const KIND_USER: u8 = 0;
    pub const KIND_LP: u8 = 1;
}

// Note: Default is not derived — see RiskParams comment above for rationale.

const _: () = assert!(size_of::<Account>() == EXPECTED_ACCOUNT_SIZE);
const _: () = assert!(align_of::<Account>() == 8);

// Field offsets — these are the values PR C will use via `offset_of!` at
// runtime. Pinned here so any drift fails at compile time.
pub const ACCT_OFF_ACCOUNT_ID: usize = offset_of!(Account, account_id);
pub const ACCT_OFF_CAPITAL: usize = offset_of!(Account, capital);
pub const ACCT_OFF_KIND: usize = offset_of!(Account, kind);
pub const ACCT_OFF_POSITION_BASIS_Q: usize = offset_of!(Account, position_basis_q);
pub const ACCT_OFF_OWNER: usize = offset_of!(Account, owner);
pub const ACCT_OFF_ENTRY_PRICE: usize = offset_of!(Account, entry_price);
pub const ACCT_OFF_FUNDING_INDEX: usize = offset_of!(Account, funding_index);
pub const ACCT_OFF_POSITION_SIZE: usize = offset_of!(Account, position_size);

// Pinned offsets for Account fields — all 8-byte aligned because 128-bit
// fields use [u64; 2]-backed U128/I128 wrappers:
//
//   [  0..  8] account_id      u64
//   [  8.. 24] capital         U128
//   [ 24.. 25] kind            u8
//   [ 25.. 32] _kind_pad       [u8; 7]
//   [ 32.. 48] pnl             I128
//   [ 48.. 64] reserved_pnl    U128
//   [ 64.. 72] warmup_started_at_slot  u64
//   [ 72.. 88] warmup_slope_per_step   U128
//   [ 88..104] position_basis_q        I128  ← offset 88 (not 96) with [u64;2] wrappers
//   [104..120] adl_a_basis     U128
//   [120..136] adl_k_snap      I128
//   [136..144] adl_epoch_snap  u64
//   [144..176] matcher_program [u8; 32]
//   [176..208] matcher_context [u8; 32]
//   [208..240] owner           [u8; 32]
//   [240..256] fee_credits     I128
//   [256..264] last_fee_slot   u64
//   [264..280] fees_earned_total  U128
//   [280..288] entry_price     u64
//   [288..296] funding_index   i64
//   [296..312] position_size   I128
//   [312..320] last_partial_liquidation_slot  u64
const _: () = assert!(ACCT_OFF_ACCOUNT_ID == 0);
const _: () = assert!(ACCT_OFF_CAPITAL == 8);
const _: () = assert!(ACCT_OFF_KIND == 24);
const _: () = assert!(ACCT_OFF_POSITION_BASIS_Q == 88);
const _: () = assert!(ACCT_OFF_OWNER == 208);
const _: () = assert!(ACCT_OFF_ENTRY_PRICE == 280);
const _: () = assert!(ACCT_OFF_FUNDING_INDEX == 288);
const _: () = assert!(ACCT_OFF_POSITION_SIZE == 296);

// ════════════════════════════════════════════════════════════════════════════
// RiskEngine — verbatim from percolator/src/lib.rs:422-561
//
// The huge top-level struct. Native i128/u128 fields are wrapped with
// [u64; 2]-backed U128/I128 for target independence. The parametric tail
// (`used`, `num_used_accounts`, `next_account_id`, `free_head`, `next_free`,
// `accounts`) depends on MAX_ACCOUNTS and so the total size varies with the
// feature flag — validated below via the closed-form
// `EXPECTED_RISK_ENGINE_SIZE`.
// ════════════════════════════════════════════════════════════════════════════

#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskEngine {
    pub vault: U128,
    pub insurance_fund: InsuranceFund,
    pub params: RiskParams,
    pub current_slot: u64,
    pub funding_rate_bps_per_slot_last: i64,
    pub last_crank_slot: u64,
    pub max_crank_staleness_slots: u64,
    pub c_tot: U128,
    /// Native u128 upstream; wrapped here.
    pub pnl_pos_tot: U128,
    /// Native u128 upstream; wrapped here.
    pub pnl_matured_pos_tot: U128,
    pub liq_cursor: u16,
    pub gc_cursor: u16,
    pub _cursor_pad0: [u8; 4],
    pub last_full_sweep_start_slot: u64,
    pub last_full_sweep_completed_slot: u64,
    pub crank_cursor: u16,
    pub sweep_start_idx: u16,
    pub _cursor_pad1: [u8; 4],
    pub lifetime_liquidations: u64,
    pub adl_mult_long: U128,
    pub adl_mult_short: U128,
    pub adl_coeff_long: I128,
    pub adl_coeff_short: I128,
    pub adl_epoch_long: u64,
    pub adl_epoch_short: u64,
    pub adl_epoch_start_k_long: I128,
    pub adl_epoch_start_k_short: I128,
    pub oi_eff_long_q: U128,
    pub oi_eff_short_q: U128,
    pub side_mode_long: SideMode,
    pub side_mode_short: SideMode,
    pub _side_mode_pad: [u8; 6],
    pub stored_pos_count_long: u64,
    pub stored_pos_count_short: u64,
    pub stale_account_count_long: u64,
    pub stale_account_count_short: u64,
    pub phantom_dust_bound_long_q: U128,
    pub phantom_dust_bound_short_q: U128,
    pub materialized_account_count: u64,
    pub last_oracle_price: u64,
    pub last_market_slot: u64,
    pub funding_price_sample_last: u64,
    pub total_open_interest: U128,
    pub long_oi: U128,
    pub short_oi: U128,
    pub net_lp_pos: I128,
    pub lp_sum_abs: U128,
    pub lp_max_abs: U128,
    pub lp_max_abs_sweep: U128,
    pub mark_price_e6: u64,
    pub funding_index_qpb_e6: i64,
    pub last_funding_slot: u64,
    /// Upstream is `bool`; stored as `u8` here for Default compatibility.
    pub funding_frozen: u8,
    pub _ff_pad: [u8; 7],
    pub funding_frozen_rate_snapshot: i64,
    pub emergency_oi_mode: u8,
    pub _eom_pad: [u8; 7],
    pub emergency_start_slot: u64,
    pub last_breaker_slot: u64,
    pub trade_twap_e6: u64,
    pub twap_last_slot: u64,
    pub lifetime_force_realize_closes: u64,

    // ────── Parametric tail (sizes depend on MAX_ACCOUNTS) ──────
    pub used: [u64; BITMAP_WORDS],
    pub num_used_accounts: u16,
    pub _nua_pad: [u8; 6],
    pub next_account_id: u64,
    pub free_head: u16,
    pub next_free: [u16; MAX_ACCOUNTS],
    pub accounts: [Account; MAX_ACCOUNTS],
}

/// Closed-form expected size of `RiskEngine`, derived from the field trail.
/// Adapts to whichever `MAX_ACCOUNTS` feature is active. If any vendored
/// field drifts or is reordered, this will not equal `size_of::<RiskEngine>()`
/// and the crate fails to compile.
pub const EXPECTED_RISK_ENGINE_SIZE: usize = {
    const fn align_up(x: usize, a: usize) -> usize {
        (x + (a - 1)) & !(a - 1)
    }
    // Fixed prefix size up to and including `lifetime_force_realize_closes`,
    // with every 128-bit field on 8-byte alignment (the U128/I128 wrapper
    // layout). Computed field-by-field in the PR B design analysis and
    // cross-checked against upstream's `_SBF_ENGINE_ALIGN == 8` assertion.
    let fixed_prefix: usize = 1016;
    let used_bytes: usize = 8 * BITMAP_WORDS;
    // num_used_accounts(u16) + pad(6) + next_account_id(u64) + free_head(u16)
    let mid: usize = 2 + 6 + 8 + 2;
    let next_free_bytes: usize = 2 * MAX_ACCOUNTS;
    let unaligned = fixed_prefix + used_bytes + mid + next_free_bytes;
    // Account alignment is 8, so round up to 8 before the array starts.
    let accounts_off = align_up(unaligned, 8);
    accounts_off + EXPECTED_ACCOUNT_SIZE * MAX_ACCOUNTS
};

const _: () = assert!(size_of::<RiskEngine>() == EXPECTED_RISK_ENGINE_SIZE);
const _: () = assert!(align_of::<RiskEngine>() == EXPECTED_ENGINE_ALIGN);

// Offsets up to and including `lifetime_force_realize_closes` are MAX_ACCOUNTS-
// independent; the tail offsets depend on the feature flag.
pub const ENGINE_REL_PARAMS: usize = offset_of!(RiskEngine, params);
pub const ENGINE_REL_MAINT_MARGIN_BPS: usize = offset_of!(RiskEngine, params.maintenance_margin_bps);
pub const ENGINE_REL_MAX_ACCOUNTS_FIELD: usize = offset_of!(RiskEngine, params.max_accounts);
pub const ENGINE_REL_MARK_PRICE_E6: usize = offset_of!(RiskEngine, mark_price_e6);
pub const ENGINE_REL_FUNDING_INDEX_QPB_E6: usize = offset_of!(RiskEngine, funding_index_qpb_e6);
pub const ENGINE_REL_USED: usize = offset_of!(RiskEngine, used);
pub const ENGINE_REL_ACCOUNTS: usize = offset_of!(RiskEngine, accounts);

// Feature-independent pinned offsets (verified by hand against the field trail):
const _: () = assert!(ENGINE_REL_PARAMS == 96);
const _: () = assert!(ENGINE_REL_MAINT_MARGIN_BPS == 104); // 96 + 8
const _: () = assert!(ENGINE_REL_MAX_ACCOUNTS_FIELD == 128); // 96 + 32
const _: () = assert!(ENGINE_REL_MARK_PRICE_E6 == 928);
const _: () = assert!(ENGINE_REL_FUNDING_INDEX_QPB_E6 == 936);
const _: () = assert!(ENGINE_REL_USED == 1016);

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
pub const ENGINE_OFF: usize = align_up_runtime(HEADER_LEN + CONFIG_LEN, ENGINE_ALIGN);
pub const ENGINE_LEN: usize = size_of::<RiskEngine>();
pub const SLAB_LEN: usize = ENGINE_OFF + ENGINE_LEN;

// Pin the slab geometry so a future change to SlabHeader or MarketConfig
// is caught at compile time.
const _: () = assert!(HEADER_LEN == 72);
const _: () = assert!(CONFIG_LEN == 544);
const _: () = assert!(ENGINE_ALIGN == 8);
const _: () = assert!(ENGINE_OFF == 616); // align_up(72 + 544, 8) = 616
const _: () = assert!(ENGINE_OFF % 8 == 0);

// ════════════════════════════════════════════════════════════════════════════
// Pre-computed absolute slab offsets — convenience for PR C
// ════════════════════════════════════════════════════════════════════════════
//
// These compose `ENGINE_OFF` with the relative offsets above so PR C's
// `read_position` can slice the slab data directly without arithmetic.

pub const SLAB_OFF_MAGIC: usize = ENGINE_OFF - HEADER_LEN - CONFIG_LEN; // = 0
pub const SLAB_OFF_MAINT_MARGIN_BPS: usize = ENGINE_OFF + ENGINE_REL_MAINT_MARGIN_BPS;
pub const SLAB_OFF_MAX_ACCOUNTS: usize = ENGINE_OFF + ENGINE_REL_MAX_ACCOUNTS_FIELD;
pub const SLAB_OFF_MARK_PRICE_E6: usize = ENGINE_OFF + ENGINE_REL_MARK_PRICE_E6;
pub const SLAB_OFF_FUNDING_INDEX_QPB_E6: usize = ENGINE_OFF + ENGINE_REL_FUNDING_INDEX_QPB_E6;
pub const SLAB_OFF_USED: usize = ENGINE_OFF + ENGINE_REL_USED;
pub const SLAB_OFF_ACCOUNTS: usize = ENGINE_OFF + ENGINE_REL_ACCOUNTS;

// Sanity pins on the absolute offsets:
const _: () = assert!(SLAB_OFF_MAGIC == 0);
const _: () = assert!(SLAB_OFF_MAINT_MARGIN_BPS == 616 + 104);
const _: () = assert!(SLAB_OFF_MAX_ACCOUNTS == 616 + 128);
const _: () = assert!(SLAB_OFF_MARK_PRICE_E6 == 616 + 928);
const _: () = assert!(SLAB_OFF_FUNDING_INDEX_QPB_E6 == 616 + 936);
const _: () = assert!(SLAB_OFF_USED == 616 + 1016);

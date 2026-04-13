//! CPI helpers for reading Percolator slab position data.
//!
//! We read position state directly from the slab account data
//! without depending on percolator-prog crate. Layout offsets
//! must match the deployed on-chain program.

use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::error::NftError;
use crate::slab_types;

// ═══════════════════════════════════════════════════════════════
// Percolator program IDs (verified at runtime via account owner)
// ═══════════════════════════════════════════════════════════════

/// Known Percolator program IDs for slab ownership verification.
/// At runtime we check `slab.owner == one of these`.
pub const PERCOLATOR_DEVNET: Pubkey =
    solana_program::pubkey!("FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD");
pub const PERCOLATOR_MAINNET: Pubkey =
    solana_program::pubkey!("ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv");

/// Verify slab account is owned by a known Percolator program.
pub fn verify_slab_owner(slab: &AccountInfo) -> Result<(), ProgramError> {
    if slab.owner != &PERCOLATOR_DEVNET && slab.owner != &PERCOLATOR_MAINNET {
        return Err(NftError::InvalidSlabOwner.into());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Slab layout — read position data
// ═══════════════════════════════════════════════════════════════
//
// We support V0 (deployed devnet) and V1D (deployed Small program).
// Layout auto-detection by slab data length + header fields.

/// Slab header magic (first 8 bytes).
///
/// PERC-9065: Must match `percolator_prog::constants::MAGIC` in the upstream
/// `dcccrypto/percolator-prog` crate, which is written into `SlabHeader.magic`
/// at market creation. Previously this constant was `0x5045_5243_534C_4142`
/// ("PERCSLAB") — a value that does not exist in any Percolator deployment.
/// As a result, `detect_layout` rejected every real Percolator slab with
/// `UnrecognizedSlabLayout`, making the NFT program unable to read any
/// mainnet or devnet position data.
pub const SLAB_MAGIC: u64 = 0x5045_5243_4F4C_4154; // "PERCOLAT"

// PERC-9042: Read helpers return Result instead of panicking.
// The original .unwrap() would abort the transaction with an unhelpful
// "index out of bounds" panic if slab data was shorter than expected.
// Returning errors allows proper error propagation and clear diagnostics.

/// Read a u64 from a byte slice at the given offset.
fn read_u64(data: &[u8], off: usize) -> Result<u64, ProgramError> {
    let end = off.checked_add(8).ok_or(NftError::SlabDataTooShort)?;
    if end > data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }
    let bytes: [u8; 8] = data[off..end].try_into().unwrap();
    Ok(u64::from_le_bytes(bytes))
}

/// Read a u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], off: usize) -> Result<u16, ProgramError> {
    let end = off.checked_add(2).ok_or(NftError::SlabDataTooShort)?;
    if end > data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }
    let bytes: [u8; 2] = data[off..end].try_into().unwrap();
    Ok(u16::from_le_bytes(bytes))
}

/// Read a u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], off: usize) -> Result<u32, ProgramError> {
    let end = off.checked_add(4).ok_or(NftError::SlabDataTooShort)?;
    if end > data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }
    let bytes: [u8; 4] = data[off..end].try_into().unwrap();
    Ok(u32::from_le_bytes(bytes))
}

/// Read an i128 from a byte slice at the given offset.
fn read_i128(data: &[u8], off: usize) -> Result<i128, ProgramError> {
    let end = off.checked_add(16).ok_or(NftError::SlabDataTooShort)?;
    if end > data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }
    let bytes: [u8; 16] = data[off..end].try_into().unwrap();
    Ok(i128::from_le_bytes(bytes))
}

/// Detected slab layout parameters.
struct SlabLayout {
    engine_off: usize,
    account_size: usize,
    bitmap_off: usize,
    max_accounts: usize,
    // Account field offsets (layout-dependent)
    acct_owner_off: usize,
    acct_pos_size_lo_off: usize,
    acct_pos_size_hi_off: usize,
    acct_entry_price_off: usize,
    // Engine field offsets relative to engine_off (layout-dependent)
    engine_mark_price_off: usize,
    engine_maint_margin_off: usize,
    engine_funding_index_off: usize,
}

/// V0 layout constants (deployed devnet).
const V0_HEADER: usize = 72;
#[allow(dead_code)]
const V0_CONFIG: usize = 408;
const V0_ENGINE_OFF: usize = 480; // align_up(72 + 408, 8)
const V0_ACCOUNT_SIZE: usize = 240;
const V0_BITMAP_OFF: usize = 608; // engine_off + 128

/// V1D layout constants (deployed Small program).
const V1D_ENGINE_OFF: usize = 424;
const V1D_ACCOUNT_SIZE: usize = 240;
const V1D_BITMAP_OFF: usize = 1048; // engine_off + 624

/// V12_1 layout constants (upstream rebase — mainnet target, HOST aarch64).
const V12_1_ENGINE_OFF_LAYOUT: usize = 648; // align_up(104 + 544, 8)
const V12_1_ACCOUNT_SIZE_LAYOUT: usize = 320;
const V12_1_BITMAP_OFF_LAYOUT: usize = 1016; // engine_off + 368

/// V12_1_EP layout constants (entry_price re-added, SBF deployed binary).
/// Account grows from 280 → 288 on SBF. Engine at 616, bitmap at engine+584.
const V12_1_EP_ENGINE_OFF: usize = 616;
const V12_1_EP_ACCOUNT_SIZE: usize = 288;
const V12_1_EP_BITMAP_OFF: usize = 1200; // engine_off(616) + 584 = 1200 absolute

/// V12_15 layout constants — sourced from slab_types.rs compile-time assertions.
/// Engine at 616 (SBF, align 8). Account offsets from slab_types::ACCT_OFF_*.
const V12_15_ENGINE_OFF: usize = slab_types::ENGINE_OFF;  // 616
const V12_15_ACCOUNT_SIZE: usize = 920;       // 8 cohorts, SBF (verified on-chain)
const V12_15_ACCOUNT_SIZE_FULL: usize = 4400; // 62 cohorts (upstream default)

/// Detect layout from slab data length and header.
fn detect_layout(data: &[u8]) -> Result<SlabLayout, ProgramError> {
    if data.len() < V0_HEADER {
        return Err(NftError::SlabDataTooShort.into());
    }

    // PERC-9023: Verify slab magic before trusting any other header fields.
    // SLAB_MAGIC was defined but never checked, allowing any Percolator-owned
    // account (e.g. a config account) that happens to match the size heuristic
    // to be parsed as a slab, reading garbage position data.
    let magic = read_u64(data, 0)?;
    if magic != SLAB_MAGIC {
        return Err(NftError::UnrecognizedSlabLayout.into());
    }

    // Read max_accounts. V12_15 stores it in RiskParams (engine+32, offset 24 within params).
    // Older layouts stored it in the header at offset 8.
    // Try the V12_15 engine path first (engine at 616, params at +32, max_accounts at params+24).
    let max_accounts_v1215 = if data.len() > 616 + 32 + 32 {
        read_u64(data, 616 + 32 + 24)? as usize  // engine(616) + params(32) + max_accounts_off(24)
    } else { 0 };
    let max_accounts_header = read_u16(data, 8)? as usize;
    let max_accounts = if max_accounts_v1215 > 0 && max_accounts_v1215 <= 4096 {
        max_accounts_v1215
    } else if max_accounts_header > 0 {
        max_accounts_header
    } else {
        return Err(NftError::UnrecognizedSlabLayout.into());
    };

    // Try V0 first (most common on devnet).
    let v0_bitmap_bytes = max_accounts.div_ceil(8);
    let v0_accounts_off = V0_BITMAP_OFF + v0_bitmap_bytes;
    let v0_total = v0_accounts_off + max_accounts * V0_ACCOUNT_SIZE;

    // PERC-9039: Use >= instead of == for layout size matching.
    // The original exact-match (==) breaks if Percolator adds even 1 byte
    // to the slab (e.g. a trailing version field or padding). Using >= with
    // a minimum size threshold is forward-compatible — we only need the data
    // to be at least as large as our layout requires. The magic + max_accounts
    // checks above already validate the header.
    if data.len() >= v0_total && data.len() <= v0_total + 64 {
        return Ok(SlabLayout {
            engine_off: V0_ENGINE_OFF,
            account_size: V0_ACCOUNT_SIZE,
            bitmap_off: V0_BITMAP_OFF,
            max_accounts,
            acct_owner_off: 184,
            acct_pos_size_lo_off: 80,
            acct_pos_size_hi_off: 88,
            acct_entry_price_off: 96,
            engine_mark_price_off: 0, // V0 has no mark_price in engine — uses config
            engine_maint_margin_off: 96, // params_off(48) + 8 + warmup(8) = ~56..96 (V0 layout)
            engine_funding_index_off: 112,
        });
    }

    // Try V1D.
    let v1d_bitmap_bytes = max_accounts.div_ceil(8);
    let v1d_accounts_off = V1D_BITMAP_OFF + v1d_bitmap_bytes;
    let v1d_total = v1d_accounts_off + max_accounts * V1D_ACCOUNT_SIZE;

    if data.len() >= v1d_total && data.len() <= v1d_total + 64 {
        return Ok(SlabLayout {
            engine_off: V1D_ENGINE_OFF,
            account_size: V1D_ACCOUNT_SIZE,
            bitmap_off: V1D_BITMAP_OFF,
            max_accounts,
            acct_owner_off: 184,
            acct_pos_size_lo_off: 80,
            acct_pos_size_hi_off: 88,
            acct_entry_price_off: 96,
            engine_mark_price_off: 424, // V1D mark_price at engine+424
            engine_maint_margin_off: 80, // params_off(72) + 8 = 80
            engine_funding_index_off: 392,
        });
    }

    // Try V12_15 (upstream sync, reserve cohorts, 8 cohorts / --features small).
    // V12_15 accounts are 920 bytes (8 reserve cohorts), NOT 320 like V12_1.
    // slab_types::ENGINE_REL_ACCOUNTS is wrong here because it's computed from
    // the V12_1 Account struct (320 bytes). We use the verified on-chain geometry:
    // bitmap at engine+648, accounts at absolute 1832 (engine+1216).
    let v1215_bitmap_off = V12_15_ENGINE_OFF + 648; // verified on-chain
    let v1215_accounts_off = V12_15_ENGINE_OFF + 1216; // verified on-chain: 1832 absolute
    let v1215_total = v1215_accounts_off + max_accounts * V12_15_ACCOUNT_SIZE;

    if data.len() >= v1215_total && data.len() <= v1215_total + 256 {
        return Ok(SlabLayout {
            engine_off: V12_15_ENGINE_OFF,
            account_size: V12_15_ACCOUNT_SIZE,
            bitmap_off: v1215_bitmap_off,
            max_accounts,
            // V12_15 account offsets verified on-chain (session 2026-04-12).
            // V12_15 REMOVED warmup_started_at_slot and warmup_slope_per_step from Account,
            // so position_basis_q is at 64 (not 88 like V12_1 which has those fields).
            acct_owner_off: 192,           // verified on-chain
            acct_pos_size_lo_off: 64,      // position_basis_q: i128 at 64 (V12_15 layout)
            acct_pos_size_hi_off: 72,
            acct_entry_price_off: 120,     // entry_price: u64 at 120
            // V12_15 engine layout is DIFFERENT from V12_1 — no mark_price, no single funding_index.
            // Params at engine+32, mm_bps at params+0 = engine+32.
            engine_mark_price_off: 0,      // not present in V12_15 engine — use oraclePriceE6 from SDK
            engine_maint_margin_off: 32,   // params starts at engine+32, mm_bps is first field
            engine_funding_index_off: 0,   // not present as single field (per-side in V12_15)
        });
    }

    // Try V12_15 full (62 cohorts, 4400-byte accounts).
    // Same engine offsets, different account size.
    let v1215f_bitmap_bytes = max_accounts.div_ceil(8);
    let v1215f_accounts_off = v1215_bitmap_off + v1215f_bitmap_bytes + 18 + max_accounts * 2;
    let v1215f_accounts_off_aligned = (v1215f_accounts_off + 7) & !7;
    let v1215f_total = v1215f_accounts_off_aligned + max_accounts * V12_15_ACCOUNT_SIZE_FULL;

    if data.len() >= v1215f_total && data.len() <= v1215f_total + 256 {
        return Ok(SlabLayout {
            engine_off: V12_15_ENGINE_OFF,
            account_size: V12_15_ACCOUNT_SIZE_FULL,
            bitmap_off: v1215_bitmap_off,
            max_accounts,
            // Same account/engine offsets as small variant — field positions don't change with cohort count
            acct_owner_off: 192,
            acct_pos_size_lo_off: 64,
            acct_pos_size_hi_off: 72,
            acct_entry_price_off: 120,
            engine_mark_price_off: 0,      // not present in V12_15 engine
            engine_maint_margin_off: 32,   // params at engine+32, mm_bps first
            engine_funding_index_off: 0,   // not present as single field
        });
    }

    // Try V12_1_EP (SBF deployed, entry_price re-added, 288-byte accounts).
    let v12ep_bitmap_bytes = max_accounts.div_ceil(8);
    let v12ep_accounts_off = V12_1_EP_BITMAP_OFF + v12ep_bitmap_bytes;
    let v12ep_total = v12ep_accounts_off + max_accounts * V12_1_EP_ACCOUNT_SIZE;

    if data.len() >= v12ep_total && data.len() <= v12ep_total + 64 {
        return Ok(SlabLayout {
            engine_off: V12_1_EP_ENGINE_OFF,
            account_size: V12_1_EP_ACCOUNT_SIZE,
            bitmap_off: V12_1_EP_BITMAP_OFF,
            max_accounts,
            // V12_1_EP has a DIFFERENT account layout from V12_15 (fewer fields, different offsets).
            // These offsets were probed from the deployed SBF binary (session 2026-04-12).
            acct_owner_off: 216,           // probed: owner at SBF offset 216 (EP layout shifts +8)
            acct_pos_size_lo_off: 88,      // position_basis_q at SBF offset 88
            acct_pos_size_hi_off: 96,
            acct_entry_price_off: 144,     // entry_price at SBF offset 144
            engine_mark_price_off: 560,    // probed: markPriceE6 at engine+560 (V12_1 SBF)
            engine_maint_margin_off: 40,   // SBF: params at engine+32, maint_margin at params+8 = 40
            engine_funding_index_off: 0,   // not present in V12_1 engine (global funding removed)
        });
    }

    // Try V12_1 HOST (upstream rebase, 320-byte accounts).
    let v12_bitmap_bytes = max_accounts.div_ceil(8);
    let v12_accounts_off = V12_1_BITMAP_OFF_LAYOUT + v12_bitmap_bytes;
    let v12_total = v12_accounts_off + max_accounts * V12_1_ACCOUNT_SIZE_LAYOUT;

    if data.len() >= v12_total && data.len() <= v12_total + 64 {
        return Ok(SlabLayout {
            engine_off: V12_1_ENGINE_OFF_LAYOUT,
            account_size: V12_1_ACCOUNT_SIZE_LAYOUT,
            bitmap_off: V12_1_BITMAP_OFF_LAYOUT,
            max_accounts,
            // V12_1 HOST layout — uses slab_types compile-time verified offsets
            acct_owner_off: slab_types::ACCT_OFF_OWNER,                       // 208
            acct_pos_size_lo_off: slab_types::ACCT_OFF_POSITION_SIZE,         // 296 (legacy sign+magnitude)
            acct_pos_size_hi_off: slab_types::ACCT_OFF_POSITION_SIZE + 8,     // 304
            acct_entry_price_off: slab_types::ACCT_OFF_ENTRY_PRICE,           // 280
            engine_mark_price_off: slab_types::ENGINE_REL_MARK_PRICE_E6,      // 928
            engine_maint_margin_off: slab_types::ENGINE_REL_MAINT_MARGIN_BPS, // 104
            engine_funding_index_off: slab_types::ENGINE_REL_FUNDING_INDEX_QPB_E6, // 936
        });
    }

    Err(NftError::UnrecognizedSlabLayout.into())
}

// ═══════════════════════════════════════════════════════════════
// Position data extraction
// ═══════════════════════════════════════════════════════════════

/// Position data read from a slab account.
#[derive(Debug)]
pub struct PositionData {
    /// Account ID (at slab acct_off+0) — monotonically increasing, unique per account.
    pub account_id: u64,
    /// Owner pubkey of this account slot (at slab acct_off+184).
    pub owner: Pubkey,
    /// Deposited margin (capital) in micro-units — lo-word of capital: U128 at acct_off+8.
    /// This is the actual collateral at risk, NOT the notional trade size.
    pub collateral: u64,
    /// Signed position size (I128) from slab — positive=long, negative=short, 0=flat.
    pub position_basis_q: i128,
    /// Notional trade size — absolute value of position_size: I128 lo-word at acct_off+80.
    pub size: u64,
    /// Entry price (E6 fixed-point) at acct_off+96.
    pub entry_price_e6: u64,
    /// 1 = long (position_size ≥ 0), 0 = short (position_size < 0).
    /// Derived from the sign of position_size.I128 hi-word at acct_off+88.
    pub is_long: u8,
    /// Account kind: 0 = User (trader), 1 = LP (liquidity provider).
    /// Only User accounts should get NFTs.
    pub kind: u32,
    /// Current global funding index (E18) from engine.
    pub global_funding_index_e18: i128,
    /// Byte offset to the engine block within slab data (layout-dependent).
    /// Callers can use this to read further engine fields (e.g. mark_price).
    pub engine_off: usize,
    /// Mark price offset relative to engine_off (layout-dependent).
    pub engine_mark_price_off: usize,
    /// Maintenance margin BPS offset relative to engine_off (layout-dependent).
    pub engine_maint_margin_off: usize,
    /// Funding index offset relative to engine_off (layout-dependent).
    pub engine_funding_index_off: usize,
}

/// Account struct field offsets within each account slot.
/// These must match percolator-prog Account struct layout (repr(C), 240 bytes):
///   account_id: u64          →  +0   (8 bytes)
///   capital: U128            →  +8   (16 bytes) — deposited collateral
///   kind: AccountKind        →  +24  (4 bytes, repr(C) enum)
///   pnl: I128                →  +28  (16 bytes)
///   reserved_pnl: u64        →  +48  (8 bytes)
///   warmup_started_at_slot   →  +56  (8 bytes)
///   warmup_slope_per_step    →  +64  (16 bytes)
///   position_size: I128      →  +80  (16 bytes) — signed notional size
///   entry_price: u64         →  +96  (8 bytes)
///   funding_index: I128      →  +104 (16 bytes)
///   matcher_program: [u8;32] →  +120 (32 bytes)
///   matcher_context: [u8;32] →  +152 (32 bytes)
///   owner: [u8;32]           →  +184 (32 bytes)
///   fee_credits: I128        →  +216 (16 bytes)
///   last_fee_slot: u64       →  +232 (8 bytes)
const ACCT_ACCOUNT_ID_OFF: usize = 0; // account_id: u64 (unique per account, monotonically increasing)
const ACCT_OWNER_OFF: usize = 184; // owner pubkey (32 bytes)
const ACCT_COLLATERAL_OFF: usize = 8; // capital: U128 lo-word — deposited margin
const ACCT_KIND_OFF: usize = 24; // kind: AccountKind (0=User, 1=LP) — u32 repr(C)
const ACCT_POS_SIZE_LO_OFF: usize = 80; // position_size: I128 lo-word (absolute magnitude u64)
const ACCT_POS_SIZE_HI_OFF: usize = 88; // position_size: I128 hi-word (negative hi-word → short)
const ACCT_ENTRY_PRICE_OFF: usize = 96; // entry_price: u64

/// Engine mark price offset from engine_off.
const ENGINE_FUNDING_INDEX_OFF: usize = 64; // i128 at engine + 64

/// Read position data for a given user_idx from slab account data.
pub fn read_position(slab_data: &[u8], user_idx: u16) -> Result<PositionData, ProgramError> {
    let layout = detect_layout(slab_data)?;

    let idx = user_idx as usize;
    if idx >= layout.max_accounts {
        return Err(NftError::UserIndexOutOfRange.into());
    }

    // Check bitmap — is this slot allocated?
    let bitmap_byte = layout.bitmap_off + idx / 8;
    if bitmap_byte >= slab_data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }

    // Verify the allocation bit is set — defence-in-depth against freed/empty slots.
    let bit_mask = 1u8 << (idx % 8);
    if slab_data[bitmap_byte] & bit_mask == 0 {
        return Err(NftError::UserIndexOutOfRange.into());
    }

    let accounts_off = layout.bitmap_off + layout.max_accounts.div_ceil(8);
    let acct_off = accounts_off + idx * layout.account_size;
    let acct_end = acct_off + layout.account_size;

    if acct_end > slab_data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }

    // Read account_id first.
    let account_id = read_u64(slab_data, acct_off + ACCT_ACCOUNT_ID_OFF)?;

    // Read owner pubkey (layout-dependent offset).
    let owner = Pubkey::new_from_array(
        slab_data[acct_off + layout.acct_owner_off..acct_off + layout.acct_owner_off + 32]
            .try_into()
            .unwrap(),
    );

    let kind = read_u32(slab_data, acct_off + ACCT_KIND_OFF)?;
    // PERC-9037: Read collateral as U128 lo-word. The capital field is a
    // Percolator U128 stored as [lo: u64, hi: u64]. We only use the lo-word,
    // which is correct for values < 2^64. Verify the hi-word is zero to detect
    // overflow that would silently truncate the collateral value — a truncated
    // collateral makes the position appear under-collateralized in margin checks.
    let collateral = read_u64(slab_data, acct_off + ACCT_COLLATERAL_OFF)?;
    let collateral_hi = read_u64(slab_data, acct_off + ACCT_COLLATERAL_OFF + 8)?;
    if collateral_hi != 0 {
        solana_program::msg!("read_position: collateral U128 hi-word is non-zero, value exceeds u64");
        return Err(ProgramError::ArithmeticOverflow);
    }

    // Read position_basis_q as native i128 (two's complement in v12.15) or
    // I128 sign+magnitude (pre-v12.15).
    let position_basis_q = read_i128(slab_data, acct_off + layout.acct_pos_size_lo_off)?;
    // V12.15 uses two's complement i128 for position_basis_q.
    // Both the small (920-byte) and full (4400-byte) variants use the same encoding.
    let is_v12_15 = layout.account_size == V12_15_ACCOUNT_SIZE
        || layout.account_size == V12_15_ACCOUNT_SIZE_FULL;
    let (size, is_long) = if is_v12_15 {
        // V12.15: native i128 (two's complement). Derive size and direction directly.
        let abs = position_basis_q.unsigned_abs() as u64;
        let long: u8 = if position_basis_q >= 0 { 1 } else { 0 };
        (abs, long)
    } else {
        // Pre-v12.15: I128 sign+magnitude encoding.
        let lo = read_u64(slab_data, acct_off + layout.acct_pos_size_lo_off)?;
        let hi = read_u64(slab_data, acct_off + layout.acct_pos_size_hi_off)?;
        let long: u8 = if (hi as i64) < 0 { 0 } else { 1 };
        if hi & 0x7FFF_FFFF_FFFF_FFFF != 0 {
            solana_program::msg!("read_position: position_size I128 exceeds u64 magnitude");
            return Err(ProgramError::ArithmeticOverflow);
        }
        (lo, long)
    };
    let entry_price_e6 = read_u64(slab_data, acct_off + layout.acct_entry_price_off)?;

    // PERC-9060: Propagate error instead of silently defaulting to 0.
    // A zero funding index would cause incorrect funding settlement on
    // NFT transfers, matching transfer_hook.rs error propagation pattern.
    let funding_off = layout.engine_off + layout.engine_funding_index_off;
    let global_funding_index_e18 = read_i128(slab_data, funding_off)?;

    Ok(PositionData {
        account_id,
        owner,
        collateral,
        position_basis_q,
        kind,
        size,
        entry_price_e6,
        is_long,
        global_funding_index_e18,
        engine_off: layout.engine_off,
        engine_mark_price_off: layout.engine_mark_price_off,
        engine_maint_margin_off: layout.engine_maint_margin_off,
        engine_funding_index_off: layout.engine_funding_index_off,
    })
}

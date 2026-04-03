//! CPI helpers for reading Percolator slab position data.
//!
//! We read position state directly from the slab account data
//! without depending on percolator-prog crate. Layout offsets
//! must match the deployed on-chain program.

use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::error::NftError;

// ═══════════════════════════════════════════════════════════════
// Percolator program IDs (verified at runtime via account owner)
// ═══════════════════════════════════════════════════════════════

/// Known Percolator program IDs for slab ownership verification.
/// At runtime we check `slab.owner == one of these`.
pub const PERCOLATOR_DEVNET: Pubkey =
    solana_program::pubkey!("FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD");
pub const PERCOLATOR_MAINNET: Pubkey =
    solana_program::pubkey!("GM8zjJ8LTBMv9xEsverh6H6wLyevgMHEJXcEzyY3rY24");

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
pub const SLAB_MAGIC: u64 = 0x5045_5243_534C_4142; // "PERCSLAB"

/// Read a u64 from a byte slice at the given offset.
fn read_u64(data: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = data[off..off + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Read a u16 from a byte slice at the given offset.
fn read_u16(data: &[u8], off: usize) -> u16 {
    let bytes: [u8; 2] = data[off..off + 2].try_into().unwrap();
    u16::from_le_bytes(bytes)
}

/// Read a u32 from a byte slice at the given offset.
fn read_u32(data: &[u8], off: usize) -> u32 {
    let bytes: [u8; 4] = data[off..off + 4].try_into().unwrap();
    u32::from_le_bytes(bytes)
}

/// Read an i128 from a byte slice at the given offset.
fn read_i128(data: &[u8], off: usize) -> i128 {
    let bytes: [u8; 16] = data[off..off + 16].try_into().unwrap();
    i128::from_le_bytes(bytes)
}

/// Detected slab layout parameters.
struct SlabLayout {
    engine_off: usize,
    account_size: usize,
    bitmap_off: usize,
    max_accounts: usize,
}

/// V0 layout constants (deployed devnet).
const V0_HEADER: usize = 72;
const V0_CONFIG: usize = 408;
const V0_ENGINE_OFF: usize = 480; // align_up(72 + 408, 8)
const V0_ACCOUNT_SIZE: usize = 240;
const V0_BITMAP_OFF: usize = 608; // engine_off + 128

/// V1D layout constants (deployed Small program).
const V1D_ENGINE_OFF: usize = 424;
const V1D_ACCOUNT_SIZE: usize = 240;
const V1D_BITMAP_OFF: usize = 1048; // engine_off + 624

/// Detect layout from slab data length and header.
fn detect_layout(data: &[u8]) -> Result<SlabLayout, ProgramError> {
    if data.len() < V0_HEADER {
        return Err(NftError::SlabDataTooShort.into());
    }

    // Read max_accounts from header offset 8.
    let max_accounts = read_u16(data, 8) as usize;
    if max_accounts == 0 {
        return Err(NftError::UnrecognizedSlabLayout.into());
    }

    // Try V0 first (most common on devnet).
    let v0_bitmap_bytes = (max_accounts + 7) / 8;
    let v0_accounts_off = V0_BITMAP_OFF + v0_bitmap_bytes;
    let v0_total = v0_accounts_off + max_accounts * V0_ACCOUNT_SIZE;

    if data.len() == v0_total || data.len() == v0_total + 8 {
        return Ok(SlabLayout {
            engine_off: V0_ENGINE_OFF,
            account_size: V0_ACCOUNT_SIZE,
            bitmap_off: V0_BITMAP_OFF,
            max_accounts,
        });
    }

    // Try V1D.
    let v1d_bitmap_bytes = (max_accounts + 7) / 8;
    let v1d_accounts_off = V1D_BITMAP_OFF + v1d_bitmap_bytes;
    let v1d_total = v1d_accounts_off + max_accounts * V1D_ACCOUNT_SIZE;

    // Accept both postBitmap=2 and postBitmap=18 sizes.
    if data.len() == v1d_total || data.len() == v1d_total + 16 {
        return Ok(SlabLayout {
            engine_off: V1D_ENGINE_OFF,
            account_size: V1D_ACCOUNT_SIZE,
            bitmap_off: V1D_BITMAP_OFF,
            max_accounts,
        });
    }

    Err(NftError::UnrecognizedSlabLayout.into())
}

// ═══════════════════════════════════════════════════════════════
// Position data extraction
// ═══════════════════════════════════════════════════════════════

/// Position data read from a slab account.
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

    let accounts_off = layout.bitmap_off + (layout.max_accounts + 7) / 8;
    let acct_off = accounts_off + idx * layout.account_size;
    let acct_end = acct_off + layout.account_size;

    if acct_end > slab_data.len() {
        return Err(NftError::SlabDataTooShort.into());
    }

    // Read account_id first.
    let account_id = read_u64(slab_data, acct_off + ACCT_ACCOUNT_ID_OFF);

    // Read owner pubkey.
    let owner = Pubkey::new_from_array(
        slab_data[acct_off + ACCT_OWNER_OFF..acct_off + ACCT_OWNER_OFF + 32]
            .try_into()
            .unwrap(),
    );

    let collateral = read_u64(slab_data, acct_off + ACCT_COLLATERAL_OFF);
    let kind = read_u32(slab_data, acct_off + ACCT_KIND_OFF);
    // position_size is I128 = [lo: u64, hi: u64]. Absolute size = lo-word; sign = hi-word MSB.
    // position_basis_q is the full signed I128.
    let position_basis_q = read_i128(slab_data, acct_off + ACCT_POS_SIZE_LO_OFF);
    let size = read_u64(slab_data, acct_off + ACCT_POS_SIZE_LO_OFF);
    let pos_hi = read_u64(slab_data, acct_off + ACCT_POS_SIZE_HI_OFF);
    let is_long: u8 = if (pos_hi as i64) < 0 { 0 } else { 1 };
    let entry_price_e6 = read_u64(slab_data, acct_off + ACCT_ENTRY_PRICE_OFF);

    // Read global funding index from engine.
    let funding_off = layout.engine_off + ENGINE_FUNDING_INDEX_OFF;
    let global_funding_index_e18 = if funding_off + 16 <= slab_data.len() {
        read_i128(slab_data, funding_off)
    } else {
        0i128
    };

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
    })
}

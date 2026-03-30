/// Tests for read_position() bitmap allocation-bit check (GH#25 / PERC-8283).
///
/// Defence-in-depth: read_position() must reject slots where the bitmap bit is 0
/// (unallocated / freed) even if the account data bytes are otherwise valid.
use percolator_nft::cpi::read_position;
use percolator_nft::error::NftError;
use solana_program::program_error::ProgramError;

// ─── Minimal V0 slab builder ────────────────────────────────────────────────
//
// V0 layout (see cpi.rs constants):
//   header_off  = 0..72        (max_accounts at byte 8 as u16)
//   config_off  = 72..480
//   engine_off  = 480..608
//   bitmap_off  = 608
//   accounts_off = 608 + ceil(max_accounts/8)
//   account_size = 240 bytes
//
// We build the minimal buffer that detect_layout() will accept.

const V0_HEADER: usize = 72;
const V0_ENGINE_OFF: usize = 480;
const V0_BITMAP_OFF: usize = 608;
const V0_ACCOUNT_SIZE: usize = 240;

fn build_v0_slab(max_accounts: u16, set_bits: &[usize]) -> Vec<u8> {
    let max = max_accounts as usize;
    let bitmap_bytes = (max + 7) / 8;
    let accounts_off = V0_BITMAP_OFF + bitmap_bytes;
    let total = accounts_off + max * V0_ACCOUNT_SIZE;

    let mut buf = vec![0u8; total];

    // Write max_accounts at offset 8 (u16 LE).
    buf[8] = (max_accounts & 0xff) as u8;
    buf[9] = (max_accounts >> 8) as u8;

    // Set requested bitmap bits.
    for &idx in set_bits {
        let byte = V0_BITMAP_OFF + idx / 8;
        buf[byte] |= 1u8 << (idx % 8);
    }

    buf
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Slot 0 with bitmap bit UNSET → must return UserIndexOutOfRange (error 5).
#[test]
fn test_unallocated_slot_returns_error() {
    let slab = build_v0_slab(4, &[]); // no bits set
    match read_position(&slab, 0) {
        Err(e) => assert_eq!(
            e,
            ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
            "unallocated slot should return UserIndexOutOfRange"
        ),
        Ok(_) => panic!("expected error for unallocated slot 0"),
    }
}

/// Slot 1 unallocated even though slot 0 is allocated.
#[test]
fn test_unallocated_slot1_returns_error() {
    let slab = build_v0_slab(4, &[0]); // only slot 0 allocated
    match read_position(&slab, 1) {
        Err(e) => assert_eq!(
            e,
            ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
            "slot 1 not in bitmap → UserIndexOutOfRange"
        ),
        Ok(_) => panic!("expected error for unallocated slot 1"),
    }
}

/// Slot 0 with bitmap bit SET → must NOT return UserIndexOutOfRange.
/// (The position data will be zeroed — that's fine for this test.)
#[test]
fn test_allocated_slot_does_not_return_bitmap_error() {
    let slab = build_v0_slab(4, &[0]); // slot 0 allocated
    let result = read_position(&slab, 0);
    // Should succeed (zeroed data is valid, owner will be system program pubkey).
    assert!(
        result.is_ok(),
        "allocated slot should be readable"
    );
}

/// Slot 3 allocated, slots 0-2 not — reading slot 3 succeeds.
#[test]
fn test_only_last_slot_allocated() {
    let slab = build_v0_slab(4, &[3]); // only slot 3 set
    // Slots 0,1,2 should fail.
    for idx in 0u16..3 {
        match read_position(&slab, idx) {
            Err(e) => assert_eq!(
                e,
                ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
                "slot {idx} should be unallocated"
            ),
            Ok(_) => panic!("expected error for unallocated slot {idx}"),
        }
    }
    // Slot 3 should succeed.
    assert!(read_position(&slab, 3).is_ok(), "slot 3 is allocated and should be readable");
}

/// All slots in a byte allocated, check every one succeeds.
#[test]
fn test_full_byte_all_slots_allocated() {
    let slab = build_v0_slab(8, &[0, 1, 2, 3, 4, 5, 6, 7]);
    for idx in 0u16..8 {
        assert!(read_position(&slab, idx).is_ok(), "slot {idx} should be allocated and readable");
    }
}

/// Slot beyond max_accounts → UserIndexOutOfRange (existing bounds check, not bitmap).
#[test]
fn test_out_of_bounds_index() {
    let slab = build_v0_slab(4, &[0, 1, 2, 3]);
    match read_position(&slab, 4) {
        Err(e) => assert_eq!(
            e,
            ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
            "index >= max_accounts → UserIndexOutOfRange"
        ),
        Ok(_) => panic!("expected error for out-of-bounds index 4"),
    }
}

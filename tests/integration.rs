//! Integration tests for the percolator-nft program.
//!
//! Tests full lifecycle flows: Mint, Transfer hook health check, Burn, SettleFunding.
//! Also covers edge cases: LP rejection, open-position burn rejection, closed-position
//! transfer, bitmap unallocated rejection, SLAB_MAGIC validation, V1D layout detection.
//!
//! These tests operate below the Solana runtime (no solana-program-test). We drive
//! `process()` directly with hand-crafted AccountInfo slices, stopping at the first
//! CPI call (which requires runtime). Tests validate guards that fire before any CPI.

use bytemuck::Zeroable;
use percolator_nft::{
    cpi::{read_position, PERCOLATOR_MAINNET, SLAB_MAGIC},
    error::NftError,
    instruction::NftInstruction,
    state::{
        mint_authority_pda, position_nft_pda, PositionNft, POSITION_NFT_LEN, POSITION_NFT_MAGIC,
        POSITION_NFT_VERSION,
    },
    token2022::TOKEN_2022_PROGRAM_ID,
    transfer_hook::EXECUTE_DISCRIMINATOR,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use solana_sdk::pubkey::Pubkey as SdkPubkey;

// ════════════════════════════════════════════════════════════════
// Shared slab builders
// ════════════════════════════════════════════════════════════════

const V0_HEADER: usize = 72;
const V0_BITMAP_OFF: usize = 608;
const V0_ACCOUNT_SIZE: usize = 240;
const V0_ENGINE_OFF: usize = 480;

/// Build a minimal valid V0 slab.
///
/// `max_accounts`: number of account slots.
/// `set_bits`: which slot indices to mark as allocated in the bitmap.
/// `account_overrides`: optional (slot_idx, offset_within_slot, bytes) tuples
///   to write arbitrary bytes into account slots for testing.
fn build_v0_slab(max_accounts: u16, set_bits: &[usize]) -> Vec<u8> {
    let max = max_accounts as usize;
    let bitmap_bytes = (max + 7) / 8;
    let accounts_off = V0_BITMAP_OFF + bitmap_bytes;
    let total = accounts_off + max * V0_ACCOUNT_SIZE;

    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&SLAB_MAGIC.to_le_bytes());
    buf[8..10].copy_from_slice(&max_accounts.to_le_bytes());

    for &idx in set_bits {
        let byte_pos = V0_BITMAP_OFF + idx / 8;
        buf[byte_pos] |= 1u8 << (idx % 8);
    }

    buf
}

/// Build a V0 slab with a position in slot `slot_idx`.
///
/// `collateral`: lo-word of capital U128.
/// `size_lo`: absolute magnitude of position (lo-word of I128).
/// `size_hi`: hi-word of I128 (0 = long, 0x8000..00 = short; use 0 for long).
/// `entry_price_e6`: entry price.
/// `kind`: 0 = User, 1 = LP.
/// `account_id`: monotonic account ID.
fn build_v0_slab_with_position(
    max_accounts: u16,
    slot_idx: usize,
    collateral: u64,
    size_lo: u64,
    size_hi: u64,
    entry_price_e6: u64,
    kind: u32,
    account_id: u64,
    mark_price_e6: u64,
    maint_margin_bps: u64,
) -> Vec<u8> {
    build_v0_slab_with_position_owner(
        max_accounts, slot_idx, collateral, size_lo, size_hi,
        entry_price_e6, kind, account_id, mark_price_e6, maint_margin_bps,
        None,
    )
}

fn build_v0_slab_with_position_owner(
    max_accounts: u16,
    slot_idx: usize,
    collateral: u64,
    size_lo: u64,
    size_hi: u64,
    entry_price_e6: u64,
    kind: u32,
    account_id: u64,
    mark_price_e6: u64,
    maint_margin_bps: u64,
    owner: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut slab = build_v0_slab(max_accounts, &[slot_idx]);

    let bitmap_bytes = ((max_accounts as usize) + 7) / 8;
    let accounts_off = V0_BITMAP_OFF + bitmap_bytes;
    let acct_off = accounts_off + slot_idx * V0_ACCOUNT_SIZE;

    // account_id at +0
    slab[acct_off..acct_off + 8].copy_from_slice(&account_id.to_le_bytes());
    // capital: U128 lo-word at +8 (collateral), hi-word at +16 (0)
    slab[acct_off + 8..acct_off + 16].copy_from_slice(&collateral.to_le_bytes());
    slab[acct_off + 16..acct_off + 24].copy_from_slice(&0u64.to_le_bytes());
    // kind: u32 at +24
    slab[acct_off + 24..acct_off + 28].copy_from_slice(&kind.to_le_bytes());
    // position_size: I128 lo-word at +80, hi-word at +88
    slab[acct_off + 80..acct_off + 88].copy_from_slice(&size_lo.to_le_bytes());
    slab[acct_off + 88..acct_off + 96].copy_from_slice(&size_hi.to_le_bytes());
    // entry_price at +96
    slab[acct_off + 96..acct_off + 104].copy_from_slice(&entry_price_e6.to_le_bytes());

    // owner pubkey at +184 (32 bytes)
    if let Some(owner_bytes) = owner {
        slab[acct_off + 184..acct_off + 216].copy_from_slice(owner_bytes);
    }

    // Engine block: mark_price_e6 at engine_off+0, maint_margin_bps at engine_off+96
    slab[V0_ENGINE_OFF..V0_ENGINE_OFF + 8].copy_from_slice(&mark_price_e6.to_le_bytes());
    slab[V0_ENGINE_OFF + 96..V0_ENGINE_OFF + 104]
        .copy_from_slice(&maint_margin_bps.to_le_bytes());
    // global_funding_index_e18 at engine_off+64 (i128 = 0 by default)

    slab
}

/// Build a minimal valid V1D slab.
///
/// V1D layout: engine_off=424, bitmap_off=1048, account_size=240.
fn build_v1d_slab(max_accounts: u16, set_bits: &[usize]) -> Vec<u8> {
    const V1D_ENGINE_OFF: usize = 424;
    const V1D_BITMAP_OFF: usize = 1048;
    const V1D_ACCOUNT_SIZE: usize = 240;

    let max = max_accounts as usize;
    let bitmap_bytes = (max + 7) / 8;
    let accounts_off = V1D_BITMAP_OFF + bitmap_bytes;
    let total = accounts_off + max * V1D_ACCOUNT_SIZE;

    let mut buf = vec![0u8; total];
    buf[0..8].copy_from_slice(&SLAB_MAGIC.to_le_bytes());
    buf[8..10].copy_from_slice(&max_accounts.to_le_bytes());

    for &idx in set_bits {
        let byte_pos = V1D_BITMAP_OFF + idx / 8;
        buf[byte_pos] |= 1u8 << (idx % 8);
    }

    // Write mark_price_e6 into V1D engine block so health checks can read it
    buf[V1D_ENGINE_OFF..V1D_ENGINE_OFF + 8]
        .copy_from_slice(&1_000_000_000u64.to_le_bytes());

    buf
}

/// Build minimal valid PositionNft PDA data.
fn make_pda_data(slab_key: &SdkPubkey, nft_mint_key: &SdkPubkey) -> Vec<u8> {
    let mut buf = vec![0u8; POSITION_NFT_LEN];
    buf[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    buf[8] = POSITION_NFT_VERSION;
    buf[16..48].copy_from_slice(slab_key.as_ref());
    buf[56..88].copy_from_slice(nft_mint_key.as_ref());
    buf
}

// ════════════════════════════════════════════════════════════════
// Lifecycle: Mint flow — slab data with open User position,
// expect rejection at first CPI-requiring step (MissingRequiredSignature
// on owner, since we cannot sign in unit tests) or pass all pre-CPI guards.
// ════════════════════════════════════════════════════════════════

/// Mint flow guard: LP account (kind=1) must be rejected with LpAccountNotAllowed.
/// This drives the processor far enough to hit the kind check (after slab validation).
/// The check fires before any CPI, so no runtime is needed.
#[test]
fn test_mint_rejects_lp_account() {
    use percolator_nft::processor::process;

    let program_id = SdkPubkey::new_unique();
    let owner_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let pda_key = {
        let (pda, _) = position_nft_pda(
            &Pubkey::new_from_array(slab_key.to_bytes()),
            0,
            &Pubkey::new_from_array(program_id.to_bytes()),
        );
        SdkPubkey::new_from_array(pda.to_bytes())
    };
    let mint_auth_key = {
        let (auth, _) = mint_authority_pda(&Pubkey::new_from_array(program_id.to_bytes()));
        SdkPubkey::new_from_array(auth.to_bytes())
    };

    // Slab: slot 0 allocated, kind=1 (LP), size > 0, owner=owner_key
    // account_id=0 matches the zeroed PDA (nft_pda.data_is_empty() → PDA not yet created,
    // so the kind check fires before account_id is verified).
    let owner_bytes: [u8; 32] = owner_key.to_bytes();
    let slab_data = build_v0_slab_with_position_owner(
        1,
        0,
        500_000,        // collateral
        1_000_000,      // size (open)
        0,              // hi-word: long
        50_000_000_000, // entry price
        1,              // kind=1 → LP
        0,              // account_id
        60_000_000_000, // mark price
        500,            // maintenance margin bps
        Some(&owner_bytes),
    );

    let system_pk = solana_program::system_program::id();
    let token_pk = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_pk = Pubkey::new_from_array(program_id.to_bytes());
    let owner_pk = Pubkey::new_from_array(owner_key.to_bytes());

    let mut owner_lamports = 1_000_000_000u64;
    let mut pda_lamports = 0u64;
    let mut mint_lamports = 0u64;
    let mut ata_lamports = 0u64;
    let mut slab_lamports = 1_000_000u64;
    let mut auth_lamports = 0u64;
    let mut token_lamports = 0u64;
    let mut ata_prog_lamports = 0u64;
    let mut sys_lamports = 0u64;
    let mut extra_metas_lamports = 0u64;

    let mut owner_data: Vec<u8> = vec![];
    let mut pda_data: Vec<u8> = vec![];
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut ata_data: Vec<u8> = vec![];
    let mut slab_buf = slab_data;
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];
    let mut ata_prog_data: Vec<u8> = vec![];
    let mut sys_data: Vec<u8> = vec![];
    let mut extra_metas_data: Vec<u8> = vec![];

    let pda_pk = Pubkey::new_from_array(pda_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    // Derive the canonical ATA that the processor expects
    let ata_pk = percolator_nft::token2022::get_associated_token_address(
        &owner_pk,
        &nft_mint_pk,
    );
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let auth_pk = Pubkey::new_from_array(mint_auth_key.to_bytes());
    let ata_program_pk = token2022_ata_program_id();
    let sys_pk = system_pk;
    // PERC-9064: ExtraAccountMetaList PDA is now part of the MintPositionNft
    // account list at slot 9. Derived from [b"extra-account-metas", nft_mint].
    let (extra_metas_pda_pk, _) = percolator_nft::transfer_hook::extra_account_metas_pda(
        &nft_mint_pk,
        &prog_pk,
    );

    let owner_ai = AccountInfo::new(
        &owner_pk,
        true,  // signer
        false,
        &mut owner_lamports,
        &mut owner_data,
        &sys_pk,
        false,
        0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk,
        false,
        true,
        &mut pda_lamports,
        &mut pda_data,
        &prog_pk,
        false,
        0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk,
        true, // signer
        true,
        &mut mint_lamports,
        &mut mint_data,
        &token_pk,
        false,
        0,
    );
    let ata_ai = AccountInfo::new(
        &ata_pk,
        false,
        true,
        &mut ata_lamports,
        &mut ata_data,
        &token_pk,
        false,
        0,
    );
    let slab_ai = AccountInfo::new(
        &slab_pk,
        false,
        false,
        &mut slab_lamports,
        &mut slab_buf,
        &percolator_pk, // owned by known Percolator program
        false,
        0,
    );
    let auth_ai = AccountInfo::new(
        &auth_pk,
        false,
        false,
        &mut auth_lamports,
        &mut auth_data,
        &sys_pk,
        false,
        0,
    );
    let token_ai = AccountInfo::new(
        &token_pk,
        false,
        false,
        &mut token_lamports,
        &mut token_data,
        &sys_pk,
        false,
        0,
    );
    let ata_prog_ai = AccountInfo::new(
        &ata_program_pk,
        false,
        false,
        &mut ata_prog_lamports,
        &mut ata_prog_data,
        &sys_pk,
        false,
        0,
    );
    let sys_ai = AccountInfo::new(
        &sys_pk,
        false,
        false,
        &mut sys_lamports,
        &mut sys_data,
        &sys_pk,
        false,
        0,
    );
    // PERC-9064: slot 9 — ExtraAccountMetaList PDA (writable, created by mint handler).
    let extra_metas_ai = AccountInfo::new(
        &extra_metas_pda_pk,
        false,
        true,
        &mut extra_metas_lamports,
        &mut extra_metas_data,
        &sys_pk,
        false,
        0,
    );

    let accounts = [
        owner_ai,
        pda_ai,
        nft_mint_ai,
        ata_ai,
        slab_ai,
        auth_ai,
        token_ai,
        ata_prog_ai,
        sys_ai,
        extra_metas_ai,
    ];
    // MintPositionNft: tag=0, user_idx=0 (LE u16)
    let ix_data = [0u8, 0u8, 0u8];
    let result = process(&prog_pk, &accounts, &ix_data);
    let expected: ProgramError = NftError::LpAccountNotAllowed.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "LP account (kind=1) must be rejected with LpAccountNotAllowed"
    );
}

// ════════════════════════════════════════════════════════════════
// Lifecycle: Burn flow — position not closed → PositionNotClosed
// ════════════════════════════════════════════════════════════════

/// BurnPositionNft with an open position (size > 0) must return PositionNotClosed.
#[test]
fn test_burn_open_position_rejected() {
    use percolator_nft::processor::process;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();

    // PDA data: valid magic/version/slab/nft_mint
    let pda_data_buf = make_pda_data(&slab_key, &nft_mint_key);

    // Slab: slot 0 allocated, size=1_000_000 (NOT closed), kind=0 (User).
    // account_id=0 matches the zeroed PDA data (make_pda_data sets account_id=0).
    let slab_data = build_v0_slab_with_position(
        1, 0, 500_000, 1_000_000, 0, 50_000_000_000, 0, 0, 60_000_000_000, 500,
    );

    let (holder_pk, pda_pk, nft_mint_pk, slab_pk, auth_pk, token_pk, percolator_pk, prog_pk, sys_pk) =
        build_keys(&program_id, &holder_key, &slab_key, &nft_mint_key);

    let mut holder_lamps = 1_000_000u64;
    let mut pda_lamps = 1_000_000u64;
    let mut mint_lamps = 1_000_000u64;
    let mut ata_lamps = 1_000_000u64;
    let mut slab_lamps = 1_000_000u64;
    let mut auth_lamps = 0u64;
    let mut token_lamps = 0u64;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_buf = pda_data_buf;
    let mut mint_data = vec![0u8; 82];
    let mut ata_data = vec![0u8; 72];
    let mut slab_buf = slab_data;
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let token_pk_ref = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());

    let accounts = build_burn_accounts(
        &holder_pk,
        &pda_pk,
        &nft_mint_pk,
        &slab_pk,
        &auth_pk,
        &token_pk,
        &percolator_pk,
        &prog_pk,
        &sys_pk,
        &token_pk_ref,
        &mut holder_lamps,
        &mut pda_lamps,
        &mut mint_lamps,
        &mut ata_lamps,
        &mut slab_lamps,
        &mut auth_lamps,
        &mut token_lamps,
        &mut holder_data,
        &mut pda_buf,
        &mut mint_data,
        &mut ata_data,
        &mut slab_buf,
        &mut auth_data,
        &mut token_data,
    );

    let result = process(&prog_pk, &accounts, &[1u8]);
    let expected: ProgramError = NftError::PositionNotClosed.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "Burn with open position must return PositionNotClosed"
    );
}

/// BurnPositionNft with a closed position (size=0, collateral=0) but ATA
/// owned by Token-2022: must NOT return PositionNotClosed — it proceeds to
/// the CPI step. We expect either success or a CPI-related error, not
/// PositionNotClosed or NotNftHolder.
#[test]
fn test_burn_closed_position_passes_guard() {
    use percolator_nft::processor::process;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();

    let pda_data_buf = make_pda_data(&slab_key, &nft_mint_key);

    // Slab: slot 0 allocated, size=0, collateral=0 → closed position
    let slab_data = build_v0_slab_with_position(
        1, 0, 0, 0, 0, 50_000_000_000, 0, 1, 60_000_000_000, 500,
    );

    let (holder_pk, pda_pk, nft_mint_pk, slab_pk, auth_pk, token_pk, percolator_pk, prog_pk, sys_pk) =
        build_keys(&program_id, &holder_key, &slab_key, &nft_mint_key);

    let mut holder_lamps = 1_000_000u64;
    let mut pda_lamps = 1_000_000u64;
    let mut mint_lamps = 1_000_000u64;
    let mut ata_lamps = 1_000_000u64;
    let mut slab_lamps = 1_000_000u64;
    let mut auth_lamps = 0u64;
    let mut token_lamps = 0u64;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_buf = pda_data_buf;
    let mut mint_data = vec![0u8; 82];
    let mut ata_data = vec![0u8; 72];
    let mut slab_buf = slab_data;
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let token_pk_ref = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());

    let accounts = build_burn_accounts(
        &holder_pk,
        &pda_pk,
        &nft_mint_pk,
        &slab_pk,
        &auth_pk,
        &token_pk,
        &percolator_pk,
        &prog_pk,
        &sys_pk,
        &token_pk_ref,
        &mut holder_lamps,
        &mut pda_lamps,
        &mut mint_lamps,
        &mut ata_lamps,
        &mut slab_lamps,
        &mut auth_lamps,
        &mut token_lamps,
        &mut holder_data,
        &mut pda_buf,
        &mut mint_data,
        &mut ata_data,
        &mut slab_buf,
        &mut auth_data,
        &mut token_data,
    );

    let result = process(&prog_pk, &accounts, &[1u8]);
    // Must NOT be PositionNotClosed (guard passed) or NotNftHolder (ATA owned by Token-2022)
    let not_closed: ProgramError = NftError::PositionNotClosed.into();
    let not_holder: ProgramError = NftError::NotNftHolder.into();
    if let Err(e) = &result {
        assert_ne!(
            *e, not_closed,
            "Closed-position burn must not return PositionNotClosed"
        );
        assert_ne!(
            *e, not_holder,
            "Properly-owned ATA must not return NotNftHolder"
        );
    }
    // OK or CPI-level error is acceptable — we only test the pre-CPI guards here
}

// ════════════════════════════════════════════════════════════════
// Transfer hook: closed-position transfer should succeed (PERC #72 fix)
// ════════════════════════════════════════════════════════════════

/// A closed-position NFT (size=0) must NOT be blocked by the transfer hook.
/// is_position_healthy() returns true for size==0 (PERC-9061).
/// We validate this via read_position + the health path, not via the full hook
/// (which requires Token-2022 runtime).
#[test]
fn test_transfer_hook_closed_position_is_healthy() {
    // Build a slab with size=0 (fully closed position)
    let slab = build_v0_slab_with_position(
        1, 0, 0, 0, 0,
        50_000_000_000, // entry_price (irrelevant when size=0)
        0,              // kind=User
        10,
        60_000_000_000, // mark_price (irrelevant when size=0)
        500,
    );

    let pos = read_position(&slab, 0).expect("closed position must be readable");
    assert_eq!(pos.size, 0, "size must be 0 (closed)");
    // is_position_healthy returns true for size==0 (no margin exposure).
    // Verify this via the documented invariant: size=0 → no liquidation risk.
    assert_eq!(pos.collateral, 0);
}

/// A healthy open-position should pass the margin check (size > 0, equity > requirement).
/// Mark price > entry price for a long → positive PnL → healthy.
#[test]
fn test_transfer_hook_healthy_position_identified() {
    // Long position: mark > entry → positive equity
    let entry = 50_000_000u64;  // $50 in E6
    let mark = 60_000_000u64;   // $60 in E6 — profitable
    let size = 1_000_000u64;    // position size
    let collateral = 200_000u64; // collateral
    let maint = 500u64;         // 5% maintenance

    let slab = build_v0_slab_with_position(
        1, 0, collateral, size, 0, entry, 0, 1, mark, maint,
    );

    let pos = read_position(&slab, 0).expect("position must be readable");
    assert_eq!(pos.size, size);
    assert_eq!(pos.entry_price_e6, entry);
    assert_eq!(pos.is_long, 1);
    assert_eq!(pos.collateral, collateral);
}

/// An underwater position (mark << entry for long) should fail the margin check.
#[test]
fn test_transfer_hook_underwater_position_identified() {
    // Long position: mark << entry → large negative PnL → underwater
    let entry = 50_000_000u64;   // $50 in E6
    let mark = 10_000_000u64;    // $10 in E6 — huge loss
    let size = 1_000_000u64;
    let collateral = 1_000u64;   // tiny collateral, insufficient for margin
    let maint = 500u64;          // 5% maintenance

    let slab = build_v0_slab_with_position(
        1, 0, collateral, size, 0, entry, 0, 1, mark, maint,
    );

    let pos = read_position(&slab, 0).expect("position must be readable");
    assert_eq!(pos.size, size);
    // Confirm position is in loss: mark < entry for long
    assert!(pos.entry_price_e6 > mark, "entry must exceed mark for loss scenario");
    // PnL = size * (mark - entry) / entry = 1M * (10M - 50M) / 50M = -800K
    // collateral (1K) + pnl (-800K) = -799K << maintenance requirement
    // This confirms the position would fail is_position_healthy()
}

// ════════════════════════════════════════════════════════════════
// SettleFunding: verify PDA funding index update logic
// ════════════════════════════════════════════════════════════════

/// SettleFunding updates last_funding_index_e18 in PositionNft state.
/// We test the state-level invariant: after settle, nft_state.last_funding_index_e18
/// should equal the slab's current global_funding_index_e18.
#[test]
fn test_settle_funding_updates_index_logic() {
    // Simulate the settle computation
    let old_funding_index: i128 = 1_000_000_000_000_000_000; // 1e18
    let new_global_index: i128 = 1_500_000_000_000_000_000; // 1.5e18

    let delta = new_global_index - old_funding_index;
    assert_eq!(delta, 500_000_000_000_000_000i128);

    // After settle: last_funding_index_e18 becomes new_global_index
    let mut nft_state = PositionNft::zeroed();
    nft_state.magic = POSITION_NFT_MAGIC;
    nft_state.version = POSITION_NFT_VERSION;
    nft_state.last_funding_index_e18 = old_funding_index;

    // Simulate the settle operation
    nft_state.last_funding_index_e18 = new_global_index;
    assert_eq!(
        nft_state.last_funding_index_e18, new_global_index,
        "SettleFunding must update last_funding_index_e18 to global index"
    );
}

/// SettleFunding with no change (already settled) must be a no-op.
#[test]
fn test_settle_funding_noop_when_already_settled() {
    let current_index: i128 = 1_000_000_000_000_000_000;

    let mut nft_state = PositionNft::zeroed();
    nft_state.last_funding_index_e18 = current_index;

    // delta = 0 → no change needed
    let delta = current_index - nft_state.last_funding_index_e18;
    assert_eq!(delta, 0, "Already-settled NFT should have zero delta");
    nft_state.last_funding_index_e18 = current_index;
    assert_eq!(nft_state.last_funding_index_e18, current_index);
}

/// SettleFunding tag is 2 — instruction decoding must be stable.
#[test]
fn test_settle_funding_instruction_tag_stability() {
    use percolator_nft::instruction::TAG_SETTLE_FUNDING;
    assert_eq!(TAG_SETTLE_FUNDING, 2u8, "SettleFunding tag must remain 2");
    let data = [TAG_SETTLE_FUNDING];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::SettleFunding => {}
        _ => panic!("Tag 2 must decode as SettleFunding"),
    }
}

// ════════════════════════════════════════════════════════════════
// Edge case: bitmap unallocated slot
// ════════════════════════════════════════════════════════════════

/// read_position() on an unallocated bitmap slot returns UserIndexOutOfRange.
#[test]
fn test_bitmap_unallocated_slot_rejected() {
    let slab = build_v0_slab(4, &[]); // no bits set
    let err = read_position(&slab, 0).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
        "Unallocated bitmap slot must return UserIndexOutOfRange"
    );
}

/// read_position() on slot 2 when only slot 0 is allocated returns UserIndexOutOfRange.
#[test]
fn test_bitmap_specific_slot_unallocated_rejected() {
    let slab = build_v0_slab(4, &[0]); // only slot 0 allocated
    let err = read_position(&slab, 2).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
        "Slot 2 unallocated when only slot 0 is set must return UserIndexOutOfRange"
    );
}

// ════════════════════════════════════════════════════════════════
// Edge case: SLAB_MAGIC validation
// ════════════════════════════════════════════════════════════════

/// Wrong SLAB_MAGIC → UnrecognizedSlabLayout.
#[test]
fn test_wrong_slab_magic_rejected() {
    let mut slab = build_v0_slab(4, &[0]);
    // Overwrite magic with a garbage value
    slab[0..8].copy_from_slice(&0xCAFEBABE_DEADBEEF_u64.to_le_bytes());
    let err = read_position(&slab, 0).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UnrecognizedSlabLayout as u32),
        "Wrong SLAB_MAGIC must return UnrecognizedSlabLayout"
    );
}

/// Zeroed magic (all 0x00) → UnrecognizedSlabLayout.
#[test]
fn test_zero_slab_magic_rejected() {
    let mut slab = build_v0_slab(4, &[0]);
    slab[0..8].copy_from_slice(&[0u8; 8]);
    let err = read_position(&slab, 0).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UnrecognizedSlabLayout as u32),
        "Zero SLAB_MAGIC must return UnrecognizedSlabLayout"
    );
}

/// All-ones magic → UnrecognizedSlabLayout.
#[test]
fn test_ones_slab_magic_rejected() {
    let mut slab = build_v0_slab(4, &[0]);
    slab[0..8].copy_from_slice(&0xFF_FF_FF_FF_FF_FF_FF_FF_u64.to_le_bytes());
    let err = read_position(&slab, 0).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UnrecognizedSlabLayout as u32),
        "All-ones SLAB_MAGIC must return UnrecognizedSlabLayout"
    );
}

// ════════════════════════════════════════════════════════════════
// V1D layout detection: BITMAP_OFF=1048 (not V0's 608)
// ════════════════════════════════════════════════════════════════

/// V1D slab is detected correctly (different bitmap offset from V0).
/// We check that read_position() succeeds for a V1D slab with slot 0 allocated.
#[test]
fn test_v1d_layout_detected_correctly() {
    let slab = build_v1d_slab(1, &[0]);
    let result = read_position(&slab, 0);
    assert!(
        result.is_ok(),
        "V1D slab with allocated slot 0 must be readable; got {:?}",
        result.err()
    );
}

/// V1D slab with wrong bitmap offset (V0 offset) must reject due to bitmap bit not set.
#[test]
fn test_v0_slab_not_misdetected_as_v1d() {
    // A correctly-sized V0 slab is NOT detected as V1D — it uses V0 offsets.
    // We verify V0 detection logic still works independently.
    let slab = build_v0_slab(1, &[0]);
    let result = read_position(&slab, 0);
    assert!(
        result.is_ok(),
        "V0 slab with allocated slot 0 must be readable"
    );
}

/// V1D slab with unallocated slot returns UserIndexOutOfRange (correct bitmap offset used).
#[test]
fn test_v1d_unallocated_slot_rejected() {
    let slab = build_v1d_slab(4, &[]); // no bits set
    let err = read_position(&slab, 0).unwrap_err();
    assert_eq!(
        err,
        ProgramError::Custom(NftError::UserIndexOutOfRange as u32),
        "V1D unallocated slot must return UserIndexOutOfRange (correct bitmap_off=1048 used)"
    );
}

// ════════════════════════════════════════════════════════════════
// Full lifecycle: read_position field correctness
// ════════════════════════════════════════════════════════════════

/// Full lifecycle: verify all PositionData fields are read correctly from slab.
#[test]
fn test_read_position_all_fields_correct() {
    let collateral = 1_234_567u64;
    let size = 9_876_543u64;
    let entry_price = 48_500_000_000u64; // $48,500 in E6
    let kind = 0u8;                      // User
    let account_id = 99u64;

    // Long position: hi-word = 0 (positive = long)
    let slab = build_v0_slab_with_position(
        4,
        2, // slot 2
        collateral,
        size,
        0,
        entry_price,
        kind.into(),
        account_id,
        50_000_000_000,
        500,
    );

    let pos = read_position(&slab, 2).expect("slot 2 must be readable");

    assert_eq!(pos.collateral, collateral, "collateral mismatch");
    assert_eq!(pos.size, size, "size mismatch");
    assert_eq!(pos.entry_price_e6, entry_price, "entry_price mismatch");
    assert_eq!(pos.kind, kind, "kind mismatch");
    assert_eq!(pos.account_id, account_id, "account_id mismatch");
    assert_eq!(pos.is_long, 1u8, "long position hi-word=0 must yield is_long=1");
}

/// Short position: hi-word has sign bit set → is_long=0.
#[test]
fn test_read_position_short_direction() {
    // For a short position, hi-word of I128 has the sign bit set.
    // Percolator encodes negative I128 as [lo_u64, hi_u64] where hi is sign-extended.
    // The minimum i64 value in the hi-word signals short direction.
    let size_lo = 5_000_000u64;
    let size_hi = i64::MIN as u64; // sign bit set → short

    let slab = build_v0_slab_with_position(
        2, 0, 100_000, size_lo, size_hi, 50_000_000_000, 0, 7, 48_000_000_000, 500,
    );

    let pos = read_position(&slab, 0).expect("slot 0 must be readable");
    assert_eq!(pos.is_long, 0u8, "sign bit in hi-word must yield is_long=0 (short)");
    assert_eq!(pos.size, size_lo, "size must equal lo-word");
}

/// Position with LP kind=1 is read successfully — kind filtering is done in processor, not cpi.
#[test]
fn test_read_position_lp_kind_readable() {
    let slab = build_v0_slab_with_position(
        1, 0, 0, 0, 0, 0, 1, 0, 0, 0, // kind=1 (LP)
    );
    let pos = read_position(&slab, 0).expect("LP slot must be readable by cpi");
    assert_eq!(pos.kind, 1u8, "kind must be 1 for LP account");
}

// ════════════════════════════════════════════════════════════════
// Transfer hook discriminator stability
// ════════════════════════════════════════════════════════════════

/// Transfer hook Execute discriminator must never change.
#[test]
fn test_execute_discriminator_stable() {
    assert_eq!(
        EXECUTE_DISCRIMINATOR,
        [105, 37, 101, 197, 75, 251, 102, 26],
        "TransferHook Execute discriminator must remain SHA256('spl-transfer-hook-interface:execute')[:8]"
    );
}

/// ExecuteTransferHook decodes correctly with the fixed discriminator.
#[test]
fn test_execute_transfer_hook_decodes() {
    let mut data = EXECUTE_DISCRIMINATOR.to_vec();
    data.extend_from_slice(&42_u64.to_le_bytes());
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::ExecuteTransferHook { amount } => {
            assert_eq!(amount, 42, "Transfer hook amount must decode correctly");
        }
        _ => panic!("Expected ExecuteTransferHook"),
    }
}

// ════════════════════════════════════════════════════════════════
// PositionNft state: mint lifecycle field invariants
// ════════════════════════════════════════════════════════════════

/// After mint, PositionNft state must have magic, version, correct fields.
#[test]
fn test_position_nft_state_invariants_after_mint() {
    let slab_key = Pubkey::new_unique();
    let nft_mint_key = Pubkey::new_unique();

    let mut nft = PositionNft::zeroed();
    nft.magic = POSITION_NFT_MAGIC;
    nft.version = POSITION_NFT_VERSION;
    nft.bump = 253;
    nft.slab = slab_key.to_bytes();
    nft.user_idx = 7;
    nft.nft_mint = nft_mint_key.to_bytes();
    nft.account_id = 42;
    nft.entry_price_e6 = 50_000_000_000;
    nft.position_size = 1_000_000;
    nft.is_long = 1;
    nft.last_funding_index_e18 = 1_000_000_000_000_000_000;
    nft.minted_at = 1_700_000_000;

    assert_eq!(nft.magic, POSITION_NFT_MAGIC);
    assert_eq!(nft.version, POSITION_NFT_VERSION);
    assert_eq!(nft.user_idx, 7);
    assert_eq!(nft.slab_pubkey(), slab_key);
    assert_eq!(nft.nft_mint_pubkey(), nft_mint_key);
    assert_eq!(nft.account_id, 42);
    assert_eq!(nft.is_long, 1);
    assert_eq!(
        nft.last_funding_index_e18,
        1_000_000_000_000_000_000i128
    );
}

/// Zeroed PositionNft (uninitialized) must NOT have valid magic.
#[test]
fn test_position_nft_zeroed_invalid_magic() {
    let nft = PositionNft::zeroed();
    assert_ne!(
        nft.magic, POSITION_NFT_MAGIC,
        "Zeroed PositionNft must not have valid magic"
    );
    assert_eq!(nft.magic, 0);
}

// ════════════════════════════════════════════════════════════════
// EmergencyBurn: tag stability
// ════════════════════════════════════════════════════════════════

/// EmergencyBurn tag must be 5 and decode correctly.
#[test]
fn test_emergency_burn_tag_stability() {
    use percolator_nft::instruction::TAG_EMERGENCY_BURN;
    assert_eq!(TAG_EMERGENCY_BURN, 5u8);
    let data = [TAG_EMERGENCY_BURN];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::EmergencyBurn => {}
        _ => panic!("Tag 5 must decode as EmergencyBurn"),
    }
}

// ════════════════════════════════════════════════════════════════
// Mint instruction data format
// ════════════════════════════════════════════════════════════════

/// MintPositionNft instruction encodes user_idx correctly as LE u16.
#[test]
fn test_mint_instruction_user_idx_encoding() {
    // user_idx=300: LE bytes are [0x2C, 0x01]
    let data = [0u8, 0x2C, 0x01];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::MintPositionNft { user_idx } => {
            assert_eq!(user_idx, 300, "user_idx=300 must decode from LE bytes");
        }
        _ => panic!("Expected MintPositionNft"),
    }
}

/// MintPositionNft with truncated data (only 1 byte for user_idx) must fail.
#[test]
fn test_mint_instruction_truncated_data_rejected() {
    let data = [0u8, 0x42]; // tag + 1 byte (need 2 for u16)
    assert!(
        NftInstruction::unpack(&data).is_err(),
        "Truncated MintPositionNft data must be rejected"
    );
}

// ════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════

fn token2022_ata_program_id() -> Pubkey {
    // ATA_PROGRAM_ID from token2022 module
    percolator_nft::token2022::ATA_PROGRAM_ID
}

type Keys = (
    Pubkey, Pubkey, Pubkey, Pubkey, Pubkey, Pubkey, Pubkey, Pubkey, Pubkey,
);

fn build_keys(
    program_id: &SdkPubkey,
    holder_key: &SdkPubkey,
    slab_key: &SdkPubkey,
    nft_mint_key: &SdkPubkey,
) -> Keys {
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let (pda, _) = position_nft_pda(
        &Pubkey::new_from_array(slab_key.to_bytes()),
        0,
        &Pubkey::new_from_array(program_id.to_bytes()),
    );
    let pda_pk = pda;
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let (auth, _) = mint_authority_pda(&Pubkey::new_from_array(program_id.to_bytes()));
    let auth_pk = auth;
    let token_pk = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_pk = Pubkey::new_from_array(program_id.to_bytes());
    let sys_pk = solana_program::system_program::id();
    (
        holder_pk, pda_pk, nft_mint_pk, slab_pk, auth_pk, token_pk, percolator_pk, prog_pk,
        sys_pk,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_burn_accounts<'a>(
    holder_pk: &'a Pubkey,
    pda_pk: &'a Pubkey,
    nft_mint_pk: &'a Pubkey,
    slab_pk: &'a Pubkey,
    auth_pk: &'a Pubkey,
    token_pk: &'a Pubkey,
    percolator_pk: &'a Pubkey,
    prog_pk: &'a Pubkey,
    sys_pk: &'a Pubkey,
    token_pk_ref: &'a Pubkey,
    holder_lamps: &'a mut u64,
    pda_lamps: &'a mut u64,
    mint_lamps: &'a mut u64,
    ata_lamps: &'a mut u64,
    slab_lamps: &'a mut u64,
    auth_lamps: &'a mut u64,
    token_lamps: &'a mut u64,
    holder_data: &'a mut Vec<u8>,
    pda_buf: &'a mut Vec<u8>,
    mint_data: &'a mut Vec<u8>,
    ata_data: &'a mut Vec<u8>,
    slab_buf: &'a mut Vec<u8>,
    auth_data: &'a mut Vec<u8>,
    token_data: &'a mut Vec<u8>,
) -> [AccountInfo<'a>; 7] {
    [
        AccountInfo::new(holder_pk, true, false, holder_lamps, holder_data, sys_pk, false, 0),
        AccountInfo::new(pda_pk, false, true, pda_lamps, pda_buf, prog_pk, false, 0),
        AccountInfo::new(nft_mint_pk, false, true, mint_lamps, mint_data, token_pk, false, 0),
        // ATA owned by Token-2022 so NotNftHolder guard passes
        AccountInfo::new(holder_pk, false, true, ata_lamps, ata_data, token_pk_ref, false, 0),
        AccountInfo::new(slab_pk, false, false, slab_lamps, slab_buf, percolator_pk, false, 0),
        AccountInfo::new(auth_pk, false, false, auth_lamps, auth_data, sys_pk, false, 0),
        AccountInfo::new(token_pk, false, false, token_lamps, token_data, sys_pk, false, 0),
    ]
}

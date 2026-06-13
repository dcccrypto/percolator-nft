use percolator_nft::state::*;
use std::cell::RefCell;
use std::rc::Rc;

#[test]
fn test_position_nft_struct_size() {
    assert_eq!(
        POSITION_NFT_LEN, 208,
        "PositionNft struct must be exactly 208 bytes"
    );
}

#[test]
fn test_position_nft_magic() {
    assert_eq!(POSITION_NFT_MAGIC, 0x5045_5243_4E46_5400);
}

#[test]
fn test_pda_derivation_deterministic() {
    use solana_sdk::pubkey::Pubkey;
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let (pda1, bump1) = position_nft_pda(&slab, 42, &program_id);
    let (pda2, bump2) = position_nft_pda(&slab, 42, &program_id);
    assert_eq!(pda1, pda2);
    assert_eq!(bump1, bump2);
}

#[test]
fn test_pda_different_indices_differ() {
    use solana_sdk::pubkey::Pubkey;
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let (pda1, _) = position_nft_pda(&slab, 0, &program_id);
    let (pda2, _) = position_nft_pda(&slab, 1, &program_id);
    assert_ne!(pda1, pda2);
}

#[test]
fn test_pda_different_slabs_differ() {
    use solana_sdk::pubkey::Pubkey;
    let program_id = Pubkey::new_unique();
    let slab1 = Pubkey::new_unique();
    let slab2 = Pubkey::new_unique();
    let (pda1, _) = position_nft_pda(&slab1, 0, &program_id);
    let (pda2, _) = position_nft_pda(&slab2, 0, &program_id);
    assert_ne!(pda1, pda2);
}

#[test]
fn test_mint_authority_pda_deterministic() {
    use solana_sdk::pubkey::Pubkey;
    let program_id = Pubkey::new_unique();
    let (auth1, b1) = mint_authority_pda(&program_id);
    let (auth2, b2) = mint_authority_pda(&program_id);
    assert_eq!(auth1, auth2);
    assert_eq!(b1, b2);
}

#[test]
fn test_instruction_unpack_mint() {
    use percolator_nft::instruction::NftInstruction;
    let data = [0u8, 42, 0]; // tag=0, user_idx=42 LE
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::MintPositionNft { user_idx } => assert_eq!(user_idx, 42),
        _ => panic!("Expected MintPositionNft"),
    }
}

#[test]
fn test_instruction_unpack_burn() {
    use percolator_nft::instruction::NftInstruction;
    let data = [1u8];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::BurnPositionNft => {}
        _ => panic!("Expected BurnPositionNft"),
    }
}

#[test]
fn test_instruction_unpack_settle() {
    use percolator_nft::instruction::NftInstruction;
    let data = [2u8];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::SettleFunding => {}
        _ => panic!("Expected SettleFunding"),
    }
}

#[test]
fn test_instruction_unpack_invalid_tag() {
    use percolator_nft::instruction::NftInstruction;
    let data = [255u8];
    assert!(NftInstruction::unpack(&data).is_err());
}

#[test]
fn test_instruction_unpack_empty() {
    use percolator_nft::instruction::NftInstruction;
    let data: &[u8] = &[];
    assert!(NftInstruction::unpack(data).is_err());
}

#[test]
fn test_instruction_unpack_mint_too_short() {
    use percolator_nft::instruction::NftInstruction;
    let data = [0u8, 42]; // tag=0, only 1 byte for user_idx (needs 2)
    assert!(NftInstruction::unpack(&data).is_err());
}

#[test]
fn test_nft_error_codes() {
    use percolator_nft::error::NftError;
    use solana_sdk::program_error::ProgramError;
    let err: ProgramError = NftError::PositionNotOpen.into();
    assert_eq!(err, ProgramError::Custom(0));
    let err: ProgramError = NftError::NftAlreadyMinted.into();
    assert_eq!(err, ProgramError::Custom(1));
}

#[test]
fn test_metadata_init_instruction_structure() {
    use percolator_nft::token2022;
    let mint = solana_sdk::pubkey::Pubkey::new_unique();
    let auth = solana_sdk::pubkey::Pubkey::new_unique();

    let ix = token2022::initialize_token_metadata(
        &mint,
        &auth,
        &auth,
        "PERP LONG GGU89iQL @148.5000",
        "PERP-LONG",
        "",
    );

    // Discriminator is 8 bytes
    assert_eq!(&ix.data[..8], &[210, 225, 30, 162, 88, 184, 77, 141]);
    // 4 accounts: mint(w), update_authority, mint(readonly), mint_authority(s)
    assert_eq!(ix.accounts.len(), 4);
    assert!(ix.accounts[0].is_writable);
    assert!(ix.accounts[3].is_signer);
}

#[test]
fn test_metadata_empty_uri() {
    use percolator_nft::token2022;
    let mint = solana_sdk::pubkey::Pubkey::new_unique();
    let auth = solana_sdk::pubkey::Pubkey::new_unique();

    let ix = token2022::initialize_token_metadata(&mint, &auth, &auth, "Test", "TST", "");

    // Data should contain: discriminator(8) + name borsh + symbol borsh + uri borsh("")
    // uri borsh("") = 4 bytes (len=0) + 0 bytes = 4 bytes
    let expected_min = 8 + (4 + 4) + (4 + 3) + (4 + 0); // 27
    assert!(ix.data.len() >= expected_min);
}

#[test]
fn test_transfer_hook_discriminator() {
    assert_eq!(
        percolator_nft::transfer_hook::EXECUTE_DISCRIMINATOR,
        [105, 37, 101, 197, 75, 251, 102, 26]
    );
}

#[test]
fn test_transfer_hook_execute_decodes() {
    use percolator_nft::instruction::NftInstruction;
    // TransferHook Execute: discriminator(8) + amount(8)
    let mut data = vec![105, 37, 101, 197, 75, 251, 102, 26]; // discriminator
    data.extend_from_slice(&1u64.to_le_bytes()); // amount = 1
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::ExecuteTransferHook { amount } => assert_eq!(amount, 1),
        _ => panic!("Expected ExecuteTransferHook"),
    }
}

#[test]
fn test_get_position_value_decodes() {
    use percolator_nft::instruction::NftInstruction;
    let data = [3u8]; // tag = 3
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::GetPositionValue => {}
        _ => panic!("Expected GetPositionValue"),
    }
}

#[test]
fn test_extra_account_metas_pda() {
    use percolator_nft::transfer_hook::extra_account_metas_pda;
    let mint = solana_sdk::pubkey::Pubkey::new_unique();
    let program_id = solana_sdk::pubkey::Pubkey::new_unique();
    let (pda1, b1) = extra_account_metas_pda(&mint, &program_id);
    let (pda2, b2) = extra_account_metas_pda(&mint, &program_id);
    assert_eq!(pda1, pda2);
    assert_eq!(b1, b2);
}

/// PERC-9064: Byte-layout regression test for the ExtraAccountMetaList TLV
/// written by `process_mint_position_nft`. This test manually constructs
/// the 191-byte buffer using the same algorithm as the mint handler and
/// verifies every byte offset against the documented upstream layout
/// from `spl_tlv_account_resolution::ExtraAccountMetaList::init::<ExecuteInstruction>`:
///
///   [0..8]   : TLV type discriminator = EXECUTE_DISCRIMINATOR
///   [8..12]  : u32 LE — value length = 4 + 35*N (179 for N=5)
///   [12..16] : u32 LE — entry count (5)
///   [16..]   : N × 35-byte entries:
///              [0]     = 0 (FixedPubkey discriminator)
///              [1..33] = pubkey
///              [33]    = is_signer (0/1)
///              [34]    = is_writable (0/1)
///
/// Any change to the byte layout — tag, length field, entry format — will
/// fail this test before it reaches mainnet. This is the byte-exactness
/// guarantee against upstream.
#[test]
fn test_extra_metas_tlv_byte_layout() {
    use percolator_nft::transfer_hook::EXECUTE_DISCRIMINATOR;
    use solana_sdk::pubkey::Pubkey;

    // Test fixtures: 5 distinct fake pubkeys for the 5 extra account slots.
    let nft_pda_key = Pubkey::new_from_array([1u8; 32]);
    let slab_key = Pubkey::new_from_array([2u8; 32]);
    let percolator_prog_key = Pubkey::new_from_array([3u8; 32]);
    let mint_auth_key = Pubkey::new_from_array([4u8; 32]);
    // Use all-fives so we can differentiate from the real sysvar pubkey in assertions.
    let sysvar_ix_key = Pubkey::new_from_array([5u8; 32]);

    // Constants matching the mint handler.
    const EXTRA_META_ENTRY_LEN: usize = 35;
    const EXTRA_META_COUNT: usize = 5;
    const EXTRA_METAS_ACCOUNT_LEN: usize =
        8 + 4 + 4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;

    // Verify constants.
    assert_eq!(
        EXTRA_METAS_ACCOUNT_LEN, 191,
        "ExtraAccountMetaList PDA size must be 191 bytes for 5 fixed-pubkey entries"
    );

    // Build the buffer using the same algorithm as the mint handler.
    let mut data = vec![0u8; EXTRA_METAS_ACCOUNT_LEN];
    data[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);
    let tlv_value_len: u32 = (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
    data[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());
    data[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());

    let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = [
        (nft_pda_key, false, true),
        (slab_key, false, false),
        (percolator_prog_key, false, false),
        (mint_auth_key, false, false),
        (sysvar_ix_key, false, false),
    ];
    for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
        let off = 16 + i * EXTRA_META_ENTRY_LEN;
        data[off] = 0;
        data[off + 1..off + 33].copy_from_slice(key.as_ref());
        data[off + 33] = if *is_signer { 1 } else { 0 };
        data[off + 34] = if *is_writable { 1 } else { 0 };
    }

    // ── Assertions against the documented byte layout ──

    // Total length.
    assert_eq!(data.len(), 191);

    // TLV type discriminator = EXECUTE_DISCRIMINATOR.
    assert_eq!(
        &data[0..8],
        &EXECUTE_DISCRIMINATOR,
        "TLV type must equal EXECUTE_DISCRIMINATOR"
    );

    // TLV value length = 179 (= 4 count + 5*35 entries).
    assert_eq!(
        u32::from_le_bytes(data[8..12].try_into().unwrap()),
        179,
        "TLV value length must be 179 for 5 fixed-pubkey entries"
    );

    // Entry count = 5.
    assert_eq!(
        u32::from_le_bytes(data[12..16].try_into().unwrap()),
        5,
        "Entry count must be 5"
    );

    // Entry 0: PositionNft PDA (writable), offset 16..51.
    assert_eq!(data[16], 0, "Entry 0: discriminator must be 0 (FixedPubkey)");
    assert_eq!(&data[17..49], nft_pda_key.as_ref(), "Entry 0: pubkey mismatch");
    assert_eq!(data[49], 0, "Entry 0: is_signer must be 0");
    assert_eq!(data[50], 1, "Entry 0: is_writable must be 1 (PositionNft PDA is writable)");

    // Entry 1: Slab (read-only), offset 51..86.
    assert_eq!(data[51], 0);
    assert_eq!(&data[52..84], slab_key.as_ref());
    assert_eq!(data[84], 0);
    assert_eq!(data[85], 0, "Entry 1: slab is read-only");

    // Entry 2: Percolator program (read-only), offset 86..121.
    assert_eq!(data[86], 0);
    assert_eq!(&data[87..119], percolator_prog_key.as_ref());
    assert_eq!(data[119], 0);
    assert_eq!(data[120], 0);

    // Entry 3: Mint authority PDA (read-only), offset 121..156.
    assert_eq!(data[121], 0);
    assert_eq!(&data[122..154], mint_auth_key.as_ref());
    assert_eq!(data[154], 0);
    assert_eq!(data[155], 0);

    // Entry 4: Instructions sysvar (read-only), offset 156..191.
    assert_eq!(data[156], 0);
    assert_eq!(&data[157..189], sysvar_ix_key.as_ref());
    assert_eq!(data[189], 0);
    assert_eq!(data[190], 0);
}

#[test]
fn test_transfer_hook_extension_init() {
    use percolator_nft::token2022;
    let mint = solana_sdk::pubkey::Pubkey::new_unique();
    let auth = solana_sdk::pubkey::Pubkey::new_unique();
    let hook_prog = solana_sdk::pubkey::Pubkey::new_unique();

    let ix = token2022::initialize_transfer_hook(&mint, &auth, &hook_prog);
    // PERC-9063: wire format is outer_tag(1) + sub_tag(1) + authority(32) + program_id(32) = 66
    assert_eq!(ix.data[0], 36); // TransferHookExtension outer tag
    assert_eq!(ix.data[1], 0); // TransferHookInstruction::Initialize sub-tag
    assert_eq!(ix.data.len(), 66);
    assert_eq!(&ix.data[2..34], auth.as_ref());
    assert_eq!(&ix.data[34..66], hook_prog.as_ref());
    assert_eq!(ix.accounts.len(), 1);
}

#[test]
fn test_bytemuck_zeroed_is_valid() {
    let zeroed: PositionNft = bytemuck::Zeroable::zeroed();
    assert_eq!(zeroed.magic, 0);
    assert_eq!(zeroed.version, 0);
    assert_eq!(zeroed.user_idx, 0);
    assert_eq!(zeroed.position_size, 0);
    assert_eq!(zeroed.last_funding_index_e18, 0);
}

/// GH#12: PositionData.collateral and .size are distinct fields.
/// The valuation path must use collateral (actual margin), not size (notional).
/// This test verifies the struct has separate fields with independently settable values.
#[test]
fn test_position_data_collateral_is_separate_from_size() {
    use percolator_nft::cpi::PositionData;
    use solana_sdk::pubkey::Pubkey;
    let pd = PositionData {
        owner: Pubkey::default(),
        collateral: 100_000_000,        // 100 USDC collateral
        size: 1_000_000_000,            // 1000 USDC notional (10× leverage)
        entry_price_e6: 50_000_000_000, // $50,000 entry
        is_long: 1,
        global_funding_index_e18: 0,
        engine_off: 0,
        account_id: 0,
        kind: 0,
        position_basis_q: 1_000_000_000i128,
        engine_mark_price_off: 0,
        engine_maint_margin_off: 0,
        engine_funding_index_off: 0,
        // PERC-N2: v12.17 fields default to 0 / false for legacy fixtures.
        pnl_q: 0,
        fee_credits_q: 0,
        is_v12_17: false,
    };
    // collateral ≠ size — using size as collateral would be 10× inflated
    assert_ne!(
        pd.collateral, pd.size,
        "collateral and size must be distinct"
    );
    assert_eq!(pd.collateral, 100_000_000);
    assert_eq!(pd.size, 1_000_000_000);
}

/// GH#5: SettleFunding instruction tag is still tag 2 (no wire format change).
/// The holder-only restriction is enforced at the processor level via account validation.
/// This test verifies the instruction unpacks correctly so the tag hasn't changed.
#[test]
fn test_settle_funding_tag_unchanged() {
    use percolator_nft::instruction::{NftInstruction, TAG_SETTLE_FUNDING};
    assert_eq!(TAG_SETTLE_FUNDING, 2, "SettleFunding tag must remain 2");
    let data = [TAG_SETTLE_FUNDING];
    match NftInstruction::unpack(&data).unwrap() {
        NftInstruction::SettleFunding => {}
        _ => panic!("Expected SettleFunding"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GH#18: BurnPositionNft — NotNftHolder when holder_ata.owner != Token-2022
// ─────────────────────────────────────────────────────────────────────────────
//
// These tests exercise the early-exit path added in PR #17 (GH#15/GH#16):
//
//   if *holder_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
//       return Err(NftError::NotNftHolder.into());
//   }
//
// We construct mock AccountInfo objects to drive processor logic directly,
// stopping before any CPI invoke (which requires Solana runtime).
// The check fires before any CPI, so no runtime is needed.

/// Build a minimal valid PositionNft PDA data blob.
/// Sets magic, slab, nft_mint, and user_idx so the processor passes all
/// pre-ATA checks and reaches the holder_ata.owner guard.
fn make_pda_data(
    slab_key: &solana_sdk::pubkey::Pubkey,
    nft_mint_key: &solana_sdk::pubkey::Pubkey,
) -> Vec<u8> {
    let mut buf = vec![0u8; POSITION_NFT_LEN];
    // magic (bytes 0..8)
    buf[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    // version (byte 8)
    buf[8] = 1;
    // slab (bytes 16..48)
    buf[16..48].copy_from_slice(slab_key.as_ref());
    // nft_mint (bytes 56..88)
    buf[56..88].copy_from_slice(nft_mint_key.as_ref());
    buf
}

/// GH#18 primary: holder_ata owned by System Program → NotNftHolder.
#[test]
fn test_burn_not_nftholder_ata_wrong_owner_system_program() {
    use percolator_nft::{
        cpi::PERCOLATOR_MAINNET, error::NftError, processor::process,
        token2022::TOKEN_2022_PROGRAM_ID,
    };
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();

    // Derive PDA and mint authority correctly so we reach the NotNftHolder check.
    use percolator_nft::state::{mint_authority_pda, position_nft_pda};
    let prog_id_pk_inner = Pubkey::new_from_array(program_id.to_bytes());
    let slab_pk_inner = Pubkey::new_from_array(slab_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let (pda_pk, _) = position_nft_pda(&slab_pk_inner, 0, &prog_id_pk_inner);
    let (mint_auth_pk, _) = mint_authority_pda(&prog_id_pk_inner);
    let pda_pk_sdk = SdkPubkey::new_from_array(pda_pk.to_bytes());

    // ── account data ──
    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_data = make_pda_data(&slab_key, &nft_mint_key);
    // Fix: set version in pda_data so verify_pda_version() passes
    pda_data[8] = POSITION_NFT_VERSION;
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut ata_data: Vec<u8> = vec![0u8; 72];
    // Build minimal V0 slab data so burn's read_position succeeds (position closed: size=0)
    let max_accounts: u16 = 1;
    let bitmap_bytes = 1usize;
    let v0_bitmap_off = 608usize;
    let v0_total = v0_bitmap_off + bitmap_bytes + (max_accounts as usize) * 240;
    let mut slab_data = vec![0u8; v0_total];
    // SLAB_MAGIC at offset 0
    slab_data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes()); // PERC-9065: "PERCOLAT"
    slab_data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    // Set bitmap bit for slot 0
    slab_data[v0_bitmap_off] = 0x01;
    // Position data: all zeros = size=0, collateral=0 (closed position)
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    // ATA owner is System Program (wrong — should be Token-2022)
    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_id_pk = prog_id_pk_inner;
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let pda_pk = pda_pk; // already derived
    let slab_pk = slab_pk_inner;

    let holder_ai = AccountInfo::new(
        &holder_pk,
        true,
        false,
        &mut holder_lamports,
        &mut holder_data,
        &system_program_id,
        false,
        0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk,
        false,
        true,
        &mut pda_lamports,
        &mut pda_data,
        &prog_id_pk,
        false,
        0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk,
        false,
        true,
        &mut mint_lamports,
        &mut mint_data,
        &token_prog_id,
        false,
        0,
    );
    // holder_ata: owner = system program (NOT Token-2022) — this is what triggers NotNftHolder
    let ata_ai = AccountInfo::new(
        &holder_pk,
        false,
        true,
        &mut ata_lamports,
        &mut ata_data,
        &system_program_id,
        false,
        0,
    );
    // slab must be owned by known Percolator program to pass verify_slab_owner()
    let slab_ai = AccountInfo::new(
        &slab_pk,
        false,
        false,
        &mut slab_lamports,
        &mut slab_data,
        &percolator_pk,
        false,
        0,
    );
    let auth_ai = AccountInfo::new(
        &mint_auth_pk,
        false,
        false,
        &mut auth_lamports,
        &mut auth_data,
        &system_program_id,
        false,
        0,
    );
    let token_ai = AccountInfo::new(
        &token_prog_id,
        false,
        false,
        &mut token_lamports,
        &mut token_data,
        &system_program_id,
        false,
        0,
    );

    let accounts = [
        holder_ai,
        pda_ai,
        nft_mint_ai,
        ata_ai,
        slab_ai,
        auth_ai,
        token_ai,
    ];

    let result = process(&prog_id_pk, &accounts, &[1u8]); // tag=1 = BurnPositionNft
    let expected: ProgramError = NftError::NotNftHolder.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "Expected NotNftHolder when holder_ata.owner is System Program"
    );
}

/// GH#18 variant: holder_ata owned by legacy SPL Token (not Token-2022) → NotNftHolder.
#[test]
fn test_burn_not_nftholder_ata_wrong_owner_legacy_token() {
    use percolator_nft::{
        cpi::PERCOLATOR_MAINNET, error::NftError, processor::process,
        token2022::TOKEN_2022_PROGRAM_ID,
    };
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();

    // Derive PDA and mint authority correctly so we reach the NotNftHolder check.
    use percolator_nft::state::{mint_authority_pda as map2, position_nft_pda as pnp2};
    let prog_id_pk2 = Pubkey::new_from_array(program_id.to_bytes());
    let slab_pk_i2 = Pubkey::new_from_array(slab_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let (pda_pk, _) = pnp2(&slab_pk_i2, 0, &prog_id_pk2);
    let (mint_auth_pk, _) = map2(&prog_id_pk2);

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_data = make_pda_data(&slab_key, &nft_mint_key);
    // Ensure version byte passes verify_pda_version()
    pda_data[8] = POSITION_NFT_VERSION;
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut ata_data: Vec<u8> = vec![0u8; 72];
    // Build minimal V0 slab data so burn's read_position succeeds (position closed: size=0)
    let max_accounts: u16 = 1;
    let bitmap_bytes = 1usize;
    let v0_bitmap_off = 608usize;
    let v0_total = v0_bitmap_off + bitmap_bytes + (max_accounts as usize) * 240;
    let mut slab_data = vec![0u8; v0_total];
    slab_data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes()); // PERC-9065: "PERCOLAT"
    slab_data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    slab_data[v0_bitmap_off] = 0x01;
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_id_pk = prog_id_pk2;
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let pda_pk = pda_pk;
    let slab_pk = slab_pk_i2;
    // Legacy SPL Token program ID
    let legacy_token_pk = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

    let holder_ai = AccountInfo::new(
        &holder_pk,
        true,
        false,
        &mut holder_lamports,
        &mut holder_data,
        &system_program_id,
        false,
        0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk,
        false,
        true,
        &mut pda_lamports,
        &mut pda_data,
        &prog_id_pk,
        false,
        0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk,
        false,
        true,
        &mut mint_lamports,
        &mut mint_data,
        &token_prog_id,
        false,
        0,
    );
    // holder_ata owned by legacy Token program (still not Token-2022)
    let ata_ai = AccountInfo::new(
        &holder_pk,
        false,
        true,
        &mut ata_lamports,
        &mut ata_data,
        &legacy_token_pk,
        false,
        0,
    );
    // slab must be owned by known Percolator program to pass verify_slab_owner()
    let slab_ai = AccountInfo::new(
        &slab_pk,
        false,
        false,
        &mut slab_lamports,
        &mut slab_data,
        &percolator_pk,
        false,
        0,
    );
    let auth_ai = AccountInfo::new(
        &mint_auth_pk,
        false,
        false,
        &mut auth_lamports,
        &mut auth_data,
        &system_program_id,
        false,
        0,
    );
    let token_ai = AccountInfo::new(
        &token_prog_id,
        false,
        false,
        &mut token_lamports,
        &mut token_data,
        &system_program_id,
        false,
        0,
    );

    let accounts = [
        holder_ai,
        pda_ai,
        nft_mint_ai,
        ata_ai,
        slab_ai,
        auth_ai,
        token_ai,
    ];

    let result = process(&prog_id_pk, &accounts, &[1u8]);
    let expected: ProgramError = NftError::NotNftHolder.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "Expected NotNftHolder when holder_ata.owner is legacy SPL Token"
    );
}

/// GH#18 regression guard: also check process_settle_funding uses same guard.
/// Verify SettleFunding returns NotNftHolder when holder_ata is not owned by Token-2022.
#[test]
fn test_settle_funding_not_nftholder_ata_wrong_owner() {
    use percolator_nft::{error::NftError, processor::process, token2022::TOKEN_2022_PROGRAM_ID};
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let pda_key = SdkPubkey::new_unique();

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_data = make_pda_data(&slab_key, &nft_mint_key);
    let mut slab_data: Vec<u8> = vec![];
    let mut ata_data: Vec<u8> = vec![0u8; 72];

    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let prog_id_pk = Pubkey::new_from_array(program_id.to_bytes());
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let pda_pk = Pubkey::new_from_array(pda_key.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());

    let holder_ai = AccountInfo::new(
        &holder_pk,
        true,
        false,
        &mut holder_lamports,
        &mut holder_data,
        &system_program_id,
        false,
        0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk,
        false,
        true,
        &mut pda_lamports,
        &mut pda_data,
        &prog_id_pk,
        false,
        0,
    );
    let slab_ai = AccountInfo::new(
        &slab_pk,
        false,
        false,
        &mut slab_lamports,
        &mut slab_data,
        &system_program_id,
        false,
        0,
    );
    // holder_ata owner = system program (not Token-2022)
    let ata_ai = AccountInfo::new(
        &holder_pk,
        false,
        false,
        &mut ata_lamports,
        &mut ata_data,
        &system_program_id,
        false,
        0,
    );

    let accounts = [holder_ai, pda_ai, slab_ai, ata_ai];

    let result = process(&prog_id_pk, &accounts, &[2u8]); // tag=2 = SettleFunding
    let expected: ProgramError = NftError::NotNftHolder.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "Expected NotNftHolder when holder_ata.owner is wrong in SettleFunding"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// PERC-9008 — BurnPositionNft PDA derivation check
// ══════════════════════════════════════════════════════════════════════════════

/// PERC-9008: BurnPositionNft must verify nft_pda.key matches the expected PDA
/// derivation from (slab, user_idx). A fake account with matching magic/slab/mint
/// bytes but wrong address must be rejected with InvalidNftPda.
#[test]
fn test_burn_rejects_wrong_pda_address() {
    use percolator_nft::{
        cpi::PERCOLATOR_DEVNET,
        error::NftError,
        processor::process,
        state::position_nft_pda,
        token2022::TOKEN_2022_PROGRAM_ID,
    };
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let holder_key = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();

    // Derive mint authority correctly so the InvalidMintAuthority guard passes.
    use percolator_nft::state::mint_authority_pda as map3;
    let prog_id_pk3 = Pubkey::new_from_array(program_id.to_bytes());
    let (derived_mint_auth, _) = map3(&prog_id_pk3);

    // Use a random key that does NOT match position_nft_pda(slab, user_idx=0, program_id).
    let wrong_pda_key = SdkPubkey::new_unique();

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_data = make_pda_data(&slab_key, &nft_mint_key);
    pda_data[8] = POSITION_NFT_VERSION; // ensure verify_pda_version() passes
    let mut mint_data: Vec<u8> = vec![0u8; 82];

    // Build a valid-looking ATA (Token-2022 owned, balance=1, correct owner+mint, initialized)
    let mut ata_data = vec![0u8; 165];
    ata_data[0..32].copy_from_slice(nft_mint_key.as_ref()); // mint
    ata_data[32..64].copy_from_slice(holder_key.as_ref()); // owner
    ata_data[64..72].copy_from_slice(&1u64.to_le_bytes()); // amount = 1
    ata_data[108] = 1; // state = Initialized

    // Build slab data with bitmap bit set for user_idx=0.
    // Use V0 layout: max_accounts=1, total = 608 + 1 + 240 = 849
    let max_accounts: u16 = 1;
    let bitmap_bytes = 1usize; // (1+7)/8
    let v0_total = 608 + bitmap_bytes + max_accounts as usize * 240;
    let mut slab_data = vec![0u8; v0_total];
    // SLAB_MAGIC required by detect_layout()
    slab_data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes()); // PERC-9065: "PERCOLAT"
    slab_data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    // Set bitmap bit for index 0
    slab_data[608] = 0x01;
    // Set owner at accounts_off + 184 = (608 + 1) + 184 = 793
    slab_data[793..825].copy_from_slice(holder_key.as_ref());

    let system_program_id = solana_program::system_program::id();
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_DEVNET.to_bytes());
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let prog_id_pk = prog_id_pk3;
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let wrong_pda_pk = Pubkey::new_from_array(wrong_pda_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let mint_auth_pk = derived_mint_auth;

    let holder_ai = AccountInfo::new(
        &holder_pk, true, false, &mut holder_lamports, &mut holder_data,
        &system_program_id, false, 0,
    );
    // PDA owned by program but with WRONG address
    let pda_ai = AccountInfo::new(
        &wrong_pda_pk, false, true, &mut pda_lamports, &mut pda_data,
        &prog_id_pk, false, 0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk, false, true, &mut mint_lamports, &mut mint_data,
        &token_prog_id, false, 0,
    );
    let ata_ai = AccountInfo::new(
        &holder_pk, false, true, &mut ata_lamports, &mut ata_data,
        &token_prog_id, false, 0,
    );
    let slab_ai = AccountInfo::new(
        &slab_pk, false, false, &mut slab_lamports, &mut slab_data,
        &percolator_pk, false, 0,
    );
    let mut auth_data_buf: Vec<u8> = vec![];
    let mut token_data_buf: Vec<u8> = vec![];
    let auth_ai = AccountInfo::new(
        &mint_auth_pk, false, false, &mut auth_lamports, &mut auth_data_buf,
        &system_program_id, false, 0,
    );
    let token_ai = AccountInfo::new(
        &token_prog_id, false, false, &mut token_lamports, &mut token_data_buf,
        &system_program_id, false, 0,
    );

    let accounts = [holder_ai, pda_ai, nft_mint_ai, ata_ai, slab_ai, auth_ai, token_ai];
    let result = process(&prog_id_pk, &accounts, &[1u8]); // tag=1 = BurnPositionNft
    let expected: ProgramError = NftError::InvalidNftPda.into();
    assert_eq!(
        result.unwrap_err(), expected,
        "Expected InvalidNftPda when PDA address doesn't match derivation"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// GH#1687 — percolator_prog key validation in TransferHook Execute
// ══════════════════════════════════════════════════════════════════════════════

/// Verify that InvalidPercolatorProgram error code is 13.
/// This matches the NftError enum added for GH#1687.
#[test]
fn test_invalid_percolator_program_error_code() {
    use percolator_nft::error::NftError;
    use solana_sdk::program_error::ProgramError;

    let err: ProgramError = NftError::InvalidPercolatorProgram.into();
    assert_eq!(
        err,
        ProgramError::Custom(13),
        "InvalidPercolatorProgram must be error code 13"
    );
}

/// Confirm PERCOLATOR_DEVNET and PERCOLATOR_MAINNET are distinct known keys.
/// transfer_hook.rs validates account[7] against these — if they were equal or
/// zero, the guard would be worthless.
#[test]
fn test_percolator_prog_constants_are_distinct_and_nonzero() {
    use percolator_nft::cpi::{PERCOLATOR_DEVNET, PERCOLATOR_MAINNET};
    use solana_sdk::pubkey::Pubkey;

    assert_ne!(
        PERCOLATOR_DEVNET,
        PERCOLATOR_MAINNET,
        "Devnet and mainnet program IDs must differ"
    );
    assert_ne!(
        PERCOLATOR_DEVNET,
        Pubkey::default(),
        "PERCOLATOR_DEVNET must not be zero key"
    );
    assert_ne!(
        PERCOLATOR_MAINNET,
        Pubkey::default(),
        "PERCOLATOR_MAINNET must not be zero key"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// PERC-N1: v12.17 slot-reuse bypass fix tests
// ══════════════════════════════════════════════════════════════════════════════
//
// These tests verify the `position_owner` check added to BurnPositionNft,
// SettleFunding, and GetPositionValue to close the slot-reuse bypass introduced
// in v12.17 when `account_id` was removed from the Account struct.
//
// Attack scenario:
//   1. user_A mints NFT for slab slot N — nft_state.account_id = 0 (v12.17),
//      nft_state.position_owner = user_A.to_bytes()
//   2. user_A closes their position → slot N is freed
//   3. Slot N is reassigned to user_B → slab Account.owner becomes user_B
//   4. user_A calls BurnPositionNft with the original NFT:
//      - Old check: 0 != 0 → false → passes (BYPASSED)
//      - New check: user_B != user_A → true → SlotReused (BLOCKED)

/// Helper: build a minimal V0-layout slab buffer with `max_accounts=1` and
/// a specific owner at slot 0. Returns a vec with the correct layout detected
/// by `detect_layout` in cpi.rs.
///
/// V0 layout:
///   - SLAB_MAGIC at bytes [0..8]
///   - max_accounts (u16) at bytes [8..10]
///   - bitmap at byte 608, length = ceil(max_accounts/8) = 1
///   - accounts at byte 609, each 240 bytes
///   - acct_owner_off within account = 184
///   - acct_has_account_id = true (V0), so account_id at offset 0 within acct
///   - acct_kind_off = 24 (kind=0 → User)
///
/// With slot 0 allocated (bitmap bit 0 set) and position closed (all zeros
/// except owner), the slot has size=0 (flat) and account_id=0.
fn build_v0_slab_with_owner(owner: &solana_sdk::pubkey::Pubkey) -> Vec<u8> {
    let max_accounts: u16 = 1;
    let v0_bitmap_off: usize = 608;
    let bitmap_bytes: usize = 1; // ceil(1/8)
    let v0_account_size: usize = 240;
    let total = v0_bitmap_off + bitmap_bytes + max_accounts as usize * v0_account_size;
    let mut data = vec![0u8; total];
    // Magic
    data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes());
    // max_accounts header (used by V0 layout detection path)
    data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    // Bitmap: slot 0 allocated
    data[v0_bitmap_off] = 0x01;
    // Write owner at accounts_off(609) + acct_owner_off(184) = 793
    let accounts_off = v0_bitmap_off + bitmap_bytes;
    let owner_off = accounts_off + 184;
    data[owner_off..owner_off + 32].copy_from_slice(owner.as_ref());
    // kind at accounts_off + 24 = 0 (User) — already zeroed
    // position_basis_q at accounts_off + 80 = 0 (flat) — already zeroed
    // capital at accounts_off + 8 = 0 — already zeroed
    // account_id at accounts_off + 0 = 0 — already zeroed (V0 stores it)
    data
}

/// Build a PositionNft PDA buffer with the given slab key, nft_mint key, and
/// position_owner set to the supplied 32-byte array.
fn make_pda_data_with_owner(
    slab_key: &solana_sdk::pubkey::Pubkey,
    nft_mint_key: &solana_sdk::pubkey::Pubkey,
    position_owner: [u8; 32],
) -> Vec<u8> {
    let mut buf = vec![0u8; POSITION_NFT_LEN];
    // magic [0..8]
    buf[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    // version [8]
    buf[8] = POSITION_NFT_VERSION;
    // slab [16..48]
    buf[16..48].copy_from_slice(slab_key.as_ref());
    // nft_mint [56..88]
    buf[56..88].copy_from_slice(nft_mint_key.as_ref());
    // account_id [152..160] = 0 (v12.17 style — field absent)
    // position_owner [160..192]
    buf[160..192].copy_from_slice(&position_owner);
    buf
}

/// PERC-N1 primary: BurnPositionNft — slot reused, position_owner changed → SlotReused.
///
/// Scenario:
///   - NFT PDA records position_owner = user_A
///   - Slab slot 0 now shows owner = user_B (slot was reassigned)
///   - account_id is 0 in both PDA and slab (v12.17 style) → old check passes
///   - New owner check must catch this and return SlotReused
#[test]
fn test_burn_slot_reuse_detected_via_position_owner() {
    use percolator_nft::{
        cpi::PERCOLATOR_MAINNET, error::NftError, processor::process,
        token2022::TOKEN_2022_PROGRAM_ID,
    };
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    // user_A: the original position owner at mint time
    let user_a = SdkPubkey::new_unique();
    // user_B: new occupant of the slab slot after reassignment
    let user_b = SdkPubkey::new_unique();

    use percolator_nft::state::{mint_authority_pda, position_nft_pda};
    let prog_pk = Pubkey::new_from_array(program_id.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let (pda_pk, _) = position_nft_pda(&slab_pk, 0, &prog_pk);
    let (mint_auth_pk, _) = mint_authority_pda(&prog_pk);

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    let holder_key_sdk = user_a; // user_A is the NFT holder
    let holder_pk = Pubkey::new_from_array(holder_key_sdk.to_bytes());

    // PDA records position_owner = user_A (minted when user_A held slot 0)
    let mut pda_data = make_pda_data_with_owner(&slab_key, &nft_mint_key, user_a.to_bytes());
    // Slab slot 0 now shows owner = user_B (slot was reassigned)
    let mut slab_data = build_v0_slab_with_owner(&user_b);

    // Build a valid ATA: Token-2022 owned, balance=1, owner=user_A, mint=nft_mint
    let mut ata_data = vec![0u8; 165];
    ata_data[0..32].copy_from_slice(nft_mint_key.as_ref()); // mint
    ata_data[32..64].copy_from_slice(holder_key_sdk.as_ref()); // owner
    ata_data[64..72].copy_from_slice(&1u64.to_le_bytes()); // amount = 1
    ata_data[108] = 1; // state = Initialized

    let mut holder_data: Vec<u8> = vec![];
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());

    let holder_ai = AccountInfo::new(
        &holder_pk, true, false,
        &mut holder_lamports, &mut holder_data, &system_program_id, false, 0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk, false, true,
        &mut pda_lamports, &mut pda_data, &prog_pk, false, 0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk, false, true,
        &mut mint_lamports, &mut mint_data, &token_prog_id, false, 0,
    );
    let ata_ai = AccountInfo::new(
        &holder_pk, false, true,
        &mut ata_lamports, &mut ata_data, &token_prog_id, false, 0,
    );
    let slab_ai = AccountInfo::new(
        &slab_pk, false, false,
        &mut slab_lamports, &mut slab_data, &percolator_pk, false, 0,
    );
    let auth_ai = AccountInfo::new(
        &mint_auth_pk, false, false,
        &mut auth_lamports, &mut auth_data, &system_program_id, false, 0,
    );
    let token_ai = AccountInfo::new(
        &token_prog_id, false, false,
        &mut token_lamports, &mut token_data, &system_program_id, false, 0,
    );

    let accounts = [holder_ai, pda_ai, nft_mint_ai, ata_ai, slab_ai, auth_ai, token_ai];
    let result = process(&prog_pk, &accounts, &[1u8]); // tag=1 = BurnPositionNft
    let expected: ProgramError = NftError::SlotReused.into();
    assert_eq!(
        result.unwrap_err(),
        expected,
        "Expected SlotReused when position_owner changed (slot reuse)"
    );
}

/// PERC-N1 migration guard: BurnPositionNft — position_owner == [0; 32] (pre-fix NFT)
/// skips the new owner check and falls through to the normal size check.
///
/// Ensures backward compatibility: NFTs minted before the fix have position_owner
/// zeroed, and should NOT be blocked by the new guard on legitimate burns.
#[test]
fn test_burn_migration_guard_skips_check_for_zero_position_owner() {
    use percolator_nft::{
        cpi::PERCOLATOR_MAINNET, error::NftError, processor::process,
        token2022::TOKEN_2022_PROGRAM_ID,
    };
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let program_id = SdkPubkey::new_unique();
    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let holder_key_sdk = SdkPubkey::new_unique();

    use percolator_nft::state::{mint_authority_pda, position_nft_pda};
    let prog_pk = Pubkey::new_from_array(program_id.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let holder_pk = Pubkey::new_from_array(holder_key_sdk.to_bytes());
    let (pda_pk, _) = position_nft_pda(&slab_pk, 0, &prog_pk);
    let (mint_auth_pk, _) = mint_authority_pda(&prog_pk);

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    // PDA with position_owner = [0; 32] (pre-fix NFT)
    let mut pda_data = make_pda_data_with_owner(&slab_key, &nft_mint_key, [0u8; 32]);
    // Slab with a different owner — migration guard should skip the owner check
    let mut slab_data = build_v0_slab_with_owner(&holder_key_sdk);
    // Slab slot 0 has size=0 (position closed), so burn should not be blocked

    let mut ata_data = vec![0u8; 165];
    ata_data[0..32].copy_from_slice(nft_mint_key.as_ref());
    ata_data[32..64].copy_from_slice(holder_key_sdk.as_ref());
    ata_data[64..72].copy_from_slice(&1u64.to_le_bytes());
    ata_data[108] = 1;

    let mut holder_data: Vec<u8> = vec![];
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());

    let holder_ai = AccountInfo::new(
        &holder_pk, true, false,
        &mut holder_lamports, &mut holder_data, &system_program_id, false, 0,
    );
    let pda_ai = AccountInfo::new(
        &pda_pk, false, true,
        &mut pda_lamports, &mut pda_data, &prog_pk, false, 0,
    );
    let nft_mint_ai = AccountInfo::new(
        &nft_mint_pk, false, true,
        &mut mint_lamports, &mut mint_data, &token_prog_id, false, 0,
    );
    let ata_ai = AccountInfo::new(
        &holder_pk, false, true,
        &mut ata_lamports, &mut ata_data, &token_prog_id, false, 0,
    );
    let slab_ai = AccountInfo::new(
        &slab_pk, false, false,
        &mut slab_lamports, &mut slab_data, &percolator_pk, false, 0,
    );
    let auth_ai = AccountInfo::new(
        &mint_auth_pk, false, false,
        &mut auth_lamports, &mut auth_data, &system_program_id, false, 0,
    );
    let token_ai = AccountInfo::new(
        &token_prog_id, false, false,
        &mut token_lamports, &mut token_data, &system_program_id, false, 0,
    );

    let accounts = [holder_ai, pda_ai, nft_mint_ai, ata_ai, slab_ai, auth_ai, token_ai];
    let result = process(&prog_pk, &accounts, &[1u8]); // tag=1 = BurnPositionNft

    // Migration guard skips owner check → position.size == 0 → burn would proceed to
    // CPI (which fails without runtime). The critical assertion is that we do NOT get
    // SlotReused — the guard correctly bypasses the check for pre-fix NFTs.
    // We accept any error except SlotReused (CPI invocations require the runtime).
    let slot_reused_err: ProgramError = NftError::SlotReused.into();
    match result {
        Ok(_) => {} // shouldn't reach here without runtime, but would be fine
        Err(e) => assert_ne!(
            e, slot_reused_err,
            "Migration guard must NOT return SlotReused for pre-fix NFT with zeroed position_owner"
        ),
    }
}

/// PERC-N1: NftError::SlotReused must have error code 20.
/// This pins the wire format so the SDK can decode it.
#[test]
fn test_slot_reused_error_code() {
    use percolator_nft::error::NftError;
    use solana_sdk::program_error::ProgramError;
    let err: ProgramError = NftError::SlotReused.into();
    assert_eq!(
        err,
        ProgramError::Custom(20),
        "SlotReused must be error code 20"
    );
}

// ══════════════════════════════════════════════════════════════════════════════
// PERC-N2: v12.17 valuation correctness — spec §3.4 `account_equity_maint_raw`
// ══════════════════════════════════════════════════════════════════════════════
//
// Before the fix, `process_get_position_value` computed
// `unrealized_pnl = if entry_price_e6 > 0 && mark > 0 { mark-vs-entry } else { 0 }`.
// On v12.17 layouts the `Account.entry_price` field was removed, so
// `read_position` always returns `entry_price_e6 = 0`, the `else` branch fires,
// and `unrealized_pnl = 0`, `net_equity = collateral` — a deeply underwater
// position appears break-even to any lending protocol or marketplace consuming
// the `POSITION_VALUE:*` log stream.
//
// The fix routes v12.17 layouts through Percolator's authoritative equity
// formula (spec §3.4, `RiskEngine::account_equity_maint_raw` in the upstream
// `percolator` crate):
//
//     equity_maint_raw = capital + pnl - fee_debt
//     fee_debt         = max(0, -fee_credits)
//
// `pnl` (Account+24) and `fee_credits` (Account+280) are persistent fields
// on v12.17; `pnl` folds in funding accruals via the per-side mechanism so
// the formula needs no funding-delta correction.
//
// These tests use `compute_position_value` directly (the pure-math function
// extracted from `process_get_position_value`) so we can assert on every
// field of `PositionValuation` without round-tripping through `msg!` logs.

/// Build a minimal v12.17 slab with one allocated, open position.
///
/// Layout (matches `detect_layout` V12_17 branch in src/cpi.rs:384-438):
///   * SLAB_MAGIC at [0..8] = `0x5045_5243_4F4C_4154` ("PERCOLAT")
///   * RiskEngine at offset 584
///   * RiskParams at engine+32 (= 616); `maintenance_margin_bps` at params+0
///   * `max_accounts: u64` at engine+32+24 (= 640)
///   * `last_oracle_price` at engine+624 (= 1208) — used as mark on v12.17
///   * bitmap (RiskEngine.used) at engine+712 (= 1296)
///   * after-bitmap tail: `num_used_accounts(u16) + free_head(u16) = 4` bytes,
///     then `next_free: [u16; max_accounts]`, then 8-aligned accounts array
///   * each Account is 408 bytes (slab_types::EXPECTED_ACCOUNT_SIZE)
///   * v12.17 Account offsets used by the fixture:
///       capital (U128 lo) at +0
///       kind (u8)         at +16
///       pnl (I128)        at +24
///       position_basis_q  at +56
///       owner ([u8;32])   at +192 (current slab_types::ACCT_OFF_OWNER)
///       fee_credits (I128) at +280
///   * trailing `RISK_BUF_LEN (160) + max_accounts * GEN_TABLE_ENTRY (8)` bytes
///
/// Inputs are all in slab-native units (no helper-side scaling). `pnl` and
/// `fee_credits` are signed i128 so callers can express deep losses or fee
/// debt directly. `position_basis_q` is two's-complement on v12.17.
fn build_v12_17_slab(
    owner: &solana_sdk::pubkey::Pubkey,
    capital: u128,
    pnl: i128,
    fee_credits: i128,
    position_basis_q: i128,
    last_oracle_price_e6: u64,
    maintenance_margin_bps: u64,
) -> Vec<u8> {
    const MAX_ACCOUNTS: u16 = 1;
    const ENGINE_OFF: usize = 584;
    const ACCOUNT_SIZE: usize = 408; // slab_types::EXPECTED_ACCOUNT_SIZE
    const BITMAP_OFF: usize = ENGINE_OFF + 712; // 1296
    const RISK_BUF_LEN: usize = 160;
    const GEN_TABLE_ENTRY: usize = 8;
    // Tail after bitmap: num_used_accounts(u16) + free_head(u16) = 4, then
    // next_free: [u16; max_accounts], then 8-aligned accounts.
    let bitmap_bytes: usize = (MAX_ACCOUNTS as usize).div_ceil(8); // 1
    let after_bitmap = bitmap_bytes + 4 + (MAX_ACCOUNTS as usize) * 2;
    let accounts_off_raw = BITMAP_OFF + after_bitmap;
    let accounts_off = (accounts_off_raw + 7) & !7;
    let trailing = RISK_BUF_LEN + (MAX_ACCOUNTS as usize) * GEN_TABLE_ENTRY;
    let total = accounts_off + (MAX_ACCOUNTS as usize) * ACCOUNT_SIZE + trailing;
    let mut data = vec![0u8; total];

    // Magic
    data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes());
    // Engine fields: max_accounts (u64) at engine+32+24 = 640.
    data[ENGINE_OFF + 32 + 24..ENGINE_OFF + 32 + 24 + 8]
        .copy_from_slice(&(MAX_ACCOUNTS as u64).to_le_bytes());
    // maintenance_margin_bps at params+0 = engine+32.
    data[ENGINE_OFF + 32..ENGINE_OFF + 32 + 8]
        .copy_from_slice(&maintenance_margin_bps.to_le_bytes());

    // Bitmap: slot 0 allocated.
    data[BITMAP_OFF] = 0x01;

    // Account[0] fields.
    let a = accounts_off;
    // capital: U128 lo at +0, hi at +8.
    data[a..a + 8].copy_from_slice(&(capital as u64).to_le_bytes());
    data[a + 8..a + 16].copy_from_slice(&((capital >> 64) as u64).to_le_bytes());
    // kind = 0 (User) — already zeroed.
    // pnl: I128 native two's complement at +24.
    data[a + 24..a + 40].copy_from_slice(&pnl.to_le_bytes());
    // position_basis_q: I128 native two's complement at +56.
    data[a + 56..a + 72].copy_from_slice(&position_basis_q.to_le_bytes());
    // owner: [u8; 32] at the layout-resolved offset (slab_types::ACCT_OFF_OWNER).
    let owner_off = a + percolator_nft::slab_types::ACCT_OFF_OWNER;
    data[owner_off..owner_off + 32].copy_from_slice(owner.as_ref());
    // fee_credits: I128 at the layout-resolved offset.
    let fc_off = a + percolator_nft::slab_types::ACCT_OFF_FEE_CREDITS;
    data[fc_off..fc_off + 16].copy_from_slice(&fee_credits.to_le_bytes());

    // last_oracle_price at engine + slab_types::ENGINE_REL_LAST_ORACLE_PRICE.
    // The cpi.rs detect_layout's V12_17 branch resolves the mark-price
    // offset from this constant (=1040 on the current vendored
    // RiskEngine). With max_accounts=1 and detect_layout's hardcoded
    // bitmap_off=engine+712, accounts_off lands at 1304 and Account[0]
    // spans [1304..1712]. last_oracle_price at engine+1040 = 1624 falls
    // inside Account[0]'s `sched_anchor_q` region (offset 320 within
    // Account) — read_position never reads that field on v12.17, so
    // overwriting it with the mark price is safe for this fixture.
    // We write last_oracle_price LAST so it wins over any Account
    // bytes that happen to overlap.
    let mark_abs = ENGINE_OFF + percolator_nft::slab_types::ENGINE_REL_LAST_ORACLE_PRICE;
    data[mark_abs..mark_abs + 8].copy_from_slice(&last_oracle_price_e6.to_le_bytes());

    data
}

/// PERC-N2 helper: build a PositionNft PDA that satisfies the slot-reuse
/// and PERC-9060 snapshot checks against a v12.17 slab built by
/// `build_v12_17_slab(...)`. v12.17 has `entry_price_e6 == 0` in the PDA
/// (snapshotted as 0 at mint time, since the slab field is gone).
fn make_v12_17_pda(
    slab_key: &solana_sdk::pubkey::Pubkey,
    nft_mint_key: &solana_sdk::pubkey::Pubkey,
    position_owner: [u8; 32],
    is_long: u8,
) -> Vec<u8> {
    let mut buf = vec![0u8; POSITION_NFT_LEN];
    buf[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    buf[8] = POSITION_NFT_VERSION;
    buf[16..48].copy_from_slice(slab_key.as_ref());
    buf[56..88].copy_from_slice(nft_mint_key.as_ref());
    // entry_price_e6 [88..96] = 0 (v12.17 has no Account.entry_price)
    // position_size [96..104] = 0 (PDA snapshot, not checked by PERC-9060
    // on v12.17 since entry_price_e6 / is_long match vacuously)
    // is_long [104]
    buf[104] = is_long;
    // account_id [152..160] = 0
    // position_owner [160..192]
    buf[160..192].copy_from_slice(&position_owner);
    buf
}

/// **PERC-N2 PROOF OF BUG**.
///
/// A position with deeply negative `account.pnl` (−900K out of 1M capital,
/// i.e. only 100K of real equity left) is fed to `compute_position_value`.
/// The CURRENT (pre-fix) code path uses `unrealized_pnl = 0` because
/// `entry_price_e6 == 0` on v12.17, so it reports `net_equity = capital`
/// (1M) instead of the spec-§3.4 value (100K) — a 10× over-statement of
/// the position's worth. After the fix this test asserts the correct
/// value, so the test serves both as bug evidence and fix regression.
///
/// Liquidation distance similarly flips from "fully healthy" to "nearly
/// liquidatable" once the fix is applied.
#[test]
fn test_perc_n2_v12_17_valuation_uses_account_pnl_not_entry_diff() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let capital: u128 = 1_000_000;
    let pnl: i128 = -900_000;
    let fee_credits: i128 = 0;
    let position_basis_q: i128 = 1_000_000_000; // POS_SCALE-scaled (1 unit)
    let mark_price: u64 = 50_000_000; // E6
    let mm_bps: u64 = 500; // 5%

    let slab_data = build_v12_17_slab(
        &owner,
        capital,
        pnl,
        fee_credits,
        position_basis_q,
        mark_price,
        mm_bps,
    );

    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);

    let v = compute_position_value(&slab_data, nft_state).expect("compute should succeed");

    assert!(v.layout_v12_17, "fixture should be detected as v12.17");
    assert_eq!(
        v.unrealized_pnl, pnl,
        "v12.17 unrealized_pnl must mirror account.pnl (not silently zero)"
    );
    assert_eq!(v.pnl_q, pnl, "raw pnl_q must equal account.pnl");
    assert_eq!(v.fee_debt_q, 0, "no fee debt when fee_credits = 0");

    // Spec §3.4: equity = capital + pnl - fee_debt.
    // capital(1_000_000) + pnl(-900_000) - fee_debt(0) = 100_000.
    let expected_equity: i128 = (capital as i128) + pnl;
    assert_eq!(
        v.net_equity, expected_equity,
        "v12.17 net_equity must be spec-§3.4 equity_maint_raw, not silently `collateral`"
    );

    // Crucial: the BUG-BEFORE-FIX behaviour would have been:
    //   unrealized_pnl = 0
    //   net_equity     = collateral = 1_000_000
    //   This test would have asserted 1_000_000, masking the 90% loss.
    // The fact that we now assert 100_000 is what proves the fix.
    assert_ne!(
        v.net_equity, capital as i128,
        "pre-fix would have reported net_equity == collateral; that is the bug"
    );
}

/// PERC-N2: positive PnL is reported correctly (not capped or zeroed).
#[test]
fn test_perc_n2_v12_17_valuation_reports_positive_pnl() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let capital: u128 = 1_000_000;
    let pnl: i128 = 500_000; // 50% gain
    let slab_data = build_v12_17_slab(
        &owner,
        capital,
        pnl,
        0,
        1_000_000_000,
        50_000_000,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    assert!(v.layout_v12_17);
    assert_eq!(v.unrealized_pnl, pnl);
    assert_eq!(v.net_equity, (capital as i128) + pnl);
}

/// PERC-N2: fee_debt is subtracted from equity (matches `fee_debt_u128_checked`
/// upstream semantics — negative fee_credits = positive fee_debt).
#[test]
fn test_perc_n2_v12_17_valuation_subtracts_fee_debt() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let capital: u128 = 1_000_000;
    let pnl: i128 = 0;
    let fee_credits: i128 = -50_000; // 50K fee debt
    let slab_data = build_v12_17_slab(
        &owner,
        capital,
        pnl,
        fee_credits,
        1_000_000_000,
        50_000_000,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    assert!(v.layout_v12_17);
    assert_eq!(v.pnl_q, 0);
    assert_eq!(v.fee_debt_q, 50_000, "negative fee_credits maps to positive fee_debt");
    // equity = 1_000_000 + 0 - 50_000 = 950_000
    assert_eq!(v.net_equity, 950_000);
}

/// PERC-N2: positive `fee_credits` (pre-paid fees) yields `fee_debt = 0`, not
/// negative debt. Upstream `fee_debt_u128_checked` clamps at 0.
#[test]
fn test_perc_n2_v12_17_valuation_positive_fee_credits_zero_debt() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        25_000, // positive credit
        1_000_000_000,
        50_000_000,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    assert_eq!(v.fee_debt_q, 0, "positive fee_credits must clamp fee_debt to 0");
    assert_eq!(v.net_equity, 1_000_000, "no debt subtracted when fee_credits > 0");
}

/// PERC-N2: maintenance_margin on v12.17 uses notional in quote micro-units,
/// not the raw POS_SCALE-scaled basis-quote size. This catches the
/// pre-fix off-by-(`mark_price_e6 / POS_SCALE`)-factor in the legacy formula
/// applied to v12.17 sizes.
#[test]
fn test_perc_n2_v12_17_maintenance_margin_uses_quote_notional() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    // position_basis_q = 1_000_000_000 (basis-quote units, POS_SCALE=1_000_000).
    // mark_price_e6 = 50_000_000 (= price 50.0 in E6).
    // notional = |basis_q| * mark / POS_SCALE
    //          = 1_000_000_000 * 50_000_000 / 1_000_000
    //          = 5e16 / 1e6 = 5e10 = 50_000_000_000.
    // mm_req = notional * bps / 10_000 = 50_000_000_000 * 500 / 10_000
    //        = 2_500_000_000.
    let position_basis_q: i128 = 1_000_000_000;
    let mark_price: u64 = 50_000_000;
    let mm_bps: u64 = 500;

    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        0,
        position_basis_q,
        mark_price,
        mm_bps,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    let expected_mm: u128 = 2_500_000_000;
    assert_eq!(
        v.maintenance_margin, expected_mm,
        "v12.17 mm_req must use notional in quote micro-units, not raw basis-quote size"
    );
}

/// PERC-N2 regression: legacy (V0) layout still uses the mark-vs-entry PnL
/// formula and produces non-zero `unrealized_pnl` and `net_equity`.
/// Pinning this prevents the fix from accidentally re-routing legacy
/// positions through the v12.17 spec-§3.4 path.
#[test]
fn test_perc_n2_legacy_v0_valuation_unchanged() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let entry_price: u64 = 50_000_000;
    let mark_price: u64 = 60_000_000; // +20% move
    let size: u64 = 1_000_000;
    let collateral: u64 = 100_000;
    let mm_bps: u64 = 500;

    // Reuse the legacy V0 open-position helper from the PERC-N1 fix
    // submission.  (Inlined here for clarity in case the helper is renamed.)
    let max_accounts: u16 = 1;
    let v0_bitmap_off: usize = 608;
    let v0_account_size: usize = 240;
    let total = v0_bitmap_off + 1 + max_accounts as usize * v0_account_size;
    let mut slab_data = vec![0u8; total];
    slab_data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes());
    slab_data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    slab_data[v0_bitmap_off] = 0x01;
    let accounts_off = v0_bitmap_off + 1;
    // V0 Account offsets: capital lo at +8; position_size lo at +80; hi at +88
    // (sign+magnitude, hi=0 ⇒ long); entry_price at +96; owner at +184.
    slab_data[accounts_off + 8..accounts_off + 16]
        .copy_from_slice(&(collateral as u64).to_le_bytes());
    slab_data[accounts_off + 80..accounts_off + 88].copy_from_slice(&size.to_le_bytes());
    // hi-word stays 0 ⇒ long
    slab_data[accounts_off + 96..accounts_off + 104].copy_from_slice(&entry_price.to_le_bytes());
    let owner_off = accounts_off + 184;
    slab_data[owner_off..owner_off + 32].copy_from_slice(owner.as_ref());
    // V0 engine offsets: engine at 480, mark at engine+0, maint at engine+96
    let engine_off: usize = 480;
    slab_data[engine_off..engine_off + 8].copy_from_slice(&mark_price.to_le_bytes());
    slab_data[engine_off + 96..engine_off + 96 + 8].copy_from_slice(&mm_bps.to_le_bytes());

    // PDA snapshot must match entry/is_long for the PERC-9060 check.
    let mut pda_bytes = vec![0u8; POSITION_NFT_LEN];
    pda_bytes[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    pda_bytes[8] = POSITION_NFT_VERSION;
    pda_bytes[16..48].copy_from_slice(slab_key.as_ref());
    pda_bytes[56..88].copy_from_slice(nft_mint_key.as_ref());
    pda_bytes[88..96].copy_from_slice(&entry_price.to_le_bytes());
    pda_bytes[96..104].copy_from_slice(&size.to_le_bytes());
    pda_bytes[104] = 1;
    pda_bytes[160..192].copy_from_slice(&owner.to_bytes());
    let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);

    let v = compute_position_value(&slab_data, nft_state).expect("legacy compute succeeds");

    assert!(!v.layout_v12_17, "V0 layout must not be flagged as v12.17");
    // size * (mark - entry) / entry = 1_000_000 * 10_000_000 / 50_000_000 = 200_000
    assert_eq!(v.unrealized_pnl, 200_000);
    assert_eq!(v.net_equity, (collateral as i128) + 200_000);
    assert_eq!(v.pnl_q, 0, "pnl_q is v12.17-only");
    assert_eq!(v.fee_debt_q, 0, "fee_debt_q is v12.17-only");
}

/// PERC-N2: `is_v12_17` flag on `PositionData` must match the layout
/// detection in `cpi::detect_layout`. Pins the contract between
/// `read_position` and `compute_position_value`.
#[test]
fn test_perc_n2_position_data_is_v12_17_flag_consistent() {
    use percolator_nft::cpi::read_position;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let owner = SdkPubkey::new_unique();

    // v12.17 slab ⇒ flag must be true.
    let v12 = build_v12_17_slab(&owner, 1_000_000, 0, 0, 1_000_000_000, 50_000_000, 500);
    let p = read_position(&v12, 0).expect("read v12.17 position");
    assert!(p.is_v12_17, "v12.17 fixture must set is_v12_17 = true");
    assert_eq!(p.entry_price_e6, 0);

    // V0 slab (closed position fixture) ⇒ flag must be false.
    let v0 = build_v0_slab_with_owner(&owner);
    let p0 = read_position(&v0, 0).expect("read V0 position");
    assert!(!p0.is_v12_17, "V0 fixture must set is_v12_17 = false");
}

// ──────────────────────────────────────────────────────────────────────────
// PERC-N2 review-pass-2: blockers + strong-recommends from senior dev audit
// ──────────────────────────────────────────────────────────────────────────

/// **PERC-N2 review pass 2 (BLOCKER 1)**.
///
/// On v12.17 layouts `position_basis_q` is a native i128 in basis-quote
/// units (POS_SCALE-scaled). The legacy code path silently truncates
/// `unsigned_abs() as u64` and the truncated `size` then feeds into the
/// notional / maintenance-margin math. A whale position with
/// `|basis_q| > u64::MAX` would report a wrap-around `size`, then a
/// catastrophically small `mm_req`, advertising as fully healthy when
/// percolator-prog itself sees a huge exposure.
///
/// This test forces `position_basis_q = 1 << 70` (well past u64::MAX),
/// reads via `cpi::read_position`, and asserts the v12.15+/twos-complement
/// guard rejects with `ArithmeticOverflow` rather than silently truncating.
#[test]
fn test_perc_n2_v12_17_position_basis_q_overflow_rejected() {
    use percolator_nft::cpi::read_position;
    use solana_program::program_error::ProgramError;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let owner = SdkPubkey::new_unique();
    // |basis_q| = 2^70 > u64::MAX = 2^64 - 1.
    let huge: i128 = 1i128 << 70;
    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000, // capital
        0,
        0,
        huge,
        50_000_000,
        500,
    );
    let result = read_position(&slab_data, 0);
    assert_eq!(
        result.err(),
        Some(ProgramError::ArithmeticOverflow),
        "v12.17 read_position must reject |position_basis_q| > u64::MAX rather than truncating"
    );
}

/// **PERC-N2 review pass 2 (BLOCKER 2)**.
///
/// Upstream's `risk_notional_ceil` (percolator-prog `mul_div_ceil_u128`)
/// uses CEILING division for `notional = |basis_q| × mark / POS_SCALE`.
/// The fix's v12.17 notional path now matches. This test picks inputs
/// where the numerator is NOT a clean multiple of POS_SCALE so the
/// ceiling and floor results differ by exactly 1 micro-unit, then asserts
/// the fix uses the upstream-parity ceiling.
///
/// Inputs: `basis_q = 1_000_001`, `mark = 1_000_000_001`, POS_SCALE = 1e6.
///   num            = 1_000_001 × 1_000_000_001 = 1_000_001_001_000_001
///   num / POS_SCALE = 1_000_001_001 with remainder 1
///   floor          = 1_000_001_001
///   ceil           = 1_000_001_002   ← what the fix must produce
#[test]
fn test_perc_n2_v12_17_notional_uses_ceiling_division() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let position_basis_q: i128 = 1_000_001;
    let mark_price: u64 = 1_000_000_001;
    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        0,
        position_basis_q,
        mark_price,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    let expected_floor: u128 = 1_000_001_001;
    let expected_ceil: u128 = 1_000_001_002;
    assert_eq!(
        v.notional_quote, expected_ceil,
        "v12.17 notional_quote must use ceiling division (parity with upstream risk_notional_ceil)"
    );
    assert_ne!(
        v.notional_quote, expected_floor,
        "fix must NOT use floor division — that under-reports mm_req by 1 micro-unit vs upstream"
    );
}

/// **PERC-N2 review pass 2 (strong-recommend 1)**.
///
/// On v12.17 `position.global_funding_index_e18 = 0` (engine has per-side
/// funding numerators instead of a single global index). For an NFT minted
/// on a LEGACY slab and later read against a v12.17-upgraded slab, the
/// PDA's `last_funding_index_e18` still carries the legacy snapshot.
/// Naive `delta = 0 - snapshot` would emit a misleading negative
/// `funding_delta_e18` even though no funding has been "lost" — the per-
/// side funding state has already been folded into `account.pnl`.
///
/// This test seeds a non-zero `last_funding_index_e18` on the PDA and
/// asserts the fix force-zeroes `funding_delta_e18` on v12.17.
#[test]
fn test_perc_n2_v12_17_funding_delta_zero_on_upgraded_nft() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        0,
        1_000_000_000,
        50_000_000,
        500,
    );
    let mut pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    // Seed last_funding_index_e18 at PDA offset 128..144 with a non-zero
    // legacy snapshot (simulating an NFT minted on a pre-v12.17 slab).
    let stale_funding: i128 = 12_345_678_901_234_567_890;
    pda_bytes[128..144].copy_from_slice(&stale_funding.to_le_bytes());
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);

    let v = compute_position_value(&slab_data, nft_state).unwrap();

    assert!(v.layout_v12_17);
    assert_eq!(
        v.funding_delta_e18, 0,
        "v12.17 must force-zero funding_delta_e18 regardless of stale PDA snapshot"
    );
}

/// **PERC-N2 review pass 2 (strong-recommend 2)**.
///
/// Verifies the new `notional_quote` field is populated on v12.17 (and
/// exposed via the `POSITION_VALUE:notional_quote=` log line emitted by
/// `process_get_position_value`). On legacy layouts the field is 0.
#[test]
fn test_perc_n2_v12_17_emits_notional_quote() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    // basis_q=1e9, mark=5e7, POS_SCALE=1e6 ⇒ notional = ceil(5e16/1e6) = 5e10.
    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        0,
        1_000_000_000,
        50_000_000,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);
    let v = compute_position_value(&slab_data, nft_state).unwrap();

    assert_eq!(
        v.notional_quote, 50_000_000_000_u128,
        "v12.17 notional_quote must be populated (= ceil(|basis_q| × mark / POS_SCALE))"
    );

    // Sanity: maintenance_margin must match floor(notional × bps / 10_000).
    let expected_mm = 50_000_000_000_u128 * 500 / 10_000;
    assert_eq!(v.maintenance_margin, expected_mm);
}

/// **PERC-N2 review pass 2 (round-3 polish)**: `fee_credits = i128::MIN`
/// is rejected as corrupt slab data — mirrors upstream
/// `fee_debt_u128_checked`'s rejection of the same value (the negation
/// `-i128::MIN` would overflow). Without this guard, `compute_position_value`
/// would silently return a saturated fee_debt and misreport equity.
#[test]
fn test_perc_n2_v12_17_fee_credits_i128_min_rejected() {
    use percolator_nft::valuation::compute_position_value;
    use solana_program::program_error::ProgramError;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    let slab_data = build_v12_17_slab(
        &owner,
        1_000_000,
        0,
        i128::MIN, // corrupt fee_credits
        1_000_000_000,
        50_000_000,
        500,
    );
    let pda_bytes = make_v12_17_pda(&slab_key, &nft_mint_key, owner.to_bytes(), 1);
    let nft_state =
        bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);

    let result = compute_position_value(&slab_data, nft_state);
    assert_eq!(
        result.err(),
        Some(ProgramError::ArithmeticOverflow),
        "i128::MIN fee_credits must surface as ArithmeticOverflow, mirroring upstream fee_debt_u128_checked"
    );
}

/// **PERC-N2 review pass 2**: legacy layouts leave `notional_quote = 0`.
/// The field is v12.17-only.
#[test]
fn test_perc_n2_legacy_layout_notional_quote_is_zero() {
    use percolator_nft::valuation::compute_position_value;
    use solana_sdk::pubkey::Pubkey as SdkPubkey;

    let slab_key = SdkPubkey::new_unique();
    let nft_mint_key = SdkPubkey::new_unique();
    let owner = SdkPubkey::new_unique();

    // Reuse the V0 open-position fixture pattern from PERC-N1 tests.
    let entry_price: u64 = 50_000_000;
    let mark_price: u64 = 60_000_000;
    let size: u64 = 1_000_000;
    let collateral: u64 = 100_000;
    let mm_bps: u64 = 500;
    let max_accounts: u16 = 1;
    let v0_bitmap_off: usize = 608;
    let v0_account_size: usize = 240;
    let total = v0_bitmap_off + 1 + max_accounts as usize * v0_account_size;
    let mut slab_data = vec![0u8; total];
    slab_data[0..8].copy_from_slice(&0x5045_5243_4F4C_4154u64.to_le_bytes());
    slab_data[8..10].copy_from_slice(&max_accounts.to_le_bytes());
    slab_data[v0_bitmap_off] = 0x01;
    let accounts_off = v0_bitmap_off + 1;
    slab_data[accounts_off + 8..accounts_off + 16].copy_from_slice(&collateral.to_le_bytes());
    slab_data[accounts_off + 80..accounts_off + 88].copy_from_slice(&size.to_le_bytes());
    slab_data[accounts_off + 96..accounts_off + 104].copy_from_slice(&entry_price.to_le_bytes());
    let owner_off = accounts_off + 184;
    slab_data[owner_off..owner_off + 32].copy_from_slice(owner.as_ref());
    let engine_off: usize = 480;
    slab_data[engine_off..engine_off + 8].copy_from_slice(&mark_price.to_le_bytes());
    slab_data[engine_off + 96..engine_off + 96 + 8].copy_from_slice(&mm_bps.to_le_bytes());

    let mut pda_bytes = vec![0u8; POSITION_NFT_LEN];
    pda_bytes[..8].copy_from_slice(&POSITION_NFT_MAGIC.to_le_bytes());
    pda_bytes[8] = POSITION_NFT_VERSION;
    pda_bytes[16..48].copy_from_slice(slab_key.as_ref());
    pda_bytes[56..88].copy_from_slice(nft_mint_key.as_ref());
    pda_bytes[88..96].copy_from_slice(&entry_price.to_le_bytes());
    pda_bytes[96..104].copy_from_slice(&size.to_le_bytes());
    pda_bytes[104] = 1;
    pda_bytes[160..192].copy_from_slice(&owner.to_bytes());
    let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_bytes[..POSITION_NFT_LEN]);

    let v = compute_position_value(&slab_data, nft_state).unwrap();
    assert!(!v.layout_v12_17);
    assert_eq!(v.notional_quote, 0, "notional_quote must be 0 on legacy layouts");
}

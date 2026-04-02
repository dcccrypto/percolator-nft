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
    assert_eq!(&ix.data[..8], &[210, 225, 30, 162, 88, 184, 238, 125]);
    // 3 accounts: mint(w), update_authority, mint_authority(s)
    assert_eq!(ix.accounts.len(), 3);
    assert!(ix.accounts[0].is_writable);
    assert!(ix.accounts[2].is_signer);
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

#[test]
fn test_transfer_hook_extension_init() {
    use percolator_nft::token2022;
    let mint = solana_sdk::pubkey::Pubkey::new_unique();
    let auth = solana_sdk::pubkey::Pubkey::new_unique();
    let hook_prog = solana_sdk::pubkey::Pubkey::new_unique();

    let ix = token2022::initialize_transfer_hook(&mint, &auth, &hook_prog);
    assert_eq!(ix.data[0], 36); // InitializeTransferHook tag
    assert_eq!(ix.data.len(), 65); // tag(1) + authority(32) + program_id(32)
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
    let mint_auth_key = SdkPubkey::new_unique();

    // PDA key must match what process_burn_position_nft will read from state.
    let pda_key = SdkPubkey::new_unique(); // not validated inside burn (only checked against recorded slab/mint)

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
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut ata_data: Vec<u8> = vec![0u8; 72];
    let mut slab_data: Vec<u8> = vec![];
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    // ATA owner is System Program (wrong — should be Token-2022)
    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_id_pk = Pubkey::new_from_array(program_id.to_bytes());
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let pda_pk = Pubkey::new_from_array(pda_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let mint_auth_pk = Pubkey::new_from_array(mint_auth_key.to_bytes());

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
    let mint_auth_key = SdkPubkey::new_unique();
    let pda_key = SdkPubkey::new_unique();

    let mut holder_lamports: u64 = 1_000_000;
    let mut pda_lamports: u64 = 1_000_000;
    let mut mint_lamports: u64 = 1_000_000;
    let mut ata_lamports: u64 = 1_000_000;
    let mut slab_lamports: u64 = 1_000_000;
    let mut auth_lamports: u64 = 0;
    let mut token_lamports: u64 = 0;

    let mut holder_data: Vec<u8> = vec![];
    let mut pda_data = make_pda_data(&slab_key, &nft_mint_key);
    let mut mint_data: Vec<u8> = vec![0u8; 82];
    let mut ata_data: Vec<u8> = vec![0u8; 72];
    let mut slab_data: Vec<u8> = vec![];
    let mut auth_data: Vec<u8> = vec![];
    let mut token_data: Vec<u8> = vec![];

    let system_program_id = solana_program::system_program::id();
    let token_prog_id = Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID.to_bytes());
    let percolator_pk = Pubkey::new_from_array(PERCOLATOR_MAINNET.to_bytes());
    let prog_id_pk = Pubkey::new_from_array(program_id.to_bytes());
    let holder_pk = Pubkey::new_from_array(holder_key.to_bytes());
    let pda_pk = Pubkey::new_from_array(pda_key.to_bytes());
    let nft_mint_pk = Pubkey::new_from_array(nft_mint_key.to_bytes());
    let slab_pk = Pubkey::new_from_array(slab_key.to_bytes());
    let mint_auth_pk = Pubkey::new_from_array(mint_auth_key.to_bytes());
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

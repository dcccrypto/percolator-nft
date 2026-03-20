use percolator_nft::state::*;

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
        collateral: 100_000_000,   // 100 USDC collateral
        size: 1_000_000_000,       // 1000 USDC notional (10× leverage)
        entry_price_e6: 50_000_000_000, // $50,000 entry
        is_long: 1,
        global_funding_index_e18: 0,
        engine_off: 0,
    };
    // collateral ≠ size — using size as collateral would be 10× inflated
    assert_ne!(pd.collateral, pd.size, "collateral and size must be distinct");
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

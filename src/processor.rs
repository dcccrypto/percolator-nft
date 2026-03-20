extern crate alloc;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::{
    cpi::{read_position, verify_slab_owner},
    error::NftError,
    instruction::NftInstruction,
    state::{
        mint_authority_pda, position_nft_pda, PositionNft, MINT_AUTHORITY_SEED,
        POSITION_NFT_LEN, POSITION_NFT_MAGIC, POSITION_NFT_SEED, POSITION_NFT_VERSION,
    },
    token2022,
};

/// Main instruction router.
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let ix = NftInstruction::unpack(data)?;
    match ix {
        NftInstruction::MintPositionNft { user_idx } => {
            process_mint_position_nft(program_id, accounts, user_idx)
        }
        NftInstruction::BurnPositionNft => process_burn_position_nft(program_id, accounts),
        NftInstruction::SettleFunding => process_settle_funding(program_id, accounts),
    }
}

// ═══════════════════════════════════════════════════════════════
// Tag 0: MintPositionNft
// ═══════════════════════════════════════════════════════════════

/// Token-2022 Mint account base size (without extensions).
const MINT_BASE_SIZE: u64 = 82;
/// Type/length header for metadata extension.
const METADATA_EXTENSION_HEADER: u64 = 4; // type(2) + length(2)
/// Rough upper bound for metadata content (name + symbol + uri + fields).
/// Actual size computed per-mint based on market symbol length.
const METADATA_MAX_LEN: u64 = 512;

fn process_mint_position_nft(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    user_idx: u16,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let owner = next_account_info(accounts_iter)?;          // 0: signer, position owner
    let nft_pda = next_account_info(accounts_iter)?;        // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?;       // 2: NFT mint (writable, Token-2022)
    let owner_ata = next_account_info(accounts_iter)?;      // 3: Owner's ATA (writable)
    let slab = next_account_info(accounts_iter)?;           // 4: Slab account (read-only)
    let mint_auth = next_account_info(accounts_iter)?;      // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?;  // 6: Token-2022 program
    let ata_program = next_account_info(accounts_iter)?;    // 7: ATA program
    let system_program = next_account_info(accounts_iter)?; // 8: System program

    // ── Verify signer ──
    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── Verify slab ownership ──
    verify_slab_owner(slab)?;

    // ── Read position from slab ──
    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, user_idx)?;
    drop(slab_data);

    // ── Verify caller owns this position ──
    if position.owner != *owner.key {
        msg!("Position owner mismatch: expected {}, got {}", position.owner, owner.key);
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify position is open ──
    if position.size == 0 {
        return Err(NftError::PositionNotOpen.into());
    }

    // ── Verify PDA derivation ──
    let (expected_pda, bump) = position_nft_pda(slab.key, user_idx, program_id);
    if *nft_pda.key != expected_pda {
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Check not already minted ──
    if !nft_pda.data_is_empty() {
        return Err(NftError::NftAlreadyMinted.into());
    }

    // ── Verify mint authority PDA ──
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Create PositionNft PDA account ──
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(POSITION_NFT_LEN);
    let pda_seeds: &[&[u8]] = &[
        POSITION_NFT_SEED,
        slab.key.as_ref(),
        &user_idx.to_le_bytes(),
        &[bump],
    ];

    invoke_signed(
        &system_instruction::create_account(
            owner.key,
            nft_pda.key,
            lamports,
            POSITION_NFT_LEN as u64,
            program_id,
        ),
        &[owner.clone(), nft_pda.clone(), system_program.clone()],
        &[pda_seeds],
    )?;

    // ── Initialize PositionNft state ──
    let clock = solana_program::clock::Clock::get()?;
    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    let nft_state = bytemuck::from_bytes_mut::<PositionNft>(&mut pda_data[..POSITION_NFT_LEN]);
    nft_state.magic = POSITION_NFT_MAGIC;
    nft_state.version = POSITION_NFT_VERSION;
    nft_state.bump = bump;
    nft_state.slab = slab.key.to_bytes();
    nft_state.user_idx = user_idx;
    nft_state.nft_mint = nft_mint.key.to_bytes();
    nft_state.entry_price_e6 = position.entry_price_e6;
    nft_state.position_size = position.size;
    nft_state.is_long = position.is_long;
    nft_state.last_funding_index_e18 = position.global_funding_index_e18;
    nft_state.minted_at = clock.unix_timestamp;
    drop(pda_data);

    // ── Build metadata strings ──
    let direction = if position.is_long == 1 { "LONG" } else { "SHORT" };
    let price_whole = position.entry_price_e6 / 1_000_000;
    let price_frac = (position.entry_price_e6 % 1_000_000) / 100; // 4 decimal places

    // Name: "PERP LONG SOL @148.5000" (slab address if no symbol available)
    let slab_short = &slab.key.to_string()[..8];
    let nft_name = if price_whole > 0 {
        alloc::format!("PERP {} {} @{}.{:04}", direction, slab_short, price_whole, price_frac)
    } else {
        alloc::format!("PERP {} {}", direction, slab_short)
    };
    let nft_symbol = alloc::format!("PERP-{}", direction);

    // URI: empty for now (no off-chain metadata server yet)
    let nft_uri = "";

    // ── Create Token-2022 mint account (with metadata extension space) ──
    let mint_space = MINT_BASE_SIZE + METADATA_EXTENSION_HEADER + METADATA_MAX_LEN;
    let mint_rent = rent.minimum_balance(mint_space as usize);
    invoke(
        &system_instruction::create_account(
            owner.key,
            nft_mint.key,
            mint_rent,
            mint_space,
            &token2022::TOKEN_2022_PROGRAM_ID,
        ),
        &[owner.clone(), nft_mint.clone(), system_program.clone()],
    )?;

    // InitializeMint2 (decimals=0, authority=mint_auth PDA, no freeze)
    invoke(
        &token2022::initialize_mint2(nft_mint.key, mint_auth.key),
        &[nft_mint.clone()],
    )?;

    // ── Initialize metadata extension ──
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::initialize_token_metadata(
            nft_mint.key,
            mint_auth.key,  // update authority = mint authority PDA
            mint_auth.key,  // mint authority signs
            &nft_name,
            &nft_symbol,
            nft_uri,
        ),
        &[nft_mint.clone(), mint_auth.clone()],
        &[mint_auth_seeds],
    )?;

    // ── Create ATA for owner ──
    invoke(
        &token2022::create_associated_token_account(owner.key, owner.key, nft_mint.key),
        &[
            owner.clone(),
            owner_ata.clone(),
            owner.clone(),
            nft_mint.clone(),
            system_program.clone(),
            token_program.clone(),
            ata_program.clone(),
        ],
    )?;

    // ── Mint 1 NFT to owner's ATA ──
    invoke_signed(
        &token2022::mint_to(nft_mint.key, owner_ata.key, mint_auth.key, 1),
        &[nft_mint.clone(), owner_ata.clone(), mint_auth.clone()],
        &[mint_auth_seeds],
    )?;

    msg!("PositionNft minted: slab={}, idx={}, mint={}", slab.key, user_idx, nft_mint.key);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 1: BurnPositionNft
// ═══════════════════════════════════════════════════════════════

fn process_burn_position_nft(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let holder = next_account_info(accounts_iter)?;         // 0: signer (NFT holder)
    let nft_pda = next_account_info(accounts_iter)?;        // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?;       // 2: NFT mint (writable)
    let holder_ata = next_account_info(accounts_iter)?;     // 3: Holder's ATA (writable)
    let slab = next_account_info(accounts_iter)?;           // 4: Slab (verify)
    let _mint_auth = next_account_info(accounts_iter)?;     // 5: Mint authority PDA
    let _token_program = next_account_info(accounts_iter)?; // 6: Token-2022

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── Verify PDA state ──
    let pda_data = nft_pda.try_borrow_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    if nft_state.slab != slab.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    let user_idx = nft_state.user_idx;
    drop(pda_data);

    // ── Verify holder owns the NFT (check ATA balance) ──
    let ata_data = holder_ata.try_borrow_data()?;
    if ata_data.len() < 72 {
        return Err(NftError::NotNftHolder.into());
    }
    let amount = u64::from_le_bytes(ata_data[64..72].try_into().unwrap());
    let ata_owner = Pubkey::new_from_array(ata_data[32..64].try_into().unwrap());
    drop(ata_data);

    if amount != 1 || ata_owner != *holder.key {
        return Err(NftError::NotNftHolder.into());
    }

    // ── Burn the NFT ──
    invoke(
        &token2022::burn(holder_ata.key, nft_mint.key, holder.key, 1),
        &[holder_ata.clone(), nft_mint.clone(), holder.clone()],
    )?;

    // ── Close the PDA (return rent to holder) ──
    let dest_lamports = holder.lamports();
    let pda_lamports = nft_pda.lamports();
    **holder.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(pda_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **nft_pda.try_borrow_mut_lamports()? = 0;

    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    pda_data.fill(0);

    msg!("PositionNft burned: slab={}, idx={}", slab.key, user_idx);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 2: SettleFunding
// ═══════════════════════════════════════════════════════════════

fn process_settle_funding(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let _cranker = next_account_info(accounts_iter)?;  // 0: signer (anyone)
    let nft_pda = next_account_info(accounts_iter)?;   // 1: PositionNft PDA (writable)
    let slab = next_account_info(accounts_iter)?;      // 2: Slab (read funding index)

    verify_slab_owner(slab)?;

    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes_mut::<PositionNft>(&mut pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }

    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;
    drop(slab_data);

    nft_state.last_funding_index_e18 = position.global_funding_index_e18;

    msg!("Funding settled: slab={}, idx={}", slab.key, nft_state.user_idx);
    Ok(())
}

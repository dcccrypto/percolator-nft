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
        mint_authority_pda, position_nft_pda, verify_pda_version, PositionNft,
        MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC, POSITION_NFT_SEED,
        POSITION_NFT_VERSION,
    },
    token2022,
};

/// Main instruction router.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = NftInstruction::unpack(data)?;
    match ix {
        NftInstruction::MintPositionNft { user_idx } => {
            process_mint_position_nft(program_id, accounts, user_idx)
        }
        NftInstruction::BurnPositionNft => process_burn_position_nft(program_id, accounts),
        NftInstruction::SettleFunding => process_settle_funding(program_id, accounts),
        NftInstruction::GetPositionValue => {
            crate::valuation::process_get_position_value(program_id, accounts)
        }
        NftInstruction::ExecuteTransferHook { amount } => {
            crate::transfer_hook::process_execute(program_id, accounts, amount)
        }
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

    let owner = next_account_info(accounts_iter)?; // 0: signer, position owner
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?; // 2: NFT mint (writable, Token-2022)
    let owner_ata = next_account_info(accounts_iter)?; // 3: Owner's ATA (writable)
    let slab = next_account_info(accounts_iter)?; // 4: Slab account (read-only)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022 program
    let ata_program = next_account_info(accounts_iter)?; // 7: ATA program
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
        msg!(
            "Position owner mismatch: expected {}, got {}",
            position.owner,
            owner.key
        );
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

    // ── GH#7: Verify nft_mint is a fresh, uninitialized account ──
    // nft_mint is a caller-supplied keypair (not a PDA). Without this check an
    // attacker can front-run the mint call by pre-funding the address so that
    // our create_account CPI fails, or supply a pre-initialized mint where
    // they hold the update authority.
    // A freshly-generated keypair has zero lamports and empty data — enforce that.
    if nft_mint.lamports() != 0 || !nft_mint.data_is_empty() {
        msg!("MintPositionNft: nft_mint account is not a fresh keypair (already funded or initialized)");
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
    let direction = if position.is_long == 1 {
        "LONG"
    } else {
        "SHORT"
    };
    let price_whole = position.entry_price_e6 / 1_000_000;
    let price_frac = (position.entry_price_e6 % 1_000_000) / 100; // 4 decimal places

    // Name: "PERP LONG SOL @148.5000" (slab address if no symbol available)
    let slab_short = &slab.key.to_string()[..8];
    let nft_name = if price_whole > 0 {
        alloc::format!(
            "PERP {} {} @{}.{:04}",
            direction,
            slab_short,
            price_whole,
            price_frac
        )
    } else {
        alloc::format!("PERP {} {}", direction, slab_short)
    };
    let nft_symbol = alloc::format!("PERP-{}", direction);

    // URI: empty for now (no off-chain metadata server yet)
    let nft_uri = "";

    // ── Create Token-2022 mint account (with metadata + transfer hook extensions) ──
    let mint_space = MINT_BASE_SIZE
        + METADATA_EXTENSION_HEADER
        + METADATA_MAX_LEN
        + token2022::TRANSFER_HOOK_EXTENSION_SIZE;
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

    // Initialize TransferHook extension BEFORE InitializeMint2.
    // Our program is the transfer hook — Token-2022 will call us on every transfer.
    invoke(
        &token2022::initialize_transfer_hook(nft_mint.key, mint_auth.key, program_id),
        &[nft_mint.clone()],
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
            mint_auth.key, // update authority = mint authority PDA
            mint_auth.key, // mint authority signs
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

    msg!(
        "PositionNft minted: slab={}, idx={}, mint={}",
        slab.key,
        user_idx,
        nft_mint.key
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 1: BurnPositionNft
// ═══════════════════════════════════════════════════════════════

fn process_burn_position_nft(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let holder = next_account_info(accounts_iter)?; // 0: signer (NFT holder)
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?; // 2: NFT mint (writable)
    let holder_ata = next_account_info(accounts_iter)?; // 3: Holder's ATA (writable)
    let slab = next_account_info(accounts_iter)?; // 4: Slab (verify)
    let _mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
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
    verify_pda_version(nft_state)?;
    if nft_state.slab != slab.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    // GH#3: Verify the nft_mint account matches the mint recorded in the PDA.
    // Without this check a caller could supply a different mint (with a balance of 1)
    // to pass the ATA balance check and burn/close the wrong NFT PDA.
    if nft_state.nft_mint != nft_mint.key.to_bytes() {
        msg!("Burn rejected: nft_mint does not match PDA's recorded mint");
        return Err(NftError::InvalidNftPda.into());
    }
    let user_idx = nft_state.user_idx;
    drop(pda_data);

    // GH#1869 (PERC-8222): Verify position is fully closed before burning the NFT.
    // Without this guard an open-position NFT can be burned, orphaning the position
    // in the slab with no way to recover the collateral (unrecoverable funds).
    // We read position data directly from the slab using the CPI helper.
    verify_slab_owner(slab)?;
    {
        let slab_data = slab.try_borrow_data()?;
        let position = read_position(&slab_data, user_idx)?;
        if position.size != 0 || position.collateral != 0 {
            msg!(
                "Burn rejected: position is not fully closed (size={}, collateral={})",
                position.size,
                position.collateral,
            );
            return Err(NftError::PositionNotClosed.into());
        }
    }

    // ── Verify holder owns the NFT (check ATA balance) ──
    // GH#15 / GH#16: Verify holder_ata is owned by Token-2022 program before
    // reading raw bytes. Mirrors GH#14 fix applied to process_settle_funding().
    // Without this, a crafted 72-byte account could satisfy the balance/owner/
    // mint byte-offset checks; the burn CPI would reject it, but this adds
    // defense-in-depth and consistency across all instructions.
    if *holder_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        return Err(NftError::NotNftHolder.into());
    }
    let ata_data = holder_ata.try_borrow_data()?;
    // Token-2022 account layout (165 bytes, same offsets as SPL Token):
    //   [32..64]  owner (Pubkey)
    //   [64..72]  amount (u64 LE)
    //   [108]     state (u8: 0=uninit, 1=initialized, 2=frozen)
    if ata_data.len() < 165 {
        return Err(NftError::NotNftHolder.into());
    }
    let amount = u64::from_le_bytes(ata_data[64..72].try_into().unwrap());
    let ata_owner = Pubkey::new_from_array(ata_data[32..64].try_into().unwrap());
    // Verify account is initialized using pinocchio-token AccountState discriminants.
    // Use explicit match instead of From<u8> to avoid panic on invalid values.
    let ata_initialized = ata_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
    drop(ata_data);

    if !ata_initialized {
        return Err(NftError::NotNftHolder.into());
    }
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

fn process_settle_funding(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // GH#5 fix: SettleFunding is now restricted to the current NFT holder.
    // Previously this was permissionless, allowing any caller to snap the
    // last_funding_index to the current global value immediately before a
    // marketplace sale, wiping the seller's accrued funding claim.
    //
    // Accounts:
    //   0. `[signer]`  NFT holder (must own the NFT)
    //   1. `[writable]` PositionNft PDA
    //   2. `[]`         Slab account (read funding index)
    //   3. `[]`         Holder's ATA (proves NFT ownership)
    let holder = next_account_info(accounts_iter)?; // 0: signer — must hold the NFT
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let slab = next_account_info(accounts_iter)?; // 2: Slab (read funding index)
    let holder_ata = next_account_info(accounts_iter)?; // 3: Holder's ATA (verify balance)

    // ── Require holder to sign ──
    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // GH#14 fix: Verify holder_ata is owned by Token-2022 program before
    // trusting its byte layout. Without this, an attacker can pass a crafted
    // 72-byte account that satisfies the balance/owner/mint checks below.
    if *holder_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        return Err(NftError::NotNftHolder.into());
    }

    verify_slab_owner(slab)?;

    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes_mut::<PositionNft>(&mut pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    verify_pda_version(nft_state)?;
    if nft_state.slab != slab.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify holder owns the NFT (ATA balance = 1, owner = holder, state = initialized) ──
    // Token-2022 account layout (165 bytes, same offsets as SPL Token):
    //   [0..32]  mint (Pubkey)
    //   [32..64] owner (Pubkey)
    //   [64..72] amount (u64 LE)
    //   [108]    state (u8: use pinocchio-token AccountState discriminants)
    let ata_data = holder_ata.try_borrow_data()?;
    if ata_data.len() < 165 {
        return Err(NftError::NotNftHolder.into());
    }
    let ata_amount = u64::from_le_bytes(ata_data[64..72].try_into().unwrap());
    let ata_owner = Pubkey::new_from_array(ata_data[32..64].try_into().unwrap());
    // ATA[0..32] = mint address
    let ata_mint = Pubkey::new_from_array(ata_data[0..32].try_into().unwrap());
    // Verify initialized via pinocchio-token AccountState constant.
    let ata_initialized = ata_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
    drop(ata_data);

    if !ata_initialized {
        return Err(NftError::NotNftHolder.into());
    }
    if ata_amount != 1 || ata_owner != *holder.key {
        msg!("SettleFunding: caller does not hold the NFT");
        return Err(NftError::NotNftHolder.into());
    }
    // Verify the ATA mint matches the NFT PDA's recorded mint.
    if ata_mint.to_bytes() != nft_state.nft_mint {
        msg!("SettleFunding: ATA mint does not match PDA nft_mint");
        return Err(NftError::InvalidNftPda.into());
    }

    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;
    drop(slab_data);

    nft_state.last_funding_index_e18 = position.global_funding_index_e18;

    msg!(
        "Funding settled: slab={}, idx={}",
        slab.key,
        nft_state.user_idx
    );
    Ok(())
}

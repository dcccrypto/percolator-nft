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
/// PERC-9057: AccountType discriminator byte between base Mint data and TLV extensions.
/// Token-2022 writes this 1-byte discriminator (value 1 for Mint) at offset 82.
/// Previously omitted — worked because METADATA_MAX_LEN was a gross overestimate,
/// absorbing the 1-byte shortfall. Without this, tightening METADATA_MAX_LEN to
/// actual usage would cause MintPositionNft to fail.
const ACCOUNT_TYPE_SIZE: u64 = 1;
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

    // ── PERC-9004: Verify well-known program account keys ──
    // Without these checks, an attacker can substitute malicious programs for
    // Token-2022, ATA, or System program. While the downstream CPIs would
    // likely fail with the wrong program, checking upfront is defence-in-depth
    // and produces clearer error messages.
    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("MintPositionNft: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }
    if *ata_program.key != token2022::ATA_PROGRAM_ID {
        msg!("MintPositionNft: invalid ATA program key");
        return Err(ProgramError::IncorrectProgramId);
    }
    if *system_program.key != solana_program::system_program::id() {
        msg!("MintPositionNft: invalid system program key");
        return Err(ProgramError::IncorrectProgramId);
    }

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
    // PERC-9049: Don't log expected/actual pubkeys — leaks account relationships
    // to transaction log readers who can use this for targeted attacks.
    if position.owner != *owner.key {
        msg!("MintPositionNft: position owner mismatch");
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

    // ── PERC-9028: Verify nft_mint is a signer ──
    // nft_mint is a caller-supplied keypair that must sign the transaction
    // (required by create_account). Checking upfront gives a clear error
    // instead of a confusing system program failure message.
    if !nft_mint.is_signer {
        msg!("MintPositionNft: nft_mint must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── GH#7: Verify nft_mint is a fresh, uninitialized account ──
    if nft_mint.lamports() != 0 || !nft_mint.data_is_empty() {
        msg!("MintPositionNft: nft_mint account is not a fresh keypair (already funded or initialized)");
        return Err(NftError::NftAlreadyMinted.into());
    }

    // ── Verify mint authority PDA ──
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── PERC-9024: Verify owner_ata matches ATA derivation ──
    // Re-derive the expected ATA from (owner, nft_mint) and verify it matches
    // the passed owner_ata. Without this, an attacker can supply an arbitrary
    // token account as owner_ata — the mint CPI would succeed into a different
    // account, allowing them to claim ownership of the NFT without holding the
    // canonical ATA.
    let expected_ata = token2022::get_associated_token_address(owner.key, nft_mint.key);
    if *owner_ata.key != expected_ata {
        msg!("MintPositionNft: owner_ata does not match expected ATA derivation");
        return Err(NftError::InvalidNftPda.into());
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
    // Name: "Percolator Position — LONG/SHORT" (self-descriptive, immutable)
    let nft_name = alloc::format!("Percolator Position \u{2014} {}", direction);
    // PERC-9056: Use a constant symbol instead of direction-dependent format!().
    // "PERC-POS" is stable across transfers; direction is encoded in nft_name.
    const NFT_SYMBOL: &str = "PERC-POS";

    // URI: Empty — all position data is on-chain in PositionNft PDA
    let nft_uri = "";

    // ── Create Token-2022 mint account (with metadata + transfer hook extensions) ──
    let mint_space = MINT_BASE_SIZE
        + ACCOUNT_TYPE_SIZE
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
            NFT_SYMBOL,
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

fn process_burn_position_nft(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let holder = next_account_info(accounts_iter)?; // 0: signer (NFT holder)
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?; // 2: NFT mint (writable)
    let holder_ata = next_account_info(accounts_iter)?; // 3: Holder's ATA (writable)
    let slab = next_account_info(accounts_iter)?; // 4: Slab (verify)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── PERC-9003: Verify PDA is owned by this program ──
    // Without this check an attacker can craft a 208-byte account (owned by
    // any program) with matching magic/slab/mint bytes and pass it as nft_pda.
    // The subsequent magic and slab checks alone are insufficient because any
    // program can write those byte patterns into its own accounts.
    if nft_pda.owner != program_id {
        msg!("Burn rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ── PERC-9005: Verify Token-2022 program key ──
    // The burn CPI instruction hardcodes TOKEN_2022_PROGRAM_ID, but the
    // account_infos passed to invoke() must include the actual program.
    // Without this check an attacker could pass a fake program that accepts
    // the burn instruction but doesn't actually burn the token.
    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("BurnPositionNft: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── PERC-9005: Verify mint authority PDA ──
    let (expected_mint_auth, _) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("BurnPositionNft: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
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
    if nft_state.nft_mint != nft_mint.key.to_bytes() {
        msg!("Burn rejected: nft_mint does not match PDA's recorded mint");
        return Err(NftError::InvalidNftPda.into());
    }
    let user_idx = nft_state.user_idx;
    drop(pda_data);

    // ── PERC-9008: Verify PDA address matches expected derivation ──
    // The code checks magic, slab, and mint inside the PDA data, but never
    // verifies that nft_pda.key is the canonical PDA for (slab, user_idx).
    // Without this, any program-owned account with matching fields could be
    // substituted. The derivation check is the definitive proof of identity.
    let (expected_pda, _) = position_nft_pda(slab.key, user_idx, program_id);
    if *nft_pda.key != expected_pda {
        msg!("Burn rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }

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
    // PERC-9007: Read ATA mint field [0..32] and verify it matches the NFT mint.
    // Without this, an attacker who holds ANY Token-2022 token with balance=1
    // could pass that ATA instead of the real NFT ATA, passing the balance and
    // owner checks while burning a completely different token.
    let ata_mint = Pubkey::new_from_array(ata_data[0..32].try_into().unwrap());
    // Verify account is initialized using pinocchio-token AccountState discriminants.
    let ata_initialized = ata_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
    drop(ata_data);

    if !ata_initialized {
        return Err(NftError::NotNftHolder.into());
    }
    if amount != 1 || ata_owner != *holder.key {
        return Err(NftError::NotNftHolder.into());
    }
    if ata_mint != *nft_mint.key {
        msg!("Burn rejected: ATA mint does not match NFT mint");
        return Err(NftError::NotNftHolder.into());
    }

    // ── Burn the NFT ──
    invoke(
        &token2022::burn(holder_ata.key, nft_mint.key, holder.key, 1),
        &[holder_ata.clone(), nft_mint.clone(), holder.clone()],
    )?;

    // ── PERC-9032: Close the ATA (return rent to holder) ──
    // Without this, the empty ATA remains open with ~0.002 SOL locked.
    invoke(
        &token2022::close_account(holder_ata.key, holder.key, holder.key),
        &[holder_ata.clone(), holder.clone()],
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

    // ── PERC-9003: Verify PDA is owned by this program ──
    if nft_pda.owner != _program_id {
        msg!("SettleFunding rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
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

    // PERC-9029: Reject settling funding on a closed position (size=0).
    // A closed position has no active funding accrual. Allowing settle on a
    // closed position could overwrite the last_funding_index with the current
    // global value, erasing the funding snapshot from when the position was
    // still open — misrepresenting historical funding to downstream consumers.
    if position.size == 0 {
        msg!("SettleFunding rejected: position is closed (size=0)");
        return Err(NftError::PositionNotOpen.into());
    }

    nft_state.last_funding_index_e18 = position.global_funding_index_e18;

    msg!(
        "Funding settled: slab={}, idx={}",
        slab.key,
        nft_state.user_idx
    );
    Ok(())
}

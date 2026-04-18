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
    sysvar::{instructions as sysvar_instructions, Sysvar},
};

use crate::{
    cpi::{read_position, verify_slab_owner, PERCOLATOR_DEVNET, PERCOLATOR_MAINNET},
    error::NftError,
    instruction::NftInstruction,
    state::{
        mint_authority_pda, position_nft_pda, verify_pda_version, PositionNft,
        MINT_AUTHORITY_SEED, POSITION_NFT_LEN, POSITION_NFT_MAGIC, POSITION_NFT_SEED,
        POSITION_NFT_VERSION,
    },
    token2022,
    transfer_hook::{extra_account_metas_pda, EXECUTE_DISCRIMINATOR, EXTRA_METAS_SEED},
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
        NftInstruction::EmergencyBurn => process_emergency_burn(program_id, accounts),
    }
}

// ═══════════════════════════════════════════════════════════════
// Tag 0: MintPositionNft
// ═══════════════════════════════════════════════════════════════

/// Token-2022 Mint account base size (without extensions).
/// Token-2022 pads the 82-byte Mint struct to 165 bytes (same as token accounts)
/// before the AccountType discriminator and TLV extensions. Using 82 causes
/// InitializeMint2 to fail with InvalidAccountData because the TLV area
/// overlaps with the padded mint region.
const MINT_BASE_SIZE: u64 = 165;
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
    let extra_metas = next_account_info(accounts_iter)?; // 9: ExtraAccountMetaList PDA (writable, created)

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

    // ── 3D.1e: Verify writable accounts are actually writable ──
    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nft_mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !owner_ata.is_writable {
        return Err(ProgramError::InvalidAccountData);
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

    // ── Verify account is a User account, not an LP account ──
    // kind=0: User (trader), kind=1: LP (liquidity provider)
    // Only trading accounts should be wrapped as NFTs.
    if position.kind != 0 {
        return Err(NftError::LpAccountNotAllowed.into());
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
    nft_state.account_id = position.account_id;
    // PERC-N1: record the 32-byte position owner pubkey for v12.17 slot-reuse detection.
    // On v12.17 slabs `account_id` is always 0; `position_owner` is the live discriminator.
    nft_state.position_owner = position.owner.to_bytes();
    nft_state.entry_price_e6 = position.entry_price_e6;
    nft_state.position_size = position.size;
    nft_state.is_long = position.is_long;
    nft_state.position_basis_q = position.position_basis_q;
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

    // ── Create Token-2022 mint account (with metadata pointer + metadata + transfer hook extensions) ──
    // Allocate space for base mint + account type + 3 pre-InitializeMint2 extensions ONLY.
    // Metadata space is NOT included here — Token-2022 rejects InitializeMint2 if
    // uninitialized TLV data follows the 3 valid extensions (parses zero-padded
    // bytes as invalid extension type). Metadata will be added via
    // initialize_token_metadata which auto-reallocs the account.
    // Token-2022 InitializeMint2 requires EXACTLY getMintLen(extensions) bytes.
    // getMintLen([MetadataPointer, TransferHook, CloseAuth]) = 338.
    // Metadata is a variable-length extension — Token-2022's initialize_token_metadata
    // calls realloc() internally to grow the account. But the Solana runtime checks
    // rent-exemption AFTER the tx. So we create the account at 338 bytes but fund it
    // with enough lamports for the FINAL size (338 + metadata TLV).
    let mint_space: u64 = MINT_BASE_SIZE
        + ACCOUNT_TYPE_SIZE
        + token2022::METADATA_POINTER_EXTENSION_SIZE
        + token2022::TRANSFER_HOOK_EXTENSION_SIZE
        + token2022::MINT_CLOSE_AUTHORITY_EXTENSION_SIZE;
    // Compute final size after metadata realloc for rent calculation
    // Metadata TLV: type(2) + len(2) + update_authority(32) + mint(32)
    // + name(4+len) + symbol(4+len) + uri(4+len) + additional_metadata(4, empty vec)
    // Add 128 bytes safety buffer for Token-2022 internal padding/alignment.
    let metadata_tlv_size: usize = {
        let name_len = 4 + nft_name.len();
        let symbol_len = 4 + NFT_SYMBOL.len();
        let uri_len = 4 + nft_uri.len();
        4 + 32 + 32 + name_len + symbol_len + uri_len + 4 // +4 for empty additional_metadata vec
    };
    let final_size = mint_space as usize + metadata_tlv_size + 128;
    // Fund with rent for final_size (post-metadata-realloc) but allocate only mint_space.
    // Token-2022 initialize_token_metadata will realloc the account larger, and the
    // Solana runtime checks rent-exemption at the FINAL size after tx completes.
    let mint_rent = rent.minimum_balance(final_size);
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

    // PERC-9061: Initialize MetadataPointer extension BEFORE InitializeMint2.
    // This tells wallets/explorers where to find the embedded metadata via standard
    // Token-2022 metadata discovery. Without it, metadata is stored but invisible.
    // Self-referencing: metadata_address = mint itself (embedded metadata).
    invoke(
        &token2022::initialize_metadata_pointer(nft_mint.key, mint_auth.key, nft_mint.key),
        std::slice::from_ref(nft_mint),
    )?;

    // Initialize TransferHook extension BEFORE InitializeMint2.
    // Our program is the transfer hook — Token-2022 will call us on every transfer.
    invoke(
        &token2022::initialize_transfer_hook(nft_mint.key, mint_auth.key, program_id),
        std::slice::from_ref(nft_mint),
    )?;

    // PERC-9060: Initialize MintCloseAuthority extension BEFORE InitializeMint2.
    // This allows the burn handler to close the mint account and reclaim rent.
    // Without this extension, Token-2022 rejects CloseAccount on mint accounts.
    invoke(
        &token2022::initialize_mint_close_authority(nft_mint.key, mint_auth.key),
        std::slice::from_ref(nft_mint),
    )?;

    // InitializeMint2 (decimals=0, authority=mint_auth PDA, no freeze)
    invoke(
        &token2022::initialize_mint2(nft_mint.key, mint_auth.key),
        std::slice::from_ref(nft_mint),
    )?;

    // ── Initialize metadata extension ──
    // Token-2022 alloc_and_serialize_variable_len_extension handles realloc internally.
    // The mint was overfunded at create_account time (rent for final_size) so
    // the runtime rent-exemption check passes after Token-2022 grows the account.
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::initialize_token_metadata(
            nft_mint.key,
            mint_auth.key,
            mint_auth.key,
            &nft_name,
            NFT_SYMBOL,
            nft_uri,
        ),
        &[nft_mint.clone(), mint_auth.clone()],
        &[mint_auth_seeds],
    )?;

    // ── PERC-9024: Verify owner_ata matches expected ATA derivation ──
    // Without this, a caller can pass an arbitrary account as owner_ata.
    // The ATA program CPI would create the correct ATA anyway, but if the
    // passed account doesn't match, the mint CPI could target the wrong account.
    let expected_ata = token2022::get_associated_token_address(owner.key, nft_mint.key);
    if *owner_ata.key != expected_ata {
        msg!("MintPositionNft: owner_ata does not match expected ATA derivation");
        return Err(ProgramError::InvalidSeeds);
    }

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

    // ── PERC-9058: Revoke mint authority (supply=1 is now immutable) ──
    // Standard NFT pattern: after minting exactly 1 token, set the mint
    // authority to None so no additional tokens can ever be minted for this
    // mint, regardless of any future program logic changes.
    invoke_signed(
        &token2022::set_mint_authority_none(nft_mint.key, mint_auth.key),
        &[nft_mint.clone(), mint_auth.clone()],
        &[mint_auth_seeds],
    )?;

    // ════════════════════════════════════════════════════════════════════
    // PERC-9064: Atomic ExtraAccountMetaList PDA initialization
    //
    // Token-2022's TransferHook extension calls our `process_execute` on
    // every NFT transfer. Before invoking the hook, Token-2022 reads the
    // `ExtraAccountMetaList` PDA at `[b"extra-account-metas", mint]` to
    // discover the extra accounts the hook requires. If that PDA is absent
    // or not owned by this program, `process_execute` rejects with
    // `InvalidExtraAccountMetas` and the NFT is non-transferable.
    //
    // We create and initialize the PDA here, inline, so every minted NFT
    // is born transferable — no separate instruction to chain on the
    // client side, no race window.
    //
    // TLV layout (byte-for-byte matches upstream
    // `spl_tlv_account_resolution::state::ExtraAccountMetaList`
    // `::init::<ExecuteInstruction>`):
    //
    //   bytes  [0..8]   : EXECUTE_DISCRIMINATOR (TLV type, 8 bytes)
    //   bytes  [8..12]  : u32 LE — TLV value length = 4 + 35 * N (179 for N=5)
    //   bytes  [12..16] : u32 LE — number of entries (5)
    //   bytes  [16..16+35*N] : N × 35-byte ExtraAccountMeta entries:
    //                            [0]      : discriminator (0 = Fixed/Literal pubkey)
    //                            [1..33]  : 32-byte raw pubkey
    //                            [33]     : is_signer (u8, 0 or 1)
    //                            [34]     : is_writable (u8, 0 or 1)
    //
    // For N=5 fixed-pubkey entries, total account size = 16 + 175 = 191 bytes.
    //
    // The 5 entries correspond to `process_execute` extra account indices 5-9:
    //   [5] PositionNft PDA      — writable  (hook updates last_funding_index_e18)
    //   [6] Slab account         — read-only
    //   [7] Percolator program   — read-only (value from slab.owner, see below)
    //   [8] Mint authority PDA   — read-only
    //   [9] Instructions sysvar  — read-only (for CPI caller verification)
    //
    // Percolator program key: taken from `*slab.owner`, which is verified
    // by `verify_slab_owner` at line 106 to be either PERCOLATOR_DEVNET or
    // PERCOLATOR_MAINNET — exactly the allow-list `process_execute` enforces
    // at account index 7. Using slab.owner avoids adding an extra account
    // to the MintPositionNft ABI.
    {
        // Re-assert the slab-owner invariant LOCALLY so the TLV block's
        // security guarantee is refactor-proof: if a future edit moves the
        // extra_metas block above the top-of-handler verify_slab_owner,
        // this re-assertion still enforces the allow-list before any
        // percolator_prog bytes are written into the validation account.
        verify_slab_owner(slab)?;
        // SAFETY: verify_slab_owner above guarantees slab.owner is one of
        // {PERCOLATOR_DEVNET, PERCOLATOR_MAINNET}. Recording this pubkey
        // in the ExtraAccountMetaList means every subsequent transfer hook
        // invocation will see it at extra account index 7, matching the
        // allow-list check already enforced in process_execute.
        let percolator_prog_id: Pubkey = *slab.owner;
        debug_assert!(
            percolator_prog_id == PERCOLATOR_DEVNET
                || percolator_prog_id == PERCOLATOR_MAINNET
        );

        // Derive the canonical ExtraAccountMetaList PDA and verify the
        // caller passed the correct account.
        let (expected_extra_metas, extra_metas_bump) =
            extra_account_metas_pda(nft_mint.key, program_id);
        if *extra_metas.key != expected_extra_metas {
            msg!("MintPositionNft: extra_metas PDA does not match expected derivation");
            return Err(NftError::InvalidExtraAccountMetas.into());
        }

        // Reject re-initialization. Because `nft_mint` is enforced to be
        // a fresh keypair earlier in this handler (line 153), the PDA
        // derived from its key should always be empty. This check is
        // defense-in-depth against any future path that might reuse a
        // mint keypair.
        if extra_metas.owner == program_id && !extra_metas.data_is_empty() {
            msg!("MintPositionNft: extra_metas PDA already initialized");
            return Err(NftError::InvalidExtraAccountMetas.into());
        }

        // TLV account size constants.
        const EXTRA_META_ENTRY_LEN: usize = 35;
        const EXTRA_META_COUNT: usize = 5;
        const EXTRA_METAS_ACCOUNT_LEN: usize =
            8 /* TLV type */ + 4 /* TLV length */ + 4 /* entry count */
            + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;

        let extra_metas_seeds: &[&[u8]] = &[
            EXTRA_METAS_SEED,
            nft_mint.key.as_ref(),
            &[extra_metas_bump],
        ];

        // Grief-resistant creation: system_instruction::create_account fails
        // if the destination already has lamports (a 1-lamport airdrop on
        // the deterministic PDA address would permanently brick this mint).
        // Instead, we transfer the rent shortfall from the payer (if any),
        // then allocate and assign via signed CPIs. This sequence succeeds
        // regardless of any pre-existing lamport balance.
        let extra_metas_rent = rent.minimum_balance(EXTRA_METAS_ACCOUNT_LEN);
        let current_lamports = extra_metas.lamports();
        if current_lamports < extra_metas_rent {
            let shortfall = extra_metas_rent - current_lamports;
            invoke(
                &system_instruction::transfer(owner.key, extra_metas.key, shortfall),
                &[owner.clone(), extra_metas.clone(), system_program.clone()],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(
                extra_metas.key,
                EXTRA_METAS_ACCOUNT_LEN as u64,
            ),
            &[extra_metas.clone(), system_program.clone()],
            &[extra_metas_seeds],
        )?;
        invoke_signed(
            &system_instruction::assign(extra_metas.key, program_id),
            &[extra_metas.clone(), system_program.clone()],
            &[extra_metas_seeds],
        )?;

        // Write the TLV-encoded validation data.
        let mut data = extra_metas.try_borrow_mut_data()?;
        if data.len() != EXTRA_METAS_ACCOUNT_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // [0..8] TLV type discriminator = ExecuteInstruction's SplDiscriminate
        //        = sha256("spl-transfer-hook-interface:execute")[..8]
        //        (same constant the hook already uses to detect its
        //        top-level Execute instruction).
        data[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);

        // [8..12] u32 LE — TLV value length = entry_count(4) + entries(N*35)
        let tlv_value_len: u32 =
            (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
        data[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());

        // [12..16] u32 LE — number of entries
        data[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());

        // [16..] 35 bytes per entry, in order matching process_execute:
        //   [disc(1) = 0 (FixedPubkey) | pubkey(32) | is_signer(1) | is_writable(1)]
        let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = [
            // 5: PositionNft PDA — writable
            (*nft_pda.key, false, true),
            // 6: Slab — read-only
            (*slab.key, false, false),
            // 7: Percolator program — read-only, from verified slab.owner
            (percolator_prog_id, false, false),
            // 8: Mint authority PDA — read-only
            (*mint_auth.key, false, false),
            // 9: Instructions sysvar — read-only
            (sysvar_instructions::id(), false, false),
        ];

        for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
            let off = 16 + i * EXTRA_META_ENTRY_LEN;
            data[off] = 0; // FixedPubkey discriminator
            data[off + 1..off + 33].copy_from_slice(key.as_ref());
            data[off + 33] = if *is_signer { 1 } else { 0 };
            data[off + 34] = if *is_writable { 1 } else { 0 };
        }
    }

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

    // ── 3D.1e: Verify writable accounts are actually writable ──
    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nft_mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !holder_ata.is_writable {
        return Err(ProgramError::InvalidAccountData);
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
    let nft_account_id = nft_state.account_id;
    // PERC-N1: extract position_owner for slot-reuse check below.
    let nft_position_owner = nft_state.position_owner;
    let _ = nft_state;
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

    // GH#1869 (PERC-8222): Verify position has no open trade before burning.
    // An open-position NFT must not be burned — it would orphan the position
    // in the slab with no way to recover or manage it.
    //
    // PERC-9035: Only check size != 0 (open trade). Residual collateral
    // (size=0, collateral>0) should NOT block burn. The collateral belongs
    // to the slab position owner and can only be withdrawn via Percolator
    // directly — it is unaffected by whether the NFT PDA exists. Requiring
    // collateral==0 traps the NFT: can't transfer (size=0 fails margin
    // check), can't burn (collateral>0 fails this check), permanently stuck.
    //
    // NOTE (PERC-9060): We intentionally skip the entry_price/is_long mismatch
    // check here. Percolator zeroes entry_price_e6 when a position is closed, so
    // comparing against the PDA snapshot would always fail for legitimate burns.
    // Slot reuse is not a risk — the slot is empty, and burn destroys the PDA.
    verify_slab_owner(slab)?;
    {
        let slab_data = slab.try_borrow_data()?;
        let position = read_position(&slab_data, user_idx)?;
        // Verify account_id matches — if mismatch, the slot was reallocated to a different account
        if position.account_id != nft_account_id {
            msg!(
                "Burn rejected: account_id mismatch (stored={}, current={})",
                nft_account_id,
                position.account_id,
            );
            return Err(NftError::InvalidAccountId.into());
        }
        // PERC-N1: v12.17 slot-reuse bypass fix — verify position owner has not changed.
        // On v12.17 slabs `account_id` is always 0 so the check above is dead.
        // `position_owner` is set at mint time and is the live slot-reuse identifier.
        // MIGRATION GUARD: skip if position_owner == [0u8; 32] (pre-fix NFT minted before
        // this commit). Tagged remove-after-devnet-wipe.
        if nft_position_owner != [0u8; 32]
            && position.owner.to_bytes() != nft_position_owner
        {
            msg!("Burn rejected: position owner changed — slot reuse detected (PERC-N1)");
            return Err(NftError::SlotReused.into());
        }
        // PERC-9035: Only block burn on open trade (size != 0). Residual collateral is fine.
        if position.size != 0 {
            msg!(
                "Burn rejected: position still has open trade (size={})",
                position.size,
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
        &[holder_ata.clone(), nft_mint.clone(), holder.clone(), token_program.clone()],
    )?;

    // ���─ PERC-9032: Close the ATA (return rent to holder) ──
    // Without this, the empty ATA remains open with ~0.002 SOL locked.
    invoke(
        &token2022::close_account(holder_ata.key, holder.key, holder.key),
        &[holder_ata.clone(), holder.clone(), token_program.clone()],
    )?;

    // ── PERC-9060: Close the mint account (return rent to holder) ──
    // Supply is now 0 after burn. The MintCloseAuthority extension designates
    // mint_auth PDA as the close authority, allowing us to reclaim ~0.003-0.005 SOL.
    // Without this, mint rent is permanently locked per NFT lifecycle.
    let (_, mint_auth_bump) = mint_authority_pda(program_id);
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::close_account(nft_mint.key, holder.key, mint_auth.key),
        &[nft_mint.clone(), holder.clone(), mint_auth.clone(), token_program.clone()],
        &[mint_auth_seeds],
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
// Tag 5: EmergencyBurn
// ═══════════════════════════════════════════════════════════════

fn process_emergency_burn(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let holder = next_account_info(accounts_iter)?; // 0: signer (NFT holder)
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?; // 2: NFT mint (writable)
    let holder_ata = next_account_info(accounts_iter)?; // 3: Holder's ATA (writable)
    let slab = next_account_info(accounts_iter)?; // 4: Slab (verify liquidation)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── 3D.1d: Validate token_program key ──
    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("EmergencyBurn: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── 3D.1a: Verify PDA is owned by this program ──
    // Without this an attacker can craft a matching-magic account owned by a
    // different program and pass it as nft_pda to bypass all state checks.
    if nft_pda.owner != program_id {
        msg!("EmergencyBurn rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ── 3D.1e: Verify writable accounts are actually writable ──
    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nft_mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !holder_ata.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify mint authority PDA ──
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("EmergencyBurn: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Verify PDA state ──
    let (user_idx, nft_account_id_em, nft_mint_bytes_em) = {
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
        if nft_state.nft_mint != nft_mint.key.to_bytes() {
            msg!("EmergencyBurn rejected: nft_mint does not match PDA's recorded mint");
            return Err(NftError::InvalidNftPda.into());
        }
        (nft_state.user_idx, nft_state.account_id, nft_state.nft_mint)
        // pda_data Ref dropped here
    };

    // ── 3D.1b: Verify PDA address matches expected derivation ──
    // Even if magic/slab/mint fields match, any program-owned account at an
    // arbitrary address could be substituted without this derivation check.
    let (expected_pda, _) = position_nft_pda(slab.key, user_idx, program_id);
    if *nft_pda.key != expected_pda {
        msg!("EmergencyBurn rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Verify position is liquidated (position_basis_q == 0) ──
    // EmergencyBurn is for positions that have been liquidated on-chain.
    // BurnPositionNft requires size==0 && collateral==0 (fully closed).
    // EmergencyBurn requires position_basis_q==0 (liquidated/flat, collateral may remain).
    verify_slab_owner(slab)?;
    {
        let slab_data = slab.try_borrow_data()?;
        let position = read_position(&slab_data, user_idx)?;

        // Verify account_id matches
        if position.account_id != nft_account_id_em {
            msg!(
                "EmergencyBurn rejected: account_id mismatch (stored={}, current={})",
                nft_account_id_em,
                position.account_id,
            );
            return Err(NftError::InvalidAccountId.into());
        }

        // Position must be flat (liquidated or closed) — position_basis_q == 0
        if position.position_basis_q != 0 {
            msg!(
                "EmergencyBurn rejected: position is still open (position_basis_q={})",
                position.position_basis_q,
            );
            return Err(NftError::PositionNotClosed.into());
        }
    }

    // ── Verify holder owns the NFT ──
    if *holder_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        return Err(NftError::NotNftHolder.into());
    }
    let ata_data = holder_ata.try_borrow_data()?;
    if ata_data.len() < 165 {
        return Err(NftError::NotNftHolder.into());
    }
    let amount = u64::from_le_bytes(ata_data[64..72].try_into().unwrap());
    let ata_owner = Pubkey::new_from_array(ata_data[32..64].try_into().unwrap());
    let ata_mint = Pubkey::new_from_array(ata_data[0..32].try_into().unwrap());
    let ata_initialized = ata_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
    drop(ata_data);

    if !ata_initialized || amount != 1 || ata_owner != *holder.key || ata_mint.to_bytes() != nft_mint_bytes_em {
        return Err(NftError::NotNftHolder.into());
    }

    // ── Burn the NFT ──
    // 3D.1d: Include token_program in invoke account slice.
    invoke(
        &token2022::burn(holder_ata.key, nft_mint.key, holder.key, 1),
        &[holder_ata.clone(), nft_mint.clone(), holder.clone(), token_program.clone()],
    )?;

    // ── 3D.1c: Close the ATA (return rent to holder) ──
    invoke(
        &token2022::close_account(holder_ata.key, holder.key, holder.key),
        &[holder_ata.clone(), holder.clone(), token_program.clone()],
    )?;

    // ── 3D.1c: Close the mint account (return rent to holder) ──
    // The MintCloseAuthority extension designates mint_auth PDA as close authority.
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::close_account(nft_mint.key, holder.key, mint_auth.key),
        &[nft_mint.clone(), holder.clone(), mint_auth.clone(), token_program.clone()],
        &[mint_auth_seeds],
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

    msg!("PositionNft emergency burned: slab={}, idx={}", slab.key, user_idx);
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

    // ── PERC-9056: Verify PDA address matches expected derivation ──
    // Consistency with Mint (line 120) and Burn (line 364, PERC-9008).
    // Without this, any program-owned account with matching magic/slab fields
    // could be substituted, allowing funding state manipulation.
    let (expected_pda, _) = position_nft_pda(slab.key, nft_state.user_idx, _program_id);
    if *nft_pda.key != expected_pda {
        msg!("SettleFunding rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
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

    // Verify account_id matches — if mismatch, the slot was reallocated to a different account
    if position.account_id != nft_state.account_id {
        msg!(
            "SettleFunding rejected: account_id mismatch (stored={}, current={})",
            nft_state.account_id,
            position.account_id,
        );
        drop(slab_data);
        return Err(NftError::InvalidAccountId.into());
    }

    // PERC-N1: v12.17 slot-reuse bypass fix — verify position owner has not changed.
    // On v12.17 slabs `account_id` is always 0 so the check above is dead.
    // MIGRATION GUARD: skip if position_owner == [0u8; 32] (pre-fix NFT). Tagged remove-after-devnet-wipe.
    if nft_state.position_owner != [0u8; 32]
        && position.owner.to_bytes() != nft_state.position_owner
    {
        msg!("SettleFunding rejected: position owner changed — slot reuse detected (PERC-N1)");
        drop(slab_data);
        return Err(NftError::SlotReused.into());
    }

    drop(slab_data);

    // ── PERC-9060: Verify slab slot still matches PDA snapshot ──
    // If the original position was closed and the slab slot reused for a
    // different position, entry_price_e6 and/or is_long will differ from
    // the values snapshotted at mint time. Without this check, the NFT
    // would settle funding on a completely different position.
    if nft_state.entry_price_e6 != position.entry_price_e6
        || nft_state.is_long != position.is_long
    {
        msg!(
            "SettleFunding rejected: slab slot reuse detected (PDA snapshot does not match live position)"
        );
        return Err(NftError::PositionMismatch.into());
    }

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

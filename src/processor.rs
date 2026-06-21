extern crate alloc;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
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
    cpi_v16,
    error::NftError,
    instruction::NftInstruction,
    slab_types_v16,
    state_v16::{
        mint_authority_pda, position_nft_pda, verify_position_nft, PositionNftV16,
        MINT_AUTHORITY_SEED, POSITION_NFT_V16_LEN, POSITION_NFT_V16_MAGIC,
        POSITION_NFT_V16_VERSION, POSITION_NFT_SEED,
    },
    token2022,
    transfer_hook::{extra_account_metas_pda, EXECUTE_DISCRIMINATOR, EXTRA_METAS_SEED},
};

/// Wrapper instruction tag: B-3 `TransferPortfolioOwnership` (escrow at mint).
const TAG_B3_TRANSFER_PORTFOLIO_OWNERSHIP: u8 = 72;
/// Wrapper instruction tag: `UnwrapEscrowedPortfolio` (release escrow on burn).
const TAG_UNWRAP_ESCROWED_PORTFOLIO: u8 = 82;

/// #105 escrow-at-mint: CPI the wrapper's B-3 `TransferPortfolioOwnership`
/// (tag 72) to set `portfolio.owner = escrow_owner` (the NFT program's
/// mint-authority PDA). Called at mint to take true custody of the position.
///
/// `percolator_prog` must be the wrapper that owns the portfolio (caller checks
/// `percolator_prog.key == *portfolio.owner` after `verify_portfolio_program`).
/// The wrapper re-derives the registry + mint-authority and fail-closed-validates
/// the CPI signer, so a valid `invoke_signed` here proves this NFT program issued it.
fn cpi_escrow_portfolio<'a>(
    percolator_prog: &AccountInfo<'a>,
    mint_auth: &AccountInfo<'a>,
    portfolio: &AccountInfo<'a>,
    nft_registry: &AccountInfo<'a>,
    escrow_owner: &Pubkey,
    asset_index: u16,
    mint_auth_bump: u8,
) -> ProgramResult {
    let mut data = alloc::vec::Vec::with_capacity(35);
    data.push(TAG_B3_TRANSFER_PORTFOLIO_OWNERSHIP);
    data.extend_from_slice(escrow_owner.as_ref());
    data.extend_from_slice(&asset_index.to_le_bytes());
    let ix = Instruction {
        program_id: *percolator_prog.key,
        accounts: alloc::vec![
            AccountMeta::new_readonly(*mint_auth.key, true),
            AccountMeta::new(*portfolio.key, false),
            AccountMeta::new_readonly(*nft_registry.key, false),
        ],
        data,
    };
    let seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &ix,
        &[
            mint_auth.clone(),
            portfolio.clone(),
            nft_registry.clone(),
            percolator_prog.clone(),
        ],
        &[seeds],
    )
}

/// #105 escrow-at-mint: CPI the wrapper's `UnwrapEscrowedPortfolio` (tag 82) to
/// release escrow back to the burning holder — set `portfolio.owner = new_owner`.
/// Called by Burn/EmergencyBurn. The wrapper releases regardless of the
/// position's leg/resolved state (so the holder can always recover residual
/// collateral or a resolved payout), gated only on the escrow invariant.
fn cpi_unwrap_portfolio<'a>(
    percolator_prog: &AccountInfo<'a>,
    mint_auth: &AccountInfo<'a>,
    portfolio: &AccountInfo<'a>,
    nft_registry: &AccountInfo<'a>,
    new_owner: &Pubkey,
    mint_auth_bump: u8,
) -> ProgramResult {
    let mut data = alloc::vec::Vec::with_capacity(33);
    data.push(TAG_UNWRAP_ESCROWED_PORTFOLIO);
    data.extend_from_slice(new_owner.as_ref());
    let ix = Instruction {
        program_id: *percolator_prog.key,
        accounts: alloc::vec![
            AccountMeta::new_readonly(*mint_auth.key, true),
            AccountMeta::new(*portfolio.key, false),
            AccountMeta::new_readonly(*nft_registry.key, false),
        ],
        data,
    };
    let seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &ix,
        &[
            mint_auth.clone(),
            portfolio.clone(),
            nft_registry.clone(),
            percolator_prog.clone(),
        ],
        &[seeds],
    )
}

/// Verify a passed `percolator_prog` AccountInfo is the wrapper that owns the
/// portfolio (so a CPI to it is genuinely the trusted wrapper). Caller must
/// have already run `cpi_v16::verify_portfolio_program(portfolio)`, which
/// allowlists `portfolio.owner`.
fn verify_percolator_prog_account(
    percolator_prog: &AccountInfo,
    portfolio: &AccountInfo,
) -> ProgramResult {
    if percolator_prog.key != portfolio.owner {
        msg!("percolator_prog account is not the wrapper that owns the portfolio");
        return Err(NftError::InvalidPortfolioOwner.into());
    }
    Ok(())
}

/// Main instruction router.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = NftInstruction::unpack(data)?;
    match ix {
        NftInstruction::MintPositionNft { asset_index } => {
            process_mint_position_nft(program_id, accounts, asset_index)
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
        NftInstruction::RepairExtraMetas => process_repair_extra_metas(program_id, accounts),
    }
}

/// Returns true when `holder_ata_key` is the canonical Token-2022 ATA
/// for `holder` and `expected_mint`.
fn holder_ata_key_matches(
    holder_ata_key: &Pubkey,
    holder: &Pubkey,
    expected_mint: &Pubkey,
) -> bool {
    *holder_ata_key == token2022::get_associated_token_address(holder, expected_mint)
}

/// Verifies that `holder_ata` is the canonical Token-2022 ATA for the holder
/// and expected NFT mint, then checks the token account owner, initialized state,
/// amount, and mint fields.
fn verify_holder_ata_account(
    holder_ata: &AccountInfo,
    holder: &AccountInfo,
    expected_mint: &Pubkey,
) -> ProgramResult {
    if !holder_ata_key_matches(holder_ata.key, holder.key, expected_mint) {
        msg!("Holder ATA does not match canonical derivation");
        return Err(NftError::NotNftHolder.into());
    }

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
    let ata_initialized =
        ata_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
    drop(ata_data);

    if !ata_initialized {
        return Err(NftError::NotNftHolder.into());
    }
    if amount != 1 || ata_owner != *holder.key {
        return Err(NftError::NotNftHolder.into());
    }
    if ata_mint != *expected_mint {
        msg!("Holder ATA mint does not match expected NFT mint");
        return Err(NftError::NotNftHolder.into());
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 0: MintPositionNft
// ═══════════════════════════════════════════════════════════════

/// Token-2022 Mint account base size (without extensions).
const MINT_BASE_SIZE: u64 = 165;
/// AccountType discriminator byte between base Mint data and TLV extensions.
const ACCOUNT_TYPE_SIZE: u64 = 1;

/// percolator-prog `state::HEADER_LEN`: the 16-byte account header precedes the
/// `NftRegistryV16` POD. (Same value already used locally for RepairExtraMetas.)
const CORE_HEADER_LEN: usize = 16;
/// Minimum length of a valid NftRegistry account: 16-byte header + 72-byte POD.
const NFT_REGISTRY_ACCOUNT_LEN: usize = CORE_HEADER_LEN + 72;
/// Byte offset of `NftRegistryV16.nft_program_id` within the account
/// (POD field offset 32, after the wrapper header).
const NFT_REGISTRY_PROGRAM_ID_OFFSET: usize = CORE_HEADER_LEN + 32;

/// Panic-safe predicate for the per-market NftRegistry account: `true` iff the
/// account is long enough to be a real `NftRegistryV16` and its stored
/// `nft_program_id` equals `program_id`. Uses `get(..)` (never indexing) so a
/// short / empty / never-created account returns `false`, never panics.
///
/// Shared by `process_mint_position_nft` and its unit tests so the on-chain
/// check and the test oracle can never drift. This is exactly equivalent to the
/// core B-3 check `derive_nft_mint_authority(nft_program_id) == mint_auth`,
/// because this program's `mint_auth == find_program_address([b"mint_authority"],
/// program_id)` — the same seed the core uses under `nft_program_id`.
fn registry_registers_program(data: &[u8], program_id: &Pubkey) -> bool {
    if data.len() < NFT_REGISTRY_ACCOUNT_LEN {
        return false;
    }
    match data.get(NFT_REGISTRY_PROGRAM_ID_OFFSET..NFT_REGISTRY_PROGRAM_ID_OFFSET + 32) {
        Some(id) => id == program_id.as_ref(),
        None => false,
    }
}

fn process_mint_position_nft(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    asset_index: u16,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let owner = next_account_info(accounts_iter)?; // 0: signer, position owner
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let nft_mint = next_account_info(accounts_iter)?; // 2: NFT mint (writable, Token-2022)
    let owner_ata = next_account_info(accounts_iter)?; // 3: Owner's ATA (writable)
    let portfolio = next_account_info(accounts_iter)?; // 4: Portfolio account (writable — future B-3 CPI mutates it)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022 program
    let ata_program = next_account_info(accounts_iter)?; // 7: ATA program
    let system_program = next_account_info(accounts_iter)?; // 8: System program
    let extra_metas = next_account_info(accounts_iter)?; // 9: ExtraAccountMetaList PDA (writable, created)
    let nft_registry = next_account_info(accounts_iter)?; // 10: per-market NftRegistry PDA (read-only) — #109
    let percolator_prog = next_account_info(accounts_iter)?; // 11: percolator wrapper program (escrow CPI target) — #105

    // ── Verify well-known program account keys ──
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

    // ── Verify writable accounts are actually writable ──
    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nft_mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !owner_ata.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify portfolio ownership (fail-closed allowlist) ──
    cpi_v16::verify_portfolio_program(portfolio)?;

    // ── Decode portfolio and check mint eligibility ──
    let portfolio_data = portfolio.try_borrow_data()?;
    let p =
        slab_types_v16::decode_portfolio(&portfolio_data).map_err(cpi_v16::map_decode_err)?;

    let slot = cpi_v16::mint_leg_slot(p, &owner.key.to_bytes(), asset_index as u32)
        .map_err(ProgramError::from)?;

    let leg = &p.legs[slot];
    // Snapshot all leg fields needed before dropping the borrow.
    let snap_side = leg.side;
    let snap_basis_pos_q = leg.basis_pos_q.get();
    let snap_f_snap = leg.f_snap.get();
    let snap_market_id = leg.market_id.get();
    let snap_epoch_snap = leg.epoch_snap.get();
    let snap_owner = p.owner();
    let market_group = Pubkey::new_from_array(p.provenance_header.market_group_id);
    // The percolator program id is the wrapper that OWNS the portfolio account.
    let percolator_prog_id: Pubkey = *portfolio.owner;
    drop(portfolio_data);

    // ── #109: validate the per-market NftRegistry BEFORE any irreversible work ──
    // Previously MintPositionNft derived this PDA only to embed it in the
    // ExtraAccountMetaList; it never checked the registry exists and registers
    // THIS NFT program. The core's B-3 TransferPortfolioOwnership handler is
    // fail-closed — it derives the trusted mint authority from
    // registry.nft_program_id and rejects any mint_auth that does not match, and
    // rejects a missing/uninitialized registry outright. Because SetNftProgramId
    // is set-once/immutable, minting against an absent or foreign registry would
    // produce a permanently non-transferable NFT with no signal to the minter.
    // Validate here so mint fails fast and atomically (before any account/rent).
    {
        // (a) Pin the account to the canonical per-market PDA (the same one B-3
        //     re-derives via find_program_address under the wrapper program id).
        let (expected_registry, _) =
            cpi_v16::derive_nft_registry(&percolator_prog_id, &market_group);
        if *nft_registry.key != expected_registry {
            msg!("MintPositionNft: nft_registry is not the canonical per-market PDA (#109)");
            return Err(NftError::RegistryNotConfigured.into());
        }
        // (b) The registry must be owned by the wrapper that owns the portfolio.
        //     A never-created registry is System-owned and fails here. (a)+(b)
        //     together make the account unforgeable: only the wrapper can create
        //     a wrapper-owned account at this PDA, and it only writes a real
        //     NftRegistryV16 there.
        if *nft_registry.owner != percolator_prog_id {
            msg!("MintPositionNft: nft_registry not owned by the percolator program (#109)");
            return Err(NftError::RegistryNotConfigured.into());
        }
        // (c)+(d) Length-guarded, panic-safe read of nft_program_id; require it
        //     registers THIS NFT program (equivalent to B-3's mint-authority check).
        let registry_data = nft_registry.try_borrow_data()?;
        if !registry_registers_program(&registry_data, program_id) {
            msg!("MintPositionNft: nft_registry missing/short or registers a different NFT program (#109)");
            return Err(NftError::RegistryNotConfigured.into());
        }
    }

    // ── Verify PDA derivation (#108: keyed on market_id, not asset_index) ──
    let (expected_pda, bump) = position_nft_pda(portfolio.key, snap_market_id, program_id);
    if *nft_pda.key != expected_pda {
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Check not already minted ──
    if !nft_pda.data_is_empty() {
        return Err(NftError::NftAlreadyMinted.into());
    }

    // ── Verify nft_mint is a signer ──
    if !nft_mint.is_signer {
        msg!("MintPositionNft: nft_mint must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── Verify nft_mint is a fresh, uninitialized account ──
    if nft_mint.lamports() != 0 || !nft_mint.data_is_empty() {
        msg!("MintPositionNft: nft_mint account is not a fresh keypair (already funded or initialized)");
        return Err(NftError::NftAlreadyMinted.into());
    }

    // ── Verify mint authority PDA ──
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Verify owner_ata matches ATA derivation ──
    let expected_ata = token2022::get_associated_token_address(owner.key, nft_mint.key);
    if *owner_ata.key != expected_ata {
        msg!("MintPositionNft: owner_ata does not match expected ATA derivation");
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Create PositionNft PDA account ──
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(POSITION_NFT_V16_LEN);
    let market_id_le = snap_market_id.to_le_bytes();
    let pda_seeds: &[&[u8]] = &[
        POSITION_NFT_SEED,
        portfolio.key.as_ref(),
        &market_id_le,
        &[bump],
    ];

    invoke_signed(
        &system_instruction::create_account(
            owner.key,
            nft_pda.key,
            lamports,
            POSITION_NFT_V16_LEN as u64,
            program_id,
        ),
        &[owner.clone(), nft_pda.clone(), system_program.clone()],
        &[pda_seeds],
    )?;

    // ── Initialize PositionNftV16 state ──
    let clock = solana_program::clock::Clock::get()?;
    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    let nft_state =
        bytemuck::from_bytes_mut::<PositionNftV16>(&mut pda_data[..POSITION_NFT_V16_LEN]);
    nft_state.magic = slab_types_v16::V16PodU64::new(POSITION_NFT_V16_MAGIC);
    nft_state.version = POSITION_NFT_V16_VERSION;
    nft_state.bump = bump;
    nft_state.portfolio_account = portfolio.key.to_bytes();
    nft_state.nft_mint = nft_mint.key.to_bytes();
    nft_state.asset_index = slab_types_v16::V16PodU32::new(asset_index as u32);
    nft_state.side_at_mint = snap_side;
    nft_state.basis_pos_q_at_mint = slab_types_v16::V16PodI128::new(snap_basis_pos_q);
    nft_state.f_snap_at_mint = slab_types_v16::V16PodI128::new(snap_f_snap);
    nft_state.market_id_at_mint = slab_types_v16::V16PodU64::new(snap_market_id);
    nft_state.epoch_snap_at_mint = slab_types_v16::V16PodU64::new(snap_epoch_snap);
    nft_state.position_owner_at_mint = snap_owner;
    nft_state.minted_at = slab_types_v16::V16PodI64::new(clock.unix_timestamp);
    drop(pda_data);

    // ── Build metadata strings ──
    let direction = if snap_side == 0 { "LONG" } else { "SHORT" };
    let nft_name = alloc::format!("Percolator Position \u{2014} {}", direction);
    const NFT_SYMBOL: &str = "PERC-POS";
    let nft_uri = "";

    // ── Create Token-2022 mint account ──
    let mint_space: u64 = MINT_BASE_SIZE
        + ACCOUNT_TYPE_SIZE
        + token2022::METADATA_POINTER_EXTENSION_SIZE
        + token2022::TRANSFER_HOOK_EXTENSION_SIZE
        + token2022::MINT_CLOSE_AUTHORITY_EXTENSION_SIZE;
    let metadata_tlv_size: usize = {
        let name_len = 4 + nft_name.len();
        let symbol_len = 4 + NFT_SYMBOL.len();
        let uri_len = 4 + nft_uri.len();
        4 + 32 + 32 + name_len + symbol_len + uri_len + 4
    };
    let final_size = mint_space as usize + metadata_tlv_size + 128;
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

    invoke(
        &token2022::initialize_metadata_pointer(nft_mint.key, mint_auth.key, nft_mint.key),
        std::slice::from_ref(nft_mint),
    )?;

    invoke(
        &token2022::initialize_transfer_hook(nft_mint.key, mint_auth.key, program_id),
        std::slice::from_ref(nft_mint),
    )?;

    invoke(
        &token2022::initialize_mint_close_authority(nft_mint.key, mint_auth.key),
        std::slice::from_ref(nft_mint),
    )?;

    invoke(
        &token2022::initialize_mint2(nft_mint.key, mint_auth.key),
        std::slice::from_ref(nft_mint),
    )?;

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

    // ── Re-check owner_ata derivation ──
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

    // ── Revoke mint authority (supply=1 is now immutable) ──
    invoke_signed(
        &token2022::set_mint_authority_none(nft_mint.key, mint_auth.key),
        &[nft_mint.clone(), mint_auth.clone()],
        &[mint_auth_seeds],
    )?;

    // ════════════════════════════════════════════════════════════════════
    // Atomic ExtraAccountMetaList PDA initialization
    //
    // TLV layout (7 entries):
    //   [5] PositionNft PDA        — writable  (hook updates f_snap_at_mint)
    //   [6] Portfolio account      — WRITABLE  (B-3 CPI mutates portfolio.owner)
    //   [7] Percolator program     — read-only (from portfolio.owner, allowlist-verified)
    //   [8] Mint authority PDA     — read-only
    //   [9] Instructions sysvar    — read-only
    //  [10] NFT program (self)     — read-only
    //  [11] NFT registry PDA       — read-only (per-market; derived under wrapper_program_id)
    // ════════════════════════════════════════════════════════════════════
    {
        // Re-assert portfolio ownership so this block's security guarantee is
        // refactor-proof: if a future edit moves this block above the top-of-handler
        // verify_portfolio_program, this re-assertion still enforces the allowlist.
        cpi_v16::verify_portfolio_program(portfolio)?;
        // SAFETY: verify_portfolio_program above guarantees portfolio.owner is one of
        // {PERCOLATOR_DEVNET, PERCOLATOR_MAINNET}.
        debug_assert!(
            percolator_prog_id == cpi_v16::PERCOLATOR_DEVNET
                || percolator_prog_id == cpi_v16::PERCOLATOR_MAINNET
        );

        // Derive the per-market NFT registry PDA under the wrapper program id.
        // The wrapper's B-3 re-derives the same PDA and validates the account.
        let (registry_pda, _) = cpi_v16::derive_nft_registry(&percolator_prog_id, &market_group);

        let (expected_extra_metas, extra_metas_bump) =
            extra_account_metas_pda(nft_mint.key, program_id);
        if *extra_metas.key != expected_extra_metas {
            msg!("MintPositionNft: extra_metas PDA does not match expected derivation");
            return Err(NftError::InvalidExtraAccountMetas.into());
        }

        if extra_metas.owner == program_id && !extra_metas.data_is_empty() {
            msg!("MintPositionNft: extra_metas PDA already initialized");
            return Err(NftError::InvalidExtraAccountMetas.into());
        }

        const EXTRA_META_ENTRY_LEN: usize = 35;
        const EXTRA_META_COUNT: usize = 7;
        const EXTRA_METAS_ACCOUNT_LEN: usize =
            8 /* TLV type */ + 4 /* TLV length */ + 4 /* entry count */
            + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;

        let extra_metas_seeds: &[&[u8]] = &[
            EXTRA_METAS_SEED,
            nft_mint.key.as_ref(),
            &[extra_metas_bump],
        ];

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

        let mut data = extra_metas.try_borrow_mut_data()?;
        if data.len() != EXTRA_METAS_ACCOUNT_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);

        let tlv_value_len: u32 =
            (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
        data[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());
        data[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());

        let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = [
            // 5: PositionNft PDA — writable (hook updates f_snap_at_mint on transfer)
            (*nft_pda.key, false, true),
            // 6: Portfolio account — WRITABLE (B-3 CPI mutates portfolio.owner)
            (*portfolio.key, false, true),
            // 7: Percolator program — read-only, from verified portfolio.owner
            (percolator_prog_id, false, false),
            // 8: Mint authority PDA — read-only
            (*mint_auth.key, false, false),
            // 9: Instructions sysvar — read-only
            (sysvar_instructions::id(), false, false),
            // 10: NFT program (self) — read-only
            (*program_id, false, false),
            // 11: Per-market NFT registry PDA — read-only, derived under wrapper_program_id
            (registry_pda, false, false),
        ];

        for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
            let off = 16 + i * EXTRA_META_ENTRY_LEN;
            data[off] = 0; // FixedPubkey discriminator
            data[off + 1..off + 33].copy_from_slice(key.as_ref());
            data[off + 33] = if *is_signer { 1 } else { 0 };
            data[off + 34] = if *is_writable { 1 } else { 0 };
        }
    }

    // ── #105 escrow-at-mint: take TRUE custody of the position ───────────────
    // Transfer portfolio ownership to this NFT program's mint-authority PDA so
    // the minter can no longer operate the position directly while it is wrapped
    // (trade / reduce / close / withdraw). The position is RELEASED back to the
    // holder only when the NFT is burned (Burn/EmergencyBurn →
    // UnwrapEscrowedPortfolio). This closes the pre-first-transfer drain window:
    // a buyer of the NFT can no longer be handed a position the seller drained.
    // verify_portfolio_program(portfolio) ran at the top (and again above); pin
    // the passed wrapper program to portfolio.owner before CPIing into it.
    verify_percolator_prog_account(percolator_prog, portfolio)?;
    cpi_escrow_portfolio(
        percolator_prog,
        mint_auth,
        portfolio,
        nft_registry,
        mint_auth.key, // escrow owner == this NFT program's mint-authority PDA
        asset_index,
        mint_auth_bump,
    )?;

    msg!(
        "PositionNft minted + escrowed: portfolio={}, asset_index={}, mint={}",
        portfolio.key,
        asset_index,
        nft_mint.key
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
// #102: close the Token-2022 ExtraAccountMetaList PDA on burn.
//
// MintPositionNft creates a program-owned `extra_metas` PDA (seeds:
// [b"extra-account-metas", nft_mint]) that the TransferHook runtime requires
// for the mint's lifetime. Once the NFT is burned and its mint closed, that PDA
// is orphaned — no later instruction can reference the (now-closed) mint to
// derive it — permanently leaking its rent (~0.00207 SOL per NFT). Closing it
// as part of burn returns that rent to the holder. The PDA is program-owned, so
// it is drained directly (same lamport-transfer pattern as the PositionNft PDA
// close); no signer/CPI is needed. Idempotent: if the account was never created
// or is already closed, it is skipped so the burn never fails on it.
fn close_extra_metas(
    program_id: &Pubkey,
    extra_metas: &AccountInfo,
    nft_mint: &Pubkey,
    holder: &AccountInfo,
) -> ProgramResult {
    let (expected, _) = extra_account_metas_pda(nft_mint, program_id);
    if *extra_metas.key != expected {
        msg!("Burn rejected: extra_metas PDA does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }
    // Never-created / already-closed → nothing to reclaim; don't fail the burn.
    if extra_metas.owner != program_id || extra_metas.data_is_empty() {
        return Ok(());
    }
    if !extra_metas.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let dest = holder.lamports();
    let amt = extra_metas.lamports();
    **holder.try_borrow_mut_lamports()? = dest
        .checked_add(amt)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **extra_metas.try_borrow_mut_lamports()? = 0;
    extra_metas.try_borrow_mut_data()?.fill(0);
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
    let portfolio = next_account_info(accounts_iter)?; // 4: Portfolio account (writable — #105 unwrap CPI)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022
    let extra_metas = next_account_info(accounts_iter)?; // 7: ExtraAccountMetaList PDA (writable, closed) — #102
    let nft_registry = next_account_info(accounts_iter)?; // 8: per-market NftRegistry PDA (read-only) — #105
    let percolator_prog = next_account_info(accounts_iter)?; // 9: percolator wrapper program (unwrap CPI target) — #105

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !nft_mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !holder_ata.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    if !portfolio.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify PDA is owned by this program ──
    if nft_pda.owner != program_id {
        msg!("Burn rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("BurnPositionNft: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }

    // ── Verify mint authority PDA ──
    let (expected_mint_auth, _) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("BurnPositionNft: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Read and validate PositionNftV16 state ──
    let pda_data = nft_pda.try_borrow_data()?;
    if pda_data.len() < POSITION_NFT_V16_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state =
        bytemuck::from_bytes::<PositionNftV16>(&pda_data[..POSITION_NFT_V16_LEN]);
    verify_position_nft(nft_state)?;
    if nft_state.portfolio_account != portfolio.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    if nft_state.nft_mint != nft_mint.key.to_bytes() {
        msg!("Burn rejected: nft_mint does not match PDA's recorded mint");
        return Err(NftError::InvalidNftPda.into());
    }
    let asset_index_u16 = nft_state.asset_index.get() as u16;
    let market_id_at_mint = nft_state.market_id_at_mint.get();
    // Take a copy for the slot-reuse check below.
    let nft_state_copy = *nft_state;
    drop(pda_data);

    // ── Verify PDA address matches expected derivation (#108: market_id) ──
    let (expected_pda, _) =
        position_nft_pda(portfolio.key, market_id_at_mint, program_id);
    if *nft_pda.key != expected_pda {
        msg!("Burn rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }

    // ── v16 slot-reuse check via verify_bound_leg (market_id anchor) ──
    // v16 Burn semantics: does NOT require position be closed (no size==0 gate).
    // verify_bound_leg is the gate: LegNotActive means holder must use EmergencyBurn.
    cpi_v16::verify_portfolio_program(portfolio)?;
    {
        let portfolio_data = portfolio.try_borrow_data()?;
        let p = slab_types_v16::decode_portfolio(&portfolio_data)
            .map_err(cpi_v16::map_decode_err)?;
        let _slot = cpi_v16::verify_bound_leg(p, &nft_state_copy)
            .map_err(ProgramError::from)?;
    }

    // ── Verify holder owns the NFT via the canonical Token-2022 ATA ──
    verify_holder_ata_account(holder_ata, holder, nft_mint.key)?;

    // ── Burn the NFT ──
    invoke(
        &token2022::burn(holder_ata.key, nft_mint.key, holder.key, 1),
        &[
            holder_ata.clone(),
            nft_mint.clone(),
            holder.clone(),
            token_program.clone(),
        ],
    )?;

    // ── #105 escrow-at-mint: release the escrow back to the holder ───────────
    // The NFT is now destroyed; return portfolio ownership to the burning holder
    // so they regain direct control of the position. UnwrapEscrowedPortfolio
    // releases regardless of the position's leg/resolved state.
    let (_, mint_auth_bump) = mint_authority_pda(program_id);
    verify_percolator_prog_account(percolator_prog, portfolio)?;
    cpi_unwrap_portfolio(
        percolator_prog,
        mint_auth,
        portfolio,
        nft_registry,
        holder.key,
        mint_auth_bump,
    )?;

    // ── Close the ATA (return rent to holder) ──
    invoke(
        &token2022::close_account(holder_ata.key, holder.key, holder.key),
        &[holder_ata.clone(), holder.clone(), token_program.clone()],
    )?;

    // ── Close the mint account (return rent to holder) ──
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::close_account(nft_mint.key, holder.key, mint_auth.key),
        &[
            nft_mint.clone(),
            holder.clone(),
            mint_auth.clone(),
            token_program.clone(),
        ],
        &[mint_auth_seeds],
    )?;

    // ── Close the PDA (return rent to holder) ──
    let dest_lamports = holder.lamports();
    let pda_lamports = nft_pda.lamports();
    **holder.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(pda_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **nft_pda.try_borrow_mut_lamports()? = 0;

    {
        let mut pda_data = nft_pda.try_borrow_mut_data()?;
        pda_data.fill(0);
    }

    // ── #102: close the ExtraAccountMetaList PDA (return rent to holder) ──
    close_extra_metas(program_id, extra_metas, nft_mint.key, holder)?;

    msg!(
        "PositionNft burned: portfolio={}, asset_index={}",
        portfolio.key,
        asset_index_u16
    );
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
    let portfolio = next_account_info(accounts_iter)?; // 4: Portfolio account (writable — #105 unwrap CPI)
    let mint_auth = next_account_info(accounts_iter)?; // 5: Mint authority PDA
    let token_program = next_account_info(accounts_iter)?; // 6: Token-2022
    let extra_metas = next_account_info(accounts_iter)?; // 7: ExtraAccountMetaList PDA (writable, closed) — #102
    let nft_registry = next_account_info(accounts_iter)?; // 8: per-market NftRegistry PDA (read-only) — #105
    let percolator_prog = next_account_info(accounts_iter)?; // 9: percolator wrapper program (unwrap CPI target) — #105

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !portfolio.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("EmergencyBurn: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }

    if nft_pda.owner != program_id {
        msg!("EmergencyBurn rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

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

    // ── Read and validate PositionNftV16 state ──
    let (asset_index_u16, market_id_at_mint, nft_state_copy) = {
        let pda_data = nft_pda.try_borrow_data()?;
        if pda_data.len() < POSITION_NFT_V16_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state =
            bytemuck::from_bytes::<PositionNftV16>(&pda_data[..POSITION_NFT_V16_LEN]);
        verify_position_nft(nft_state)?;
        if nft_state.portfolio_account != portfolio.key.to_bytes() {
            return Err(ProgramError::InvalidAccountData);
        }
        if nft_state.nft_mint != nft_mint.key.to_bytes() {
            msg!("EmergencyBurn rejected: nft_mint does not match PDA's recorded mint");
            return Err(NftError::InvalidNftPda.into());
        }
        (
        nft_state.asset_index.get() as u16,
        nft_state.market_id_at_mint.get(),
        *nft_state,
    )
    };

    // ── Verify PDA address matches expected derivation (#108: market_id) ──
    let (expected_pda, _) =
        position_nft_pda(portfolio.key, market_id_at_mint, program_id);
    if *nft_pda.key != expected_pda {
        msg!("EmergencyBurn rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Check emergency burn eligibility (position flat / no active leg) ──
    cpi_v16::verify_portfolio_program(portfolio)?;
    {
        let portfolio_data = portfolio.try_borrow_data()?;
        let p = slab_types_v16::decode_portfolio(&portfolio_data)
            .map_err(cpi_v16::map_decode_err)?;
        cpi_v16::emergency_burn_ok(p, &nft_state_copy)
            .map_err(ProgramError::from)?;
    }

    // ── Verify holder owns the NFT via the canonical Token-2022 ATA ──
    verify_holder_ata_account(holder_ata, holder, nft_mint.key)?;

    // ── Burn the NFT ──
    invoke(
        &token2022::burn(holder_ata.key, nft_mint.key, holder.key, 1),
        &[
            holder_ata.clone(),
            nft_mint.clone(),
            holder.clone(),
            token_program.clone(),
        ],
    )?;

    // ── #105 escrow-at-mint: release the escrow back to the holder ───────────
    // EmergencyBurn handles closed / flat / slot-reused positions; the portfolio
    // is still escrowed to this NFT program's PDA from mint, so return ownership
    // to the burning holder. UnwrapEscrowedPortfolio is deliberately not gated on
    // leg/resolved state, so residual collateral / resolved payouts remain
    // recoverable by the holder via their own owner-gated calls afterwards.
    verify_percolator_prog_account(percolator_prog, portfolio)?;
    cpi_unwrap_portfolio(
        percolator_prog,
        mint_auth,
        portfolio,
        nft_registry,
        holder.key,
        mint_auth_bump,
    )?;

    invoke(
        &token2022::close_account(holder_ata.key, holder.key, holder.key),
        &[holder_ata.clone(), holder.clone(), token_program.clone()],
    )?;

    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::close_account(nft_mint.key, holder.key, mint_auth.key),
        &[
            nft_mint.clone(),
            holder.clone(),
            mint_auth.clone(),
            token_program.clone(),
        ],
        &[mint_auth_seeds],
    )?;

    // ── Close the PDA (return rent to holder) ──
    let dest_lamports = holder.lamports();
    let pda_lamports = nft_pda.lamports();
    **holder.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(pda_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **nft_pda.try_borrow_mut_lamports()? = 0;

    {
        let mut pda_data = nft_pda.try_borrow_mut_data()?;
        pda_data.fill(0);
    }

    // ── #102: close the ExtraAccountMetaList PDA (return rent to holder) ──
    close_extra_metas(program_id, extra_metas, nft_mint.key, holder)?;

    msg!(
        "PositionNft emergency burned: portfolio={}, asset_index={}",
        portfolio.key,
        asset_index_u16
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 2: SettleFunding
// ═══════════════════════════════════════════════════════════════

fn process_settle_funding(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let holder = next_account_info(accounts_iter)?; // 0: signer — must hold the NFT
    let nft_pda = next_account_info(accounts_iter)?; // 1: PositionNft PDA (writable)
    let portfolio = next_account_info(accounts_iter)?; // 2: Portfolio account
    let holder_ata = next_account_info(accounts_iter)?; // 3: Holder's ATA (verify balance)

    if !holder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if *holder_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        return Err(NftError::NotNftHolder.into());
    }

    if nft_pda.owner != program_id {
        msg!("SettleFunding rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    cpi_v16::verify_portfolio_program(portfolio)?;

    let mut pda_data = nft_pda.try_borrow_mut_data()?;
    if pda_data.len() < POSITION_NFT_V16_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state =
        bytemuck::from_bytes_mut::<PositionNftV16>(&mut pda_data[..POSITION_NFT_V16_LEN]);
    verify_position_nft(nft_state)?;
    if nft_state.portfolio_account != portfolio.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Verify PDA address matches expected derivation (#108: market_id) ──
    let asset_index_u16 = nft_state.asset_index.get() as u16;
    let market_id_at_mint = nft_state.market_id_at_mint.get();
    let (expected_pda, _) = position_nft_pda(portfolio.key, market_id_at_mint, program_id);
    if *nft_pda.key != expected_pda {
        msg!("SettleFunding rejected: PDA address does not match expected derivation");
        return Err(NftError::InvalidNftPda.into());
    }

    // ── Verify holder owns the NFT via the canonical Token-2022 ATA ──
    let expected_nft_mint = Pubkey::new_from_array(nft_state.nft_mint);
    verify_holder_ata_account(holder_ata, holder, &expected_nft_mint)?;

    // Take snapshot of nft_state fields needed for the leg check (cannot hold
    // nft_state borrow while borrowing portfolio_data since both are mut).
    let nft_state_copy = *nft_state;

    // ── v16 slot-reuse check + update f_snap ──
    let portfolio_data = portfolio.try_borrow_data()?;
    let p = slab_types_v16::decode_portfolio(&portfolio_data)
        .map_err(cpi_v16::map_decode_err)?;
    let slot = cpi_v16::verify_bound_leg(p, &nft_state_copy)
        .map_err(ProgramError::from)?;

    // Update f_snap snapshot to current leg value.
    let new_f_snap = p.legs[slot].f_snap;
    drop(portfolio_data);

    // Write back — nft_state is still live via pda_data (mut borrow held).
    nft_state.f_snap_at_mint = new_f_snap;

    msg!(
        "Funding settled: portfolio={}, asset_index={}",
        portfolio.key,
        asset_index_u16
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tag 6: RepairExtraAccountMetas
// ═══════════════════════════════════════════════════════════════

/// Rewrite the ExtraAccountMetaList PDA for an existing NFT mint.
///
/// Permissionless: data written is fully determined by on-chain state
/// (portfolio key + percolator-prog id via portfolio.owner).
fn process_repair_extra_metas(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let payer = next_account_info(accounts_iter)?; // 0: signer, writable
    let extra_metas = next_account_info(accounts_iter)?; // 1: writable
    let nft_mint = next_account_info(accounts_iter)?; // 2: PDA seed input
    let nft_pda = next_account_info(accounts_iter)?; // 3: position NFT PDA
    let portfolio = next_account_info(accounts_iter)?; // 4: portfolio account (read-only, for keys)
    let mint_auth = next_account_info(accounts_iter)?; // 5: mint auth PDA
    let system_program = next_account_info(accounts_iter)?; // 6: system program

    if !payer.is_signer {
        msg!("RepairExtraMetas: payer must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !extra_metas.is_writable {
        msg!("RepairExtraMetas: extra_metas must be writable");
        return Err(ProgramError::InvalidAccountData);
    }
    if *system_program.key != solana_program::system_program::id() {
        msg!("RepairExtraMetas: invalid system program");
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_extra_metas, _bump) = extra_account_metas_pda(nft_mint.key, program_id);
    if *extra_metas.key != expected_extra_metas {
        msg!("RepairExtraMetas: extra_metas PDA does not match derivation");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }
    if extra_metas.owner != program_id {
        msg!("RepairExtraMetas: extra_metas PDA not owned by this program");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }

    // Verify nft_pda is this program's PositionNftV16 state account.
    if nft_pda.owner != program_id {
        msg!("RepairExtraMetas: nft_pda not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }
    let market_id_at_mint;
    {
        let nft_state_data = nft_pda.try_borrow_data()?;
        if nft_state_data.len() < POSITION_NFT_V16_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state =
            bytemuck::from_bytes::<PositionNftV16>(&nft_state_data[..POSITION_NFT_V16_LEN]);
        verify_position_nft(nft_state)?;
        if nft_state.portfolio_account != portfolio.key.to_bytes() {
            msg!("RepairExtraMetas: nft_pda.portfolio_account does not match portfolio account");
            return Err(NftError::InvalidNftPda.into());
        }
        if nft_state.nft_mint != nft_mint.key.to_bytes() {
            msg!("RepairExtraMetas: nft_pda.nft_mint does not match nft_mint account");
            return Err(NftError::InvalidNftPda.into());
        }
        market_id_at_mint = nft_state.market_id_at_mint.get();
        // Verify canonical PDA derivation (#108: market_id, not asset_index).
        let (expected_pda, _) = position_nft_pda(portfolio.key, market_id_at_mint, program_id);
        if *nft_pda.key != expected_pda {
            msg!("RepairExtraMetas: nft_pda does not match canonical derivation");
            return Err(NftError::InvalidNftPda.into());
        }
    }

    // Percolator program id from portfolio.owner (allowlist-verified).
    cpi_v16::verify_portfolio_program(portfolio)?;
    let percolator_prog_id = *portfolio.owner;

    // Decode portfolio to read market_group_id for the registry PDA derivation.
    let market_group: Pubkey = {
        let portfolio_data = portfolio.try_borrow_data()?;
        let p = slab_types_v16::decode_portfolio(&portfolio_data)
            .map_err(cpi_v16::map_decode_err)?;
        Pubkey::new_from_array(p.provenance_header.market_group_id)
    };

    // Derive the per-market NFT registry PDA under the wrapper program id.
    let (registry_pda, _) = cpi_v16::derive_nft_registry(&percolator_prog_id, &market_group);

    // mint_auth is validated as a canonical PDA of this program.
    let (expected_mint_auth, _) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("RepairExtraMetas: mint_auth PDA does not match derivation");
        return Err(NftError::InvalidMintAuthority.into());
    }

    const EXTRA_META_ENTRY_LEN: usize = 35;
    const EXTRA_META_COUNT: usize = 7;
    const HEADER_LEN: usize = 16;
    const EXTRA_METAS_ACCOUNT_LEN: usize =
        HEADER_LEN + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;

    let mut data = extra_metas.try_borrow_mut_data()?;
    if data.len() < EXTRA_METAS_ACCOUNT_LEN {
        drop(data);
        let rent = Rent::get()?;
        let needed = rent.minimum_balance(EXTRA_METAS_ACCOUNT_LEN);
        let current = extra_metas.lamports();
        if needed > current {
            let top_up = needed - current;
            invoke(
                &system_instruction::transfer(payer.key, extra_metas.key, top_up),
                &[payer.clone(), extra_metas.clone(), system_program.clone()],
            )?;
        }
        extra_metas.resize(EXTRA_METAS_ACCOUNT_LEN)?;
        data = extra_metas.try_borrow_mut_data()?;
    }

    data[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);
    let tlv_value_len: u32 = (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
    data[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());
    data[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());

    let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = [
        (*nft_pda.key, false, true),                     // 5: PositionNft PDA — writable
        (*portfolio.key, false, true),                   // 6: Portfolio account — WRITABLE (B-3 CPI)
        (percolator_prog_id, false, false),              // 7: Percolator program — read-only
        (*mint_auth.key, false, false),                  // 8: Mint authority PDA — read-only
        (sysvar_instructions::id(), false, false),       // 9: Instructions sysvar — read-only
        (*program_id, false, false),                     // 10: NFT program (self) — read-only
        (registry_pda, false, false),                    // 11: Per-market NFT registry PDA — read-only
    ];
    for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
        let off = HEADER_LEN + i * EXTRA_META_ENTRY_LEN;
        data[off] = 0;
        data[off + 1..off + 33].copy_from_slice(key.as_ref());
        data[off + 33] = if *is_signer { 1 } else { 0 };
        data[off + 34] = if *is_writable { 1 } else { 0 };
    }

    msg!(
        "RepairExtraMetas: rewrote ExtraAccountMetaList for mint {} (portfolio now writable)",
        nft_mint.key
    );
    Ok(())
}

#[cfg(test)]
mod holder_ata_canonical_tests {
    use super::*;

    #[test]
    fn holder_ata_key_guard_rejects_non_canonical_token_account() {
        let holder = Pubkey::new_from_array([7u8; 32]);
        let nft_mint = Pubkey::new_from_array([9u8; 32]);
        let canonical_ata = token2022::get_associated_token_address(&holder, &nft_mint);
        let non_canonical_token_account = Pubkey::new_from_array([3u8; 32]);

        assert!(holder_ata_key_matches(&canonical_ata, &holder, &nft_mint));
        assert!(
            !holder_ata_key_matches(&non_canonical_token_account, &holder, &nft_mint),
            "holder-only paths must reject non-canonical token accounts even when the token account data has amount=1, owner=holder, and mint=nft_mint"
        );
    }
}

#[cfg(test)]
mod registry_validation_tests {
    use super::*;

    /// Build an 88-byte registry image like the core `SetNftProgramId` writes:
    /// `nft_program_id` at account offset `CORE_HEADER_LEN + 32` (= 48).
    fn registry_image(nft_program_id: &Pubkey) -> [u8; NFT_REGISTRY_ACCOUNT_LEN] {
        let mut d = [0u8; NFT_REGISTRY_ACCOUNT_LEN];
        d[NFT_REGISTRY_PROGRAM_ID_OFFSET..NFT_REGISTRY_PROGRAM_ID_OFFSET + 32]
            .copy_from_slice(nft_program_id.as_ref());
        d
    }

    #[test]
    fn offsets_match_core_nft_registry_layout() {
        // percolator-prog: HEADER_LEN=16, NftRegistryV16.nft_program_id at POD
        // offset 32, POD size 72 → account offset 48, account len 88.
        assert_eq!(CORE_HEADER_LEN, 16);
        assert_eq!(NFT_REGISTRY_PROGRAM_ID_OFFSET, 48);
        assert_eq!(NFT_REGISTRY_ACCOUNT_LEN, 88);
    }

    #[test]
    fn accepts_registry_that_registers_this_program() {
        let me = Pubkey::new_from_array([5u8; 32]);
        assert!(registry_registers_program(&registry_image(&me), &me));
    }

    #[test]
    fn rejects_registry_that_registers_a_different_program() {
        let me = Pubkey::new_from_array([5u8; 32]);
        let other = Pubkey::new_from_array([6u8; 32]);
        assert!(
            !registry_registers_program(&registry_image(&other), &me),
            "a registry bound to a different NFT program must be rejected at mint (#109)"
        );
    }

    #[test]
    fn rejects_short_or_empty_registry_without_panic() {
        let me = Pubkey::new_from_array([5u8; 32]);
        let full = registry_image(&me);
        // Empty (never-created / System-owned 0-byte), header-only, and one byte
        // short of a full registry must all reject — and must NOT panic.
        assert!(!registry_registers_program(&[], &me));
        assert!(!registry_registers_program(&full[..CORE_HEADER_LEN], &me));
        assert!(!registry_registers_program(&full[..NFT_REGISTRY_ACCOUNT_LEN - 1], &me));
    }

    #[test]
    fn rejects_zeroed_registry() {
        // A correctly-sized but all-zero account (allocated-but-uninitialized)
        // registers the zero program id, which is never this program.
        let me = Pubkey::new_from_array([5u8; 32]);
        assert!(!registry_registers_program(&[0u8; NFT_REGISTRY_ACCOUNT_LEN], &me));
    }
}


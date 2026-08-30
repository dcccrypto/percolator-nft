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
        NftInstruction::ReconcileBurnedNft => process_reconcile_burned_nft(program_id, accounts),
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

/// `(is_signer, is_writable)` for the seven ExtraAccountMetaList entries, which the
/// Token-2022 transfer hook receives at account indices 5..=11.
///
/// Shared by the mint path and by RepairExtraMetas so the two can never disagree.
/// RepairExtraMetas is PERMISSIONLESS, so a divergence would let any caller rewrite a
/// live NFT's metas into a shape the hook cannot use.
///
/// Entry 5 (PositionNft PDA) must stay writable: #105 removed the f_snap_at_mint write,
/// but #152/#153 added `nft_state.last_holder = new_owner` in process_transfer_hook
/// (transfer_hook.rs:542-545), which runs on every genuine Token-2022 transfer. A
/// read-only meta there makes each such TransferChecked fail.
///
/// Entry 6 (Portfolio) is read-only: the hook performs no invoke/invoke_signed and never
/// mutably borrows `portfolio` — it only reads it to check the NFT PDA binding.
pub(crate) const EXTRA_META_ENTRY_FLAGS: [(bool, bool); 7] = [
    (false, true),  // 5: PositionNft PDA        — writable (hook writes last_holder)
    (false, false), // 6: Portfolio account      — read-only (hook only reads)
    (false, false), // 7: Percolator program     — read-only
    (false, false), // 8: Mint authority PDA     — read-only
    (false, false), // 9: Instructions sysvar    — read-only
    (false, false), // 10: NFT program (self)    — read-only
    (false, false), // 11: NFT registry PDA      — read-only
];

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

    // #110C: assert provenance header matches the passed portfolio account
    // to prevent a spoofed portfolio with a mismatched account_id.
    if p.provenance_header.portfolio_account_id != portfolio.key.to_bytes() {
        msg!("MintPositionNft: portfolio account ID does not match provenance header");
        return Err(NftError::InvalidNftPda.into());
    }

    let slot = cpi_v16::mint_leg_slot(p, &owner.key.to_bytes(), asset_index as u32)
        .map_err(ProgramError::from)?;

    // Fail-fast (#127): the escrow CPI at the END of mint runs the wrapper's B-3
    // gate, which rejects a locked / stale / resolved / mid-close position. Mirror
    // that gate here — `transfer_gate_check` maps the same `leg_transfer_gate` the
    // wrapper's B-3 enforces — so mint reverts with a precise error BEFORE any
    // irreversible Token-2022 work (mint/ATA/metadata/extra-metas) instead of
    // after it. This rejects exactly the set B-3 would reject (no legitimate mint
    // is blocked); the escrow CPI remains the authoritative final check.
    cpi_v16::transfer_gate_check(p, asset_index as u32).map_err(ProgramError::from)?;

    // #137: only single-position portfolios are wrappable. Escrow-at-mint binds the
    // ENTIRE portfolio to this one NFT, so minting one leg of a multi-leg
    // (cross-margin) portfolio would convey the other, un-tokenized legs on sale —
    // the NFT would represent more than its named position. Require exactly one
    // active leg so "1 NFT = 1 position" holds. (Cross-margin baskets are simply
    // not NFT-wrappable; wrap individual positions instead.)
    let active_legs = p.legs.iter().filter(|l| l.active != 0).count();
    if active_legs != 1 {
        msg!(
            "MintPositionNft rejected: portfolio has {} active legs — only single-position portfolios are wrappable (#137)",
            active_legs
        );
        return Err(NftError::MultiLegNotWrappable.into());
    }

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

    // #117: Replace create_account with transfer-allocate-assign so a
    // griefing pre-fund (1 lamport to the PDA address) cannot cause
    // create_account to fail with "already in use".
    // Mirror the extra_metas pattern above: top up shortfall, then
    // invoke_signed allocate, then invoke_signed assign.
    {
        let current_lamports = nft_pda.lamports();
        if current_lamports < lamports {
            let shortfall = lamports - current_lamports;
            invoke(
                &system_instruction::transfer(owner.key, nft_pda.key, shortfall),
                &[owner.clone(), nft_pda.clone(), system_program.clone()],
            )?;
        }
        invoke_signed(
            &system_instruction::allocate(nft_pda.key, POSITION_NFT_V16_LEN as u64),
            &[nft_pda.clone(), system_program.clone()],
            &[pda_seeds],
        )?;
        invoke_signed(
            &system_instruction::assign(nft_pda.key, program_id),
            &[nft_pda.clone(), system_program.clone()],
            &[pda_seeds],
        )?;
    }

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
    nft_state.last_holder = owner.key.to_bytes(); // #138: minter is the first holder
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
    // #115: allocate `final_size` bytes (not just `mint_space`), because
    // `mint_rent = rent.minimum_balance(final_size)` already pays for the
    // full extent — allocating only `mint_space` here would cause the
    // token-metadata TLV init to fail with AccountDataTooSmall.
    invoke(
        &system_instruction::create_account(
            owner.key,
            nft_mint.key,
            mint_rent,
            final_size as u64,
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
    //   [5] PositionNft PDA        — WRITABLE (hook records last_holder, #152/#153)
    //   [6] Portfolio account      — read-only (hook only reads it; B-3 CPI moved to mint/burn per #105)
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
        // Derived from the shared flags table, never re-typed: EXTRA_META_ENTRY_FLAGS
        // is what actually decides the entries, so a count declared independently
        // could silently disagree with it.
        const EXTRA_META_COUNT: usize = EXTRA_META_ENTRY_FLAGS.len();
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

        let keys: [Pubkey; EXTRA_META_COUNT] = [
            *nft_pda.key,
            *portfolio.key,
            percolator_prog_id,
            *mint_auth.key,
            sysvar_instructions::id(),
            *program_id,
            registry_pda,
        ];
        // Flags come from the shared table so mint and RepairExtraMetas cannot diverge.
        let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = core::array::from_fn(|i| {
            let (is_signer, is_writable) = EXTRA_META_ENTRY_FLAGS[i];
            (keys[i], is_signer, is_writable)
        });

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
/// Ensures the burn rent recipient can receive returned lamports.
fn require_writable_rent_recipient(holder: &AccountInfo) -> ProgramResult {
    if !holder.is_writable {
         return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

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

    require_writable_rent_recipient(holder)?;
    
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

    require_writable_rent_recipient(holder)?;

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
        // #110C: apply the same provenance check that MintPositionNft (line 304)
        // enforces. Without this, a portfolio with a mismatched portfolio_account_id
        // passes decode_portfolio at burn even though it would be rejected at mint.
        if p.provenance_header.portfolio_account_id != portfolio.key.to_bytes() {
            msg!("BurnPositionNft: portfolio_account_id mismatch (#110C)");
            return Err(NftError::InvalidNftPda.into());
        }
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

    require_writable_rent_recipient(holder)?;

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

    // ── #131: tolerate a bound portfolio the core has already closed ──────────
    // Under #105 escrow the core can permissionlessly close an EMPTY escrowed
    // portfolio (deregister + close_portfolio_account_to_market_slab zeroes the
    // data, realloc(0)s, and sweeps lamports). The NFT is uniquely pinned to this
    // portfolio by the `nft_state.portfolio_account == portfolio.key` binding
    // checked above, so a closed account here means the bound position is
    // unrecoverably gone AND the escrow was already released by that closure —
    // without this, both Burn and EmergencyBurn would revert forever, stranding
    // the NFT-side rent (#131, escalated by #105's permissionless close path).
    //
    // Detect the closure footprint NARROWLY: 0-byte OR zero-lamport. A LIVE
    // escrowed portfolio is wrapper-owned, non-empty, and rent-funded, so this is
    // false and the normal eligibility check + unwrap run unchanged. Any OTHER
    // anomaly (e.g. somehow non-empty but not wrapper-owned) is deliberately NOT
    // treated as "gone" — it falls through to `verify_portfolio_program` below and
    // is rejected, never silently skipping the unwrap on a live escrow. The core
    // only closes value-empty portfolios, so this never abandons recoverable funds.
    let portfolio_gone = portfolio.data_is_empty() || portfolio.lamports() == 0;

    // ── Check emergency burn eligibility (position flat / no active leg) ──
    if portfolio_gone {
        msg!("EmergencyBurn: bound portfolio already closed/reclaimed by the core — skipping eligibility + unwrap (#131)");
    } else {
        cpi_v16::verify_portfolio_program(portfolio)?;
        let portfolio_data = portfolio.try_borrow_data()?;
        match slab_types_v16::decode_portfolio(&portfolio_data) {
            Ok(p) => {
                // #110C: apply the same provenance check that MintPositionNft (line 304)
                // enforces. Without this, a portfolio with a mismatched portfolio_account_id
                // passes decode_portfolio at emergency-burn even though it would be rejected at mint.
                if p.provenance_header.portfolio_account_id != portfolio.key.to_bytes() {
                    msg!("EmergencyBurn: portfolio_account_id mismatch (#110C)");
                    return Err(NftError::InvalidNftPda.into());
                }
                cpi_v16::emergency_burn_ok(p, &nft_state_copy).map_err(ProgramError::from)?;
            }
            // #110B, NARROWED: only a genuine layout migration may bypass the
            // eligibility gate.
            //
            // Skipping the gate lets a position be emergency-burned without proving it
            // is flat, and this falls through to UnwrapEscrowedPortfolio, which is not
            // itself leg-gated — so the set of errors that reach it must be exactly the
            // set this fallback was justified by ("a future layout migration changed
            // magic/version"), not every decode failure.
            //
            // Admitted: BadVersion / BadAccountVersion / BadLayoutDiscriminator — the
            // account IS ours (wrapper-owned, verified above by verify_portfolio_program)
            // and is a shape this build predates.
            //
            // Rejected: TooShort, BadMagic, BadKind, Cast, OwnerMismatch — on a
            // wrapper-owned account these mean corruption or a wrong account, not a
            // migration. OwnerMismatch in particular is a violated engine invariant and
            // must never widen burn eligibility.
            Err(
                e @ (slab_types_v16::PortfolioDecodeError::BadVersion
                | slab_types_v16::PortfolioDecodeError::BadAccountVersion
                | slab_types_v16::PortfolioDecodeError::BadLayoutDiscriminator),
            ) => {
                msg!(
                    "EmergencyBurn: portfolio present but from an unknown layout version ({:?}) — skipping eligibility, proceeding to unwrap (#110B)",
                    e
                );
            }
            Err(e) => return Err(cpi_v16::map_decode_err(e)),
        }
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
    //
    // #131: if the core already closed the bound portfolio (portfolio_gone) there
    // is no account left to unwrap — the escrow was released by that closure — so
    // skip the CPI and proceed to burn + reclaim the NFT-side rent.
    if !portfolio_gone {
    verify_percolator_prog_account(percolator_prog, portfolio)?;
    cpi_unwrap_portfolio(
        percolator_prog,
        mint_auth,
        portfolio,
        nft_registry,
        holder.key,
        mint_auth_bump,
    )?;
    }

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
// Tag 7: ReconcileBurnedNft (#138)
// ═══════════════════════════════════════════════════════════════
//
// Self-healing recovery for an out-of-band burn: a holder can call Token-2022
// `Burn` directly (bypassing BurnPositionNft), which sets supply→0 WITHOUT
// releasing the escrow — the position would otherwise be stranded (owner stuck at
// the mint-authority PDA, no NFT left to authorize anyone). ReconcileBurnedNft is
// permissionless: when the NFT mint supply is 0 and the PositionNft PDA still
// exists, it releases the stranded position to the RECORDED last holder (set at
// mint and on every transfer, #138) and closes the PDA, returning rent to them.
// Funds always go to the recorded last holder regardless of who cranks it.
//
// Accounts:
//   0. [writable] PositionNft PDA (closed)
//   1. [writable] NFT mint (Token-2022 — supply must be 0; closed, #182)
//   2. [writable] Portfolio account (escrow released by the unwrap CPI)
//   3. []         Mint authority PDA (unwrap CPI signer)
//   4. []         Per-market NftRegistry PDA
//   5. []         Percolator wrapper program (unwrap CPI target)
//   6. [writable] Recorded last-holder wallet (escrow + all rent recipient)
//   7. [writable] ExtraAccountMetaList PDA (closed, #182)
//   8. []         Token-2022 program (mint-close CPI target, #182)
fn process_reconcile_burned_nft(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let nft_pda = next_account_info(accounts_iter)?; // 0
    let nft_mint = next_account_info(accounts_iter)?; // 1
    let portfolio = next_account_info(accounts_iter)?; // 2 (writable)
    let mint_auth = next_account_info(accounts_iter)?; // 3
    let nft_registry = next_account_info(accounts_iter)?; // 4
    let percolator_prog = next_account_info(accounts_iter)?; // 5
    let last_holder_ai = next_account_info(accounts_iter)?; // 6 (writable)
    // #182: required, not optional. Reconcile is permissionless, irreversible
    // and one-shot — it closes nft_pda, and every path that could later reclaim
    // the mint or the metas PDA needs nft_pda alive. An opt-in would mean any
    // stale client, helpful third party or griefer could permanently destroy
    // that rent with a single short call, with no second chance to notice.
    let extra_metas = next_account_info(accounts_iter)?; // 7 (writable, closed)
    let token_program = next_account_info(accounts_iter)?; // 8

    if nft_pda.owner != program_id {
        msg!("ReconcileBurnedNft: nft_pda not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }
    if !nft_pda.is_writable || !portfolio.is_writable || !last_holder_ai.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // ── Read the bound PositionNft state ──
    let (recorded_portfolio, recorded_mint, market_id_at_mint, last_holder) = {
        let data = nft_pda.try_borrow_data()?;
        if data.len() < POSITION_NFT_V16_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state = bytemuck::from_bytes::<PositionNftV16>(&data[..POSITION_NFT_V16_LEN]);
        verify_position_nft(nft_state)?;
        (
            nft_state.portfolio_account,
            nft_state.nft_mint,
            nft_state.market_id_at_mint.get(),
            nft_state.last_holder,
        )
    };

    // ── Bindings: mint, portfolio, canonical PDA (#108 market_id), recipient ──
    if nft_mint.key.to_bytes() != recorded_mint {
        return Err(NftError::InvalidNftPda.into());
    }
    if portfolio.key.to_bytes() != recorded_portfolio {
        return Err(NftError::InvalidNftPda.into());
    }
    let (expected_pda, _) = position_nft_pda(portfolio.key, market_id_at_mint, program_id);
    if *nft_pda.key != expected_pda {
        return Err(NftError::InvalidNftPda.into());
    }
    // The escrow + PDA rent are released to the RECORDED last holder, whoever cranks.
    if last_holder_ai.key.to_bytes() != last_holder {
        msg!("ReconcileBurnedNft: recipient is not the recorded last holder");
        return Err(NftError::NotNftHolder.into());
    }

    // ── Verify mint authority PDA (unwrap CPI signer) ──
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── The NFT must be genuinely burned: Token-2022 mint with supply == 0 ──
    if *nft_mint.owner != token2022::TOKEN_2022_PROGRAM_ID {
        return Err(NftError::InvalidNftPda.into());
    }
    {
        let mint_data = nft_mint.try_borrow_data()?;
        // SPL/Token-2022 base Mint layout: supply is a u64 at offset 36.
        if mint_data.len() < 44 {
            return Err(ProgramError::InvalidAccountData);
        }
        let supply = u64::from_le_bytes(mint_data[36..44].try_into().unwrap());
        if supply != 0 {
            msg!("ReconcileBurnedNft: NFT supply != 0 — not burned; use BurnPositionNft");
            return Err(NftError::PositionNotClosed.into());
        }
    }

    // ── Release the stranded escrow to the last holder (wrapper tag 82). This
    //    succeeds ONLY if the portfolio is still escrowed (owner == mint-auth PDA);
    //    if it was already unwrapped (a normal burn ran first), the wrapper rejects
    //    on the escrow invariant — i.e. there was nothing stranded to reconcile. ──
    //
    // verify_portfolio_program checks portfolio.owner is on the {DEVNET, MAINNET}
    // allowlist. verify_percolator_prog_account then checks percolator_prog.key ==
    // portfolio.owner. Both checks are required: verify_percolator_prog_account alone
    // is satisfied by any (percolator_prog, portfolio) pair the attacker controls.
    cpi_v16::verify_portfolio_program(portfolio)?;
    verify_percolator_prog_account(percolator_prog, portfolio)?;
    cpi_unwrap_portfolio(
        percolator_prog,
        mint_auth,
        portfolio,
        nft_registry,
        last_holder_ai.key,
        mint_auth_bump,
    )?;

    // ── #182: optionally reclaim the mint + ExtraAccountMetaList rent ──
    // #102 stopped this leak for BurnPositionNft/EmergencyBurn. ReconcileBurnedNft
    // was added later (#138) and never got the same treatment, so ~0.0077 SOL per
    // reconciled NFT was abandoned unrecoverably (2,707,440 for the 261-byte metas
    // PDA + 4,969,440 for the 586-byte mint). The two accounts are in fact dead
    // from the out-of-band burn onward, not merely from Reconcile: BurnPositionNft
    // and EmergencyBurn are the only instructions that close them and both require
    // the holder ATA to hold amount == 1, which is already 0. Reconcile is
    // therefore the ONLY place a recovery can live, and it runs at most once.
    //
    // They grant no new authority: `close_extra_metas` re-derives extra_metas
    // from nft_mint, nft_mint is itself pinned to nft_state.nft_mint above, and
    // the rent goes to the same `last_holder_ai` the PDA rent already goes to.
    //
    // This does NOT recover everything. The holder's own ATA (~0.0021 SOL) is
    // still theirs to close directly against Token-2022 — closing the mint here
    // does not block that, since Token-2022's mint close checks only the
    // close-authority extension, supply and signature, and never scans for live
    // token accounts.
    //
    // Requires the mint to carry MintCloseAuthority. Every mint this program
    // creates has it (added before ReconcileBurnedNft existed), but a mint
    // predating that would make this CPI — and therefore the whole reconcile,
    // including the escrow release — revert.
    if *token_program.key != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("ReconcileBurnedNft: invalid Token-2022 program key");
        return Err(ProgramError::IncorrectProgramId);
    }
    if !nft_mint.is_writable {
        msg!("ReconcileBurnedNft: nft_mint must be writable to reclaim its rent");
        return Err(ProgramError::InvalidAccountData);
    }
    // Supply was verified 0 above, so Token-2022 permits the close. Both rents
    // go to `last_holder_ai`, the same address the PDA rent already goes to and
    // the one BurnPositionNft/EmergencyBurn already pay these to.
    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];
    invoke_signed(
        &token2022::close_account(nft_mint.key, last_holder_ai.key, mint_auth.key),
        &[
            nft_mint.clone(),
            last_holder_ai.clone(),
            mint_auth.clone(),
            token_program.clone(),
        ],
        &[mint_auth_seeds],
    )?;
    close_extra_metas(program_id, extra_metas, nft_mint.key, last_holder_ai)?;

    // ── Close the PositionNft PDA — rent to the last holder (the rightful party) ──
    let dest_lamports = last_holder_ai.lamports();
    let pda_lamports = nft_pda.lamports();
    **last_holder_ai.try_borrow_mut_lamports()? = dest_lamports
        .checked_add(pda_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **nft_pda.try_borrow_mut_lamports()? = 0;
    {
        let mut pda_data = nft_pda.try_borrow_mut_data()?;
        pda_data.fill(0);
    }

    msg!(
        "ReconcileBurnedNft: released stranded position {} to last holder {}",
        portfolio.key,
        last_holder_ai.key
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

    // #120: reject non-writable nft_pda before attempting to borrow_mut_data.
    if !nft_pda.is_writable {
        return Err(ProgramError::InvalidAccountData);
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

    cpi_v16::verify_portfolio_account_id(p, portfolio.key, "SettleFunding")?;
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

    let (expected_extra_metas, extra_metas_bump) = extra_account_metas_pda(nft_mint.key, program_id);
    if *extra_metas.key != expected_extra_metas {
        msg!("RepairExtraMetas: extra_metas PDA does not match derivation");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }
    // The PDA is normally owned by this program. A System-owned PDA is admitted as the
    // recovery case this instruction exists for: an NFT whose extra_metas account was
    // never created at all. A nonexistent account is presented to a program as
    // System-owned with zero lamports and no data, so the previous
    // `owner != program_id -> reject` gate meant RepairExtraMetas could only fix a
    // WRONG-SIZED metas account, never a MISSING one — the case that actually bricks
    // transfers, because the Token-2022 hook cannot resolve its account list without it.
    //
    // Why this is safe to admit:
    //  * the address is already pinned to our own derivation immediately above, so a
    //    System-owned account here can never be someone else's state;
    //  * it must be EMPTY, so an account carrying data is rejected rather than
    //    silently overwritten;
    //  * nft_pda is separately required to be program-owned and to carry a valid
    //    PositionNftV16 bound to this mint and portfolio (checked below), so metas
    //    cannot be conjured for an NFT that does not exist.
    //
    // On the post-burn state: a burned NFT's extra_metas DOES eventually present this
    // way. close_extra_metas (:747) zeroes its lamports and data without reassigning
    // the owner, but the runtime reaps zero-lamport accounts at end of transaction, so
    // on any LATER transaction it loads as System-owned and empty and reaches this
    // branch. (An earlier revision of this comment claimed the opposite; that was
    // wrong.) What actually keeps a burned NFT out is the NEXT gate: the same burn
    // drains nft_pda, so `nft_pda.owner != program_id` below rejects before anything
    // is written. The safety rests on that check, not on the owner byte here.
    let extra_metas_system_owned =
        *extra_metas.owner == solana_program::system_program::id();

    if extra_metas.owner != program_id && !extra_metas_system_owned {
        msg!("RepairExtraMetas: extra_metas PDA not owned by this program or System Program");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }

    if extra_metas_system_owned && !extra_metas.data_is_empty() {
        msg!("RepairExtraMetas: System-owned extra_metas PDA must be empty before recovery");
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
    // Derived from the shared flags table — see the note at the mint path.
    const EXTRA_META_COUNT: usize = EXTRA_META_ENTRY_FLAGS.len();
    const HEADER_LEN: usize = 16;
    const EXTRA_METAS_ACCOUNT_LEN: usize =
        HEADER_LEN + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT;

    let mut data = extra_metas.try_borrow_mut_data()?;
    // GROW ONLY, as on main. An earlier revision used `!=` here, which also SHRANK an
    // oversized program-owned account back to EXTRA_METAS_ACCOUNT_LEN — a brand-new
    // destructive capability on a PERMISSIONLESS instruction, and one nothing asked
    // for. `<` still covers the recovery case: a never-created (System-owned) account
    // has len 0, which is < the target.
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

        if extra_metas_system_owned {
            // Same seeds as the mint path (processor.rs:631) — use the shared
            // constant so a seed change cannot desynchronise the two derivations.
            let extra_metas_seeds: &[&[u8]] =
                &[EXTRA_METAS_SEED, nft_mint.key.as_ref(), &[extra_metas_bump]];

            invoke_signed(
                &system_instruction::allocate(extra_metas.key, EXTRA_METAS_ACCOUNT_LEN as u64),
                &[extra_metas.clone(), system_program.clone()],
                &[extra_metas_seeds],
            )?;

            invoke_signed(
                &system_instruction::assign(extra_metas.key, program_id),
                &[extra_metas.clone(), system_program.clone()],
                &[extra_metas_seeds],
            )?;
        }

        extra_metas.resize(EXTRA_METAS_ACCOUNT_LEN)?;
        data = extra_metas.try_borrow_mut_data()?;
    }

    data[0..8].copy_from_slice(&EXECUTE_DISCRIMINATOR);
    let tlv_value_len: u32 = (4 + EXTRA_META_ENTRY_LEN * EXTRA_META_COUNT) as u32;
    data[8..12].copy_from_slice(&tlv_value_len.to_le_bytes());
    data[12..16].copy_from_slice(&(EXTRA_META_COUNT as u32).to_le_bytes());

    let keys: [Pubkey; EXTRA_META_COUNT] = [
        *nft_pda.key,
        *portfolio.key,
        percolator_prog_id,
        *mint_auth.key,
        sysvar_instructions::id(),
        *program_id,
        registry_pda,
    ];
    // Same shared table as the mint path — see EXTRA_META_ENTRY_FLAGS.
    let entries: [(Pubkey, bool, bool); EXTRA_META_COUNT] = core::array::from_fn(|i| {
        let (is_signer, is_writable) = EXTRA_META_ENTRY_FLAGS[i];
        (keys[i], is_signer, is_writable)
    });
    for (i, (key, is_signer, is_writable)) in entries.iter().enumerate() {
        let off = HEADER_LEN + i * EXTRA_META_ENTRY_LEN;
        data[off] = 0;
        data[off + 1..off + 33].copy_from_slice(key.as_ref());
        data[off + 33] = if *is_signer { 1 } else { 0 };
        data[off + 34] = if *is_writable { 1 } else { 0 };
    }

    msg!(
        "RepairExtraMetas: rewrote ExtraAccountMetaList for mint {} (nft_pda writable, portfolio read-only)",
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

#[cfg(test)]
mod burn_rent_recipient_writable_tests {
    use super::close_extra_metas;
    use crate::transfer_hook::extra_account_metas_pda;
    use solana_program::{
        account_info::AccountInfo,
        program_error::ProgramError,
        pubkey::Pubkey
    };    

    #[test]
    fn close_extra_metas_rejects_non_writable_holder_before_lamport_mutation() {
        let program_id = Pubkey::new_from_array([9u8; 32]);
        let holder_key = Pubkey::new_from_array([1u8; 32]);
        let nft_mint = Pubkey::new_from_array([2u8; 32]);
        let system_program_id = solana_program::system_program::id();

        let (extra_metas_key, _) = extra_account_metas_pda(&nft_mint, &program_id);

        let mut holder_lamports = 10u64;
        let mut extra_metas_lamports = 5u64;

        let mut holder_data = vec![];
        let mut extra_metas_data = vec![1u8; 16];

        let holder = AccountInfo::new(
            &holder_key,
            true,
            false, // intentionally NOT writable
            &mut holder_lamports,
            &mut holder_data,
            &system_program_id,
            false,
            0,
        );

        let extra_metas = AccountInfo::new(
            &extra_metas_key,
            false,
            true,
            &mut extra_metas_lamports,
            &mut extra_metas_data,
            &program_id,
            false,
            0,
        );

        let result = close_extra_metas(&program_id, &extra_metas, &nft_mint, &holder);

        assert_eq!(result, Err(ProgramError::InvalidAccountData));
        assert_eq!(holder.lamports(), 10);
        assert_eq!(extra_metas.lamports(), 5);
        assert!(extra_metas.data.borrow().iter().all(|byte| *byte == 1));
    }

    #[test]
    fn close_extra_metas_allows_writable_holder_rent_return() {
        let program_id = Pubkey::new_from_array([9u8; 32]);
        let holder_key = Pubkey::new_from_array([1u8; 32]);
        let nft_mint = Pubkey::new_from_array([2u8; 32]);
        let system_program_id = solana_program::system_program::id();

        let (extra_metas_key, _) = extra_account_metas_pda(&nft_mint, &program_id);

        let mut holder_lamports = 10u64;
        let mut extra_metas_lamports = 5u64;

        let mut holder_data = vec![];
        let mut extra_metas_data = vec![1u8; 16];

        let holder = AccountInfo::new(
            &holder_key,
            true,
            true, // writable rent recipient
            &mut holder_lamports,
            &mut holder_data,
            &system_program_id,
            false,
            0,
        );

        let extra_metas = AccountInfo::new(
            &extra_metas_key,
            false,
            true,
            &mut extra_metas_lamports,
            &mut extra_metas_data,
            &program_id,
            false,
            0,
        );

        let result = close_extra_metas(&program_id, &extra_metas, &nft_mint, &holder);

        assert!(result.is_ok());
        assert_eq!(holder.lamports(), 15);
        assert_eq!(extra_metas.lamports(), 0);
        assert!(extra_metas.data.borrow().iter().all(|byte| *byte == 0));
    }
}

#[cfg(test)]
#[test]
fn rent_recipient_guard_rejects_non_writable_holder() {
    let holder_key = Pubkey::new_from_array([1u8; 32]);
    let system_program_id = solana_program::system_program::id();

    let mut holder_lamports = 10u64;
    let mut holder_data = vec![];

    let holder = AccountInfo::new(
        &holder_key,
        true,
        false, // intentionally NOT writable
        &mut holder_lamports,
        &mut holder_data,
        &system_program_id,
        false,
        0,
    );

    let result = require_writable_rent_recipient(&holder);

    assert_eq!(result, Err(ProgramError::InvalidAccountData));
    assert_eq!(holder.lamports(), 10);
}

#[cfg(test)]
#[test]
fn rent_recipient_guard_accepts_writable_holder() {
    let holder_key = Pubkey::new_from_array([1u8; 32]);
    let system_program_id = solana_program::system_program::id();

    let mut holder_lamports = 10u64;
    let mut holder_data = vec![];

    let holder = AccountInfo::new(
        &holder_key,
        true,
        true, // writable rent recipient
        &mut holder_lamports,
        &mut holder_data,
        &system_program_id,
        false,
        0,
    );

    let result = require_writable_rent_recipient(&holder);

    assert!(result.is_ok());
}


#[cfg(test)]
mod extra_meta_flag_tests {
    use super::*;

    /// Entry 5 is the PositionNft PDA and the transfer hook WRITES it
    /// (`nft_state.last_holder = new_owner`, transfer_hook.rs:542-545, gated on
    /// `is_genuine_token2022_transfer`). Flipping it read-only makes every genuine
    /// Token-2022 TransferChecked fail, and because RepairExtraMetas is permissionless
    /// that is a free brick-any-NFT vector. This pins the flag so the regression cannot
    /// return silently — the 34 pre-existing tests all passed with it read-only.
    #[test]
    fn position_nft_pda_meta_entry_is_writable() {
        assert_eq!(
            EXTRA_META_ENTRY_FLAGS[0],
            (false, true),
            "entry 5 (PositionNft PDA) must be non-signer and WRITABLE: the transfer hook \
             writes last_holder to it on every genuine Token-2022 transfer"
        );
    }

    /// Entry 6 is the Portfolio account. The hook performs no invoke/invoke_signed and
    /// never mutably borrows it, so read-only is correct and narrows the write lock.
    #[test]
    fn portfolio_meta_entry_is_read_only() {
        assert_eq!(
            EXTRA_META_ENTRY_FLAGS[1],
            (false, false),
            "entry 6 (Portfolio) is read-only: the hook only reads it to check the NFT \
             PDA binding"
        );
    }

    /// Everything from entry 7 on is a program/sysvar/PDA the hook only reads.
    #[test]
    fn remaining_meta_entries_are_read_only_non_signers() {
        for (i, flags) in EXTRA_META_ENTRY_FLAGS.iter().enumerate().skip(2) {
            assert_eq!(
                *flags,
                (false, false),
                "entry {} must be a read-only non-signer",
                i + 5
            );
        }
    }

    /// No entry is ever a signer — the hook is invoked by Token-2022, which cannot
    /// produce signatures for these accounts.
    #[test]
    fn no_meta_entry_is_a_signer() {
        assert!(EXTRA_META_ENTRY_FLAGS.iter().all(|(s, _)| !*s));
    }
}

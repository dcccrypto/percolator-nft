//! Token-2022 TransferHook implementation — v16 wiring (A.4).
//!
//! This module implements the SPL TransferHook Execute interface. Token-2022
//! calls `process_execute` on every NFT transfer. The hook:
//!
//! 1. Validates structural preconditions (amount == 1, Instructions sysvar,
//!    extra_metas PDA, source/dest ATA ownership + initialization + mint match).
//! 2. Extracts `new_owner` from `dest_ata.data[32..64]` — the WALLET that owns
//!    the destination ATA, NOT the ATA address itself. Setting it to the ATA
//!    address would brick the portfolio by assigning a token-account pubkey as
//!    the portfolio owner. (v12 bug-fix, preserved verbatim.)
//! 3. Verifies the outer instruction in the Instructions sysvar is a Token-2022
//!    Transfer/TransferChecked/TransferCheckedWithFee targeting this mint. This
//!    prevents direct invocation of Execute, which would otherwise let any caller
//!    remap portfolio ownership without moving the NFT. (v12 verbatim port.)
//! 4. Validates NFT PDA state and verifies the PDA address against canonical
//!    derivation.
//! 5. Verifies the portfolio program key is on the fail-closed allowlist, decodes
//!    the portfolio, and checks the nft_pda key against `position_nft_pda`.
//! 6. Defense-in-depth: verifies the `nft_registry` key against
//!    `derive_nft_registry(portfolio.owner, market_group)`.
//! 7. Applies the v16 transfer gate: `verify_bound_leg` (market_id slot-reuse)
//!    then `transfer_gate_check` (flags). Both must pass; either Err → reject.
//!    Replaces v12's `is_position_healthy` margin check — v16 uses flag-based
//!    gating, not live margin math at transfer time.
//! 8. CPIs to the wrapper's B-3 `TransferPortfolioOwnership` (tag 72) with
//!    `mint_auth` as the PDA signer, passing `new_owner` and `asset_index`.
//! 9. Optionally refreshes `nft_state.f_snap_at_mint` to the current leg value.

extern crate alloc;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::instructions as sysvar_instructions,
};

use crate::{
    cpi_v16::{
        derive_nft_registry, map_decode_err, transfer_gate_check, verify_bound_leg,
        verify_portfolio_program, PERCOLATOR_DEVNET, PERCOLATOR_MAINNET,
    },
    error::NftError,
    slab_types_v16,
    state_v16::{
        mint_authority_pda, position_nft_pda, verify_position_nft, PositionNftV16,
        MINT_AUTHORITY_SEED, POSITION_NFT_V16_LEN,
    },
    token2022,
};

// ═══════════════════════════════════════════════════════════════
// SPL TransferHook interface constants
// ═══════════════════════════════════════════════════════════════

/// Discriminator for the TransferHook `Execute` instruction.
/// SHA256("spl-transfer-hook-interface:execute")[:8]
pub const EXECUTE_DISCRIMINATOR: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];

/// PDA seed for the ExtraAccountMetaList account.
pub const EXTRA_METAS_SEED: &[u8] = b"extra-account-metas";

/// Derive the ExtraAccountMetaList PDA for a given mint.
pub fn extra_account_metas_pda(mint: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EXTRA_METAS_SEED, mint.as_ref()], program_id)
}

/// Instruction tag for B-3 `TransferPortfolioOwnership` in the wrapper.
/// Tag 72 is the CPI-only ownership reassignment handler (3-account flow):
///   data: tag(1) + new_owner(32) + asset_index_le(2)
///   accounts: [mint_auth(signer), portfolio(writable), nft_registry(read-only)]
const TAG_B3_TRANSFER_PORTFOLIO_OWNERSHIP: u8 = 72;

// ═══════════════════════════════════════════════════════════════
// CPI caller verification — ensure Execute is called via Token-2022
// ═══════════════════════════════════════════════════════════════

/// SPL Token Transfer instruction tag.
const TOKEN_IX_TRANSFER: u8 = 3;
/// SPL Token TransferChecked instruction tag.
const TOKEN_IX_TRANSFER_CHECKED: u8 = 12;
/// SPL Token-2022 TransferCheckedWithFee instruction tag.
/// Accept tag 26 in addition to 3 and 12 — Token-2022 uses this tag when the
/// mint has a TransferFeeConfig extension. Without it, NFTs on fee-enabled mints
/// fail with UnauthorizedDirectInvocation on every transfer.
const TOKEN_IX_TRANSFER_CHECKED_WITH_FEE: u8 = 26;

/// Verify that the current instruction was invoked via CPI from the Token-2022
/// program, and that the outer instruction is a Transfer or TransferChecked
/// targeting the expected mint.
///
/// This is the standard defense used by SPL TransferHook reference
/// implementations. It prevents direct invocation of the Execute handler.
///
/// How it works:
/// - On Solana, when program A CPI-calls program B, program B's instruction
///   still runs in the context of program A's top-level instruction index.
/// - We use `load_current_index_checked` to find which top-level instruction
///   is currently executing, then `load_instruction_at_checked` to read it.
/// - If we were invoked via CPI from Token-2022, the top-level instruction
///   will be Token-2022's Transfer/TransferChecked.
/// - If we were invoked directly (not via CPI), the top-level instruction
///   will be our own program — which we reject.
fn verify_cpi_caller_is_token2022(
    sysvar_ix: &AccountInfo,
    expected_mint: &Pubkey,
) -> Result<(), ProgramError> {
    // Load the index of the currently executing top-level instruction.
    let current_ix_idx = sysvar_instructions::load_current_index_checked(sysvar_ix)?;

    // Load the top-level instruction at that index.
    let current_ix =
        sysvar_instructions::load_instruction_at_checked(current_ix_idx as usize, sysvar_ix)?;

    // The outer instruction must be from Token-2022.
    if current_ix.program_id != token2022::TOKEN_2022_PROGRAM_ID {
        msg!(
            "Transfer rejected: outer instruction program {} is not Token-2022",
            current_ix.program_id
        );
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    // Verify the outer instruction is Transfer (tag 3) or TransferChecked (tag 12).
    // Both are valid Token-2022 instructions that trigger the transfer hook.
    if current_ix.data.is_empty() {
        msg!("Transfer rejected: Token-2022 instruction data is empty");
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    let ix_tag = current_ix.data[0];
    match ix_tag {
        TOKEN_IX_TRANSFER => {
            // #103: reject plain Transfer (tag 3). Its instruction layout carries NO mint
            // account, so the in-program mint anchor cannot be verified (unlike the
            // TransferChecked arm below). Rather than rely on Token-2022 runtime routing to
            // guarantee the hook fires only for the correct mint, fail closed and require
            // TransferChecked (tag 12) — which every legitimate NFT-transfer flow already
            // uses (e.g. the launch useTransferPositionNft path). This makes the program's
            // safety independent of runtime behaviour (defense-in-depth).
            msg!("Transfer rejected: plain Transfer is unsupported for Position NFTs — use TransferChecked");
            Err(NftError::UnauthorizedDirectInvocation.into())
        }
        TOKEN_IX_TRANSFER_CHECKED => {
            // TransferChecked: tag(1) + amount(8) + decimals(1)
            // Accounts: [source, mint, dest, authority]
            // Verify the mint account in the instruction matches our expected mint.
            if current_ix.accounts.len() < 2 {
                msg!("Transfer rejected: TransferChecked has insufficient accounts");
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            let ix_mint = &current_ix.accounts[1].pubkey;
            if ix_mint != expected_mint {
                msg!(
                    "Transfer rejected: TransferChecked mint {} does not match expected {}",
                    ix_mint,
                    expected_mint
                );
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            Ok(())
        }
        TOKEN_IX_TRANSFER_CHECKED_WITH_FEE => {
            // TransferCheckedWithFee — same account layout as TransferChecked.
            // Accounts: [source, mint, dest, authority]
            // Verify the mint matches to prevent cross-mint hook invocation.
            if current_ix.accounts.len() < 2 {
                msg!("Transfer rejected: TransferCheckedWithFee has insufficient accounts");
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            let ix_mint = &current_ix.accounts[1].pubkey;
            if ix_mint != expected_mint {
                msg!(
                    "Transfer rejected: TransferCheckedWithFee mint {} does not match expected {}",
                    ix_mint,
                    expected_mint
                );
                return Err(NftError::UnauthorizedDirectInvocation.into());
            }
            Ok(())
        }
        _ => {
            msg!(
                "Transfer rejected: Token-2022 instruction tag {} is not Transfer, TransferChecked, or TransferCheckedWithFee",
                ix_tag
            );
            Err(NftError::UnauthorizedDirectInvocation.into())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Execute — called by Token-2022 on every NFT transfer
// ═══════════════════════════════════════════════════════════════

/// Process the TransferHook Execute instruction.
///
/// Account layout (Token-2022 passes the 4 interface accounts then the 7
/// extra-meta entries written by `MintPositionNft` / `RepairExtraMetas`):
///
///  0. `[]`          Source ATA (Token-2022-owned, initialized, mint matches)
///  1. `[]`          NFT mint
///  2. `[]`          Destination ATA (Token-2022-owned, initialized, mint matches)
///  3. `[]`          Source authority (unused — per SPL Transfer Hook spec)
///  4. `[]`          ExtraAccountMetaList PDA (owner == program_id)
///  5. `[writable]`  PositionNft PDA
///  6. `[writable]`  Portfolio account
///  7. `[]`          Percolator program (wrapper, from allowlist)
///  8. `[]`          Mint authority PDA
///  9. `[]`          Instructions sysvar
/// 10. `[]`          NFT program (self)
/// 11. `[]`          Per-market NFT registry PDA
///
/// Data: discriminator(8) + amount(8)
pub fn process_execute(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    // PERC-9036: Validate transfer amount is exactly 1.
    // This is an NFT (decimals=0, supply=1). Defense-in-depth: reject any
    // amount != 1 to prevent unexpected behavior if Token-2022 ever changes
    // semantics or if the hook is called directly (outside Token-2022 CPI).
    if amount != 1 {
        msg!("Transfer rejected: expected amount=1 for NFT, got {}", amount);
        return Err(ProgramError::InvalidInstructionData);
    }

    let accounts_iter = &mut accounts.iter();

    let source_ata = next_account_info(accounts_iter)?;       // 0: source ATA
    let mint = next_account_info(accounts_iter)?;             // 1: NFT mint
    let dest_ata = next_account_info(accounts_iter)?;         // 2: destination ATA
    let _source_authority = next_account_info(accounts_iter)?; // 3: source authority (unused per spec)
    let extra_metas = next_account_info(accounts_iter)?;      // 4: ExtraAccountMetaList PDA
    let nft_pda = next_account_info(accounts_iter)?;          // 5: PositionNft PDA (writable)
    let portfolio = next_account_info(accounts_iter)?;        // 6: Portfolio account (writable)
    let percolator_prog = next_account_info(accounts_iter)?;  // 7: Percolator program
    let mint_auth = next_account_info(accounts_iter)?;        // 8: Mint authority PDA
    let sysvar_ix = next_account_info(accounts_iter)?;        // 9: Instructions sysvar
    let nft_program_self = next_account_info(accounts_iter)?; // 10: NFT program (self)
    let nft_registry = next_account_info(accounts_iter)?;     // 11: Per-market NFT registry PDA

    // ────────────────────────────────────────────────────────────────────
    // SECURITY: Instructions sysvar key check.
    // Any attacker that can spoof this can bypass verify_cpi_caller_is_token2022.
    // ────────────────────────────────────────────────────────────────────
    if *sysvar_ix.key != sysvar_instructions::id() {
        msg!("Transfer rejected: account 9 is not the Instructions sysvar");
        return Err(NftError::UnauthorizedDirectInvocation.into());
    }

    // ────────────────────────────────────────────────────────────────────
    // Validate the extra_metas PDA against canonical derivation AND owner.
    // The key derivation check alone is not sufficient — an attacker could
    // compute the correct PDA address but pass an uninitialized account (owned
    // by System program). The owner check proves the PDA was created by this
    // program during InitializeExtraAccountMetas.
    // ────────────────────────────────────────────────────────────────────
    let (expected_extra_metas, _) = extra_account_metas_pda(mint.key, program_id);
    if *extra_metas.key != expected_extra_metas {
        msg!("Transfer rejected: extra_metas PDA does not match expected derivation");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }
    if extra_metas.owner != program_id {
        msg!("Transfer rejected: extra_metas PDA not owned by this program");
        return Err(NftError::InvalidExtraAccountMetas.into());
    }

    // ────────────────────────────────────────────────────────────────────
    // Validate source ATA (defense-in-depth).
    // Token-2022 invokes TransferHook AFTER moving the tokens, so for a 1-of-1
    // NFT the source balance is already 0. Do NOT re-check balance; check the
    // account is a Token-2022 initialized ATA for this mint instead.
    // ────────────────────────────────────────────────────────────────────
    if *source_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("Transfer rejected: source token account not owned by Token-2022");
        return Err(NftError::InvalidTokenAccount.into());
    }
    {
        let src_data = source_ata.try_borrow_data()?;
        // Token-2022 account layout (same offsets as SPL Token):
        //   [0..32]  mint (Pubkey)
        //   [32..64] owner (Pubkey)
        //   [108]    state (u8: 0=uninit, 1=initialized, 2=frozen)
        if src_data.len() < 165 {
            msg!("Transfer rejected: source token account data too short");
            return Err(NftError::InvalidTokenAccount.into());
        }
        let src_mint = Pubkey::new_from_array(src_data[0..32].try_into().unwrap());
        let src_initialized =
            src_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
        if !src_initialized {
            msg!("Transfer rejected: source token account not initialized");
            return Err(NftError::InvalidTokenAccount.into());
        }
        if src_mint != *mint.key {
            msg!("Transfer rejected: source token account mint mismatch");
            return Err(NftError::InvalidTokenAccount.into());
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Validate destination ATA and extract new_owner.
    //
    // MANDATORY GUARD (v12 verbatim): new_owner = dst_data[32..64] is the
    // WALLET that owns the destination ATA — NOT the dest ATA address.
    // Setting it to the ATA address would assign a token-account pubkey as
    // the portfolio owner, permanently bricking the portfolio.
    // ────────────────────────────────────────────────────────────────────
    if *dest_ata.owner != token2022::TOKEN_2022_PROGRAM_ID {
        msg!("Transfer rejected: dest token account not owned by Token-2022");
        return Err(NftError::InvalidTokenAccount.into());
    }
    let new_owner: Pubkey;
    {
        let dst_data = dest_ata.try_borrow_data()?;
        if dst_data.len() < 165 {
            msg!("Transfer rejected: dest token account data too short");
            return Err(NftError::InvalidTokenAccount.into());
        }
        let dst_mint = Pubkey::new_from_array(dst_data[0..32].try_into().unwrap());
        let dst_initialized =
            dst_data[108] == pinocchio_token::state::AccountState::Initialized as u8;
        if !dst_initialized {
            msg!("Transfer rejected: dest token account not initialized");
            return Err(NftError::InvalidTokenAccount.into());
        }
        if dst_mint != *mint.key {
            msg!("Transfer rejected: dest token account mint mismatch");
            return Err(NftError::InvalidTokenAccount.into());
        }
        // Extract the wallet from the ATA's owner field (bytes 32..64).
        // This is the real new owner of the portfolio position.
        new_owner = Pubkey::new_from_array(dst_data[32..64].try_into().unwrap());
    }

    // ────────────────────────────────────────────────────────────────────
    // MANDATORY GUARD: verify CPI caller is Token-2022.
    //
    // Without this, anyone can call Execute directly with a dest_ata they
    // own and steal the portfolio by forging `new_owner`. PORT VERBATIM.
    // ────────────────────────────────────────────────────────────────────
    verify_cpi_caller_is_token2022(sysvar_ix, mint.key)?;

    // ── Validate percolator_prog key against known constants ──────────
    // Prevents an attacker from supplying a malicious program as account[7].
    // Without this, the CPI target is attacker-controlled.
    if percolator_prog.key != &PERCOLATOR_DEVNET && percolator_prog.key != &PERCOLATOR_MAINNET {
        msg!(
            "Transfer rejected: percolator_prog key {} is not a known Percolator program",
            percolator_prog.key
        );
        return Err(NftError::InvalidPercolatorProgram.into());
    }

    // ── Validate mint authority PDA ───────────────────────────────────
    // mint_auth is used as the CPI signer for B-3. Without verification an
    // attacker could pass a different PDA, causing the CPI to fail or —
    // if the wrapper does not re-derive — allowing an unauthorized transfer.
    let (expected_mint_auth, mint_auth_bump) = mint_authority_pda(program_id);
    if *mint_auth.key != expected_mint_auth {
        msg!("Transfer rejected: invalid mint authority PDA");
        return Err(NftError::InvalidMintAuthority.into());
    }

    // ── Validate NFT PDA owner ────────────────────────────────────────
    if nft_pda.owner != program_id {
        msg!("Transfer rejected: PositionNft PDA not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ── Read PositionNftV16 state (scoped borrow; must drop before CPI) ──
    // Copy out all needed fields so no borrow is live at invoke_signed.
    let (asset_index_u16, market_id_at_mint, nft_state_copy);
    {
        let pda_data = nft_pda.try_borrow_data()?;
        if pda_data.len() < POSITION_NFT_V16_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let nft_state =
            bytemuck::from_bytes::<PositionNftV16>(&pda_data[..POSITION_NFT_V16_LEN]);
        verify_position_nft(nft_state)?;

        // Verify the PDA's recorded mint matches the mint account.
        if nft_state.nft_mint != mint.key.to_bytes() {
            msg!("Transfer rejected: mint does not match NFT PDA nft_mint binding");
            return Err(NftError::InvalidNftPda.into());
        }

        // Verify the PDA's recorded portfolio matches the portfolio account.
        if nft_state.portfolio_account != portfolio.key.to_bytes() {
            msg!("Transfer rejected: portfolio account does not match NFT PDA binding");
            return Err(NftError::InvalidNftPda.into());
        }

        asset_index_u16 = nft_state.asset_index.get() as u16;
        market_id_at_mint = nft_state.market_id_at_mint.get();
        nft_state_copy = *nft_state;

        // Verify the PDA address against canonical derivation.
        // Without this, any program-owned account with matching magic/mint/portfolio
        // fields could be substituted.
        let (expected_pda, _) =
            position_nft_pda(portfolio.key, asset_index_u16, program_id);
        if *nft_pda.key != expected_pda {
            msg!("Transfer rejected: PDA address does not match expected derivation");
            return Err(NftError::InvalidNftPda.into());
        }
        // pda_data (immutable Ref) is dropped here.
    }
    let _ = market_id_at_mint; // used via nft_state_copy in verify_bound_leg

    // ── Verify portfolio program (fail-closed allowlist) ─────────────
    verify_portfolio_program(portfolio)?;

    // ── Decode portfolio and run both gate checks ─────────────────────
    // All portfolio data must be read and borrows dropped before the CPI.
    let (market_group, new_f_snap);
    {
        let portfolio_data = portfolio.try_borrow_data()?;
        let p = slab_types_v16::decode_portfolio(&portfolio_data).map_err(map_decode_err)?;

        market_group = Pubkey::new_from_array(p.provenance_header.market_group_id);

        // Slot-reuse guard (market_id anchor — monotonic, never reused).
        let slot = verify_bound_leg(p, &nft_state_copy).map_err(ProgramError::from)?;

        // Transfer-gate check (flags: active leg + no lock/stale/resolved/mid-close).
        transfer_gate_check(p, asset_index_u16 as u32).map_err(ProgramError::from)?;

        // Capture leg's current f_snap for the post-CPI snapshot refresh.
        new_f_snap = p.legs[slot].f_snap;
        // portfolio_data (Ref) is dropped here.
    }

    // ── Defense-in-depth: verify nft_registry key ────────────────────
    // The wrapper re-validates too, but checking here means a mis-wired
    // registry fails early at the NFT program boundary.
    let (expected_registry, _) = derive_nft_registry(portfolio.owner, &market_group);
    if *nft_registry.key != expected_registry {
        msg!(
            "Transfer rejected: nft_registry key {} does not match expected {}",
            nft_registry.key,
            expected_registry
        );
        return Err(NftError::InvalidNftPda.into());
    }

    // ── CPI to wrapper B-3: TransferPortfolioOwnership (tag 72) ───────
    //
    // data: tag(1) + new_owner(32) + asset_index_le16(2) = 35 bytes
    // accounts:
    //   0. mint_auth   — signer (proves THIS NFT program called)
    //   1. portfolio   — writable (B-3 updates portfolio.owner)
    //   2. nft_registry — read-only (wrapper validates it is the canonical registry)
    //
    // The wrapper verifies `mint_auth.key == mint_authority_pda(registry.nft_program_id)`
    // so a valid invoke_signed signature here proves this NFT program issued the CPI.
    let cpi_data = {
        let mut d = alloc::vec::Vec::with_capacity(35);
        d.push(TAG_B3_TRANSFER_PORTFOLIO_OWNERSHIP);
        d.extend_from_slice(new_owner.as_ref());
        d.extend_from_slice(&asset_index_u16.to_le_bytes());
        d
    };

    let cpi_accounts = alloc::vec![
        AccountMeta::new_readonly(*mint_auth.key, true),     // signer
        AccountMeta::new(*portfolio.key, false),             // writable
        AccountMeta::new_readonly(*nft_registry.key, false), // read-only
    ];

    let cpi_ix = Instruction {
        program_id: *percolator_prog.key,
        accounts: cpi_accounts,
        data: cpi_data,
    };

    let mint_auth_seeds: &[&[u8]] = &[MINT_AUTHORITY_SEED, &[mint_auth_bump]];

    // All borrows (pda_data, portfolio_data) are dropped. CPI is safe.
    // nft_program_self is forwarded so the runtime can locate the AccountInfo
    // for the NFT program if the wrapper includes it as an account meta; it is
    // not a CPI target but may be needed in the account_infos slice by the
    // runtime to resolve the account.
    invoke_signed(
        &cpi_ix,
        &[
            mint_auth.clone(),
            portfolio.clone(),
            nft_registry.clone(),
            nft_program_self.clone(),
        ],
        &[mint_auth_seeds],
    )?;

    // ── Refresh f_snap_at_mint on the PositionNft PDA ─────────────────
    // Re-borrow nft_pda after the CPI completes. Mirrors v12's funding-index
    // snapshot update: keeps the NFT's snapshot in sync with the live leg.
    {
        let mut pda_data = nft_pda.try_borrow_mut_data()?;
        let nft_state =
            bytemuck::from_bytes_mut::<PositionNftV16>(&mut pda_data[..POSITION_NFT_V16_LEN]);
        nft_state.f_snap_at_mint = new_f_snap;
    }

    msg!(
        "Position transferred: portfolio={}, asset_index={}, new_owner={}",
        portfolio.key,
        asset_index_u16,
        new_owner
    );

    Ok(())
}

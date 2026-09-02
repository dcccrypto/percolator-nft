//! The NFT-PDA close paths must hand the account back to the System program.
//!
//! Before the fix they zeroed the data and drained the lamports but did neither
//! `resize(0)` nor `assign`, so a same-transaction lamport credit left the
//! account alive — program-owned, still 199 bytes, all zero — which permanently
//! blocked minting for that (portfolio, market_id) slot and could be cleared by
//! nothing. These tests pin the corrected behaviour.
//!
//! Before the fix each close path did exactly this (ReconcileBurnedNft, and the
//! same shape in BurnPositionNft and EmergencyBurn):
//!
//!     **nft_pda.try_borrow_mut_lamports()? = 0;
//!     { let mut d = nft_pda.try_borrow_mut_data()?; d.fill(0); }
//!
//! There is no `assign` back to the System program and no `resize(0)`. Solana
//! reaps zero-lamport accounts only at the END of a transaction, so a later
//! instruction in the SAME transaction that credits lamports back leaves the
//! account alive: still owned by this program, still 199 bytes, all zero.
//!
//! That state is a permanent deadlock:
//!   * `MintPositionNft` gates on `!nft_pda.data_is_empty()` (`:417`), so a
//!     199-byte zeroed account is "already minted" forever;
//!   * every other handler runs `verify_position_nft`, which rejects `magic == 0`
//!     (`state_v16.rs:154`), so nothing can clear it.
//!
//! `ReconcileBurnedNft` needs NO signer at all, so the whole thing is one cheap
//! permissionless transaction:
//!     ix0: ReconcileBurnedNft
//!     ix1: System::transfer(attacker -> nft_pda, rent_exempt_minimum)

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{derive_nft_registry, PERCOLATOR_MAINNET},
    instruction::{TAG_MINT_POSITION_NFT, TAG_RECONCILE_BURNED_NFT},
    processor, slab_types_v16 as sl,
    state_v16::{
        mint_authority_pda, position_nft_pda, verify_position_nft, PositionNftV16,
        POSITION_NFT_V16_LEN, POSITION_NFT_V16_MAGIC, POSITION_NFT_V16_VERSION,
    },
    token2022::{get_associated_token_address, ATA_PROGRAM_ID, TOKEN_2022_PROGRAM_ID},
    transfer_hook::extra_account_metas_pda,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]);
const OWNER: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);

const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;
/// Rent-exempt minimum for a 199-byte account, (128 + 199) * 3480 * 2 — what an
/// attacker credits back in ix1 to keep the account from being reaped.
const PDA_RENT: u64 = 2_275_920;

const CORE_HEADER_LEN: usize = 16;
const NFT_REGISTRY_ACCOUNT_LEN: usize = CORE_HEADER_LEN + 72;
const NFT_REGISTRY_PROGRAM_ID_OFFSET: usize = CORE_HEADER_LEN + 32;

fn leak<T>(v: T) -> &'static mut T {
    Box::leak(Box::new(v))
}

fn acct(
    key: Pubkey,
    owner: Pubkey,
    data: Vec<u8>,
    lamports: u64,
    writable: bool,
    signer: bool,
) -> AccountInfo<'static> {
    AccountInfo::new(
        leak(key),
        signer,
        writable,
        leak(lamports),
        Box::leak(data.into_boxed_slice()),
        leak(owner),
        false,
        0,
    )
}

fn mint_account(supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[45] = 1;
    d
}

fn portfolio_buf(owner: [u8; 32]) -> Vec<u8> {
    let mut a: sl::PortfolioAccountV16Account = Zeroable::zeroed();
    a.provenance_header.market_group_id = MARKET_GROUP.to_bytes();
    a.provenance_header.portfolio_account_id = PORTFOLIO.to_bytes();
    a.provenance_header.owner = owner;
    a.provenance_header.version = sl::V16PodU16::new(sl::V16_ACCOUNT_VERSION);
    a.provenance_header.layout_discriminator = sl::V16PodU16::new(sl::V16_LAYOUT_DISCRIMINATOR);
    a.owner = owner;
    a.legs[0].active = 1;
    a.legs[0].asset_index = sl::V16PodU32::new(ASSET_INDEX);
    a.legs[0].market_id = sl::V16PodU64::new(MARKET_ID);
    let mut buf = vec![0u8; sl::HEADER_LEN + sl::EXPECTED_PORTFOLIO_ACCOUNT_SIZE];
    buf[0..8].copy_from_slice(&sl::MAGIC.to_le_bytes());
    buf[8..10].copy_from_slice(&sl::VERSION.to_le_bytes());
    buf[10] = sl::KIND_PORTFOLIO;
    buf[sl::HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&a));
    buf
}

fn live_nft_pda_buf(bump: u8) -> Vec<u8> {
    let mut s: PositionNftV16 = Zeroable::zeroed();
    s.magic = sl::V16PodU64::new(POSITION_NFT_V16_MAGIC);
    s.version = POSITION_NFT_V16_VERSION;
    s.bump = bump;
    s.portfolio_account = PORTFOLIO.to_bytes();
    s.nft_mint = NFT_MINT.to_bytes();
    s.asset_index = sl::V16PodU32::new(ASSET_INDEX);
    s.market_id_at_mint = sl::V16PodU64::new(MARKET_ID);
    s.last_holder = OWNER.to_bytes();
    bytemuck::bytes_of(&s).to_vec()
}

fn registry_buf() -> Vec<u8> {
    let mut d = vec![0u8; NFT_REGISTRY_ACCOUNT_LEN];
    d[NFT_REGISTRY_PROGRAM_ID_OFFSET..NFT_REGISTRY_PROGRAM_ID_OFFSET + 32]
        .copy_from_slice(PROG.as_ref());
    d
}

/// Run `ReconcileBurnedNft` on a live NFT whose token was burned out of band.
/// Returns the nft_pda account so the caller can inspect the post-close state.
fn run_reconcile() -> (Result<(), ProgramError>, AccountInfo<'static>) {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let (extra_metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);

    let nft_pda = acct(
        nft_pda_key,
        PROG,
        live_nft_pda_buf(bump),
        PDA_RENT,
        true,
        false,
    );

    let accounts = vec![
        nft_pda.clone(),
        // #182: the mint must be WRITABLE now — reconcile closes it to reclaim
        // its rent, and refuses a read-only one.
        acct(
            NFT_MINT,
            TOKEN_2022_PROGRAM_ID,
            mint_account(0),
            0,
            true,
            false,
        ),
        acct(
            PORTFOLIO,
            PERCOLATOR_MAINNET,
            portfolio_buf(mint_auth.to_bytes()),
            0,
            true,
            false,
        ),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(
            registry,
            PERCOLATOR_MAINNET,
            registry_buf(),
            0,
            false,
            false,
        ),
        acct(
            PERCOLATOR_MAINNET,
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ),
        acct(OWNER, Pubkey::default(), vec![], 0, true, false), // 6 last_holder
        // #182 made these two REQUIRED rather than optional, so that the mint
        // and ExtraAccountMetaList rent can be reclaimed while nft_pda is still
        // alive. This fixture predates that change (#179) and was not updated
        // when it landed, which is what turned main's CI red.
        acct(extra_metas, PROG, vec![0u8; 8], PDA_RENT, true, false), // 7 (writable, closed)
        acct(
            TOKEN_2022_PROGRAM_ID,
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ), // 8
    ];

    // Permissionless: assert it, do not merely assume it.
    assert!(
        accounts.iter().all(|a| !a.is_signer),
        "ReconcileBurnedNft fixture must contain NO signer at all",
    );
    let r = processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT]);
    (r, nft_pda)
}

/// Drive `MintPositionNft` with `nft_pda` supplied in the given state.
/// `Rent::get()` (processor.rs:447) is the first syscall and sits AFTER the
/// `data_is_empty()` gate at `:417`, so `UnsupportedSysvar` is a clean sentinel
/// meaning "every pre-syscall check passed".
fn run_mint(nft_pda: AccountInfo<'static>) -> Result<(), ProgramError> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);

    let accounts = vec![
        acct(OWNER, Pubkey::default(), vec![], 1_000_000_000, true, true), // 0 owner, signer
        nft_pda,                                                           // 1
        acct(NFT_MINT, Pubkey::default(), vec![], 0, true, true),          // 2 fresh + signer
        acct(
            get_associated_token_address(&OWNER, &NFT_MINT),
            Pubkey::default(),
            vec![],
            0,
            true,
            false,
        ), // 3
        acct(
            PORTFOLIO,
            PERCOLATOR_MAINNET,
            portfolio_buf(OWNER.to_bytes()),
            0,
            true,
            false,
        ), // 4
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),       // 5
        acct(
            TOKEN_2022_PROGRAM_ID,
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ), // 6
        acct(ATA_PROGRAM_ID, Pubkey::default(), vec![], 0, false, false),  // 7 ata prog
        acct(
            Pubkey::default(),
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ), // 8 system
        acct(metas, Pubkey::default(), vec![], 0, true, false),            // 9
        acct(
            registry,
            PERCOLATOR_MAINNET,
            registry_buf(),
            0,
            false,
            false,
        ), // 10
        acct(
            PERCOLATOR_MAINNET,
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ), // 11
    ];

    let mut data = vec![TAG_MINT_POSITION_NFT];
    data.extend_from_slice(&(ASSET_INDEX as u16).to_le_bytes());
    processor::process(&PROG, &accounts, &data)
}

// -- 1. the close now hands the account back --------------------------------

#[test]
fn reconcile_hands_the_pda_back_to_the_system_program() {
    let (r, nft_pda) = run_reconcile();
    assert!(r.is_ok(), "reconcile must succeed: {r:?}");
    // The signer-free precondition is asserted inside run_reconcile().

    assert_eq!(**nft_pda.lamports.borrow(), 0, "lamports drained");
    assert!(nft_pda.data.borrow().iter().all(|b| *b == 0), "data zeroed",);
    assert_eq!(
        nft_pda.owner,
        &solana_program::system_program::id(),
        "assigned back to the System program — a same-transaction lamport credit          can no longer leave a program-owned husk behind",
    );
    // The accompanying `resize(0)` is `target_os = "solana"`-gated (see
    // release_closed_account_to_system), matching percolator-prog's
    // close_portfolio_account_to_market_slab, so it is not exercised host-side.
    // `a_revived_closed_pda_no_longer_bricks_the_mint_slot` below asserts the
    // resulting state is accepted by the mint path.
}

#[test]
fn the_zeroed_pda_is_rejected_by_every_handler_that_reads_it() {
    // Unchanged by the fix, and the other half of why the old state was a
    // deadlock: a zeroed PositionNft fails verification, so Burn, EmergencyBurn,
    // Reconcile and RepairExtraMetas could none of them have cleared it.
    let zeroed: PositionNftV16 = Zeroable::zeroed();
    assert!(verify_position_nft(&zeroed).is_err());
}

// -- 2. the brick is gone ----------------------------------------------------

#[test]
fn a_revived_closed_pda_no_longer_bricks_the_mint_slot() {
    // Exactly what an attacker's `ix1: System::transfer(-> nft_pda, rent)` now
    // produces after the close: System-owned and zero-length, but funded.
    // Reaching the first syscall proves every pre-syscall check passed.
    let (nft_pda_key, _) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let revived = acct(
        nft_pda_key,
        solana_program::system_program::id(),
        vec![],
        PDA_RENT,
        true,
        false,
    );

    let r = run_mint(revived);
    assert!(
        matches!(r, Err(ProgramError::UnsupportedSysvar)),
        "a revived closed PDA must no longer block minting, got {r:?}",
    );
}

// -- 3. regression guards ----------------------------------------------------

#[test]
fn guard_a_program_owned_full_length_pda_is_still_rejected() {
    // The mint gate itself is deliberately unchanged: if a program-owned,
    // full-length PDA ever arises again, mint must still refuse it. This pins
    // that the fix is in the CLOSE path, not a loosening of the mint gate.
    let (nft_pda_key, _) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let stale = acct(
        nft_pda_key,
        PROG,
        vec![0u8; POSITION_NFT_V16_LEN],
        PDA_RENT,
        true,
        false,
    );
    let r = run_mint(stale);
    assert!(
        matches!(r, Err(ProgramError::Custom(c)) if c == 1), // NftAlreadyMinted
        "the data_is_empty gate must still reject a full-length PDA, got {r:?}",
    );
}

#[test]
fn guard_a_live_nft_still_blocks_a_second_mint() {
    // The gate's real job, unaffected: a genuine live NFT still blocks re-mint.
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let live = acct(
        nft_pda_key,
        PROG,
        live_nft_pda_buf(bump),
        PDA_RENT,
        true,
        false,
    );
    let r = run_mint(live);
    assert!(matches!(r, Err(ProgramError::Custom(c)) if c == 1));
}

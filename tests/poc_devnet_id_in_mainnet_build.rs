//! The devnet wrapper program id must not compile into a mainnet binary.
//!
//! Before the `devnet` feature gate, `PERCOLATOR_DEVNET` was unconditional and a
//! default build -- the artifact a mainnet deploy produces -- trusted it end to
//! end. These tests pin both halves: a default build now REJECTS it, and a
//! `--features devnet` build still accepts it so devnet deploys keep working.
//!
//! The sibling repos state the rule this violates. percolator-prog's own
//! Cargo.toml, on its `devnet` feature:
//!
//!   "Mirrors percolator-stake's own `devnet` feature and its N-3 rationale: a
//!    devnet id must never compile into a mainnet binary, so that a compromised
//!    devnet deploy keypair cannot inherit mainnet authority."
//!
//! percolator-stake gates this same pair of ids the same way
//! (percolator-stake/src/processor.rs).

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{derive_nft_registry, verify_portfolio_program, PERCOLATOR_MAINNET},
    slab_types_v16 as sl,
    state_v16::{
        mint_authority_pda, position_nft_pda, PositionNftV16, POSITION_NFT_V16_MAGIC,
        POSITION_NFT_V16_VERSION,
    },
    token2022::TOKEN_2022_PROGRAM_ID,
    transfer_hook::{extra_account_metas_pda, process_execute},
};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey,
    sysvar::instructions as sysvar_instructions,
};

const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]);
const ALICE: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const BOB: Pubkey = Pubkey::new_from_array([0xB0; 32]);
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);
const SRC_ATA: Pubkey = Pubkey::new_from_array([0x71; 32]);
const DST_ATA: Pubkey = Pubkey::new_from_array([0x72; 32]);
/// The devnet wrapper id as a literal, so these tests can name it without
/// depending on the gated constant existing in this build.
const DEVNET_WRAPPER_ID: Pubkey =
    solana_program::pubkey!("DhSkE7uTb8HBUYYWF1xkxMYBGtLYJEoDq1tfBD7SnHcj");

const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;

fn leak<T>(v: T) -> &'static mut T {
    Box::leak(Box::new(v))
}

fn acct(key: Pubkey, owner: Pubkey, data: Vec<u8>, writable: bool) -> AccountInfo<'static> {
    AccountInfo::new(
        leak(key),
        false,
        writable,
        leak(0u64),
        Box::leak(data.into_boxed_slice()),
        leak(owner),
        false,
        0,
    )
}

fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn mint_account() -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[36..44].copy_from_slice(&1u64.to_le_bytes());
    d[45] = 1;
    d
}

/// A portfolio shaped exactly like a real one, but owned by whichever program
/// the caller names -- that is the whole variable under test.
fn portfolio_buf(escrow_owner: [u8; 32]) -> Vec<u8> {
    let mut a: sl::PortfolioAccountV16Account = Zeroable::zeroed();
    a.provenance_header.market_group_id = MARKET_GROUP.to_bytes();
    a.provenance_header.portfolio_account_id = PORTFOLIO.to_bytes();
    a.provenance_header.owner = escrow_owner;
    a.provenance_header.version = sl::V16PodU16::new(sl::V16_ACCOUNT_VERSION);
    a.provenance_header.layout_discriminator = sl::V16PodU16::new(sl::V16_LAYOUT_DISCRIMINATOR);
    a.owner = escrow_owner;
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

fn nft_pda_buf(bump: u8) -> Vec<u8> {
    let mut s: PositionNftV16 = Zeroable::zeroed();
    s.magic = sl::V16PodU64::new(POSITION_NFT_V16_MAGIC);
    s.version = POSITION_NFT_V16_VERSION;
    s.bump = bump;
    s.portfolio_account = PORTFOLIO.to_bytes();
    s.nft_mint = NFT_MINT.to_bytes();
    s.asset_index = sl::V16PodU32::new(ASSET_INDEX);
    s.market_id_at_mint = sl::V16PodU64::new(MARKET_ID);
    s.last_holder = ALICE.to_bytes();
    bytemuck::bytes_of(&s).to_vec()
}

fn build_sysvar(top_prog: &Pubkey, data: &[u8], accounts: &[Pubkey]) -> Vec<u8> {
    let mut ib: Vec<u8> = Vec::new();
    ib.extend_from_slice(&(accounts.len() as u16).to_le_bytes());
    for a in accounts {
        ib.push(0u8);
        ib.extend_from_slice(a.as_ref());
    }
    ib.extend_from_slice(top_prog.as_ref());
    ib.extend_from_slice(&(data.len() as u16).to_le_bytes());
    ib.extend_from_slice(data);
    let total = 2 + 2 + ib.len() + 2;
    let mut sv = vec![0u8; total];
    sv[0..2].copy_from_slice(&1u16.to_le_bytes());
    sv[2..4].copy_from_slice(&4u16.to_le_bytes());
    sv[4..4 + ib.len()].copy_from_slice(&ib);
    sv[total - 2..].copy_from_slice(&0u16.to_le_bytes());
    sv
}

/// Run the full transfer hook with every wrapper-bound account pointing at
/// `wrapper` -- the portfolio's owner, the `percolator_prog` account, and the
/// registry PDA's derivation base.
fn run_hook_under_wrapper(wrapper: Pubkey) -> Result<(), ProgramError> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);
    let (registry, _) = derive_nft_registry(&wrapper, &MARKET_GROUP);

    let mut t22_data = vec![12u8];
    t22_data.extend_from_slice(&1u64.to_le_bytes());
    t22_data.push(0);

    let accounts = vec![
        acct(SRC_ATA, TOKEN_2022_PROGRAM_ID, token_account(&NFT_MINT, &ALICE, 1), false),
        acct(NFT_MINT, TOKEN_2022_PROGRAM_ID, mint_account(), false),
        acct(DST_ATA, TOKEN_2022_PROGRAM_ID, token_account(&NFT_MINT, &BOB, 0), false),
        acct(ALICE, Pubkey::default(), vec![], false),
        acct(metas, PROG, vec![0u8; 261], false),
        acct(nft_pda_key, PROG, nft_pda_buf(bump), true),
        acct(PORTFOLIO, wrapper, portfolio_buf(mint_auth.to_bytes()), false),
        acct(wrapper, Pubkey::default(), vec![], false),
        acct(mint_auth, Pubkey::default(), vec![], false),
        acct(
            sysvar_instructions::ID,
            Pubkey::default(),
            build_sysvar(&TOKEN_2022_PROGRAM_ID, &t22_data, &[SRC_ATA, NFT_MINT, DST_ATA, ALICE]),
            false,
        ),
        acct(PROG, Pubkey::default(), vec![], false),
        acct(registry, wrapper, vec![], false),
    ];

    process_execute(&PROG, &accounts, 1)
}

// -- 1. a default (mainnet) build must not trust the devnet wrapper -----------

#[cfg(not(feature = "devnet"))]
#[test]
fn a_default_build_rejects_the_devnet_wrapper_id() {
    let devnet_owned = acct(PORTFOLIO, DEVNET_WRAPPER_ID, vec![], false);
    assert!(
        verify_portfolio_program(&devnet_owned).is_err(),
        "a default (mainnet) build must reject a portfolio owned by the DEVNET wrapper",
    );
}

#[cfg(not(feature = "devnet"))]
#[test]
fn a_default_build_rejects_it_through_the_whole_hook() {
    // End to end, not just the predicate.
    assert!(
        run_hook_under_wrapper(DEVNET_WRAPPER_ID).is_err(),
        "the full transfer hook must reject the devnet wrapper in a mainnet build",
    );
}

// -- 2. controls -------------------------------------------------------------

#[test]
fn control_the_mainnet_wrapper_is_accepted() {
    // Proves the rejection above is about the devnet id specifically, not a
    // harness that fails for everything.
    assert!(run_hook_under_wrapper(PERCOLATOR_MAINNET).is_ok());
    let owned = acct(PORTFOLIO, PERCOLATOR_MAINNET, vec![], false);
    assert!(verify_portfolio_program(&owned).is_ok());
}

#[test]
fn control_an_unrelated_program_is_rejected() {
    let stranger = Pubkey::new_from_array([0xEE; 32]);
    let owned = acct(PORTFOLIO, stranger, vec![], false);
    assert!(verify_portfolio_program(&owned).is_err());
    assert!(run_hook_under_wrapper(stranger).is_err());
}

// -- 3. a devnet build must still work ---------------------------------------

#[cfg(feature = "devnet")]
#[test]
fn a_devnet_build_still_accepts_the_devnet_wrapper() {
    // The gate must not break devnet deploys: built with --features devnet, the
    // same id is trusted exactly as before.
    assert_eq!(percolator_nft::cpi_v16::PERCOLATOR_DEVNET, DEVNET_WRAPPER_ID);
    let devnet_owned = acct(PORTFOLIO, DEVNET_WRAPPER_ID, vec![], false);
    assert!(verify_portfolio_program(&devnet_owned).is_ok());
    assert!(run_hook_under_wrapper(DEVNET_WRAPPER_ID).is_ok());
}

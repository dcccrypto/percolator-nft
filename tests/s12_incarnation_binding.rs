//! S1-2 (audit 2026-10-17): host tests of the NFT program's incarnation binding with a
//! RECORDING CPI stub, so "the wrapper release (tag 82) was / was not invoked" is observable.
//! The real-binary equivalents (LiteSVM, real wrapper + Token-2022) live in percolator-prog
//! tests/v16_nft_e2e.rs (s12_*).

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{derive_nft_registry, PERCOLATOR_MAINNET},
    instruction::{TAG_EMERGENCY_BURN, TAG_RECONCILE_BURNED_NFT},
    processor, slab_types_v16 as sl,
    state_v16::{
        mint_authority_pda, position_nft_pda, PositionNftV16, POSITION_NFT_V16_MAGIC,
        POSITION_NFT_V16_VERSION,
    },
    token2022::{get_associated_token_address, TOKEN_2022_PROGRAM_ID},
    transfer_hook::extra_account_metas_pda,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, instruction::Instruction,
    program_error::ProgramError, program_stubs, pubkey::Pubkey,
};
use std::cell::{Cell, RefCell};
use std::sync::Once;

thread_local! {
    /// The portfolio's LIVE incarnation id for the test running on this thread.
    static LIVE_ID: Cell<u64> = const { Cell::new(7) };
    /// (program_id, first data byte) of every CPI this thread made.
    static CPIS: RefCell<Vec<(Pubkey, u8)>> = const { RefCell::new(Vec::new()) };
}

struct Recorder;
impl program_stubs::SyscallStubs for Recorder {
    fn sol_invoke_signed(
        &self,
        ix: &Instruction,
        _infos: &[AccountInfo],
        _seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        CPIS.with(|c| c.borrow_mut().push((ix.program_id, ix.data.first().copied().unwrap_or(0))));
        Ok(())
    }
}
static INSTALL: Once = Once::new();
fn install_recorder() {
    INSTALL.call_once(|| {
        program_stubs::set_syscall_stubs(Box::new(Recorder));
    });
}
fn set_live_id(id: u64) {
    install_recorder();
    LIVE_ID.with(|c| c.set(id));
    CPIS.with(|c| c.borrow_mut().clear());
}
/// Wrapper tag 82 = UnwrapEscrowedPortfolio.
fn unwrap_cpis() -> usize {
    CPIS.with(|c| c.borrow().iter().filter(|(p, t)| *p == PERCOLATOR_MAINNET && *t == 82).count())
}

const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]);
const ALICE: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);
const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;
/// S1-2: portfolio incarnation id used by the fixtures (nonzero, as the wrapper allocates).
const PORTFOLIO_INCARNATION: u64 = 7;

/// Rent-exempt minimums, `(128 + len) * 3480 * 2`.
const PDA_RENT: u64 = 2_275_920; // 199 bytes
const METAS_RENT: u64 = 2_707_440; // 261 bytes
                                   // The mint is allocated `mint_space + metadata_tlv_size + 128` = 338 + 120 + 128
                                   // = 586 bytes and funded at minimum_balance(586). Nothing ever reallocs it — the
                                   // Token-2022 metadata Initialize writes into the existing TLV region — so the
                                   // trailing 128 bytes of slack are funded and never refunded.
const MINT_RENT: u64 = 4_969_440; // 586 bytes

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

fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn mint_account(supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[45] = 1;
    d
}

fn portfolio_buf(live_id: u64) -> Vec<u8> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let mut a: sl::PortfolioAccountV16Account = Zeroable::zeroed();
    a.provenance_header.market_group_id = MARKET_GROUP.to_bytes();
    a.provenance_header.portfolio_account_id = PORTFOLIO.to_bytes();
    a.provenance_header.owner = mint_auth.to_bytes();
    a.provenance_header.version = sl::V16PodU16::new(sl::V16_ACCOUNT_VERSION);
    a.provenance_header.layout_discriminator = sl::V16PodU16::new(sl::V16_LAYOUT_DISCRIMINATOR);
    a.owner = mint_auth.to_bytes();
    // Terminal: no active leg — the EmergencyBurn-eligible shape.
    let mut buf = vec![0u8; sl::PORTFOLIO_ACCOUNT_LEN];
    // S1-2: the wrapper-assigned permanent portfolio id (incarnation) the NFT is bound to.
    buf[sl::PORTFOLIO_ID_OFF..sl::PORTFOLIO_ID_OFF + 8].copy_from_slice(&live_id.to_le_bytes());
    buf[0..8].copy_from_slice(&sl::MAGIC.to_le_bytes());
    buf[8..10].copy_from_slice(&sl::VERSION.to_le_bytes());
    buf[10] = sl::KIND_PORTFOLIO;
    buf[sl::HEADER_LEN..sl::HEADER_LEN + sl::EXPECTED_PORTFOLIO_ACCOUNT_SIZE].copy_from_slice(bytemuck::bytes_of(&a));
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
    s.portfolio_market_group = MARKET_GROUP.to_bytes();
    s.portfolio_id_at_mint = sl::V16PodU64::new(PORTFOLIO_INCARNATION);
    s.last_holder = ALICE.to_bytes();
    bytemuck::bytes_of(&s).to_vec()
}

/// The three accounts whose fate this test is about, shared across a scenario so
/// their post-state can be inspected.
struct Fixture {
    nft_pda: AccountInfo<'static>,
    nft_mint: AccountInfo<'static>,
    extra_metas: AccountInfo<'static>,
}

fn fixture(mint_supply: u64) -> Fixture {
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);
    Fixture {
        nft_pda: acct(nft_pda_key, PROG, nft_pda_buf(bump), PDA_RENT, true, false),
        nft_mint: acct(
            NFT_MINT,
            TOKEN_2022_PROGRAM_ID,
            mint_account(mint_supply),
            MINT_RENT,
            true,
            false,
        ),
        extra_metas: acct(metas, PROG, vec![7u8; 261], METAS_RENT, true, false),
    }
}

const RECONCILE_ACCOUNTS: usize = 9;

fn reconcile(f: &Fixture) -> (Result<(), ProgramError>, AccountInfo<'static>) {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let last_holder = acct(ALICE, Pubkey::default(), vec![], 0, true, false);
    let accounts = vec![
        f.nft_pda.clone(),
        f.nft_mint.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(LIVE_ID.with(|c| c.get())), 0, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
        last_holder.clone(),
        f.extra_metas.clone(),
        acct(TOKEN_2022_PROGRAM_ID, Pubkey::default(), vec![], 0, false, false),
    ];
    assert_eq!(accounts.len(), RECONCILE_ACCOUNTS);
    (processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT]), last_holder)
}

fn burn_emergency(f: &Fixture) -> Result<(), ProgramError> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let accounts = vec![
        acct(ALICE, Pubkey::default(), vec![], 0, true, true),
        f.nft_pda.clone(),
        f.nft_mint.clone(),
        acct(
            get_associated_token_address(&ALICE, &NFT_MINT),
            TOKEN_2022_PROGRAM_ID,
            token_account(&NFT_MINT, &ALICE, 1),
            0,
            true,
            false,
        ),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(LIVE_ID.with(|c| c.get())), 1_000_000, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(TOKEN_2022_PROGRAM_ID, Pubkey::default(), vec![], 0, false, false),
        f.extra_metas.clone(),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
    ];
    processor::process(&PROG, &accounts, &[TAG_EMERGENCY_BURN])
}

// -- Reconcile ---------------------------------------------------------------

#[test]
fn reconcile_of_a_current_nft_releases_the_escrow_to_the_last_holder() {
    set_live_id(PORTFOLIO_INCARNATION);
    let f = fixture(0);
    let (r, _) = reconcile(&f);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(unwrap_cpis(), 1, "the wrapper's UnwrapEscrowedPortfolio (tag 82) is invoked once");
}

#[test]
fn reconcile_of_a_stale_nft_never_releases_the_live_escrow_but_reclaims_the_rent() {
    set_live_id(PORTFOLIO_INCARNATION + 2); // the portfolio keypair was re-created
    let f = fixture(0);
    let (r, last_holder) = reconcile(&f);
    assert!(r.is_ok(), "the dead NFT's rent is still reclaimable: {r:?}");
    assert_eq!(unwrap_cpis(), 0, "S1-2: tag 82 must NOT be invoked for a stale NFT");
    assert_eq!(**f.nft_pda.lamports.borrow(), 0, "PDA closed");
    assert_eq!(**last_holder.lamports.borrow(), PDA_RENT + METAS_RENT, "rent to the recorded last holder");
}

// -- EmergencyBurn -------------------------------------------------------------

#[test]
fn emergency_burn_of_a_current_nft_unwraps() {
    set_live_id(PORTFOLIO_INCARNATION);
    let f = fixture(1);
    let r = burn_emergency(&f);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(unwrap_cpis(), 1);
}

#[test]
fn emergency_burn_of_a_stale_nft_burns_without_unwrapping() {
    set_live_id(PORTFOLIO_INCARNATION + 2);
    let f = fixture(1);
    let r = burn_emergency(&f);
    assert!(r.is_ok(), "{r:?}");
    assert_eq!(unwrap_cpis(), 0, "S1-2: tag 82 must NOT be invoked for a stale NFT");
    assert_eq!(**f.nft_pda.lamports.borrow(), 0, "PDA closed");
}

#[test]
fn an_unallocated_live_id_is_treated_as_stale() {
    set_live_id(0);
    let f = fixture(1);
    assert!(burn_emergency(&f).is_ok());
    assert_eq!(unwrap_cpis(), 0);
}

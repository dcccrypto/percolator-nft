//! PoC: `ReconcileBurnedNft` closes the PositionNft PDA but abandons the NFT
//! mint and the ExtraAccountMetaList PDA, and once it has run neither can ever
//! be reclaimed.
//!
//! Before this fix, `#102` had closed exactly this leak — for the two burn instructions that existed
//! at the time, `BurnPositionNft` and `EmergencyBurn`, both of which now call
//! `close_extra_metas` and close the mint. `ReconcileBurnedNft` (tag 7) was
//! added later by `#138` and takes only seven accounts: `nft_pda`, `nft_mint`,
//! `portfolio`, `mint_auth`, `nft_registry`, `percolator_prog`, `last_holder`.
//! There is no `extra_metas` slot and no token-program slot, so it structurally
//! cannot close either account.
//!
//! The leak is permanent, not merely deferred. Reconcile closes `nft_pda`, and
//! every path that could reclaim the two accounts requires `nft_pda` to still be
//! program-owned and to hold a valid `PositionNftV16`:
//!   * `BurnPositionNft` / `EmergencyBurn` — the only callers of
//!     `close_extra_metas` and the only signers of a mint close — additionally
//!     require the holder's ATA to hold `amount == 1`, but supply is already 0.
//!   * `RepairExtraMetas` requires `nft_pda.owner == program_id`.
//!
//! Both are dead the moment Reconcile returns.

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{derive_nft_registry, PERCOLATOR_MAINNET},
    instruction::{TAG_EMERGENCY_BURN, TAG_RECONCILE_BURNED_NFT},
    processor,
    slab_types_v16 as sl,
    state_v16::{
        mint_authority_pda, position_nft_pda, PositionNftV16, POSITION_NFT_V16_MAGIC,
        POSITION_NFT_V16_VERSION,
    },
    token2022::{get_associated_token_address, TOKEN_2022_PROGRAM_ID},
    transfer_hook::extra_account_metas_pda,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]);
const ALICE: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);
const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;

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

fn portfolio_buf() -> Vec<u8> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let mut a: sl::PortfolioAccountV16Account = Zeroable::zeroed();
    a.provenance_header.market_group_id = MARKET_GROUP.to_bytes();
    a.provenance_header.portfolio_account_id = PORTFOLIO.to_bytes();
    a.provenance_header.owner = mint_auth.to_bytes();
    a.provenance_header.version = sl::V16PodU16::new(sl::V16_ACCOUNT_VERSION);
    a.provenance_header.layout_discriminator = sl::V16PodU16::new(sl::V16_LAYOUT_DISCRIMINATOR);
    a.owner = mint_auth.to_bytes();
    // Terminal: no active leg — the EmergencyBurn-eligible shape.
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

/// `extended = false` builds the pre-fix seven-account call, which must now be
/// rejected; `true` builds the full nine-account form.
fn run_reconcile_form(f: &Fixture, extended: bool) -> Result<(), ProgramError> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let accounts = vec![
        f.nft_pda.clone(),
        f.nft_mint.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(), 0, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
        acct(ALICE, Pubkey::default(), vec![], 0, true, false),
    ];
    let mut accounts = accounts;
    if extended {
        accounts.push(f.extra_metas.clone());
        accounts.push(acct(
            TOKEN_2022_PROGRAM_ID,
            Pubkey::default(),
            vec![],
            0,
            false,
            false,
        ));
    }
    processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT])
}

/// EmergencyBurn is the only other path that closes BOTH the mint and the
/// extra-metas PDA. Run it against the post-reconcile state.
fn run_emergency_burn(f: &Fixture) -> Result<(), ProgramError> {
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
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(), 0, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(TOKEN_2022_PROGRAM_ID, Pubkey::default(), vec![], 0, false, false),
        f.extra_metas.clone(),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
    ];
    processor::process(&PROG, &accounts, &[TAG_EMERGENCY_BURN])
}

// -- 1. the fix: both rents are now reclaimed -------------------------------

#[test]
fn reconcile_reclaims_the_metas_rent_and_issues_the_mint_close() {
    let f = fixture(0); // supply 0 — the out-of-band-burn state Reconcile handles
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let last_holder = acct(ALICE, Pubkey::default(), vec![], 0, true, false);

    let accounts = vec![
        f.nft_pda.clone(),
        f.nft_mint.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(), 0, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
        last_holder.clone(),
        f.extra_metas.clone(),
        acct(TOKEN_2022_PROGRAM_ID, Pubkey::default(), vec![], 0, false, false),
    ];
    let r = processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT]);
    assert!(r.is_ok(), "reconcile must succeed: {r:?}");

    assert_eq!(**f.nft_pda.lamports.borrow(), 0, "PDA rent reclaimed");
    assert_eq!(**f.extra_metas.lamports.borrow(), 0, "metas rent reclaimed");
    // Conservation: the last holder received exactly what this program moved.
    // The mint close is a Token-2022 CPI, a no-op under host SyscallStubs, so
    // MINT_RENT is not included here — what this asserts is that the two rents
    // percolator-nft moves DIRECTLY both land on the right address.
    assert_eq!(
        **last_holder.lamports.borrow(),
        PDA_RENT + METAS_RENT,
        "both directly-moved rents credited to the recorded last holder",
    );
}

#[test]
fn the_stranded_amount_this_recovers() {
    // Recorded so the cost is explicit rather than implied.
    assert_eq!(METAS_RENT + MINT_RENT, 7_676_880); // ≈ 0.00768 SOL per NFT
}

// -- 2. the accounts are required, deliberately ------------------------------

#[test]
fn the_short_seven_account_form_is_rejected() {
    // Reconcile is permissionless, irreversible and one-shot. Making the two
    // reclaiming accounts OPTIONAL would let any stale client or griefer destroy
    // the rent permanently with one short call, with no second chance. So a
    // short call must fail loudly instead.
    let f = fixture(0);
    let r = run_reconcile_form(&f, false);
    assert!(
        matches!(r, Err(ProgramError::NotEnoughAccountKeys)),
        "a 7-account call must be rejected, got {r:?}",
    );
    assert_eq!(
        **f.extra_metas.lamports.borrow(),
        METAS_RENT,
        "and must not have destroyed anything on the way out",
    );
}

#[test]
fn a_substituted_token_program_is_rejected() {
    let f = fixture(0);
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);
    let accounts = vec![
        f.nft_pda.clone(),
        f.nft_mint.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(), 0, true, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false, false),
        acct(ALICE, Pubkey::default(), vec![], 0, true, false),
        f.extra_metas.clone(),
        acct(Pubkey::new_from_array([0xCC; 32]), Pubkey::default(), vec![], 0, false, false),
    ];
    let r = processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT]);
    assert!(
        matches!(r, Err(ProgramError::IncorrectProgramId)),
        "a substituted token program must be rejected, got {r:?}",
    );
}

// -- 3. control: parity with the burn paths ----------------------------------

#[test]
fn control_emergency_burn_reclaims_both_when_the_pda_is_alive() {
    // Establishes that these accounts were always closeable — Reconcile simply
    // had no way to reach them. This is what makes the omission a bug rather
    // than an inherent limitation.
    let f = fixture(1); // a live NFT: supply 1, holder holds it
    let r = run_emergency_burn(&f);
    assert!(r.is_ok(), "EmergencyBurn on a live NFT must succeed: {r:?}");
    assert_eq!(
        **f.extra_metas.lamports.borrow(),
        0,
        "EmergencyBurn already reclaimed the extra-metas rent (#102)",
    );
}

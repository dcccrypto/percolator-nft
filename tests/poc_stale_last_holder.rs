//! PoC: a marketplace sale leaves `last_holder` at the SELLER, and
//! `ReconcileBurnedNft` then pays the entire escrowed portfolio to that seller.
//!
//! PR #159 gated the `last_holder` write on a genuine top-level Token-2022
//! transfer to close the #152/#153 forgery. Its stated residual was:
//!
//!   "an NFT acquired ONLY via marketplace-CPI leaves `last_holder` stale,
//!    affecting only the rare out-of-band-burn ReconcileBurnedNft recovery
//!    (which then routes to the prior genuine holder - no theft, no new drain)."
//!
//! These tests exercise the four links of the chain that claim depends on:
//!
//!   1. mint            -> last_holder = minter          (processor.rs:500)
//!   2. marketplace CPI -> hook returns Ok, NO write     (transfer_hook.rs:166,542)
//!   3. out-of-band burn (supply -> 0), the #138 scenario
//!   4. ReconcileBurnedNft -> buyer REJECTED, seller PAID (processor.rs:1275,1326)

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{derive_nft_registry, PERCOLATOR_MAINNET},
    instruction::TAG_RECONCILE_BURNED_NFT,
    processor,
    slab_types_v16 as sl,
    state_v16::{
        mint_authority_pda, position_nft_pda, PositionNftV16, POSITION_NFT_V16_LEN,
        POSITION_NFT_V16_MAGIC, POSITION_NFT_V16_VERSION,
    },
    token2022::TOKEN_2022_PROGRAM_ID,
    transfer_hook::{extra_account_metas_pda, process_execute},
};
use solana_program::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey,
    sysvar::instructions as sysvar_instructions,
};

// -- cast --------------------------------------------------------------------
const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]); // this NFT program
const ALICE: Pubkey = Pubkey::new_from_array([0xA1; 32]); // minter, then SELLER
const BOB: Pubkey = Pubkey::new_from_array([0xB0; 32]); // BUYER
const MARKETPLACE: Pubkey = Pubkey::new_from_array([0x33; 32]); // escrow marketplace
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);
const SRC_ATA: Pubkey = Pubkey::new_from_array([0x71; 32]);
const DST_ATA: Pubkey = Pubkey::new_from_array([0x72; 32]);

const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;
const PDA_RENT: u64 = 2_000_000;

fn leak<T>(v: T) -> &'static mut T {
    Box::leak(Box::new(v))
}

fn acct(
    key: Pubkey,
    owner: Pubkey,
    data: Vec<u8>,
    lamports: u64,
    writable: bool,
) -> AccountInfo<'static> {
    AccountInfo::new(
        leak(key),
        false,
        writable,
        leak(lamports),
        Box::leak(data.into_boxed_slice()),
        leak(owner),
        false,
        0,
    )
}

/// Token-2022 base token-account image (165 bytes).
fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // Initialized
    d
}

/// Same, plus a `TransferHookAccount` TLV entry (ExtensionType 15, 1-byte
/// PodBool). Token-2022 sets `transferring` on source AND destination for the
/// duration of a real transfer, so this is what the hook sees in flight.
fn token_account_ext(mint: &Pubkey, owner: &Pubkey, amount: u64, transferring: bool) -> Vec<u8> {
    token_account_ext_typed(mint, owner, amount, transferring, 2)
}

fn token_account_ext_typed(
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    transferring: bool,
    account_type: u8,
) -> Vec<u8> {
    let mut d = token_account(mint, owner, amount);
    d.resize(171, 0);
    d[165] = account_type;
    d[166..168].copy_from_slice(&15u16.to_le_bytes()); // TransferHookAccount
    d[168..170].copy_from_slice(&1u16.to_le_bytes()); // value length
    d[170] = u8::from(transferring);
    d
}

/// The layout a REAL ATA has: the ATA program installs `ImmutableOwner`
/// (type 7, length 0) first, then Token-2022 appends `TransferHookAccount`
/// (type 15, length 1) because the mint carries the TransferHook extension.
/// A parser that mishandles the leading zero-length entry would silently read
/// `false` here and restore the very bug this fix closes.
fn token_account_realistic_ata(
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    transferring: bool,
) -> Vec<u8> {
    let mut d = token_account(mint, owner, amount);
    d.resize(175, 0);
    d[165] = 2; // account_type = Account
    d[166..168].copy_from_slice(&7u16.to_le_bytes()); // ImmutableOwner
    d[168..170].copy_from_slice(&0u16.to_le_bytes()); // length 0, no value
    d[170..172].copy_from_slice(&15u16.to_le_bytes()); // TransferHookAccount
    d[172..174].copy_from_slice(&1u16.to_le_bytes());
    d[174] = u8::from(transferring);
    d
}

/// Token-2022 base mint image; `supply` is a u64 at offset 36.
fn mint_account(supply: u64) -> Vec<u8> {
    let mut d = vec![0u8; 200];
    d[36..44].copy_from_slice(&supply.to_le_bytes());
    d[45] = 1; // is_initialized
    d
}

/// Wrapper-framed portfolio, escrowed to the mint-authority PDA (#105).
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
    a.legs[0].stale = 0;

    let mut buf = vec![0u8; sl::HEADER_LEN + sl::EXPECTED_PORTFOLIO_ACCOUNT_SIZE];
    buf[0..8].copy_from_slice(&sl::MAGIC.to_le_bytes());
    buf[8..10].copy_from_slice(&sl::VERSION.to_le_bytes());
    buf[10] = sl::KIND_PORTFOLIO;
    buf[sl::HEADER_LEN..].copy_from_slice(bytemuck::bytes_of(&a));
    buf
}

fn nft_pda_buf(bump: u8, last_holder: [u8; 32]) -> Vec<u8> {
    let mut s: PositionNftV16 = Zeroable::zeroed();
    s.magic = sl::V16PodU64::new(POSITION_NFT_V16_MAGIC);
    s.version = POSITION_NFT_V16_VERSION;
    s.bump = bump;
    s.portfolio_account = PORTFOLIO.to_bytes();
    s.nft_mint = NFT_MINT.to_bytes();
    s.asset_index = sl::V16PodU32::new(ASSET_INDEX);
    s.market_id_at_mint = sl::V16PodU64::new(MARKET_ID);
    s.last_holder = last_holder;
    bytemuck::bytes_of(&s).to_vec()
}

/// Instructions-sysvar image with exactly one top-level instruction.
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
    sv[0..2].copy_from_slice(&1u16.to_le_bytes()); // num instructions
    sv[2..4].copy_from_slice(&4u16.to_le_bytes()); // offset of instruction 0
    sv[4..4 + ib.len()].copy_from_slice(&ib);
    sv[total - 2..].copy_from_slice(&0u16.to_le_bytes()); // current index
    sv
}

fn read_last_holder(nft_pda: &AccountInfo) -> [u8; 32] {
    let d = nft_pda.data.borrow();
    bytemuck::from_bytes::<PositionNftV16>(&d[..POSITION_NFT_V16_LEN]).last_holder
}

/// Drive `process_execute` for a transfer whose TOP-LEVEL instruction is
/// `top_prog`. Returns the result plus the nft_pda so callers can inspect it.
fn run_hook(
    top_prog: Pubkey,
    top_data: Vec<u8>,
    top_accounts: Vec<Pubkey>,
    starting_last_holder: [u8; 32],
    in_flight: Option<(bool, bool)>,
) -> (Result<(), ProgramError>, AccountInfo<'static>) {
    run_hook_inner(top_prog, top_data, top_accounts, starting_last_holder, in_flight, false)
}

fn run_hook_inner(
    top_prog: Pubkey,
    top_data: Vec<u8>,
    top_accounts: Vec<Pubkey>,
    starting_last_holder: [u8; 32],
    in_flight: Option<(bool, bool)>,
    realistic: bool,
) -> (Result<(), ProgramError>, AccountInfo<'static>) {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);

    let nft_pda = acct(
        nft_pda_key,
        PROG,
        nft_pda_buf(bump, starting_last_holder),
        PDA_RENT,
        true,
    );

    let accounts = vec![
        acct(
            SRC_ATA,
            TOKEN_2022_PROGRAM_ID,
            match in_flight {
                None => token_account(&NFT_MINT, &ALICE, 1),
                Some((src, _)) if realistic => {
                    token_account_realistic_ata(&NFT_MINT, &ALICE, 1, src)
                }
                Some((src, _)) => token_account_ext(&NFT_MINT, &ALICE, 1, src),
            },
            0,
            false,
        ),
        acct(NFT_MINT, TOKEN_2022_PROGRAM_ID, mint_account(1), 0, false),
        acct(
            DST_ATA,
            TOKEN_2022_PROGRAM_ID,
            match in_flight {
                None => token_account(&NFT_MINT, &BOB, 0),
                Some((_, dst)) if realistic => {
                    token_account_realistic_ata(&NFT_MINT, &BOB, 0, dst)
                }
                Some((_, dst)) => token_account_ext(&NFT_MINT, &BOB, 0, dst),
            },
            0,
            false,
        ),
        acct(ALICE, Pubkey::default(), vec![], 0, false),
        acct(metas, PROG, vec![0u8; 261], 0, false),
        nft_pda.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(mint_auth.to_bytes()), 0, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false),
        acct(
            sysvar_instructions::ID,
            Pubkey::default(),
            build_sysvar(&top_prog, &top_data, &top_accounts),
            0,
            false,
        ),
        acct(PROG, Pubkey::default(), vec![], 0, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false),
    ];

    let r = process_execute(&PROG, &accounts, 1);
    (r, nft_pda)
}

/// Drive `ReconcileBurnedNft` (tag 7) with `recipient` supplied as account 6.
/// Returns the result plus the recipient's lamports afterwards.
fn run_reconcile(
    last_holder_in_state: [u8; 32],
    recipient: Pubkey,
) -> (Result<(), ProgramError>, u64) {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);

    let recipient_ai = acct(recipient, Pubkey::default(), vec![], 0, true);

    let accounts = vec![
        acct(nft_pda_key, PROG, nft_pda_buf(bump, last_holder_in_state), PDA_RENT, true),
        // supply == 0: the NFT really was burned out of band
        acct(NFT_MINT, TOKEN_2022_PROGRAM_ID, mint_account(0), 0, false),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(mint_auth.to_bytes()), 0, true),
        acct(mint_auth, Pubkey::default(), vec![], 0, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false),
        recipient_ai.clone(),
    ];

    let r = processor::process(&PROG, &accounts, &[TAG_RECONCILE_BURNED_NFT]);
    let got = **recipient_ai.lamports.borrow();
    (r, got)
}

// -- 1. the finding ----------------------------------------------------------

#[test]
fn marketplace_sale_without_the_extension_degrades_to_prior_behaviour() {
    // Alice minted, so last_holder == Alice (processor.rs:500).
    // She now sells to Bob through a marketplace that moves the token by CPI,
    // so the TOP-LEVEL instruction is the marketplace, not Token-2022.
    let (r, nft_pda) = run_hook(MARKETPLACE, vec![7u8], vec![], ALICE.to_bytes(), None);

    assert!(r.is_ok(), "the sale itself must succeed (#145 composability): {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        ALICE.to_bytes(),
        "last_holder still points at the SELLER after the sale settled",
    );
    assert_ne!(read_last_holder(&nft_pda), BOB.to_bytes(), "the buyer was never recorded");
}

// -- 2. control: the harness DOES observe a write ----------------------------

#[test]
fn control_a_direct_transfer_does_record_the_buyer() {
    // Identical in every respect except the top-level program. This is the A/B
    // control: it proves the assertion above is a real skipped write, not a
    // harness that silently fails before reaching the write.
    let mut data = vec![12u8]; // TransferChecked
    data.extend_from_slice(&1u64.to_le_bytes());
    data.push(0); // decimals
    let top_accounts = vec![SRC_ATA, NFT_MINT, DST_ATA, ALICE];

    let (r, nft_pda) = run_hook(TOKEN_2022_PROGRAM_ID, data, top_accounts, ALICE.to_bytes(), None);

    assert!(r.is_ok(), "genuine direct transfer must succeed: {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        BOB.to_bytes(),
        "a genuine top-level Token-2022 transfer DOES record the buyer",
    );
}

// -- 3+4. the impact: buyer locked out, seller paid --------------------------

#[test]
fn buyer_cannot_reconcile_his_own_burned_nft() {
    // Bob owns the NFT and burns it out of band (#138). He tries to recover.
    let (r, _) = run_reconcile(ALICE.to_bytes(), BOB);
    assert!(
        matches!(r, Err(ProgramError::Custom(c)) if c == 7), // NftError::NotNftHolder
        "the actual owner is rejected by the last_holder gate, got {r:?}",
    );
}

#[test]
fn seller_is_paid_the_escrowed_portfolio_and_the_rent() {
    // Anyone may crank it; the escrow + rent go to the RECORDED last_holder.
    let (r, alice_lamports) = run_reconcile(ALICE.to_bytes(), ALICE);
    assert!(r.is_ok(), "reconcile to the stale seller succeeds: {r:?}");
    assert_eq!(
        alice_lamports, PDA_RENT,
        "PDA rent swept to the seller (the unwrap CPI likewise names her as new owner)",
    );
}

#[test]
fn control_a_correctly_recorded_buyer_can_reconcile() {
    // Same accounts, same burned mint, same everything as the rejection test --
    // only the recorded last_holder differs. This isolates the gate at
    // processor.rs:1275 as the sole reason Bob was refused above.
    let (r, bob_lamports) = run_reconcile(BOB.to_bytes(), BOB);
    assert!(r.is_ok(), "with the buyer correctly recorded, he recovers: {r:?}");
    assert_eq!(bob_lamports, PDA_RENT);
}

// -- 5. the fix ---------------------------------------------------------------

#[test]
fn marketplace_sale_in_flight_records_the_buyer() {
    // The same marketplace-CPI sale as above, except the source and destination
    // now carry Token-2022's in-flight `transferring` flag -- exactly what the
    // token program sets around `invoke_execute`. The buyer is now recorded.
    let (r, nft_pda) = run_hook(MARKETPLACE, vec![7u8], vec![], ALICE.to_bytes(), Some((true, true)));

    assert!(r.is_ok(), "the marketplace sale must still succeed: {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        BOB.to_bytes(),
        "the buyer who actually holds the NFT is now the recorded last_holder",
    );
}

#[test]
fn buyer_recorded_by_the_fix_can_reconcile_and_seller_cannot() {
    // The end-to-end consequence: run the sale, take the resulting state, and
    // feed it to ReconcileBurnedNft. The roles are now the right way round.
    let (_, nft_pda) = run_hook(MARKETPLACE, vec![7u8], vec![], ALICE.to_bytes(), Some((true, true)));
    let recorded = read_last_holder(&nft_pda);

    let (bob_r, bob_lamports) = run_reconcile(recorded, BOB);
    assert!(bob_r.is_ok(), "the real owner recovers his own position: {bob_r:?}");
    assert_eq!(bob_lamports, PDA_RENT);

    let (alice_r, _) = run_reconcile(recorded, ALICE);
    assert!(
        matches!(alice_r, Err(ProgramError::Custom(c)) if c == 7),
        "the paid-out seller is now refused, got {alice_r:?}",
    );
}

// -- 6. #152/#153 must stay closed -------------------------------------------

#[test]
fn spoofed_direct_execute_still_cannot_forge_last_holder() {
    // The #152/#153 attack: an attacker invokes Execute top-level with a
    // dest_ata they own. No transfer is in flight, so both flags read false and
    // the write must still be suppressed.
    let (r, nft_pda) = run_hook(MARKETPLACE, vec![7u8], vec![], ALICE.to_bytes(), Some((false, false)));

    assert!(r.is_ok(), "gates pass, as before: {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        ALICE.to_bytes(),
        "a spoofed Execute cannot forge last_holder",
    );
}

#[test]
fn a_half_set_flag_pair_is_not_enough() {
    // Both source and destination must be in flight. Token-2022 always sets the
    // pair together, so a single flag is not a real transfer window.
    for (src, dst) in [(true, false), (false, true)] {
        let (r, nft_pda) =
            run_hook(MARKETPLACE, vec![7u8], vec![], ALICE.to_bytes(), Some((src, dst)));
        assert!(r.is_ok(), "gates still pass for ({src},{dst}): {r:?}");
        assert_eq!(
            read_last_holder(&nft_pda),
            ALICE.to_bytes(),
            "half-set pair ({src},{dst}) must not authorise the write",
        );
    }
}

#[test]
fn a_non_account_type_tlv_is_not_honoured() {
    // TransferHookAccount is account-scoped. A buffer whose account_type byte is
    // not `Account` must not have its TLV honoured, even with the flag byte set.
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let (metas, _) = extra_account_metas_pda(&NFT_MINT, &PROG);
    let (registry, _) = derive_nft_registry(&PERCOLATOR_MAINNET, &MARKET_GROUP);

    let nft_pda = acct(nft_pda_key, PROG, nft_pda_buf(bump, ALICE.to_bytes()), PDA_RENT, true);
    let accounts = vec![
        acct(
            SRC_ATA,
            TOKEN_2022_PROGRAM_ID,
            token_account_ext_typed(&NFT_MINT, &ALICE, 1, true, 1), // 1 = Mint, not Account
            0,
            false,
        ),
        acct(NFT_MINT, TOKEN_2022_PROGRAM_ID, mint_account(1), 0, false),
        acct(
            DST_ATA,
            TOKEN_2022_PROGRAM_ID,
            token_account_ext_typed(&NFT_MINT, &BOB, 0, true, 1),
            0,
            false,
        ),
        acct(ALICE, Pubkey::default(), vec![], 0, false),
        acct(metas, PROG, vec![0u8; 261], 0, false),
        nft_pda.clone(),
        acct(PORTFOLIO, PERCOLATOR_MAINNET, portfolio_buf(mint_auth.to_bytes()), 0, false),
        acct(PERCOLATOR_MAINNET, Pubkey::default(), vec![], 0, false),
        acct(mint_auth, Pubkey::default(), vec![], 0, false),
        acct(
            sysvar_instructions::ID,
            Pubkey::default(),
            build_sysvar(&MARKETPLACE, &[7u8], &[]),
            0,
            false,
        ),
        acct(PROG, Pubkey::default(), vec![], 0, false),
        acct(registry, PERCOLATOR_MAINNET, vec![], 0, false),
    ];

    let r = process_execute(&PROG, &accounts, 1);
    assert!(r.is_ok(), "gates still pass: {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        ALICE.to_bytes(),
        "a non-Account account_type must not authorise the write",
    );
}

#[test]
fn the_real_on_chain_ata_layout_is_parsed_correctly() {
    // ImmutableOwner (type 7, len 0) precedes TransferHookAccount in every real
    // ATA. The zero-length entry must be walked over, not tripped on.
    let (r, nft_pda) = run_hook_inner(
        MARKETPLACE,
        vec![7u8],
        vec![],
        ALICE.to_bytes(),
        Some((true, true)),
        true,
    );
    assert!(r.is_ok(), "marketplace sale must succeed: {r:?}");
    assert_eq!(
        read_last_holder(&nft_pda),
        BOB.to_bytes(),
        "the buyer must be recorded through a realistic multi-extension TLV",
    );

    // ...and the same layout with the flag clear must NOT authorise the write.
    let (r2, pda2) = run_hook_inner(
        MARKETPLACE,
        vec![7u8],
        vec![],
        ALICE.to_bytes(),
        Some((false, false)),
        true,
    );
    assert!(r2.is_ok());
    assert_eq!(read_last_holder(&pda2), ALICE.to_bytes());
}

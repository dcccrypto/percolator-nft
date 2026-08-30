//! PoC: `GetPositionValue` documents itself as fail-CLOSED on stale state, but
//! reads no staleness field at all.
//!
//! `src/valuation.rs:9-11`:
//!
//!   "This instruction does NOT return a value via CPI (no `set_return_data`).
//!    It is fail-CLOSED: stale/slot-reuse/no-active-leg conditions return an
//!    error rather than `Ok(())` so callers cannot silently observe invalid
//!    state."
//!
//! Before the fix only two of those three were implemented — `no_active_leg`
//! and `slot_reuse` returned `Err`, the "stale" half did not. The handler never reads `leg.stale`,
//! `leg.b_stale`, `stale_state`, `b_stale_state`, `liquidation_lock`,
//! `resolved_payout_receipt.present` or `close_progress`, and emits none of
//! them either — nor does it emit a `status` line on the success path — so a
//! consumer has neither an error nor a field to check.
//!
//! The crate already has one consolidated gate for exactly this. Its doc
//! (`slab_types_v16.rs:559-561`) calls `leg_transfer_gate` the "single
//! consolidated gate for both the transfer-hook and the wrapper's B-3
//! `TransferPortfolioOwnership`". Valuation now routes through it instead of
//! reimplementing one of its five checks, so the two can no longer disagree.
//! These tests pin that: for every state, the hook's gate and the valuation
//! reach the same verdict.

use bytemuck::Zeroable;
use percolator_nft::{
    cpi_v16::{transfer_gate_check, PERCOLATOR_MAINNET},
    instruction::TAG_GET_POSITION_VALUE,
    processor,
    slab_types_v16::{self as sl, decode_portfolio},
    state_v16::{
        mint_authority_pda, position_nft_pda, PositionNftV16, POSITION_NFT_V16_MAGIC,
        POSITION_NFT_V16_VERSION,
    },
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

// NOTE on coverage: this instruction's `status=` vocabulary cannot be asserted
// from an integration test. `solana-msg`'s non-BPF `sol_log` is a bare
// `println!` that bypasses `program_stubs`, so `SyscallStubs` cannot observe
// `msg!` output on this solana-program pin. The vocabulary is instead pinned by
// unit tests on the pure `gate_status` mapping in `src/valuation.rs`, which is
// what the emission reads from.

const PROG: Pubkey = Pubkey::new_from_array([9u8; 32]);
const ALICE: Pubkey = Pubkey::new_from_array([0xA1; 32]);
const PORTFOLIO: Pubkey = Pubkey::new_from_array([0x50; 32]);
const MARKET_GROUP: Pubkey = Pubkey::new_from_array([0x60; 32]);
const NFT_MINT: Pubkey = Pubkey::new_from_array([0x11; 32]);
const ASSET_INDEX: u32 = 7;
const MARKET_ID: u64 = 42;

/// Which blocked state to stamp into an otherwise healthy portfolio.
#[derive(Clone, Copy, Debug)]
enum Blocked {
    None,
    LegStale,
    LegBStale,
    PortfolioStale,
    PortfolioBStale,
    LiquidationLock,
    ResolvedReceipt,
    CloseInProgress,
    /// The control: this one valuation DOES fail closed on.
    NoActiveLeg,
}

fn leak<T>(v: T) -> &'static mut T {
    Box::leak(Box::new(v))
}

fn acct(key: Pubkey, owner: Pubkey, data: Vec<u8>) -> AccountInfo<'static> {
    AccountInfo::new(
        leak(key),
        false,
        false,
        leak(1_000_000u64),
        Box::leak(data.into_boxed_slice()),
        leak(owner),
        false,
        0,
    )
}

fn portfolio_buf(state: Blocked) -> Vec<u8> {
    portfolio_buf_with_market_id(state, MARKET_ID)
}

fn portfolio_buf_with_market_id(state: Blocked, market_id: u64) -> Vec<u8> {
    let (mint_auth, _) = mint_authority_pda(&PROG);
    let mut a: sl::PortfolioAccountV16Account = Zeroable::zeroed();
    a.provenance_header.market_group_id = MARKET_GROUP.to_bytes();
    a.provenance_header.portfolio_account_id = PORTFOLIO.to_bytes();
    a.provenance_header.owner = mint_auth.to_bytes();
    a.provenance_header.version = sl::V16PodU16::new(sl::V16_ACCOUNT_VERSION);
    a.provenance_header.layout_discriminator = sl::V16PodU16::new(sl::V16_LAYOUT_DISCRIMINATOR);
    a.owner = mint_auth.to_bytes();

    if !matches!(state, Blocked::NoActiveLeg) {
        a.legs[0].active = 1;
        a.legs[0].asset_index = sl::V16PodU32::new(ASSET_INDEX);
        a.legs[0].market_id = sl::V16PodU64::new(market_id);
    }

    match state {
        Blocked::None | Blocked::NoActiveLeg => {}
        Blocked::LegStale => a.legs[0].stale = 1,
        Blocked::LegBStale => a.legs[0].b_stale = 1,
        Blocked::PortfolioStale => a.stale_state = 1,
        Blocked::PortfolioBStale => a.b_stale_state = 1,
        Blocked::LiquidationLock => a.liquidation_lock = 1,
        Blocked::ResolvedReceipt => a.resolved_payout_receipt.present = 1,
        Blocked::CloseInProgress => {
            a.close_progress.active = 1;
            a.close_progress.asset_index = sl::V16PodU32::new(ASSET_INDEX);
        }
    }

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

/// Run `GetPositionValue` (tag 3) over a portfolio in the given state.
fn run_valuation(state: Blocked) -> Result<(), ProgramError> {
    run_valuation_with_market_id(state, MARKET_ID)
}

fn run_valuation_with_market_id(state: Blocked, market_id: u64) -> Result<(), ProgramError> {
    let (nft_pda_key, bump) = position_nft_pda(&PORTFOLIO, MARKET_ID, &PROG);
    let accounts = vec![
        acct(nft_pda_key, PROG, nft_pda_buf(bump)),
        acct(
            PORTFOLIO,
            PERCOLATOR_MAINNET,
            portfolio_buf_with_market_id(state, market_id),
        ),
    ];
    processor::process(&PROG, &accounts, &[TAG_GET_POSITION_VALUE])
}

/// Ask the crate's own consolidated gate — the one the transfer hook uses —
/// whether this portfolio is transferable.
fn gate_says_transferable(state: Blocked) -> bool {
    let buf = portfolio_buf(state);
    let p = decode_portfolio(&buf).expect("fixture must decode");
    transfer_gate_check(p, ASSET_INDEX).is_ok()
}

// -- 1. the fix -------------------------------------------------------------

#[test]
fn valuation_now_fails_closed_on_every_blocked_state() {
    for state in [
        Blocked::LegStale,
        Blocked::LegBStale,
        Blocked::PortfolioStale,
        Blocked::PortfolioBStale,
        Blocked::LiquidationLock,
        Blocked::ResolvedReceipt,
        Blocked::CloseInProgress,
    ] {
        assert!(
            !gate_says_transferable(state),
            "{state:?}: fixture must actually be blocked by leg_transfer_gate",
        );
        let r = run_valuation(state);
        assert!(
            matches!(r, Err(ProgramError::Custom(c)) if c == 24), // TransferBlocked
            "{state:?}: valuation must now fail CLOSED as documented, got {r:?}",
        );
    }
}

// -- 2. controls -------------------------------------------------------------

#[test]
fn control_a_clean_portfolio_is_still_valued() {
    // The fix must not break the normal path: a healthy position still reports.
    assert!(gate_says_transferable(Blocked::None));
    assert!(
        run_valuation(Blocked::None).is_ok(),
        "a clean portfolio must still produce a valuation",
    );
}

#[test]
fn control_no_active_leg_keeps_its_own_error_code() {
    // #100/#118's arm is preserved verbatim rather than folded into the generic
    // blocked case, so existing consumers keying on LegNotActive still work.
    let r = run_valuation(Blocked::NoActiveLeg);
    assert!(
        matches!(r, Err(ProgramError::Custom(c)) if c == 22), // LegNotActive
        "no_active_leg must still return LegNotActive, got {r:?}",
    );
}

// -- 4. ordering: a terminal signal must not be masked by a transient one ----

#[test]
fn slot_reuse_outranks_a_transient_stale_flag() {
    // A portfolio that is BOTH slot-reused and stale must report the slot reuse.
    // MarketIdMismatch is TERMINAL and routes the holder to EmergencyBurn;
    // b_stale is transient and merely says "retry later". Reporting the
    // transient one would send the holder into an indefinite wait. This mirrors
    // the transfer hook, which runs verify_bound_leg before transfer_gate_check.
    let r = run_valuation_with_market_id(Blocked::PortfolioBStale, MARKET_ID + 57);
    assert!(
        matches!(r, Err(ProgramError::Custom(c)) if c == 25), // MarketIdMismatch
        "slot reuse must outrank the transient stale flag, got {r:?}",
    );
}

#[test]
fn control_slot_reuse_alone_is_unchanged() {
    let r = run_valuation_with_market_id(Blocked::None, MARKET_ID + 57);
    assert!(matches!(r, Err(ProgramError::Custom(c)) if c == 25));
}

// -- 5. the one-directional invariant that is actually true ------------------

#[test]
fn every_gate_blocked_state_is_also_valuation_blocked() {
    // NOT an equivalence: valuation is deliberately STRICTER, because it also
    // rejects a market_id mismatch that leg_transfer_gate never examines. The
    // true property is the one-way implication.
    for state in [
        Blocked::LegStale,
        Blocked::LegBStale,
        Blocked::PortfolioStale,
        Blocked::PortfolioBStale,
        Blocked::LiquidationLock,
        Blocked::ResolvedReceipt,
        Blocked::CloseInProgress,
        Blocked::NoActiveLeg,
    ] {
        assert!(!gate_says_transferable(state), "{state:?}");
        assert!(run_valuation(state).is_err(), "{state:?} must also be blocked");
    }
    // ...and the converse genuinely does not hold:
    assert!(gate_says_transferable(Blocked::None));
    assert!(run_valuation_with_market_id(Blocked::None, MARKET_ID + 57).is_err());
}

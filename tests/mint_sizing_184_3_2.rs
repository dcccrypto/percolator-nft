//! #184 (3.2): the position-NFT mint account sizes, checked against the REAL
//! Token-2022 program instead of trusted.
//!
//! The mint path (`process_mint_position_nft`) creates the mint at EXACTLY
//! `mint_space`, initializes three pre-mint extensions and `InitializeMint2`, tops
//! up the rent delta, and then lets `initialize_token_metadata` realloc the account
//! in place to `mint_space + metadata_tlv_size`. Both sizes come from
//! `processor::mint_account_sizes`.
//!
//! main carried a `+ 128` slack on the create ("#184 (3.2) NOT TAKEN"), which the
//! deployed lineage had already removed (53fcd90) because it made `InitializeMint2`
//! fail on-chain. No test covered either version, since no harness here reached the
//! Token-2022 CPIs. This one replays the SAME instruction sequence, built with the
//! crate's own `token2022` builders and sizes, as top-level instructions in LiteSVM,
//! with a keypair standing in for the mint-authority PDA.
//!
//! What it pins:
//! - the exact sizes succeed for both names the program mints (LONG and SHORT), the
//!   final account length is exactly `mint_space + metadata_tlv_size`, and the
//!   account is rent-exempt at that length. So the hand-rolled TLV arithmetic
//!   is exact, neither short (the realloc would fail) nor padded.
//! - negative control: the old `+ 128` create slack makes `InitializeMint2` fail.
//! - negative control: `metadata_tlv_size - 1` of top-up leaves the realloc'd mint
//!   below rent-exemption, so the transaction fails. The top-up is load-bearing.

use litesvm::LiteSVM;
use percolator_nft::processor::{mint_account_sizes, NFT_SYMBOL};
use percolator_nft::token2022;
use solana_keypair::Keypair;
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use solana_rent::Rent;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;

fn nft_name(direction: &str) -> String {
    // Must match process_mint_position_nft's `format!`.
    format!("Percolator Position \u{2014} {}", direction)
}

struct Outcome {
    result: Result<(), String>,
    data_len: usize,
    lamports: u64,
}

/// Replays the mint path's Token-2022 sequence. `create_slack` is added to the
/// created size; `topup_tlv_delta` adjusts the metadata size the top-up is sized for.
fn run(name: &str, create_slack: u64, topup_tlv_delta: i64) -> Outcome {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    let mint = Keypair::new();
    let mint_authority = Keypair::new(); // stands in for the MINT_AUTHORITY PDA
    let hook_program = Pubkey::new_unique(); // stands in for this program's id
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    let rent = Rent::default();
    let (mint_space, metadata_tlv_size) = mint_account_sizes(name, NFT_SYMBOL, "");
    let created = mint_space + create_slack;
    let final_size = mint_space as usize + metadata_tlv_size;
    let topup_final = (final_size as i64 + topup_tlv_delta) as usize;
    // saturating: with the old +128 slack the create already over-funds the final size.
    let top_up = rent
        .minimum_balance(topup_final)
        .saturating_sub(rent.minimum_balance(created as usize));

    let ixs: Vec<Instruction> = vec![
        system_instruction::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent.minimum_balance(created as usize),
            created,
            &token2022::TOKEN_2022_PROGRAM_ID,
        ),
        token2022::initialize_metadata_pointer(&mint.pubkey(), &Pubkey::default(), &mint.pubkey()),
        token2022::initialize_transfer_hook(&mint.pubkey(), &Pubkey::default(), &hook_program),
        token2022::initialize_mint_close_authority(&mint.pubkey(), &mint_authority.pubkey()),
        token2022::initialize_mint2(&mint.pubkey(), &mint_authority.pubkey()),
        system_instruction::transfer(&payer.pubkey(), &mint.pubkey(), top_up),
        token2022::initialize_token_metadata(
            &mint.pubkey(),
            &mint_authority.pubkey(),
            &mint_authority.pubkey(),
            &payer.pubkey(),
            name,
            NFT_SYMBOL,
            "",
        ),
    ];
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer, &mint, &mint_authority],
        svm.latest_blockhash(),
    );
    let result = svm
        .send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?}\n{}", e.err, e.meta.logs.join("\n")));
    let (data_len, lamports) = svm
        .get_account(&mint.pubkey())
        .map(|a| (a.data.len(), a.lamports))
        .unwrap_or((0, 0));
    Outcome {
        result,
        data_len,
        lamports,
    }
}

#[test]
fn exact_sizes_mint_succeeds_for_both_directions() {
    for dir in ["LONG", "SHORT"] {
        let name = nft_name(dir);
        let (mint_space, tlv) = mint_account_sizes(&name, NFT_SYMBOL, "");
        let o = run(&name, 0, 0);
        o.result
            .unwrap_or_else(|e| panic!("{dir}: exact-size mint sequence must succeed: {e}"));
        assert_eq!(
            o.data_len,
            mint_space as usize + tlv,
            "{dir}: realloc'd mint length must be EXACTLY mint_space + metadata_tlv_size \
             (proves the hand-rolled TLV arithmetic is exact)"
        );
        assert!(
            o.lamports >= Rent::default().minimum_balance(o.data_len),
            "{dir}: mint must be rent-exempt at its final length"
        );
    }
}

#[test]
fn old_128_byte_create_slack_breaks_initialize_mint2() {
    let o = run(&nft_name("LONG"), 128, 0);
    let err = o.result.expect_err(
        "#184 (3.2): creating the mint with the old +128 slack must fail. If this now \
         passes, Token-2022 stopped enforcing the exact length and the note in \
         processor.rs is stale",
    );
    assert!(err.contains("InvalidAccountData"), "{err}");
}

#[test]
fn metadata_topup_is_load_bearing() {
    let o = run(&nft_name("SHORT"), 0, -1);
    let err = o.result.expect_err(
        "a top-up one byte short of the metadata TLV must leave the mint below \
         rent-exemption and fail the transaction",
    );
    assert!(err.contains("InsufficientFundsForRent"), "{err}");
}

//! v2.2: the NFT vendors the wrapper's header VERSION and the portfolio account length, and
//! compares VERSION for EXACT equality in `decode_portfolio` — a stale value turns every
//! portfolio entry point into `PortfolioDecodeFailed` (Custom 23). `layout_parity_160.rs`
//! pins the ENGINE half (offsets, sizes, layout discriminator); the wrapper-side half
//! (`VERSION`, `PORTFOLIO_ACCOUNT_LEN`) had no test in this repo, only a wrapper-side
//! parity script. This reads the wrapper SOURCE and asserts both.
//!
//! Wrapper source: `NFT_WRAPPER_SRC` (path to v16_program.rs), else
//! `../percolator-prog/src/v16_program.rs`. If neither exists the test SKIPS loudly unless
//! `NFT_REQUIRE_WRAPPER_SRC=1`, which turns a missing sibling into a hard failure (CI sets it).

use percolator_nft::slab_types_v16::{EXPECTED_PORTFOLIO_ACCOUNT_SIZE, HEADER_LEN, VERSION};

fn wrapper_src() -> Option<String> {
    let p = std::env::var("NFT_WRAPPER_SRC").unwrap_or_else(|_| {
        format!("{}/../percolator-prog/src/v16_program.rs", env!("CARGO_MANIFEST_DIR"))
    });
    match std::fs::read_to_string(&p) {
        Ok(s) => Some(s),
        Err(e) => {
            assert!(
                std::env::var("NFT_REQUIRE_WRAPPER_SRC").as_deref() != Ok("1"),
                "NFT_REQUIRE_WRAPPER_SRC=1 but no wrapper source at {p}: {e}"
            );
            eprintln!("SKIP wrapper_version_parity: no wrapper source at {p} ({e})");
            None
        }
    }
}

#[test]
fn nft_header_version_equals_the_wrapper_version() {
    let Some(src) = wrapper_src() else { return };
    let needle = "pub const VERSION: u16 = ";
    let i = src.find(needle).expect("wrapper has no `pub const VERSION: u16`");
    let v: u16 = src[i + needle.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap();
    assert_eq!(
        VERSION, v,
        "NFT slab_types_v16::VERSION must equal the wrapper's state::VERSION (flag day)"
    );
}

#[test]
fn portfolio_account_len_equals_header_plus_pod_plus_matcher_tail_and_trailer() {
    // wrapper: PORTFOLIO_ACCOUNT_LEN = HEADER_LEN + PORTFOLIO_STATE_LEN + 104 (matcher cfg) + 24 (id trailer)
    const MATCHER_CONFIG_LEN: usize = 104;
    const IDENTITY_TRAILER_LEN: usize = 24;
    let len = HEADER_LEN + EXPECTED_PORTFOLIO_ACCOUNT_SIZE + MATCHER_CONFIG_LEN + IDENTITY_TRAILER_LEN;
    assert_eq!(len, 10091);
    let Some(src) = wrapper_src() else { return };
    assert!(
        src.contains(&format!("assert!(PORTFOLIO_ACCOUNT_LEN == {len})")),
        "wrapper no longer pins PORTFOLIO_ACCOUNT_LEN == {len}; NFT mirror would be out of step"
    );
}

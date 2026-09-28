//! #184 audit tail — items 2.2 and 3.1.
//!
//! Both are program-source changes and therefore deploy-gated. These tests prove
//! the change is what it claims to be; they do not prove it is deployed.

use percolator_nft::token2022;
use solana_program::pubkey::Pubkey;

/// Offsets inside the serialized extension-initialize instruction:
/// `[extension_tag][sub_tag][authority: 32][second_pubkey: 32]`
const AUTHORITY_OFF: usize = 2;
const AUTHORITY_LEN: usize = 32;

fn authority_bytes(data: &[u8]) -> &[u8] {
    &data[AUTHORITY_OFF..AUTHORITY_OFF + AUTHORITY_LEN]
}

#[test]
fn zero_authority_serializes_as_all_zero_bytes() {
    // OptionalNonZeroPubkey reads all-zero as `None`. This is the property the
    // whole of 3.1 rests on, so assert it on the real encoder rather than assume it.
    let mint = Pubkey::new_unique();
    let ix = token2022::initialize_metadata_pointer(&mint, &Pubkey::default(), &mint);
    assert_eq!(authority_bytes(&ix.data), &[0u8; 32]);

    let ix = token2022::initialize_transfer_hook(&mint, &Pubkey::default(), &Pubkey::new_unique());
    assert_eq!(authority_bytes(&ix.data), &[0u8; 32]);
}

#[test]
fn a_real_authority_still_serializes_non_zero() {
    // Control: the encoder is not simply always writing zeros. Without this, the
    // test above would pass against a broken encoder.
    let mint = Pubkey::new_unique();
    let auth = Pubkey::new_unique();
    let ix = token2022::initialize_metadata_pointer(&mint, &auth, &mint);
    assert_eq!(authority_bytes(&ix.data), auth.as_ref());
    assert_ne!(authority_bytes(&ix.data), &[0u8; 32]);
}

/// 3.1 — the MINT PATH must pass the zero pubkey, not `mint_auth`.
///
/// Structural, and deliberately so. The encoder tests above prove zero means None;
/// what they cannot prove is that the mint path actually passes zero. A behavioural
/// test would need a full Token-2022 mint under LiteSVM with the `.so` built. This
/// asserts the call site, which is the part that regressed-by-omission in the first
/// place and the part a future edit would silently undo.
#[test]
fn mint_path_passes_the_zero_authority_for_both_extensions() {
    let src = include_str!("../src/processor.rs");

    for call in ["initialize_metadata_pointer(", "initialize_transfer_hook("] {
        let at = src
            .find(call)
            .unwrap_or_else(|| panic!("{call} not found in processor.rs"));
        // Scan to the MATCHING close paren, not the first one — `Pubkey::default()`
        // contains its own, which an earlier version of this test tripped over.
        let bytes = src.as_bytes();
        let mut depth = 0usize;
        let mut end = at;
        for (k, &b) in bytes[at..].iter().enumerate() {
            if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 {
                    end = at + k + 1;
                    break;
                }
            }
        }
        let args = &src[at..end];
        assert!(
            args.contains("&Pubkey::default()"),
            "#184 (3.1): {call} must pass the ZERO pubkey as authority so the \
             extension is permanently immutable — found: {args}"
        );
        assert!(
            !args.contains("mint_auth.key"),
            "#184 (3.1): {call} must NOT pass mint_auth as authority — found: {args}"
        );
    }
}

/// 2.2 — the normal burn path validates the registry; the two RECOVERY paths
/// deliberately do not, and say why.
///
/// The audit proposed making all four sites symmetric with mint. That is right for
/// `BurnPositionNft` and wrong for `EmergencyBurn` / `ReconcileBurnedNft`: those are
/// recovery paths whose purpose is releasing an already-stranded position. Requiring
/// a healthy registry there converts "stranded but recoverable" into "stranded
/// permanently".
///
/// This was not reasoned out in advance — adding the check everywhere failed two
/// existing tests in `poc_reconcile_rent_leak.rs`, whose fixtures build an EMPTY
/// registry precisely because recovery must not depend on one. This test pins the
/// resulting asymmetry as intentional so it is not "fixed" again later.
#[test]
fn registry_validation_is_on_the_normal_path_and_deliberately_absent_from_recovery() {
    let src = include_str!("../src/processor.rs");
    let lines: Vec<&str> = src.lines().collect();

    let unwrap_sites: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("cpi_unwrap_portfolio("))
        .map(|(i, _)| i)
        .collect();

    assert_eq!(
        unwrap_sites.len(),
        3,
        "expected 3 unwrap call sites (BurnPositionNft, EmergencyBurn, ReconcileBurnedNft)"
    );

    // Site 0 is the normal burn path: it MUST validate.
    let normal = lines[unwrap_sites[0].saturating_sub(25)..unwrap_sites[0]].join("\n");
    assert!(
        normal.contains("validate_nft_registry("),
        "#184 (2.2): BurnPositionNft is the normal path and must validate the registry"
    );

    // Sites 1 and 2 are recovery paths: they must NOT validate, and must carry the
    // reason, so the omission reads as a decision rather than an oversight.
    for &i in &unwrap_sites[1..] {
        let window = lines[i.saturating_sub(25)..i].join("\n");
        assert!(
            !window.contains("validate_nft_registry("),
            "line {}: a recovery path must NOT gate on registry health — that bricks \
             the stranded positions it exists to rescue",
            i + 1
        );
        assert!(
            window.contains("DELIBERATELY NOT"),
            "line {}: the absence of validation on a recovery path must be documented, \
             or the next audit will 'fix' it and brick recovery",
            i + 1
        );
    }
}

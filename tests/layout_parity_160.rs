//! GH#160 — the vendored portfolio mirror, checked against the REAL engine layout.
//!
//! `slab_types_v16.rs` mirrors the converged v17 `PortfolioAccountV16Account` and
//! reads it by `bytemuck` cast in `decode_portfolio`. That cast is the only place
//! portfolio bytes are interpreted, and every security decision downstream — owner,
//! the `market_id` slot-reuse anchor, the lock/stale transfer gates — is a read at a
//! byte offset through it.
//!
//! The module's `const_assert!`s measure the mirror against ITSELF. They prove
//! internal consistency and say nothing about correspondence to the engine. That is
//! exactly the failure SCHEMA_DRIFT_v12.19.md warns about: "mirror schema drift can
//! mask itself as compile-pass". If the engine inserts or reorders a field ahead of
//! the ones read here, the provenance checks still pass while `owner` and the gate
//! flags come from the wrong bytes — mint against a position you do not own,
//! transfer decisions on garbage.
//!
//! These tests compare the mirror to the pinned real engine crate, so drift is a
//! FAILING TEST rather than a silent misread. The pin is deliberate: bumping it is a
//! decision with a diff to read, not something that follows `main` on its own.

use core::mem::{align_of, offset_of, size_of};

use percolator::PortfolioAccountV16Account as EnginePortfolio;
use percolator_nft::slab_types_v16::PortfolioAccountV16Account as MirrorPortfolio;

#[test]
fn mirror_total_size_matches_the_engine() {
    // The headline number. `EXPECTED_PORTFOLIO_ACCOUNT_SIZE` is 9227 and is asserted
    // against the mirror at compile time — here it is asserted against the thing it
    // is supposed to describe.
    assert_eq!(
        size_of::<MirrorPortfolio>(),
        size_of::<EnginePortfolio>(),
        "the vendored portfolio mirror has drifted from the engine's layout — \
         decode_portfolio reads every security-relevant field at a fixed offset, so \
         this is a silent misread, not a compile error"
    );
}

#[test]
fn mirror_alignment_matches_the_engine() {
    // A bytemuck cast over a differently-aligned type is a different failure from a
    // differently-sized one, and it would not show up in the size check.
    assert_eq!(
        align_of::<MirrorPortfolio>(),
        align_of::<EnginePortfolio>(),
        "mirror alignment differs from the engine's"
    );
}

/// Every field the NFT program actually reads, at its byte offset in both types.
///
/// Scoped to what is read rather than to every field: those are the offsets a
/// security decision depends on, and pinning fields nobody reads would make this
/// test fail on harmless upstream churn and get weakened or deleted.
#[test]
fn every_field_the_nft_program_reads_sits_at_the_same_offset() {
    assert_eq!(
        offset_of!(MirrorPortfolio, owner),
        offset_of!(EnginePortfolio, owner),
        "`owner` offset drift — mint/burn authorization reads this; a wrong offset \
         means minting against a position you do not own"
    );
    assert_eq!(
        offset_of!(MirrorPortfolio, provenance_header),
        offset_of!(EnginePortfolio, provenance_header),
        "`provenance_header` offset drift — the market_id slot-reuse anchor and the \
         header checks are read through this"
    );
    assert_eq!(
        offset_of!(MirrorPortfolio, capital),
        offset_of!(EnginePortfolio, capital),
        "`capital` offset drift — position valuation reads this"
    );
}

#[test]
fn the_provenance_header_itself_matches() {
    // The header is where market_id lives, and market_id is the slot-reuse anchor
    // the transfer gate turns on. A header that is the right SIZE but the wrong
    // SHAPE would pass the total-size check above.
    use percolator::ProvenanceHeaderV16Account as EngineHeader;
    use percolator_nft::slab_types_v16::ProvenanceHeaderV16Account as MirrorHeader;
    assert_eq!(
        size_of::<MirrorHeader>(),
        size_of::<EngineHeader>(),
        "provenance header size drift"
    );
    // Pin EVERY header field, not a sample. The header is small and entirely
    // security-relevant: `market_group_id` + `portfolio_account_id` are the
    // slot-reuse anchor the transfer gate turns on, `owner` is the authorization,
    // and `version`/`layout_discriminator` are what make a mismatched account fail
    // closed instead of being reinterpreted.
    assert_eq!(
        offset_of!(MirrorHeader, market_group_id),
        offset_of!(EngineHeader, market_group_id),
        "`market_group_id` offset drift — part of the slot-reuse anchor; a wrong \
         offset makes transfer-gate decisions read garbage"
    );
    assert_eq!(
        offset_of!(MirrorHeader, portfolio_account_id),
        offset_of!(EngineHeader, portfolio_account_id),
        "`portfolio_account_id` offset drift"
    );
    assert_eq!(
        offset_of!(MirrorHeader, owner),
        offset_of!(EngineHeader, owner),
        "header `owner` offset drift"
    );
    assert_eq!(
        offset_of!(MirrorHeader, version),
        offset_of!(EngineHeader, version),
        "`version` offset drift — this is what makes a foreign account fail closed"
    );
    assert_eq!(
        offset_of!(MirrorHeader, layout_discriminator),
        offset_of!(EngineHeader, layout_discriminator),
        "`layout_discriminator` offset drift"
    );
}

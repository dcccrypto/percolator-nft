//! SDK parity fixture binary for percolator-nft.
//!
//! Emits the JSON that `percolator-sdk/scripts/check-parity-fixtures.mjs`
//! compares against `percolator-sdk/specs/nft-parity.json`.
//!
//!   cargo run --quiet --bin sdk_parity_fixtures
//!
//! #375: this binary did not exist, so the Parity Gate's `percolator-nft` target
//! failed with `cargo run failed` on every run — and had done since at least
//! 2026-08-23. Three of the gate's four targets were in that state, which meant
//! ABI drift in prog, stake and nft had NO automated detection at all. Every
//! drift defect found in that period (sdk#376, sdk#379, nft#182) was found by
//! hand.
//!
//! WHY offset_of! AND NOT LITERALS. The whole value of this file is that it reads
//! the real struct. A hand-copied offset table would restate the same numbers the
//! spec already holds, so the check would compare a copy against a copy and pass
//! no matter what the program does — the exact failure mode of the `const_assert!`s
//! described in #160, and of the stale `CYCLE_CAP` copy in percolator-keeper.
//! If `PositionNftV16` changes, these values move and the gate goes red.
//!
//! No serde: this crate builds an on-chain program, and the fixture shape is
//! small and fixed, so the JSON is emitted directly rather than adding a
//! dependency to the program's graph for a dev-only binary.

use core::mem::offset_of;
use percolator_nft::state_v16::{
    PositionNftV16, MINT_AUTHORITY_SEED, POSITION_NFT_SEED, POSITION_NFT_V16_LEN,
};

fn main() {
    // Keys are emitted in sorted order to match the committed spec, which the
    // SDK writes with sorted keys. Sorting here rather than relying on
    // declaration order keeps the diff stable when a field is added.
    let offsets: [(&str, usize); 14] = [
        ("asset_index", offset_of!(PositionNftV16, asset_index)),
        (
            "basis_pos_q_at_mint",
            offset_of!(PositionNftV16, basis_pos_q_at_mint),
        ),
        ("bump", offset_of!(PositionNftV16, bump)),
        (
            "epoch_snap_at_mint",
            offset_of!(PositionNftV16, epoch_snap_at_mint),
        ),
        ("f_snap_at_mint", offset_of!(PositionNftV16, f_snap_at_mint)),
        // #375 caught this the moment the gate could run: the committed spec
        // still called this field "reserved". #138 renamed `_reserved` ->
        // `last_holder` at the SAME offset (167) with the SAME total length
        // (199), so nothing broke at runtime and nothing flagged it — the SDK
        // reads by offset. A naming drift is exactly the kind that survives
        // indefinitely without a gate, and then misleads whoever next reads the
        // spec to work out what a byte range means.
        ("last_holder", offset_of!(PositionNftV16, last_holder)),
        ("magic", offset_of!(PositionNftV16, magic)),
        (
            "market_id_at_mint",
            offset_of!(PositionNftV16, market_id_at_mint),
        ),
        ("minted_at", offset_of!(PositionNftV16, minted_at)),
        ("nft_mint", offset_of!(PositionNftV16, nft_mint)),
        (
            "portfolio_account",
            offset_of!(PositionNftV16, portfolio_account),
        ),
        (
            "position_owner_at_mint",
            offset_of!(PositionNftV16, position_owner_at_mint),
        ),
        ("side_at_mint", offset_of!(PositionNftV16, side_at_mint)),
        ("version", offset_of!(PositionNftV16, version)),
    ];

    let mut out = String::from("{\n  \"offsets\": {\n");
    for (i, (name, off)) in offsets.iter().enumerate() {
        let comma = if i + 1 == offsets.len() { "" } else { "," };
        out.push_str(&format!("    \"{name}\": {off}{comma}\n"));
    }
    out.push_str("  },\n");
    out.push_str(&format!(
        "  \"position_nft_len\": {POSITION_NFT_V16_LEN},\n"
    ));
    out.push_str("  \"program\": \"percolator-nft\",\n");
    out.push_str("  \"seeds\": {\n");
    out.push_str(&format!(
        "    \"mint_authority\": \"{}\",\n",
        core::str::from_utf8(MINT_AUTHORITY_SEED).expect("seed is ASCII")
    ));
    out.push_str(&format!(
        "    \"position_nft\": \"{}\"\n",
        core::str::from_utf8(POSITION_NFT_SEED).expect("seed is ASCII")
    ));
    out.push_str("  }\n}\n");
    print!("{out}");
}

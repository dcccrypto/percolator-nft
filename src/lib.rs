#![forbid(unsafe_code)]
// #184 (4.2): the `unexpected_cfgs` allow is NOT crate-wide.
//
// It exists for the `entrypoint!` macro's SBF-toolchain internals (custom-heap,
// custom-panic, target_os="solana"), so it now lives on that module alone.
//
// Crate-wide, it silenced every misspelled cfg in the crate: a typo'd
// `#[cfg(feature = "devnett")]` produced NO diagnostic — not from build, not under
// -D warnings, not from clippy — even though cargo passes --check-cfg correctly.
// That was harmless until a feature became load-bearing; with the devnet gate it is
// the difference between a devnet build that trusts nothing and a silent mainnet one.

pub mod cpi_v16;
#[cfg(not(feature = "no-entrypoint"))]
pub mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod slab_types_v16;
pub mod state_v16;
pub mod token2022;
pub mod transfer_hook;
pub mod valuation;

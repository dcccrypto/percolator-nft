#![forbid(unsafe_code)]
// The solana_program `entrypoint!` macro uses platform-specific cfgs
// (custom-heap, custom-panic, target_os="solana") that are not in our
// check-cfg list. These are SBF-toolchain internals — suppress here.
#![allow(unexpected_cfgs)]

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

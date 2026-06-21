//! v16 `PositionNft` account state — the NFT program's OWN on-chain account.
//!
//! The v16-sync replacement for [`crate::state`] (v12). v12 bound an NFT to a
//! `(slab, user_idx)` slot; v16 binds to a `(portfolio_account, asset_index)`
//! pair — `asset_index` is the asset identifier (matched against the active
//! leg's `asset_index`, NOT an array slot). Per-leg NFT model (design §4.1
//! Option B): seeds `[b"position_nft", portfolio_account, asset_index_le]`.
//!
//! Snapshot fields capture the leg state at mint so the handlers can detect
//! slot-reuse and position-flip. The PRIMARY slot-reuse anchor is
//! `market_id_at_mint` — v16 `market_id` is strictly monotonic and never
//! reused (engine `next_market_id` only ever `checked_add(1)`), so a reused
//! leg slot necessarily carries a different market_id (stronger than v12's
//! `account_id`/`position_owner`). `epoch_snap_at_mint` and
//! `position_owner_at_mint` are belt-and-braces.
//!
//! All multi-byte scalars use the align-1 `V16Pod*` byte-array wrappers, so the
//! account image is host==SBF byte-identical with no padding (the v12 struct
//! relied on careful i128-at-16-aligned-offset placement; v16 sidesteps that).

use bytemuck::{Pod, Zeroable};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

use crate::slab_types_v16::{V16PodI128, V16PodI64, V16PodU32, V16PodU64};

/// `"PERCNFT\0"` little-endian (unchanged from v12 — same family of accounts).
pub const POSITION_NFT_V16_MAGIC: u64 = 0x5045_5243_4E46_5400;

/// PositionNft state-layout version. v12 = 1; v16 = 2.
pub const POSITION_NFT_V16_VERSION: u8 = 2;

/// PDA seed prefix for PositionNft accounts (unchanged from v12).
pub const POSITION_NFT_SEED: &[u8] = b"position_nft";

/// PDA seed prefix for the program-wide mint authority (unchanged from v12).
pub const MINT_AUTHORITY_SEED: &[u8] = b"mint_authority";

/// Size of `PositionNftV16` account data.
pub const POSITION_NFT_V16_LEN: usize = core::mem::size_of::<PositionNftV16>();

/// On-chain state for a v16 Position NFT. 199 bytes (align 1).
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct PositionNftV16 {
    // ── Header ──
    pub magic: V16PodU64,
    pub version: u8,
    pub bump: u8,

    // ── Position reference ──
    /// The portfolio account this NFT wraps (v16 replaces v12's `slab`).
    pub portfolio_account: [u8; 32],
    /// The Token-2022 NFT mint.
    pub nft_mint: [u8; 32],
    /// Asset identifier of the bound leg (v16 replaces v12's `user_idx`).
    /// Matched against `legs[].asset_index`, NOT an array index.
    pub asset_index: V16PodU32,
    /// Leg `side` at mint (0/1) — detects a position flip vs. burn time.
    pub side_at_mint: u8,

    // ── v16 position snapshot (per-leg) ──
    /// `leg.basis_pos_q` at mint (signed; detects size/flip changes).
    pub basis_pos_q_at_mint: V16PodI128,
    /// `leg.f_snap` at mint (v16 funding-index snapshot; i128 in v16).
    pub f_snap_at_mint: V16PodI128,

    // ── Slot-reuse anchors ──
    /// `leg.market_id` at mint — PRIMARY slot-reuse anchor (monotonic, never
    /// reused). A reused leg slot carries a different market_id → mismatch.
    pub market_id_at_mint: V16PodU64,
    /// `leg.epoch_snap` at mint — belt-and-braces slot-reuse anchor.
    pub epoch_snap_at_mint: V16PodU64,
    /// `provenance.owner` at mint — detects owner change / slot reassignment.
    pub position_owner_at_mint: [u8; 32],

    /// Unix-seconds timestamp at mint.
    pub minted_at: V16PodI64,

    /// Forward-compat headroom; zeroed. Size enforced by the compile-time
    /// assert below, not hand-trusted (32 = a bytemuck-supported array size;
    /// further fields can extend the account via realloc if ever needed).
    pub _reserved: [u8; 32],
}

const _: () = assert!(POSITION_NFT_V16_LEN == 199);
const _: () = assert!(core::mem::align_of::<PositionNftV16>() == 1);

impl PositionNftV16 {
    pub fn portfolio_account_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.portfolio_account)
    }

    pub fn nft_mint_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.nft_mint)
    }
}

/// Derive the PositionNft PDA for a `(portfolio_account, market_id)` pair
/// (design §4.1 Option B — per-position NFT). `market_id` is the v16 position
/// **instance** id (`legs[].market_id`), encoded as u64 LE.
///
/// #108: the seed is keyed on `market_id`, NOT `asset_index`. The engine
/// **reuses** `asset_index` when a portfolio closes a position and opens a new
/// one on the same asset, so an `asset_index`-keyed PDA would let a stale NFT
/// squat the slot and permanently block (`NftAlreadyMinted`) wrapping the new
/// position — a third-party liveness DoS, since only the stale NFT's holder can
/// `EmergencyBurn` it. `market_id` is strictly monotonic and never reused
/// (mirrors `market_id_at_mint`, the slot-reuse anchor), so every distinct
/// position instance derives a distinct PDA and the alias/lock cannot occur.
///
/// At mint the caller has the active leg, so it derives with `leg.market_id`.
/// On every later op (transfer/burn/settle/valuation) the handler reads the
/// NFT's stored `market_id_at_mint` and re-derives with it, then asserts the
/// result equals the passed `nft_pda` key — the address is self-authenticating
/// (no extra instruction argument is required).
pub fn position_nft_pda(
    portfolio_account: &Pubkey,
    market_id: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            POSITION_NFT_SEED,
            portfolio_account.as_ref(),
            &market_id.to_le_bytes(),
        ],
        program_id,
    )
}

/// Derive the program-wide mint authority PDA (unchanged from v12). The wrapper
/// B-3 handler authenticates the NFT program by checking the CPI signer equals
/// this PDA derived from the registered NFT program ID.
pub fn mint_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[MINT_AUTHORITY_SEED], program_id)
}

/// Verify the PositionNft magic + version. Mirrors v12 `verify_pda_version`.
pub fn verify_position_nft(nft_state: &PositionNftV16) -> Result<(), ProgramError> {
    if nft_state.magic.get() != POSITION_NFT_V16_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    if nft_state.version != POSITION_NFT_V16_VERSION {
        solana_program::msg!("Unsupported PositionNftV16 version: {}", nft_state.version);
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_is_199_align1_pod() {
        assert_eq!(POSITION_NFT_V16_LEN, 199);
        assert_eq!(core::mem::align_of::<PositionNftV16>(), 1);
        // Zeroable round-trip.
        let z: PositionNftV16 = Zeroable::zeroed();
        assert_eq!(z.magic.get(), 0);
        assert_eq!(z.version, 0);
    }

    #[test]
    fn snapshot_round_trips() {
        let mut s: PositionNftV16 = Zeroable::zeroed();
        s.magic = V16PodU64::new(POSITION_NFT_V16_MAGIC);
        s.version = POSITION_NFT_V16_VERSION;
        s.bump = 254;
        s.portfolio_account = [9u8; 32];
        s.nft_mint = [3u8; 32];
        s.asset_index = V16PodU32::new(11);
        s.side_at_mint = 1;
        s.basis_pos_q_at_mint = V16PodI128::new(-12345);
        s.f_snap_at_mint = V16PodI128::new(777);
        s.market_id_at_mint = V16PodU64::new(42);
        s.epoch_snap_at_mint = V16PodU64::new(5);
        s.position_owner_at_mint = [9u8; 32];
        s.minted_at = V16PodI64::new(1_700_000_000);

        // bytemuck cast round-trip (the on-chain read path).
        let bytes = bytemuck::bytes_of(&s).to_vec();
        let back: &PositionNftV16 = bytemuck::from_bytes(&bytes);
        assert_eq!(back.asset_index.get(), 11);
        assert_eq!(back.basis_pos_q_at_mint.get(), -12345);
        assert_eq!(back.market_id_at_mint.get(), 42);
        assert_eq!(back.minted_at.get(), 1_700_000_000);
        assert_eq!(back.portfolio_account_pubkey(), Pubkey::new_from_array([9u8; 32]));
        verify_position_nft(back).expect("valid");
    }

    #[test]
    fn verify_rejects_bad_magic_and_version() {
        let mut s: PositionNftV16 = Zeroable::zeroed();
        s.version = POSITION_NFT_V16_VERSION;
        assert!(verify_position_nft(&s).is_err()); // magic 0
        s.magic = V16PodU64::new(POSITION_NFT_V16_MAGIC);
        s.version = 1; // v12 version
        assert!(verify_position_nft(&s).is_err());
        s.version = POSITION_NFT_V16_VERSION;
        assert!(verify_position_nft(&s).is_ok());
    }

    #[test]
    fn pda_is_per_position_instance_and_deterministic() {
        let prog = Pubkey::new_unique();
        let portfolio = Pubkey::new_unique();
        // #108: keyed on market_id (position-instance id), not asset_index.
        let (a0, _) = position_nft_pda(&portfolio, 100, &prog);
        let (a0b, _) = position_nft_pda(&portfolio, 100, &prog);
        let (a1, _) = position_nft_pda(&portfolio, 101, &prog);
        assert_eq!(a0, a0b); // deterministic
        assert_ne!(a0, a1); // distinct per market_id (per-position-instance NFT)
        // Re-opening the SAME asset_index yields a NEW market_id → a NEW PDA,
        // so a stale NFT can never squat the new position's wrap slot.
    }
}

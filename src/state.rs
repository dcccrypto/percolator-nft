use bytemuck::{Pod, Zeroable};
use solana_program::pubkey::Pubkey;

// ═══════════════════════════════════════════════════════════════
// PositionNft PDA — links an NFT mint to a slab position
// ═══════════════════════════════════════════════════════════════

/// Magic number to identify valid PositionNft accounts.
pub const POSITION_NFT_MAGIC: u64 = 0x5045_5243_4E46_5400; // "PERCNFT\0"

/// Current version of the PositionNft state layout.
pub const POSITION_NFT_VERSION: u8 = 1;

/// PDA seed prefix for PositionNft accounts.
pub const POSITION_NFT_SEED: &[u8] = b"position_nft";

/// PDA seed prefix for the program-wide mint authority.
pub const MINT_AUTHORITY_SEED: &[u8] = b"mint_authority";

/// Size of PositionNft account data.
pub const POSITION_NFT_LEN: usize = core::mem::size_of::<PositionNft>();

/// On-chain state for a Position NFT.
///
/// Uses `[u8; 32]` for pubkey fields (Pubkey doesn't implement Pod/Zeroable).
/// Layout: 208 bytes total (multiple of 16, required by i128 alignment).
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PositionNft {
    // ── Header (16 bytes) ──
    pub magic: u64,     // 0..8
    pub version: u8,    // 8
    pub bump: u8,       // 9
    pub _pad0: [u8; 6], // 10..16

    // ── Position reference (88 bytes) ──
    /// The slab (market) this position belongs to.
    pub slab: [u8; 32], // 16..48
    /// User index within the slab's account array.
    pub user_idx: u16, // 48..50
    pub _pad1: [u8; 6], // 50..56
    /// The Token-2022 NFT mint address.
    pub nft_mint: [u8; 32], // 56..88

    // ── Position snapshot (24 bytes) ──
    /// Entry price (E6 fixed-point) at time of NFT mint.
    pub entry_price_e6: u64, // 88..96
    /// Position size (absolute, in collateral micro-units) at mint time.
    pub position_size: u64, // 96..104
    /// 1=long, 0=short.
    pub is_long: u8, // 104
    pub _pad2: [u8; 7], // 105..112

    // ── Funding tracking (24 bytes) ──
    /// Last funding index applied (E18 fixed-point).
    pub last_funding_index_e18: i128, // 112..128
    /// Timestamp (unix seconds) when this NFT was minted.
    pub minted_at: i64, // 128..136

    // ── Reserved (72 bytes — includes tail alignment for i128) ──
    pub _reserved0: [u8; 64], // 136..200
    pub _reserved1: [u8; 8],  // 200..208
}

const _: () = assert!(core::mem::size_of::<PositionNft>() == 208);

impl PositionNft {
    /// Get the slab pubkey.
    pub fn slab_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.slab)
    }

    /// Get the NFT mint pubkey.
    pub fn nft_mint_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.nft_mint)
    }
}

/// Derives the PositionNft PDA address.
pub fn position_nft_pda(slab: &Pubkey, user_idx: u16, program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[POSITION_NFT_SEED, slab.as_ref(), &user_idx.to_le_bytes()],
        program_id,
    )
}

/// Derives the program-wide mint authority PDA.
pub fn mint_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[MINT_AUTHORITY_SEED], program_id)
}

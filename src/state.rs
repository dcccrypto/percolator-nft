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
/// Layout: 216 bytes total (multiple of 8, required by i128 alignment).
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

    // ── Position snapshot (32 bytes) ──
    /// Entry price (E6 fixed-point) at time of NFT mint.
    pub entry_price_e6: u64, // 88..96
    /// Position size (absolute, in collateral micro-units) at mint time.
    pub position_size: u64, // 96..104
    /// 1=long, 0=short.
    pub is_long: u8, // 104
    pub _pad2: [u8; 7], // 105..112
    /// Signed position size (position_basis_q from slab) at mint — allows detecting position flips.
    pub position_basis_q: i128, // 112..128

    // ── Funding tracking (16 bytes) ──
    /// Last funding index applied (E18 fixed-point).
    pub last_funding_index_e18: i128, // 128..144

    /// Timestamp (unix seconds) when this NFT was minted.
    pub minted_at: i64, // 144..152

    // ── Slot reuse protection (8 bytes) ──
    /// Account ID at mint time — monotonically increasing u64 unique per account.
    /// Verified on burn/settle to detect if the slab slot was reallocated.
    /// Always 0 on v12.17+ (field removed from Account struct); use `position_owner` instead.
    pub account_id: u64, // 152..160

    // ── Slot reuse protection: position owner pubkey (32 bytes) ──
    /// Owner pubkey of the position at mint time.
    ///
    /// PERC-N1 / v12.17 slot-reuse bypass fix: on v12.17 slabs `account_id` is always 0
    /// (field removed from Account), so `account_id != nft_state.account_id` is always
    /// `0 != 0` = false and never fires. `position_owner` is the live identifier that
    /// DOES change when a slab slot is closed and reassigned to a different user.
    ///
    /// Compared against `position.owner` (the 32-byte owner pubkey read from the live slab)
    /// in BurnPositionNft, SettleFunding, and GetPositionValue.
    ///
    /// MIGRATION GUARD: existing PositionNft accounts minted before this fix have
    /// `position_owner == [0u8; 32]`. The owner check is skipped for those accounts to avoid
    /// breaking legitimate burns/settles on pre-fix NFTs. Remove this guard once all pre-fix
    /// NFTs have been retired (tagged: remove-after-devnet-wipe).
    ///
    /// Occupies what was previously `_reserved0`. Struct size is unchanged (208 bytes).
    pub position_owner: [u8; 32], // 160..192

    // ── Reserved (16 bytes) ──
    // Total struct size = 208 bytes (multiple of 16, required by i128 Pod alignment).
    pub _reserved1: [u8; 16], // 192..208
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

/// PERC-9030: Verify PDA version is supported.
/// All instruction handlers check magic but not version. If a future version
/// introduces breaking layout changes, old code would misinterpret the data.
pub fn verify_pda_version(nft_state: &PositionNft) -> Result<(), solana_program::program_error::ProgramError> {
    if nft_state.version != POSITION_NFT_VERSION {
        solana_program::msg!("Unsupported PositionNft version: {}", nft_state.version);
        return Err(solana_program::program_error::ProgramError::InvalidAccountData);
    }
    Ok(())
}

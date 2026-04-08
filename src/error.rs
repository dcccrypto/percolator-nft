use solana_program::program_error::ProgramError;

/// Errors specific to the Position NFT wrapper program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NftError {
    /// Position is not open (size == 0).
    PositionNotOpen = 0,
    /// NFT already minted for this position.
    NftAlreadyMinted = 1,
    /// NFT PDA does not match expected derivation.
    InvalidNftPda = 2,
    /// Slab account not owned by the Percolator program.
    InvalidSlabOwner = 3,
    /// Account data too short to read position.
    SlabDataTooShort = 4,
    /// User index out of range for this slab.
    UserIndexOutOfRange = 5,
    /// Position has changed since NFT was minted (entry price mismatch).
    PositionMismatch = 6,
    /// Only the NFT holder can burn / settle.
    NotNftHolder = 7,
    /// Funding settlement overflow.
    FundingOverflow = 8,
    /// Invalid mint authority — expected program PDA.
    InvalidMintAuthority = 9,
    /// Slab layout version not recognized.
    UnrecognizedSlabLayout = 10,
    /// Cannot transfer — position is being liquidated.
    PositionInLiquidation = 11,
    /// Transfer hook: funding must be settled before transfer.
    FundingNotSettled = 12,
    /// Transfer hook: account[7] is not a known Percolator program (GH#1687).
    InvalidPercolatorProgram = 13,
    /// BurnPositionNft: position must be fully closed (size=0, collateral=0) before burn (GH#1869).
    PositionNotClosed = 14,
    /// Transfer hook: ExtraAccountMetaList PDA does not match expected derivation.
    InvalidExtraAccountMetas = 15,
    /// Transfer hook: source or destination token account validation failed.
    InvalidTokenAccount = 16,
    /// TransferHook Execute was invoked directly, not via Token-2022 CPI.
    UnauthorizedDirectInvocation = 17,
    /// MintPositionNft: account is an LP account, not a trading account.
    LpAccountNotAllowed = 18,
    /// Position account_id mismatch — slot was reallocated to a different account.
    InvalidAccountId = 19,
}

impl From<NftError> for ProgramError {
    fn from(e: NftError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

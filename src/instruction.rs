use solana_program::program_error::ProgramError;

// ═══════════════════════════════════════════════════════════════
// Instruction tags — append-only, never reorder or reuse
// ═══════════════════════════════════════════════════════════════

/// Tag 0: MintPositionNft
/// Mint an NFT for an open position. Caller must be the position owner.
///
/// Accounts:
///   0. `[signer]`    Position owner (pays rent)
///   1. `[writable]`  PositionNft PDA (created)
///   2. `[writable]`  NFT mint (Token-2022, created)
///   3. `[writable]`  Owner's NFT token account (ATA, created)
///   4. `[]`          Slab account (read position data)
///   5. `[]`          Mint authority PDA
///   6. `[]`          Token-2022 program
///   7. `[]`          Associated token account program
///   8. `[]`          System program
///   9. `[]`          Rent sysvar
///
/// Data: tag(1) + user_idx(2)
pub const TAG_MINT_POSITION_NFT: u8 = 0;

/// Tag 1: BurnPositionNft
/// Burn the NFT, releasing the position back to direct ownership.
/// Caller must hold the NFT.
///
/// Accounts:
///   0. `[signer]`    NFT holder
///   1. `[writable]`  PositionNft PDA (closed, rent returned)
///   2. `[writable]`  NFT mint (supply → 0)
///   3. `[writable]`  Holder's NFT token account (closed)
///   4. `[]`          Slab account (verify position)
///   5. `[]`          Mint authority PDA
///   6. `[]`          Token-2022 program
///
/// Data: tag(1)
pub const TAG_BURN_POSITION_NFT: u8 = 1;

/// Tag 2: SettleFunding
/// Permissionless crank — update the NFT's last_funding_index from on-chain state.
/// Must be called before transfer if funding has accrued.
///
/// Accounts:
///   0. `[signer]`    Cranker (anyone)
///   1. `[writable]`  PositionNft PDA
///   2. `[]`          Slab account (read current funding index)
///
/// Data: tag(1)
pub const TAG_SETTLE_FUNDING: u8 = 2;

/// Decoded instruction for the Position NFT program.
pub enum NftInstruction {
    /// Mint an NFT for a position.
    MintPositionNft { user_idx: u16 },
    /// Burn an NFT, releasing the position.
    BurnPositionNft,
    /// Settle accrued funding on the NFT state.
    SettleFunding,
}

impl NftInstruction {
    /// Decode instruction data.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
        match tag {
            TAG_MINT_POSITION_NFT => {
                if rest.len() < 2 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let user_idx = u16::from_le_bytes([rest[0], rest[1]]);
                Ok(NftInstruction::MintPositionNft { user_idx })
            }
            TAG_BURN_POSITION_NFT => Ok(NftInstruction::BurnPositionNft),
            TAG_SETTLE_FUNDING => Ok(NftInstruction::SettleFunding),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

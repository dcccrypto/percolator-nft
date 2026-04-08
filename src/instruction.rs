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
/// Holder-only — update the NFT's last_funding_index from on-chain state.
/// GH#5 fix: previously permissionless, now restricted to the NFT holder to prevent
/// front-running attacks that wipe accrued funding before a marketplace sale.
///
/// Accounts:
///   0. `[signer]`    NFT holder (must own the NFT via ATA)
///   1. `[writable]`  PositionNft PDA
///   2. `[]`          Slab account (read current funding index)
///   3. `[]`          Holder's ATA (proves NFT ownership; balance must be 1)
///
/// Data: tag(1)
pub const TAG_SETTLE_FUNDING: u8 = 2;

/// Tag 3: GetPositionValue
/// Read-only valuation for marketplaces and lending protocols.
/// Returns position value data via transaction logs.
///
/// Accounts:
///   0. `[]`  PositionNft PDA
///   1. `[]`  Slab account
///
/// Data: tag(1)
pub const TAG_GET_POSITION_VALUE: u8 = 3;

/// Tag 4: ExecuteTransferHook (SPL TransferHook interface)
/// Called automatically by Token-2022 on every NFT transfer.
/// DO NOT call directly — Token-2022 invokes this via the TransferHook extension.
///
/// Data: discriminator(8) + amount(8) [SPL TransferHook format]
pub const TAG_EXECUTE_TRANSFER_HOOK: u8 = 4;

/// Tag 5: EmergencyBurn
/// Burn an NFT for a liquidated/closed position where position_basis_q == 0.
/// Callable only by NFT holder. Used when a position is liquidated and collateral cannot be recovered.
///
/// Accounts:
///   0. `[signer]`    NFT holder
///   1. `[writable]`  PositionNft PDA (closed, rent returned)
///   2. `[writable]`  NFT mint (supply → 0)
///   3. `[writable]`  Holder's NFT token account (closed)
///   4. `[]`          Slab account (verify liquidation)
///   5. `[]`          Mint authority PDA
///   6. `[]`          Token-2022 program
///
/// Data: tag(1)
pub const TAG_EMERGENCY_BURN: u8 = 5;

/// Decoded instruction for the Position NFT program.
pub enum NftInstruction {
    /// Mint an NFT for a position.
    MintPositionNft { user_idx: u16 },
    /// Burn an NFT, releasing the position.
    BurnPositionNft,
    /// Settle accrued funding on the NFT state.
    SettleFunding,
    /// Read-only position valuation (logs output).
    GetPositionValue,
    /// TransferHook execute (called by Token-2022, not directly).
    ExecuteTransferHook { amount: u64 },
    /// Emergency burn for liquidated positions.
    EmergencyBurn,
}

impl NftInstruction {
    /// Decode instruction data.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        // Check for TransferHook Execute discriminator first (8 bytes).
        if data.len() >= 16 {
            let disc = &data[..8];
            if disc == &crate::transfer_hook::EXECUTE_DISCRIMINATOR {
                let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
                return Ok(NftInstruction::ExecuteTransferHook { amount });
            }
        }

        let (&tag, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
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
            TAG_GET_POSITION_VALUE => Ok(NftInstruction::GetPositionValue),
            TAG_EMERGENCY_BURN => Ok(NftInstruction::EmergencyBurn),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

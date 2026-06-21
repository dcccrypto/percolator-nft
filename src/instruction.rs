use solana_program::program_error::ProgramError;

// ═══════════════════════════════════════════════════════════════
// Instruction tags — append-only, never reorder or reuse
// ═══════════════════════════════════════════════════════════════

/// Tag 0: MintPositionNft
/// Mint an NFT for an open position. Caller must be the position owner.
/// Atomically creates and initializes the ExtraAccountMetaList PDA
/// required by Token-2022 TransferHook, so the NFT is born transferable.
///
/// Accounts:
///   0. `[signer, writable]`  Position owner (pays rent)
///   1. `[writable]`          PositionNft PDA (created)
///   2. `[writable, signer]`  NFT mint (Token-2022, created — fresh keypair)
///   3. `[writable]`          Owner's NFT token account (ATA, created)
///   4. `[]`                  Portfolio account (read position data)
///   5. `[]`                  Mint authority PDA
///   6. `[]`                  Token-2022 program
///   7. `[]`                  Associated token account program
///   8. `[]`                  System program
///   9. `[writable]`          ExtraAccountMetaList PDA (created);
///      seeds: `[b"extra-account-metas", nft_mint]`
///  10. `[]`                  Per-market NftRegistry PDA (read-only) — #109;
///      seeds: `[b"nft_registry", market_group]` UNDER the percolator wrapper
///      (portfolio.owner). Mint fails (`RegistryNotConfigured`) unless it exists,
///      is wrapper-owned, and registers THIS NFT program — otherwise the minted
///      NFT would be permanently non-transferable (core B-3 transfer gate).
///
/// Data: tag(1) + asset_index(2)
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

/// Tag 6: RepairExtraAccountMetas
///
/// Rewrite the ExtraAccountMetaList PDA data for an existing NFT mint so
/// its flags match the current processor's `build_extra_account_metas`
/// output — most importantly, marking the slab account writable.
///
/// Historical mints produced an ExtraAccountMetaList where the slab was
/// declared read-only. That was wrong — the transfer hook CPIs into
/// percolator-prog with `TransferOwnershipCpi` (tag 69), which mutates
/// `Account.owner` in the slab. Without slab writable, the CPI fails with
/// `writable privilege escalated` and every transfer bounces. Burn + remint
/// is not a workaround: burn requires the position already be closed.
///
/// Permissionless by design. The only data written to the PDA is
/// deterministic from the on-chain state of `nft_mint` + its `nft_pda`
/// (slab, user_idx, percolator_prog_id). A caller cannot use this to forge
/// anything — at worst they pay the tx fee to reset the PDA to its correct
/// shape. No rent change (account is pre-sized by MintPositionNft).
///
/// Accounts:
///   0. `[signer, writable]`  Payer — tops up rent when the account grows
///                            from a 5-entry (191-byte) layout to a 6-entry
///                            (226-byte) layout. No-op on accounts already
///                            sized for 6 entries.
///   1. `[writable]`          ExtraAccountMetaList PDA;
///      seeds: `[b"extra-account-metas", nft_mint]`
///   2. `[]`                  NFT mint (PDA seed input, no reads)
///   3. `[]`                  PositionNft PDA;
///      seeds: `[b"position_nft", slab, user_idx LE]`;
///      read for user_idx + slab + nft_mint verification.
///   4. `[]`                  Slab account (provides slab.key + percolator_prog_id)
///   5. `[]`                  Mint authority PDA — entry #8 in the rewritten list
///   6. `[]`                  System program (rent top-up CPI)
///
/// Data: tag(1)
pub const TAG_REPAIR_EXTRA_METAS: u8 = 6;

/// Decoded instruction for the Position NFT program.
pub enum NftInstruction {
    /// Mint an NFT for a position. `asset_index` identifies the portfolio leg
    /// (matched against `legs[].asset_index`), not an array slot.
    MintPositionNft { asset_index: u16 },
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
    /// Rewrite ExtraAccountMetaList for an existing mint (permissionless).
    RepairExtraMetas,
}

impl NftInstruction {
    /// Decode instruction data.
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        // Check for TransferHook Execute discriminator first (8 bytes).
        if data.len() >= 16 {
            let disc = &data[..8];
            if disc == crate::transfer_hook::EXECUTE_DISCRIMINATOR {
                let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
                return Ok(NftInstruction::ExecuteTransferHook { amount });
            }
        }

        let (&tag, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        match tag {
            TAG_MINT_POSITION_NFT => {
                if rest.len() != 2 {
                    return Err(ProgramError::InvalidInstructionData);
                }

                let asset_index = u16::from_le_bytes([rest[0], rest[1]]);
                Ok(NftInstruction::MintPositionNft { asset_index })
            }
            TAG_BURN_POSITION_NFT => {
                if !rest.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(NftInstruction::BurnPositionNft)
            }
            TAG_SETTLE_FUNDING => {
                if !rest.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(NftInstruction::SettleFunding)
            }
            TAG_GET_POSITION_VALUE => {
                if !rest.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(NftInstruction::GetPositionValue)
            }
            TAG_EMERGENCY_BURN => {
                if !rest.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(NftInstruction::EmergencyBurn)
            }
            TAG_REPAIR_EXTRA_METAS => {
                if !rest.is_empty() {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(NftInstruction::RepairExtraMetas)
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_position_nft_rejects_trailing_bytes() {
        let data = [TAG_MINT_POSITION_NFT, 7, 0, 99, 100];

        let result = NftInstruction::unpack(&data);

        assert!(
            matches!(result, Err(ProgramError::InvalidInstructionData)),
            "MintPositionNft should reject trailing bytes"
        );
    }

    #[test]
    fn fixed_size_instruction_tags_reject_trailing_bytes() {
        let fixed_tags = [
            TAG_BURN_POSITION_NFT,
            TAG_SETTLE_FUNDING,
            TAG_GET_POSITION_VALUE,
            TAG_EMERGENCY_BURN,
            TAG_REPAIR_EXTRA_METAS,
        ];

        for tag in fixed_tags {
            let data = [tag, 99];

            let result = NftInstruction::unpack(&data);

            assert!(
                matches!(result, Err(ProgramError::InvalidInstructionData)),
                "tag {} should reject trailing bytes",
                tag
            );
        }
    }

    #[test]
    fn fixed_size_instruction_tags_accept_exact_payloads() {
        let fixed_tags = [
            TAG_BURN_POSITION_NFT,
            TAG_SETTLE_FUNDING,
            TAG_GET_POSITION_VALUE,
            TAG_EMERGENCY_BURN,
            TAG_REPAIR_EXTRA_METAS,
        ];

        for tag in fixed_tags {
            let data = [tag];

            let result = NftInstruction::unpack(&data);

            assert!(
                result.is_ok(),
                "tag {} should accept exact-size payload",
                tag
            );
        }
    }

    #[test]
    fn mint_position_nft_accepts_exact_payload() {
        let data = [TAG_MINT_POSITION_NFT, 7, 0];

        let result = NftInstruction::unpack(&data);

        assert!(
            matches!(
                result,
                Ok(NftInstruction::MintPositionNft { asset_index: 7 })
            ),
            "MintPositionNft should accept exactly two asset_index bytes"
        );
    }
}

# percolator-nft

Position NFT wrapper for Percolator — mint transferable Token-2022 NFTs representing open perpetual futures positions.

## Architecture

```
percolator-nft (this program)
  ├── Reads position state from Percolator slab accounts (CPI-free, direct data read)
  ├── SPL Token-2022 (mint/burn position NFTs, decimals=0, supply=1)
  ├── PositionNft PDA (links NFT mint → slab + user_idx)
  └── SettleFunding (permissionless crank to sync funding index before transfer)
```

**Why a wrapper?**
- Core program stays lean — no Token-2022 dependency in the BPF binary
- Independent upgradability — iterate on NFT logic without touching core
- Security isolation — NFT bugs can't affect core funds
- Same pattern as `percolator-stake`

## Instructions

| Tag | Name | Description |
|-----|------|-------------|
| 0 | `MintPositionNft` | Mint an NFT for an open position (caller must own the position) |
| 1 | `BurnPositionNft` | Burn the NFT, release position back to direct ownership (requires portfolio verification) |
| 2 | `SettleFunding` | Holder-only crank — update funding index snapshot `f_snap_at_mint` |
| 3 | `GetPositionValue` | Read-only valuation diagnostics (emits raw leg/valuation fields via transaction logs; for use with simulateTransaction) |
| 4 | `ExecuteTransferHook` | SPL TransferHook interface execute (called by Token-2022 automatically on transfer) |
| 5 | `EmergencyBurn` | Holder-only emergency burn for flat or liquidated positions (allows cleanup if portfolio is missing or corrupt) |
| 6 | `RepairExtraMetas` | Permissionless rewrite of the `ExtraAccountMetaList` PDA to fix historical layout issues |

## PDA Seeds

- **PositionNft**: `["position_nft", portfolio_pubkey, asset_index_le_bytes]` (where `asset_index` is `u16` little-endian, max 65535)
- **MintAuthority**: `["mint_authority"]` (program-wide, signs all mint operations)
- **ExtraAccountMetaList**: `["extra-account-metas", nft_mint]` (stores extra accounts required for TransferHook)

## Custody and Security

- **Custody Model**: Minting binds the NFT to the portfolio position, but ownership reassignment to the buyer's wallet occurs dynamically during the TransferHook execution (at NFT transfer time).
- **Freeze Authority**: The freeze authority is set to the program's mint authority PDA as a latent security control. It enables emergency freezes in future program upgrades if a vulnerability is discovered.
- **no-entrypoint Feature**: Program entrypoint is gated behind a `no-entrypoint` feature for library-style composition.


## v17 Layout Support

The NFT program mirrors the converged v17 portfolio layout (`PortfolioAccountV16Account`, 9227 bytes) to read position state directly without CPI. Struct offsets are validated at compile-time with size and offset assertions.

## Transfer Hook

The transfer hook performs a health check at NFT transfer time using the last-cranked oracle price. See deferred finding C-12 for the known limitation on price staleness at transfer time.

## Build and Test

```bash
# Build BPF binary
cargo build-sbf

# Run tests — 65 tests, 0 failures
cargo test
```

## Security Notes

- `forbid(unsafe_code)` enforced
- Slab owner verified against known Percolator program IDs (devnet + mainnet)
- Position ownership verified before minting
- Transfer hook enforces health check before position transfer
- NFT burn closes PDA and returns rent to holder

## Known Deferred Findings

- **C-7:** The `account_id` guard is inoperative under the v12.17 layout. Impact is approximately 0.002 SOL PDA rent loss. No position or fund risk. Fix is scheduled for next upgrade.
- **C-12:** The transfer hook uses the cached oracle price (last crank), not a fresh feed read. Bounded by keeper crank frequency. Fix requires an `ExtraAccountMeta` interface change.

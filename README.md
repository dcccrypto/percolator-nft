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
| 1 | `BurnPositionNft` | Burn the NFT, release position back to direct ownership |
| 2 | `SettleFunding` | Permissionless crank — update funding index before transfer |
| 3 | `EmergencyBurn` | Admin-only emergency burn of a position NFT |
| 4 | `GetPositionValue` | Read-only CPI: returns current position value at oracle price |

## PDA Seeds

- **PositionNft**: `["position_nft", slab_pubkey, user_idx_le_bytes]`
- **MintAuthority**: `["mint_authority"]` (program-wide, signs all mint operations)

## v12.17 Layout Support

The NFT program mirrors the v12.17 slab layout to read position state directly without CPI. The `small`, `medium`, and default (large) feature flags must match the feature used to build the deployed percolator-prog binary so that struct offsets align correctly.

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

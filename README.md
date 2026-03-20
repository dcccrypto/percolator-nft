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

## PDA Seeds

- **PositionNft**: `["position_nft", slab_pubkey, user_idx_le_bytes]`
- **MintAuthority**: `["mint_authority"]` (program-wide, signs all mint operations)

## Build

```bash
cargo build-sbf
cargo test
```

## Security Notes

- `forbid(unsafe_code)` enforced
- Slab owner verified against known Percolator program IDs (devnet + mainnet)
- Position ownership verified before minting
- Funding must be settled before NFT transfer (checked by transfer hook, future)
- NFT burn closes PDA and returns rent to holder

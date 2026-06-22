# percolator-nft

Position NFT wrapper for Percolator — mint transferable Token-2022 NFTs representing open perpetual futures positions.

## Architecture

```
percolator-nft (this program)
  ├── Reads position state from Percolator portfolio accounts (CPI-free, direct data read)
  ├── SPL Token-2022 (mint/burn position NFTs, decimals=0, supply=1)
  ├── PositionNft PDA (links NFT mint → portfolio + market_id)
  └── SettleFunding (holder-only crank to sync funding index before transfer)
```

**Why a wrapper?**
- Core program stays lean — no Token-2022 dependency in the BPF binary
- Independent upgradability — iterate on NFT logic without touching core
- Security isolation — NFT bugs can't affect core funds
- Same pattern as `percolator-stake`

## Instructions

| Tag | Name | Accounts | Description |
|-----|------|----------|-------------|
| 0 | `MintPositionNft` | 12 | Mint an NFT for an open position (caller must own the position) |
| 1 | `BurnPositionNft` | 10 | Burn the NFT, release position back to direct ownership (requires active bound leg) |
| 2 | `SettleFunding` | 4 | Holder-only crank — update funding index snapshot `f_snap_at_mint` |
| 3 | `GetPositionValue` | 2 | Read-only valuation diagnostics (emits raw leg/valuation fields via transaction logs; does NOT return via CPI; clients use simulateTransaction; fail-CLOSED) |
| 4 | `ExecuteTransferHook` | 12+ | SPL TransferHook interface execute (called by Token-2022 automatically on transfer; do NOT call directly) |
| 5 | `EmergencyBurn` | 10 | Holder-only emergency burn for flat or liquidated positions (not admin-only) |
| 6 | `RepairExtraMetas` | 7 | Permissionless rewrite of the `ExtraAccountMetaList` PDA to fix historical layout issues |

### MintPositionNft: account layout (12 accounts)

| # | Flags | Account |
|---|-------|---------|
| 0 | signer, writable | Position owner (pays rent) |
| 1 | writable | PositionNft PDA (created) |
| 2 | writable, signer | NFT mint (fresh keypair) |
| 3 | writable | Owner's ATA (created) |
| 4 | writable | Portfolio account |
| 5 | — | Mint authority PDA |
| 6 | — | Token-2022 program |
| 7 | — | ATA program |
| 8 | — | System program |
| 9 | writable | ExtraAccountMetaList PDA (created) |
| 10 | — | Per-market NftRegistry PDA |
| 11 | — | Percolator wrapper program |

### BurnPositionNft / EmergencyBurn: account layout (10 accounts)

| # | Flags | Account |
|---|-------|---------|
| 0 | signer | NFT holder |
| 1 | writable | PositionNft PDA (closed) |
| 2 | writable | NFT mint |
| 3 | writable | Holder's ATA (closed) |
| 4 | writable | Portfolio account |
| 5 | — | Mint authority PDA |
| 6 | — | Token-2022 program |
| 7 | writable | ExtraAccountMetaList PDA (closed) |
| 8 | — | Per-market NftRegistry PDA |
| 9 | — | Percolator wrapper program |

## PDA Seeds

- **PositionNft**: `["position_nft", portfolio_pubkey, market_id_u64_le]`
  - Keyed on `market_id` (the v16 position **instance** id), NOT `asset_index` — #108.
  - `market_id` is strictly monotonic and never reused, so every distinct position
    instance derives a distinct PDA. An `asset_index`-keyed PDA would be squattable
    by a stale NFT when the same asset slot is re-opened after close.
  - The `asset_index` field in `MintPositionNft` data is u16 (max 65535); it identifies
    the leg (`legs[].asset_index`) and is stored in `PositionNftV16.asset_index`, but
    it is NOT part of the PDA seed.
- **MintAuthority**: `["mint_authority"]` (program-wide, signs all mint operations)
- **ExtraAccountMetaList**: `["extra-account-metas", nft_mint]` (stores extra accounts required for TransferHook)

## Custody and Security

- **Custody Model**: Minting takes true custody of the position via B-3
  `TransferPortfolioOwnership` CPI (escrow at mint). The portfolio owner becomes the
  NFT program's mint-authority PDA. On burn (`BurnPositionNft`/`EmergencyBurn`), the
  escrow is released via `UnwrapEscrowedPortfolio` CPI, returning ownership to the holder.
- **Freeze Authority**: The freeze authority is set to the mint authority PDA as a latent
  security control. It is currently INERT — no `FreezeAccount`/`ThawAccount` instruction
  is exposed. Gated by program-upgrade governance.
- **no-entrypoint Feature**: Program entrypoint is gated behind a `no-entrypoint` cargo
  feature for library-style composition (e.g. embedding in test harnesses).
- **GetPositionValue is fail-CLOSED**: stale/slot-reuse/no-active-leg conditions return
  errors, not `Ok(())`. Clients using `simulateTransaction` must check the error.

## v17 Layout Support

The NFT program mirrors the converged v17 portfolio layout (`PortfolioAccountV16Account`,
9227 bytes) to read position state directly without CPI. Struct offsets are validated at
compile-time with size and offset assertions.

## Transfer Hook

The transfer hook validates the transfer at NFT transfer time (Token-2022-caller
check, bound-leg / market_id slot-reuse guard, transfer gate, registry check). It
does **not** reassign portfolio ownership: under the escrow-at-mint model (#105)
the position is owned by this NFT program's mint-authority PDA for its entire
wrapped life — escrow is set once at mint (via the wrapper's `TransferPortfolioOwnership`
tag 72) and released only at burn (via `UnwrapEscrowedPortfolio` tag 82). An NFT
transfer moves only the bearer token; the underlying position stays escrowed.

## Build and Test

```bash
# Build BPF binary (no warnings expected)
cargo build-sbf --no-default-features

# Run tests
RUST_MIN_STACK=8388608 cargo test
```

## Security Notes

- `forbid(unsafe_code)` enforced
- Portfolio owner verified against known Percolator program IDs (devnet + mainnet)
- Position ownership verified before minting; provenance header validated (#110C)
- PDA re-derivation on every read operation uses `market_id_at_mint` (u64), not
  `asset_index` (#108 / #118 — the #122 critical bug used asset_index here)
- Transfer hook enforces ATA canonicality, CPI caller verification, and writable guards
- NFT burn closes PDA, mint, ATA, and ExtraAccountMetaList, returning all rent to holder
- SettleFunding requires nft_pda to be writable before attempting mutation (#120)
- GetPositionValue: fail-CLOSED on stale state (#118/#119/#100)
- EmergencyBurn is holder-only (not admin-only) (#122 README correction)

## Known Deferred Findings

- **#110B (EmergencyBurn wedge when portfolio is gone/undecodable)**: needs a security-
  sensitive relaxation of `verify_portfolio_program`; deferred to a follow-up PR.

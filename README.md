# percolator-nft

Position NFT program for [Percolator](https://github.com/dcccrypto/percolator), a perpetual futures protocol on Solana. It mints a transferable Token-2022 NFT (decimals 0, supply 1) that represents an open position, so the position can be held or moved as a token.

It is a separate program so the core wrapper does not depend on Token-2022 and can be upgraded independently. Same pattern as [percolator-stake](https://github.com/dcccrypto/percolator-stake).

## How it works

- `MintPositionNft` takes custody of the portfolio: ownership is transferred to this program's mint-authority PDA through a wrapper CPI, and an NFT is minted to the owner.
- Transferring the NFT moves only the token. The position stays escrowed. A transfer hook checks the transfer and records the last holder.
- `BurnPositionNft` and `EmergencyBurn` burn the NFT and release the portfolio back to the holder. `ReconcileBurnedNft` recovers positions whose NFT was burned out-of-band.
- `GetPositionValue` is read-only and reports through transaction logs, so clients call it with `simulateTransaction`. It fails closed: any non-transferable state returns an error, so check `err` as well as the logs.
- The program reads the wrapper's portfolio account directly (no CPI) through a mirrored layout. `tests/layout_parity_160.rs` checks that mirror against the real `percolator` crate, and CI runs `scripts/engine-pin-check.sh` to check it against the engine the wrapper actually builds with.

| Tag | Instruction |
|-----|-------------|
| 0 | `MintPositionNft` |
| 1 | `BurnPositionNft` |
| 2 | `SettleFunding` |
| 3 | `GetPositionValue` |
| 4 | `ExecuteTransferHook` (called by Token-2022, not directly) |
| 5 | `EmergencyBurn` |
| 6 | `RepairExtraMetas` |
| 7 | `ReconcileBurnedNft` |

Account lists and data layouts are documented in [`src/instruction.rs`](src/instruction.rs).

PDA seeds:

- `PositionNft`: `["position_nft", portfolio, market_id_u64_le]`, keyed on the position instance id (`market_id`), not the asset index
- Mint authority: `["mint_authority"]`
- `ExtraAccountMetaList`: `["extra-account-metas", nft_mint]`

## Integrator notes

- A burned NFT's mint address is not a durable identity. The keypair that created the mint can re-create an account at the same address after it is closed. This has no on-chain effect, but indexers and marketplaces should key burned-position records on the `PositionNft` PDA or `market_id`.
- `GetPositionValue` logs are capped at 10,000 bytes per transaction, and a failing instruction aborts the whole simulation, so batching many calls in one simulation can hide results.

## Build and test

```bash
# Mainnet-style build (devnet wrapper ID not compiled in)
cargo build-sbf --no-default-features

# Devnet build; required to accept devnet portfolios
cargo build-sbf -- --features devnet

# Tests
RUST_MIN_STACK=8388608 cargo test
```

The wrapper program ID this program trusts is set in `src/cpi_v16.rs`. The devnet ID is compiled in only with the `devnet` feature. Current devnet IDs are pinned in [percolator-sdk](https://github.com/dcccrypto/percolator-sdk) (`src/config/program-ids.ts`).

## Related repositories

- [percolator-prog](https://github.com/dcccrypto/percolator-prog): on-chain wrapper program
- [percolator-sdk](https://github.com/dcccrypto/percolator-sdk): TypeScript SDK
- [percolator-stake](https://github.com/dcccrypto/percolator-stake): insurance LP staking program

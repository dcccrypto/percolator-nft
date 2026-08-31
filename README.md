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
| 7 | `ReconcileBurnedNft` | 9 | Permissionless recovery for an NFT burned out-of-band: releases the stranded escrow to the recorded last holder and closes the PositionNft PDA, NFT mint and ExtraAccountMetaList, returning all rent to that holder |
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
- **GetPositionValue is fail-CLOSED**: every non-transferable condition returns
  errors, not `Ok(())`. Clients using `simulateTransaction` must check the error.

### GetPositionValue log contract

The instruction returns nothing via CPI, so its logs are its API. Every response
emits `POSITION_VALUE_V16:portfolio=`, `POSITION_VALUE_V16:asset_index=` and
exactly one `POSITION_VALUE_V16:status=`:

| `status=` | Meaning | Error |
|---|---|---|
| `ok` | Healthy bound leg; the economic fields follow under `POSITION_VALUE_V16:`. | — |
| `no_active_leg` | The position is closed or never existed; route to `EmergencyBurn`. | `LegNotActive` (22) |
| `leg_stale` | The bound leg owes chunked settlement. Transient — a crank clears it. | `TransferBlocked` (24) |
| `portfolio_locked_or_stale` | Portfolio-level liquidation lock or stale state. | `TransferBlocked` (24) |
| `resolved` | Terminal resolved-payout receipt present; claim rather than price it. | `TransferBlocked` (24) |
| `close_in_progress` | A close is mid-flight for this asset. Transient. | `TransferBlocked` (24) |
| `slot_reuse_detected` | The slot was reused by a different position instance; this NFT is dead. Accompanied by `market_id_at_mint=` and `current_market_id=`. | `MarketIdMismatch` (25) |

Notes for integrators:

- `simulateTransaction` returns `logs` alongside `err`, so the status line is
  readable on a failed instruction. (`logs` is `null` only when simulation fails
  *before* execution — bad blockhash, unloadable account, signature verification.)
- On a blocked status the economic fields are emitted under the separate
  **`POSITION_BLOCKED_V16:`** prefix, not `POSITION_VALUE_V16:`. A parser
  scanning for the latter therefore fails closed by construction; opt into
  distressed pricing deliberately by reading the former. `slot_reuse_detected`
  emits no economics at all — they would describe a different position.
- **Batching caveat:** a failing instruction aborts the whole transaction, so
  packing many `GetPositionValue` calls into one simulation means a single
  blocked position suppresses every instruction after it. Batch defensively, or
  price positions individually.
- Logs are capped at 10,000 bytes per transaction and truncate silently.

## v17 Layout Support

The NFT program mirrors the converged v17 portfolio layout (`PortfolioAccountV16Account`,
9227 bytes) to read position state directly without CPI. Struct field offsets are verified
for internal consistency via compile-time `const_assert!` macros; alignment with the live
engine layout requires runtime validation against real on-chain data (deferred, see #110H).

## Transfer Hook

The transfer hook validates the transfer at NFT transfer time (Token-2022-caller
check, bound-leg / market_id slot-reuse guard, transfer gate, registry check). It
does **not** reassign portfolio ownership: under the escrow-at-mint model (#105)
the position is owned by this NFT program's mint-authority PDA for its entire
wrapped life — escrow is set once at mint (via the wrapper's `TransferPortfolioOwnership`
tag 72) and released only at burn (via `UnwrapEscrowedPortfolio` tag 82). An NFT
transfer moves only the bearer token; the underlying position stays escrowed.

The hook's one state write is `PositionNftV16.last_holder`, recorded whenever a
transfer provably moved the token — a direct Token-2022 transfer, or one
Token-2022 is executing on behalf of another program (marketplace, orderbook,
multisig). It is detected via Token-2022's own in-flight `transferring` flag, so
a spoofed direct `Execute` cannot forge it. `ReconcileBurnedNft` uses this field
as the sole authorisation for releasing an escrowed portfolio after an
out-of-band burn, so it must track the current holder, and extra-meta entry [5]
must stay writable for every such transfer.

## Build and Test

```bash
# Build BPF binary for MAINNET (no warnings expected).
# The point is simply that `devnet` is OFF: the crate declares no `default`
# feature, so --no-default-features is a no-op and a bare `cargo build-sbf`
# produces a byte-identical artifact.
cargo build-sbf --no-default-features

# Build BPF binary for DEVNET — the `devnet` feature is required, and is what
# compiles the devnet wrapper id into the allowlist. Omitting it produces a
# binary that will reject every devnet portfolio.
cargo build-sbf -- --features devnet

# Run tests
RUST_MIN_STACK=8388608 cargo test
```

## Security Notes

- `forbid(unsafe_code)` enforced
- Portfolio owner verified against the mainnet Percolator program ID. The devnet
  ID is compiled in only under the `devnet` feature, so it can never be trusted by
  a mainnet artifact (mirrors percolator-stake and percolator-prog)
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

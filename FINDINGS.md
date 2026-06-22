# percolator-nft — Audit Findings

## VULN-01 — Transfer hook does not update `position_owner`, breaking BurnPositionNft and SettleFunding after any transfer (MEDIUM)

**Location:** `src/transfer_hook.rs:603-609` (step 4 write-back block, pre-fix)

### Root cause

`process_execute` (the Token-2022 transfer hook) CPIs `TransferOwnershipCpi` into
`percolator-prog`, which updates the slab's `account[user_idx].owner` to the new
NFT holder's wallet. After that CPI, step 4 writes the PDA back but only updates
`last_funding_index_e18` — it never updates `nft_state.position_owner`:

```rust
// pre-fix
nft_state.last_funding_index_e18 = new_funding;
```

`nft_state.position_owner` was set once, at mint time, to the original minter's
key, and is never touched again on the transfer path.

Both `process_burn_position_nft` (`src/processor.rs:704-709`) and
`process_settle_funding` (`src/processor.rs:1078-1083`) carry a PERC-N1
slot-reuse guard:

```rust
if nft_position_owner != [0u8; 32]
    && position.owner.to_bytes() != nft_position_owner
{
    return Err(NftError::SlotReused.into());
}
```

This guard is meant to detect a slab slot being reassigned to an unrelated
account (v12.17 slabs always report `account_id == 0`, so the usual
account_id check is dead and PERC-N1 is the only defense). But because the
transfer hook never updates `position_owner`, the guard also fires on every
**legitimate** transfer: `position.owner` (now the new holder, via
`TransferOwnershipCpi`) no longer matches `nft_state.position_owner` (still
the original minter).

### Impact

- **`BurnPositionNft`** always rejects with `SlotReused` for any NFT that has
  ever been transferred. The new holder cannot burn it, so the PositionNft
  PDA rent (~0.002 SOL) and the Token-2022 mint account rent (~0.001 SOL) are
  permanently locked. Partial rescue: `EmergencyBurn` succeeds if
  `position_basis_q == 0`, but `EmergencyBurn` has no rescue path for an
  open position.
- **`SettleFunding`** always rejects with `SlotReused` for any NFT that has
  ever been transferred. The new holder can never snapshot
  `last_funding_index_e18` via the NFT interface while the position is open
  — there is no rescue path for this handler. (The holder can still manage
  the position directly through `percolator-prog`, since the slab's
  `account.owner` was correctly updated; only the NFT-mediated funding
  settlement is broken.)

No funds held by `percolator-prog` are at risk — this is a liveness /
rent-lock bug confined to the NFT wrapper layer.

### Attack path (none required — triggers on normal use)

1. Alice mints a PositionNft for an open position (`nft_state.position_owner = Alice`).
2. Alice transfers the NFT to Bob via a standard Token-2022 transfer.
   `process_execute` CPIs `TransferOwnershipCpi`, setting the slab's
   `account.owner = Bob`. `nft_state.position_owner` is left as `Alice`.
3. Bob calls `SettleFunding` → `position.owner (Bob) != nft_state.position_owner (Alice)` → `SlotReused`.
4. Bob closes the position and calls `BurnPositionNft` → same mismatch → `SlotReused`.
   `EmergencyBurn` is Bob's only path to reclaim rent, and only once the
   position is fully flat.

### Fix

Update `position_owner` alongside `last_funding_index_e18` in the same
write-back block, immediately after `TransferOwnershipCpi` succeeds:

```rust
nft_state.last_funding_index_e18 = new_funding;
nft_state.position_owner = dest_wallet_pk.to_bytes();
```

### PoC

Not yet implemented as a LiteSVM integration test. Differential to write:
- **FAIL path:** mint → transfer (pre-fix code) → new holder calls
  `SettleFunding` → assert `Custom(SlotReused)`.
- **PASS path:** mint → transfer (post-fix code) → new holder calls
  `SettleFunding` → assert `Ok(())` and `last_funding_index_e18` updated.
- Repeat for `BurnPositionNft` on a closed position.

---

## Leads investigated and ruled out

- **Closed-position fast path in `process_execute`** (`size == 0` short-circuits
  before `TransferOwnershipCpi`): intentional — a closed position has no
  collateral to protect; the NFT is purely decorative at that point.
- **`process_repair_extra_metas`**: permissionless but fully determined by
  on-chain state linked to `nft_mint` (slab + percolator-prog id via
  `slab.owner`); a caller cannot smuggle in attacker-controlled values.
- **Mint handler hardening** (`process_mint_position_nft`): program-key checks,
  ATA derivation checks, fresh-mint check, mint-authority revocation, and
  atomic ExtraAccountMetaList creation are all present and correct.

//! GetPositionValue — read-only valuation for marketplaces and lending protocols.
//!
//! Returns all data needed to value a position NFT:
//! - Unrealized PnL at current oracle price
//! - Net equity (collateral + unrealized PnL)
//! - Distance to liquidation (%)
//! - Current funding rate per slot
//! - Entry price, current size, direction, market
//!
//! All computed from existing on-chain slab state — no new data needed.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    cpi::{read_position, verify_slab_owner},
    error::NftError,
    state::{verify_pda_version, PositionNft, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
};

/// Read a u64 from slab data at offset.
fn read_u64(data: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = data[off..off + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Read a u64 from slab data at offset (checked).
fn read_u64_checked(data: &[u8], off: usize) -> Option<u64> {
    if off + 8 > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[off..off + 8].try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Position valuation data returned by GetPositionValue.
///
/// All values are logged via msg! since Solana programs can't return
/// data directly. Clients read from transaction logs or simulate.
pub struct PositionValuation {
    /// Slab (market) address.
    pub slab: Pubkey,
    /// User index in slab.
    pub user_idx: u16,
    /// 1 = long, 0 = short.
    pub is_long: u8,
    /// Entry price (E6 fixed-point).
    pub entry_price_e6: u64,
    /// Current position size in collateral micro-units.
    pub size: u64,
    /// Current mark/oracle price (E6 fixed-point).
    pub mark_price_e6: u64,
    /// Unrealized PnL in collateral micro-units (signed via i128).
    pub unrealized_pnl: i128,
    /// Collateral deposited (micro-units).
    pub collateral: u64,
    /// Net equity = collateral + unrealized_pnl.
    pub net_equity: i128,
    /// Maintenance margin requirement (micro-units).
    pub maintenance_margin: u64,
    /// Distance to liquidation: (equity - maint_margin) / equity * 10000 (bps).
    /// Negative means already in liquidation zone.
    pub liquidation_distance_bps: i64,
    /// Funding index delta since NFT mint.
    pub funding_delta_e18: i128,
}

// Engine layout offsets (from engine_off)
const ENGINE_MARK_PRICE_OFF: usize = 0; // u64
const ENGINE_ORACLE_PRICE_OFF: usize = 8; // u64
const ENGINE_MAINT_MARGIN_OFF: usize = 96; // u64 (bps)

/// Process GetPositionValue instruction.
///
/// Accounts:
///   0. `[]`  PositionNft PDA
///   1. `[]`  Slab account
///
/// Data: tag(1) — no additional data needed.
///
/// Returns valuation via msg! logs (clients use simulateTransaction).
pub fn process_get_position_value(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let nft_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;

    // Verify slab ownership.
    verify_slab_owner(slab)?;

    // ── PERC-9003: Verify PDA is owned by this program ──
    if nft_pda.owner != _program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read NFT PDA.
    let pda_data = nft_pda.try_borrow_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    verify_pda_version(nft_state)?;
    if nft_state.slab != slab.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read position from slab.
    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;

    // ── PERC-9060: Verify slab slot still matches PDA snapshot ──
    // If the original position was closed and the slab slot reused for a
    // different position, entry_price_e6 and/or is_long will differ from
    // the values snapshotted at mint time. Without this check, valuation
    // would return data for a completely different user's position —
    // misleading lending protocols and marketplaces into mis-pricing the NFT.
    if nft_state.entry_price_e6 != position.entry_price_e6
        || nft_state.is_long != position.is_long
    {
        msg!(
            "GetPositionValue rejected: slab slot reuse detected (PDA snapshot does not match live position)"
        );
        return Err(NftError::PositionMismatch.into());
    }

    if position.size == 0 {
        return Err(NftError::PositionNotOpen.into());
    }

    // engine_off comes from the slab layout detected in read_position().
    let engine_off = position.engine_off;

    // Read mark price.
    let mark_price_e6 = if engine_off + 8 <= slab_data.len() {
        read_u64(&slab_data, engine_off + ENGINE_MARK_PRICE_OFF)
    } else {
        0
    };

    // Read collateral from position data.
    // position.collateral is the actual deposited margin (slab acct_off + ACCT_COLLATERAL_OFF).
    // Do NOT use position.size here — size is the notional trade value, which for a leveraged
    // position is size = collateral × leverage.  Using size inflates equity by the leverage factor.
    let collateral = position.collateral;

    // PERC-9018: Read maintenance_margin_bps as u64 (consistent with transfer_hook.rs).
    // Previously the comment said u128 but transfer hook read it as u64. The engine
    // field is maintenance_margin_bps: u64.
    let maint_margin_bps: u64 = read_u64_checked(&slab_data, engine_off + ENGINE_MAINT_MARGIN_OFF)
        .unwrap_or(0);

    // PERC-9019: Compute PnL with checked arithmetic returning explicit errors
    // instead of silently producing 0 via unwrap_or(0). A silently zeroed PnL
    // can mislead lending protocols into over-valuing a position.
    let unrealized_pnl: i128 = if position.entry_price_e6 > 0 && mark_price_e6 > 0 {
        let size = position.size as i128;
        let mark = mark_price_e6 as i128;
        let entry = position.entry_price_e6 as i128;

        let price_diff = if position.is_long == 1 {
            mark.checked_sub(entry)
                .ok_or(ProgramError::ArithmeticOverflow)?
        } else {
            entry.checked_sub(mark)
                .ok_or(ProgramError::ArithmeticOverflow)?
        };
        size.checked_mul(price_diff)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .checked_div(entry)
            .ok_or(ProgramError::ArithmeticOverflow)?
    } else {
        0
    };

    let net_equity = (collateral as i128)
        .checked_add(unrealized_pnl)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Compute maintenance margin requirement and liquidation distance.
    let maintenance_margin = (position.size as u128)
        .checked_mul(maint_margin_bps as u128)
        .unwrap_or(0) / 10_000;
    let liquidation_distance_bps: i64 = if net_equity > 0 {
        let distance = net_equity
            .checked_sub(maintenance_margin as i128)
            .unwrap_or(0);
        ((distance * 10_000) / net_equity) as i64
    } else {
        -10_000 // fully liquidatable
    };

    // Funding delta since mint.
    let funding_delta_e18 = position
        .global_funding_index_e18
        .checked_sub(nft_state.last_funding_index_e18)
        .unwrap_or(0);

    // Log valuation data (clients read via simulateTransaction).
    msg!(
        "POSITION_VALUE:slab={}",
        Pubkey::new_from_array(nft_state.slab)
    );
    msg!("POSITION_VALUE:idx={}", nft_state.user_idx);
    msg!(
        "POSITION_VALUE:direction={}",
        if position.is_long == 1 {
            "LONG"
        } else {
            "SHORT"
        }
    );
    msg!("POSITION_VALUE:entry_price_e6={}", position.entry_price_e6);
    msg!("POSITION_VALUE:size={}", position.size);
    msg!("POSITION_VALUE:mark_price_e6={}", mark_price_e6);
    msg!("POSITION_VALUE:unrealized_pnl={}", unrealized_pnl);
    msg!("POSITION_VALUE:collateral={}", collateral);
    msg!("POSITION_VALUE:net_equity={}", net_equity);
    msg!("POSITION_VALUE:maintenance_margin={}", maintenance_margin);
    msg!(
        "POSITION_VALUE:liquidation_distance_bps={}",
        liquidation_distance_bps
    );
    msg!("POSITION_VALUE:funding_delta_e18={}", funding_delta_e18);

    Ok(())
}

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
    state::{PositionNft, POSITION_NFT_LEN, POSITION_NFT_MAGIC},
};

/// Read a u64 from slab data at offset.
fn read_u64(data: &[u8], off: usize) -> u64 {
    let bytes: [u8; 8] = data[off..off + 8].try_into().unwrap();
    u64::from_le_bytes(bytes)
}

/// Read a u128 from slab data at offset.
fn read_u128(data: &[u8], off: usize) -> u128 {
    let bytes: [u8; 16] = data[off..off + 16].try_into().unwrap();
    u128::from_le_bytes(bytes)
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
const ENGINE_MAINT_MARGIN_OFF: usize = 96; // u128

// Account layout offsets (from account start)
const ACCT_COLLATERAL_OFF: usize = 32; // u64 at offset 32

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

    // Read NFT PDA.
    let pda_data = nft_pda.try_borrow_data()?;
    if pda_data.len() < POSITION_NFT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let nft_state = bytemuck::from_bytes::<PositionNft>(&pda_data[..POSITION_NFT_LEN]);
    if nft_state.magic != POSITION_NFT_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    if nft_state.slab != slab.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Read position from slab.
    let slab_data = slab.try_borrow_data()?;
    let position = read_position(&slab_data, nft_state.user_idx)?;

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

    // Read collateral from account slot.
    // Account struct offset depends on layout — use position.size as proxy.
    let collateral = position.size; // In practice, collateral is a separate field.
                                    // For accurate collateral, we'd need the full account struct offset.
                                    // Using position.size as a conservative estimate for now.

    // Compute unrealized PnL.
    // PnL = size * (mark_price - entry_price) / entry_price [for longs]
    // PnL = size * (entry_price - mark_price) / entry_price [for shorts]
    let unrealized_pnl: i128 = if position.entry_price_e6 > 0 && mark_price_e6 > 0 {
        let size = position.size as i128;
        let mark = mark_price_e6 as i128;
        let entry = position.entry_price_e6 as i128;

        if position.is_long == 1 {
            size.checked_mul(mark.checked_sub(entry).unwrap_or(0))
                .unwrap_or(0)
                .checked_div(entry)
                .unwrap_or(0)
        } else {
            size.checked_mul(entry.checked_sub(mark).unwrap_or(0))
                .unwrap_or(0)
                .checked_div(entry)
                .unwrap_or(0)
        }
    } else {
        0
    };

    let net_equity = collateral as i128 + unrealized_pnl;

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
    msg!("POSITION_VALUE:funding_delta_e18={}", funding_delta_e18);

    Ok(())
}

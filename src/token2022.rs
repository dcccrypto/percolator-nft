//! Raw Token-2022 instruction construction.
//!
//! We build instructions manually to avoid spl-token-2022 crate
//! dependency conflicts (it pins solana 2.1, we use 2.2.1).
//! Same pattern as percolator-stake's manual spl-token CPI.

use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

/// Token-2022 program ID.
pub const TOKEN_2022_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

/// Associated Token Account program ID.
pub const ATA_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// SPL Token instruction tags (same for Token and Token-2022).
const IX_INITIALIZE_MINT2: u8 = 20;
const IX_MINT_TO: u8 = 7;
const IX_BURN: u8 = 8;

/// Build InitializeMint2 instruction (Token-2022).
/// decimals=0, mint_authority=authority, freeze_authority=None.
pub fn initialize_mint2(
    mint: &Pubkey,
    authority: &Pubkey,
) -> Instruction {
    // Layout: tag(1) + decimals(1) + mint_authority(32) + freeze_option(1) [+ freeze_authority(32)]
    let mut data = Vec::with_capacity(35);
    data.push(IX_INITIALIZE_MINT2);
    data.push(0); // decimals = 0
    data.extend_from_slice(authority.as_ref()); // mint authority
    data.push(0); // no freeze authority

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
        ],
        data,
    }
}

/// Build MintTo instruction (Token-2022).
pub fn mint_to(
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    // Layout: tag(1) + amount(8)
    let mut data = Vec::with_capacity(9);
    data.push(IX_MINT_TO);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Build Burn instruction (Token-2022).
pub fn burn(
    account: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(IX_BURN);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// Derive the associated token account address for Token-2022.
pub fn get_associated_token_address(
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[
            wallet.as_ref(),
            TOKEN_2022_PROGRAM_ID.as_ref(),
            mint.as_ref(),
        ],
        &ATA_PROGRAM_ID,
    )
    .0
}

/// Build CreateAssociatedTokenAccount instruction for Token-2022.
pub fn create_associated_token_account(
    payer: &Pubkey,
    wallet: &Pubkey,
    mint: &Pubkey,
) -> Instruction {
    let ata = get_associated_token_address(wallet, mint);

    Instruction {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*wallet, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(solana_program::system_program::id(), false),
            AccountMeta::new_readonly(TOKEN_2022_PROGRAM_ID, false),
        ],
        data: vec![],
    }
}

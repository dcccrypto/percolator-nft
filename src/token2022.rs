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
/// decimals=0, mint_authority=authority, freeze_authority=authority (same PDA).
///
/// PERC-9033: The freeze authority is set to the mint_authority PDA so that the
/// program can emergency-freeze NFT token accounts if a vulnerability is
/// discovered. Without a freeze authority, there is no way to pause transfers
/// while a fix is deployed — a critical gap in incident response capability.
pub fn initialize_mint2(mint: &Pubkey, authority: &Pubkey) -> Instruction {
    // Layout: tag(1) + decimals(1) + mint_authority(32) + freeze_option(1) + freeze_authority(32)
    let mut data = Vec::with_capacity(67);
    data.push(IX_INITIALIZE_MINT2);
    data.push(0); // decimals = 0
    data.extend_from_slice(authority.as_ref()); // mint authority
    data.push(1); // has freeze authority
    data.extend_from_slice(authority.as_ref()); // freeze authority = same PDA

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
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
pub fn burn(account: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
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

/// SPL Token SetAuthority instruction tag (same for Token and Token-2022).
const IX_SET_AUTHORITY: u8 = 6;

/// Build SetAuthority instruction to remove the mint authority (set to None).
///
/// This is the standard NFT pattern: after minting supply=1, revoke the mint
/// authority so no additional tokens can ever be minted for this mint.
///
/// Data layout: tag(1) + authority_type(1) + new_authority_option(1)
///   authority_type 0 = MintTokens
///   new_authority_option 0 = None (no new authority)
pub fn set_mint_authority_none(mint: &Pubkey, current_authority: &Pubkey) -> Instruction {
    let data = vec![
        IX_SET_AUTHORITY,
        0, // authority_type = MintTokens
        0, // COption::None — no new authority
    ];

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*current_authority, true),
        ],
        data,
    }
}

/// SPL Token CloseAccount instruction tag (same for Token and Token-2022).
const IX_CLOSE_ACCOUNT: u8 = 9;

/// Build CloseAccount instruction (Token-2022).
/// PERC-9031/9032: Close a token account or mint, returning rent to destination.
pub fn close_account(account: &Pubkey, destination: &Pubkey, owner: &Pubkey) -> Instruction {
    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data: vec![IX_CLOSE_ACCOUNT],
    }
}

/// Derive the associated token account address for Token-2022.
pub fn get_associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
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

// ═══════════════════════════════════════════════════════════════
// Token Metadata (spl_token_metadata_interface)
// ═══════════════════════════════════════════════════════════════

/// Token metadata program discriminator for Initialize.
/// SHA256("spl_token_metadata_interface:initialize_account")[:8]
const METADATA_INIT_DISCRIMINATOR: [u8; 8] = [210, 225, 30, 162, 88, 184, 77, 141];

/// Encode a string as borsh: u32 LE length + utf8 bytes.
///
/// PERC-9043: Use u32::try_from to detect strings exceeding u32::MAX.
/// The original `as u32` cast silently truncates, producing malformed borsh.
fn borsh_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).expect("borsh_string: length exceeds u32::MAX");
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Build Token-2022 metadata initialize instruction.
/// This uses the embedded metadata extension (no separate Metaplex program needed).
///
/// Accounts: [mint(w), update_authority, mint_authority(s)]
pub fn initialize_token_metadata(
    mint: &Pubkey,
    update_authority: &Pubkey,
    mint_authority: &Pubkey,
    name: &str,
    symbol: &str,
    uri: &str,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 12 + name.len() + symbol.len() + uri.len());
    data.extend_from_slice(&METADATA_INIT_DISCRIMINATOR);
    data.extend(borsh_string(name));
    data.extend(borsh_string(symbol));
    data.extend(borsh_string(uri));

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*update_authority, false),
            AccountMeta::new_readonly(*mint_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════
// MetadataPointer Extension
// ═══════════════════════════════════════════════════════════════

/// Outer Token-2022 instruction tag for the MetadataPointer extension family.
pub const METADATA_POINTER_EXTENSION_TAG: u8 = 39;
/// Sub-tag within the MetadataPointer family for `Initialize`.
pub const METADATA_POINTER_INITIALIZE_SUB_TAG: u8 = 0;
/// Exact wire-format length of an `InitializeMetadataPointer` instruction.
///
/// Layout (matches upstream `encode_instruction`):
///   outer_tag(1) + sub_tag(1) + authority(32) + metadata_address(32) = 66
pub const INITIALIZE_METADATA_POINTER_IX_LEN: usize = 66;

/// Initialize MetadataPointer extension on a Token-2022 mint.
/// Must be called BEFORE InitializeMint2.
///
/// PERC-9061: Without this extension, wallets and explorers using standard
/// Token-2022 metadata discovery will not find the embedded metadata, even
/// though the bytes are physically present in the mint account.
///
/// For self-referencing embedded metadata:
///   authority     = mint_auth PDA (can update the pointer later)
///   metadata_addr = mint itself (metadata lives in this account)
///
/// PERC-9063: Wire format correction. Token-2022 extension instructions use a
/// two-byte discriminator (outer extension tag + sub-instruction tag), and the
/// payload is `InitializeInstructionData` — a `#[repr(C)]` struct of two
/// `OptionalNonZeroPubkey` fields. `OptionalNonZeroPubkey` is
/// `#[repr(transparent)]` over `Pubkey` (32 raw bytes; zero = None).
/// Confirmed against upstream `solana-program/token-2022/interface`.
///
/// Wire format:
///   byte  0      : outer tag = 39 (MetadataPointerExtension family)
///   byte  1      : sub-tag   = 0  (Initialize variant)
///   bytes 2..34  : authority        (OptionalNonZeroPubkey, 32 bytes, no option flag)
///   bytes 34..66 : metadata_address (OptionalNonZeroPubkey, 32 bytes, no option flag)
///
/// Total: 66 bytes. A zero Pubkey encodes `None`; callers pass real PDA
/// pubkeys so both fields are always `Some`.
pub fn initialize_metadata_pointer(
    mint: &Pubkey,
    authority: &Pubkey,
    metadata_address: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(INITIALIZE_METADATA_POINTER_IX_LEN);
    data.push(METADATA_POINTER_EXTENSION_TAG);
    data.push(METADATA_POINTER_INITIALIZE_SUB_TAG);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(metadata_address.as_ref());

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Size of MetadataPointer extension: type(2) + length(2) + authority(32) + metadata_address(32) = 68 bytes.
pub const METADATA_POINTER_EXTENSION_SIZE: u64 = 68;

// ═══════════════════════════════════════════════════════════════
// TransferHook Extension
// ═══════════════════════════════════════════════════════════════

/// Outer Token-2022 instruction tag for the TransferHook extension family.
pub const TRANSFER_HOOK_EXTENSION_TAG: u8 = 36;
/// Sub-tag within the TransferHook family for `Initialize`.
pub const TRANSFER_HOOK_INITIALIZE_SUB_TAG: u8 = 0;
/// Exact wire-format length of an `InitializeTransferHook` instruction.
///
/// Layout (matches upstream `encode_instruction`):
///   outer_tag(1) + sub_tag(1) + authority(32) + program_id(32) = 66
pub const INITIALIZE_TRANSFER_HOOK_IX_LEN: usize = 66;

/// Initialize TransferHook extension on a Token-2022 mint.
/// Must be called BEFORE InitializeMint2.
///
/// PERC-9063: Wire format correction. Prior versions emitted 65 bytes,
/// omitting the sub-tag — Token-2022 rejected the instruction with
/// InvalidInstructionData. Like MetadataPointer, TransferHook uses the
/// two-byte extension discriminator (outer tag + sub-tag) followed by
/// `InitializeInstructionData` — two `OptionalNonZeroPubkey` fields.
/// Confirmed against upstream `solana-program/token-2022/interface`.
///
/// Wire format:
///   byte  0      : outer tag = 36 (TransferHookExtension family)
///   byte  1      : sub-tag   = 0  (Initialize variant)
///   bytes 2..34  : authority   (OptionalNonZeroPubkey, 32 bytes, no option flag)
///   bytes 34..66 : program_id  (OptionalNonZeroPubkey, 32 bytes, no option flag)
///
/// Total: 66 bytes.
pub fn initialize_transfer_hook(
    mint: &Pubkey,
    authority: &Pubkey,
    hook_program_id: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(INITIALIZE_TRANSFER_HOOK_IX_LEN);
    data.push(TRANSFER_HOOK_EXTENSION_TAG);
    data.push(TRANSFER_HOOK_INITIALIZE_SUB_TAG);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(hook_program_id.as_ref());

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Size of TransferHook extension data (authority + program_id).
pub const TRANSFER_HOOK_EXTENSION_SIZE: u64 = 4 + 64; // type(2) + len(2) + authority(32) + program_id(32)

/// Size of MintCloseAuthority extension (TLV header + authority pubkey).
pub const MINT_CLOSE_AUTHORITY_EXTENSION_SIZE: u64 = 4 + 32; // type(2) + len(2) + authority(32)

/// Initialize MintCloseAuthority extension on a Token-2022 mint.
/// Must be called BEFORE InitializeMint2.
///
/// This extension allows closing the mint account (reclaiming rent) when
/// supply reaches 0. Without it, Token-2022 rejects CloseAccount on mints.
///
/// Instruction tag 25 = InitializeMintCloseAuthority.
/// Data: tag(1) + option(1) + authority(32)
pub fn initialize_mint_close_authority(
    mint: &Pubkey,
    close_authority: &Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(34);
    data.push(25); // InitializeMintCloseAuthority instruction tag
    data.push(1);  // COption::Some
    data.extend_from_slice(close_authority.as_ref());

    Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
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

// #184 (4.2): scoped here from the crate root. The `entrypoint!` macro below uses
// platform cfgs (custom-heap, custom-panic, target_os="solana") that are not in our
// check-cfg list; suppressing them crate-wide also hid feature-name typos everywhere.
#![allow(unexpected_cfgs)]
use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
};

use crate::processor;

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, instruction_data)
}

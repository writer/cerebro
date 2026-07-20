#![allow(unsafe_code)]

use crate::{ABI_VERSION, MAX_QUERY_BYTES, validate};
use cerebro_wasm_guest::MemoryError;

const RESULT_SIZE: usize = 24;

#[repr(u32)]
#[derive(Clone, Copy)]
enum AbiStatus {
    Success = 0,
    InvalidMemory = 1,
    QueryTooLarge = 2,
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc_bounded(length, MAX_QUERY_BYTES)
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_validate(
    query_pointer: u32,
    query_length: u32,
    max_rows: u64,
    result_pointer: u32,
) -> u32 {
    let result = cerebro_wasm_guest::with_input_and_output::<_, RESULT_SIZE>(
        query_pointer,
        query_length,
        result_pointer,
        MAX_QUERY_BYTES,
        |query_bytes| {
            let query = std::str::from_utf8(query_bytes).map_err(|_| MemoryError::OutOfBounds)?;
            let validation = validate(query, max_rows);
            let mut result = [0_u8; RESULT_SIZE];
            result[0..4].copy_from_slice(&(validation.decision as u32).to_le_bytes());
            result[8..16].copy_from_slice(&validation.limit.to_le_bytes());
            result[16..24].copy_from_slice(&validation.detail.to_le_bytes());
            cerebro_wasm_guest::write_fixed(result_pointer, &result)
        },
    );
    match result {
        Ok(Ok(())) => AbiStatus::Success as u32,
        Err(MemoryError::TooLarge) => AbiStatus::QueryTooLarge as u32,
        Ok(Err(_)) | Err(_) => AbiStatus::InvalidMemory as u32,
    }
}

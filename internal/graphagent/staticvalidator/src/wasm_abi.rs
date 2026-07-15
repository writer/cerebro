#![allow(unsafe_code)]

use crate::{ABI_VERSION, MAX_QUERY_BYTES, validate};

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
    if length as usize > MAX_QUERY_BYTES {
        return 0;
    }
    let mut bytes = vec![0_u8; length as usize];
    let pointer = bytes.as_mut_ptr() as usize;
    std::mem::forget(bytes);
    u32::try_from(pointer).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_validator_validate(
    query_pointer: u32,
    query_length: u32,
    max_rows: u64,
    result_pointer: u32,
) -> u32 {
    if query_length as usize > MAX_QUERY_BYTES {
        return AbiStatus::QueryTooLarge as u32;
    }
    let query_start = query_pointer as usize;
    let result_start = result_pointer as usize;
    let Some(query_end) = query_start.checked_add(query_length as usize) else {
        return AbiStatus::InvalidMemory as u32;
    };
    let Some(result_end) = result_start.checked_add(RESULT_SIZE) else {
        return AbiStatus::InvalidMemory as u32;
    };
    let memory_size = core::arch::wasm32::memory_size(0) * 65_536;
    if query_end > memory_size || result_end > memory_size {
        return AbiStatus::InvalidMemory as u32;
    }

    // SAFETY: Both ranges were checked against the current linear-memory size. The host allocates
    // disjoint query and result ranges through cerebro_validator_alloc before invoking this export.
    let query_bytes =
        unsafe { std::slice::from_raw_parts(query_pointer as *const u8, query_length as usize) };
    let Ok(query) = std::str::from_utf8(query_bytes) else {
        return AbiStatus::InvalidMemory as u32;
    };
    let validation = validate(query, max_rows);
    let mut result = [0_u8; RESULT_SIZE];
    result[0..4].copy_from_slice(&(validation.decision as u32).to_le_bytes());
    result[8..16].copy_from_slice(&validation.limit.to_le_bytes());
    result[16..24].copy_from_slice(&validation.detail.to_le_bytes());
    // SAFETY: result_pointer..result_pointer+RESULT_SIZE was checked against linear memory above.
    unsafe {
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_pointer as *mut u8, result.len());
    }
    AbiStatus::Success as u32
}

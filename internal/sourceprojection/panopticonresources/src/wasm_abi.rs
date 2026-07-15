#![allow(unsafe_code)]

use crate::{ABI_VERSION, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, extract};
use cerebro_wasm_guest::{BoundedOutput, MemoryError};

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_panopticon_resources_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_panopticon_resources_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc_bounded(length, MAX_INPUT_BYTES)
}

#[unsafe(no_mangle)]
pub extern "C" fn cerebro_panopticon_resources_extract(
    input_pointer: u32,
    input_length: u32,
    descriptor_pointer: u32,
) -> u32 {
    let result = cerebro_wasm_guest::with_input_and_output::<
        _,
        { cerebro_wasm_guest::JSON_RESULT_DESCRIPTOR_SIZE },
    >(
        input_pointer,
        input_length,
        descriptor_pointer,
        MAX_INPUT_BYTES,
        |input| {
            let mut output = BoundedOutput::new(MAX_OUTPUT_BYTES);
            serde_json::to_writer(&mut output, &extract(input)).map_err(|_| 2_u32)?;
            cerebro_wasm_guest::write_json_result(
                descriptor_pointer,
                output.into_inner(),
                MAX_OUTPUT_BYTES,
            )
            .map_err(|_| 2_u32)
        },
    );
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(status)) => status,
        Err(
            MemoryError::TooLarge
            | MemoryError::Null
            | MemoryError::OutOfBounds
            | MemoryError::Overlap,
        ) => 1,
    }
}

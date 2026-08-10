#![allow(unsafe_code)]

use crate::evaluation::evaluate;
use crate::{ABI_VERSION, EvaluationRequest, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
use cerebro_wasm_guest::{BoundedOutput, MemoryError};

#[unsafe(no_mangle)]
/// Returns the version of this module's host/guest memory contract.
pub extern "C" fn cerebro_security_path_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
/// Allocates up to the kernel input limit and returns its linear-memory pointer.
///
/// A return value of zero means the requested length was zero, exceeded the
/// limit, or could not be allocated. The host transfers ownership of a successful
/// allocation back to the guest by passing it to
/// [`cerebro_security_path_evaluate`].
pub extern "C" fn cerebro_security_path_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc_bounded(length, MAX_INPUT_BYTES)
}

#[unsafe(no_mangle)]
/// Evaluates one JSON request from WebAssembly linear memory.
///
/// `request_pointer` and `request_length` identify the buffer returned by
/// [`cerebro_security_path_alloc`]. `result_pointer` identifies the fixed-size
/// result descriptor defined by `cerebro-wasm-guest`; on success that descriptor
/// receives the pointer and length of the JSON response.
///
/// Status codes are stable host-facing outcomes: `0` is success, `1` is invalid
/// request JSON, `2` is a rejected kernel input, `3` is response serialization or
/// result-write failure, and `4` is an invalid, overlapping, or oversized memory
/// range. Detailed validation errors intentionally do not cross this ABI.
///
/// # Safety contract
///
/// Hosts must treat all pointers as offsets into this module's current linear
/// memory and must not reuse the input allocation after this call consumes it.
pub extern "C" fn cerebro_security_path_evaluate(
    request_pointer: u32,
    request_length: u32,
    result_pointer: u32,
) -> u32 {
    let result = cerebro_wasm_guest::with_input_and_output::<
        _,
        { cerebro_wasm_guest::JSON_RESULT_DESCRIPTOR_SIZE },
    >(
        request_pointer,
        request_length,
        result_pointer,
        MAX_INPUT_BYTES,
        |request_bytes| {
            let request: EvaluationRequest =
                serde_json::from_slice(request_bytes).map_err(|_| 1_u32)?;
            let response = evaluate(request).map_err(|_| 2_u32)?;
            let mut output = BoundedOutput::new(MAX_OUTPUT_BYTES);
            serde_json::to_writer(&mut output, &response).map_err(|_| 3_u32)?;
            cerebro_wasm_guest::write_json_result(
                result_pointer,
                output.into_inner(),
                MAX_OUTPUT_BYTES,
            )
            .map_err(|_| 3_u32)
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
        ) => 4,
    }
}

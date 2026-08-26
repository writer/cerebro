#![allow(unsafe_code)]

use crate::{ABI_VERSION, EvaluationEnvelope, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, evaluate};
use cerebro_wasm_guest::{BoundedOutput, MemoryError};

#[unsafe(no_mangle)]
/// Returns the finding-rule host/guest ABI version.
pub extern "C" fn cerebro_finding_rule_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
/// Allocates a bounded finding-rule request buffer.
pub extern "C" fn cerebro_finding_rule_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc_bounded(length, MAX_INPUT_BYTES)
}

#[unsafe(no_mangle)]
/// Evaluates one bounded JSON finding-rule request.
pub extern "C" fn cerebro_finding_rule_evaluate(
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
            let request: EvaluationEnvelope =
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

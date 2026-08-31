#![allow(unsafe_code)]

//! Bounded C ABI exported only by `wasm32` finding-rule builds.
//!
//! Unsafe export attributes are isolated in this module. Pointer ownership and
//! overlap validation are delegated to `cerebro-wasm-guest`; rule evaluation
//! receives only an owned, bounded JSON slice after those checks pass.

use crate::{ABI_VERSION, EvaluationEnvelope, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, evaluate};
use cerebro_wasm_guest::{BoundedOutput, MemoryError};

#[unsafe(no_mangle)]
/// Returns the finding-rule host/guest memory-contract version.
pub extern "C" fn cerebro_finding_rule_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
/// Allocates up to the kernel input limit and returns its linear-memory pointer.
///
/// Zero means the requested length was zero, exceeded [`MAX_INPUT_BYTES`], or
/// could not be allocated. The host transfers a successful allocation back to
/// the guest by passing it to [`cerebro_finding_rule_evaluate`].
pub extern "C" fn cerebro_finding_rule_alloc(length: u32) -> u32 {
    cerebro_wasm_guest::alloc_bounded(length, MAX_INPUT_BYTES)
}

#[unsafe(no_mangle)]
/// Evaluates one JSON request from WebAssembly linear memory.
///
/// `request_pointer` and `request_length` identify the allocation returned by
/// [`cerebro_finding_rule_alloc`]. `result_pointer` identifies the fixed-size
/// JSON result descriptor defined by `cerebro-wasm-guest`; success writes the
/// response allocation pointer and length into that descriptor.
///
/// Status codes are stable and intentionally coarse: `0` is success, `1` is
/// invalid request JSON, `2` is a rejected kernel request, `3` is bounded output
/// serialization or descriptor-write failure, and `4` is a null, overlapping,
/// oversized, or out-of-bounds memory range. Detailed rule errors do not cross
/// the ABI.
///
/// # Safety contract
///
/// Hosts must treat all pointers as offsets into this module's current linear
/// memory and must not reuse the input allocation after this call consumes it.
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
            // Keep parse, domain evaluation, and response-write failures in
            // separate status classes without serializing internal diagnostics.
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
    // Memory shape errors are indistinguishable to an untrusted host and share
    // one status code. Domain failures have already been classified above.
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

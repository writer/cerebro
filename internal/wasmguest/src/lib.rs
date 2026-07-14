//! Shared linear-memory mechanics for Cerebro's embedded Wasm guests.
//!
//! Export names, ABI versions, status codes, and domain protocols remain owned by each guest.

/// Size of the result descriptor used by JSON guest protocols.
pub const JSON_RESULT_DESCRIPTOR_SIZE: usize = 16;

/// Allocates guest memory for a host-provided input or result descriptor.
#[cfg(target_arch = "wasm32")]
pub fn alloc(length: u32) -> u32 {
    let mut bytes = vec![0_u8; length as usize];
    let pointer = bytes.as_mut_ptr() as usize;
    std::mem::forget(bytes);
    u32::try_from(pointer).unwrap_or_default()
}

/// Runs `operation` with an input slice after validating the input and fixed-output ranges.
///
/// The ranges must be disjoint because the operation receives a shared input slice and may write
/// the fixed output before it returns.
#[cfg(target_arch = "wasm32")]
pub fn with_input_and_output<R, const OUTPUT_SIZE: usize>(
    input_pointer: u32,
    input_length: u32,
    output_pointer: u32,
    operation: impl FnOnce(&[u8]) -> R,
) -> Option<R> {
    if !range_in_bounds(input_pointer, input_length as usize)
        || !range_in_bounds(output_pointer, OUTPUT_SIZE)
        || ranges_overlap(
            input_pointer,
            input_length as usize,
            output_pointer,
            OUTPUT_SIZE,
        )
    {
        return None;
    }
    if input_length == 0 {
        return Some(operation(&[]));
    }
    if input_pointer == 0 {
        return None;
    }

    // SAFETY: The non-empty range is non-null and was checked against the current linear-memory
    // size. The output range is disjoint, and Wasm execution cannot concurrently mutate memory.
    let input =
        unsafe { std::slice::from_raw_parts(input_pointer as *const u8, input_length as usize) };
    Some(operation(input))
}

/// Writes a fixed-size protocol response into a validated guest-memory range.
#[cfg(target_arch = "wasm32")]
pub fn write_fixed<const OUTPUT_SIZE: usize>(
    output_pointer: u32,
    output: &[u8; OUTPUT_SIZE],
) -> bool {
    if output_pointer == 0 || !range_in_bounds(output_pointer, OUTPUT_SIZE) {
        return false;
    }
    // SAFETY: The non-empty output range is non-null and was checked against linear memory.
    unsafe {
        std::ptr::copy_nonoverlapping(output.as_ptr(), output_pointer as *mut u8, output.len())
    };
    true
}

/// Leaks a JSON output buffer to the host and writes its 16-byte result descriptor.
#[cfg(target_arch = "wasm32")]
pub fn write_json_result(descriptor_pointer: u32, output: Vec<u8>) -> bool {
    if descriptor_pointer == 0 || !range_in_bounds(descriptor_pointer, JSON_RESULT_DESCRIPTOR_SIZE)
    {
        return false;
    }
    let mut output = output.into_boxed_slice();
    let Ok(output_pointer) = u32::try_from(output.as_mut_ptr() as usize) else {
        return false;
    };
    let Ok(output_length) = u32::try_from(output.len()) else {
        return false;
    };
    let descriptor = json_result_descriptor(output_pointer, output_length);
    std::mem::forget(output);
    write_fixed(descriptor_pointer, &descriptor)
}

#[cfg(target_arch = "wasm32")]
fn range_in_bounds(pointer: u32, length: usize) -> bool {
    let Ok(length) = u64::try_from(length) else {
        return false;
    };
    let Some(end) = u64::from(pointer).checked_add(length) else {
        return false;
    };
    let memory_size = (core::arch::wasm32::memory_size(0) as u64) * 65_536;
    end <= memory_size
}

#[cfg(target_arch = "wasm32")]
fn ranges_overlap(
    left_pointer: u32,
    left_length: usize,
    right_pointer: u32,
    right_length: usize,
) -> bool {
    let left_start = u64::from(left_pointer);
    let right_start = u64::from(right_pointer);
    let left_end = left_start + left_length as u64;
    let right_end = right_start + right_length as u64;
    left_start < right_end && right_start < left_end
}

#[cfg(any(test, target_arch = "wasm32"))]
fn json_result_descriptor(output_pointer: u32, output_length: u32) -> [u8; 16] {
    let mut descriptor = [0_u8; JSON_RESULT_DESCRIPTOR_SIZE];
    descriptor[4..8].copy_from_slice(&output_pointer.to_le_bytes());
    descriptor[8..12].copy_from_slice(&output_length.to_le_bytes());
    descriptor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_descriptor_preserves_status_pointer_length_and_reserved_fields() {
        let descriptor = json_result_descriptor(0x1020_3040, 0x5060_7080);
        assert_eq!(&descriptor[0..4], &[0; 4]);
        assert_eq!(&descriptor[4..8], &0x1020_3040_u32.to_le_bytes());
        assert_eq!(&descriptor[8..12], &0x5060_7080_u32.to_le_bytes());
        assert_eq!(&descriptor[12..16], &[0; 4]);
    }
}

#![deny(unsafe_code)]

//! Shared linear-memory mechanics for Cerebro's embedded Wasm guests.
//!
//! Export names, ABI versions, status codes, and domain protocols remain owned by each guest.

use std::io::{self, Write};

/// Size of the result descriptor used by JSON guest protocols.
pub const JSON_RESULT_DESCRIPTOR_SIZE: usize = 16;

/// A rejected guest-memory contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// A required pointer was null.
    Null,
    /// A requested input or output exceeded its protocol limit.
    TooLarge,
    /// A range extended beyond the current linear memory.
    OutOfBounds,
    /// Input and output ranges were not disjoint.
    Overlap,
}

/// A serializer destination that never grows beyond its protocol limit.
#[derive(Debug)]
pub struct BoundedOutput {
    bytes: Vec<u8>,
    max_length: usize,
}

impl BoundedOutput {
    /// Creates an empty bounded output.
    pub const fn new(max_length: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_length,
        }
    }

    /// Returns the serialized bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(new_length) = self.bytes.len().checked_add(bytes.len()) else {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "Wasm output limit exceeded",
            ));
        };
        if new_length > self.max_length {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "Wasm output limit exceeded",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| io::Error::other("Wasm output allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm32 {
    #![allow(unsafe_code)]

    use super::{JSON_RESULT_DESCRIPTOR_SIZE, MemoryError, ranges_overlap};

    /// Allocates guest memory only when `length` is within the guest protocol's input limit.
    pub fn alloc_bounded(length: u32, max_length: usize) -> u32 {
        if length as usize > max_length {
            return 0;
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(length as usize).is_err() {
            return 0;
        }
        bytes.resize(length as usize, 0_u8);
        let pointer = bytes.as_mut_ptr() as usize;
        std::mem::forget(bytes);
        u32::try_from(pointer).unwrap_or_default()
    }

    /// Runs `operation` after validating bounded, non-null, disjoint input and output ranges.
    pub fn with_input_and_output<R, const OUTPUT_SIZE: usize>(
        input_pointer: u32,
        input_length: u32,
        output_pointer: u32,
        max_input_length: usize,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, MemoryError> {
        if input_length as usize > max_input_length {
            return Err(MemoryError::TooLarge);
        }
        if input_pointer == 0 || output_pointer == 0 {
            return Err(MemoryError::Null);
        }
        if !range_in_bounds(input_pointer, input_length as usize)
            || !range_in_bounds(output_pointer, OUTPUT_SIZE)
        {
            return Err(MemoryError::OutOfBounds);
        }
        if ranges_overlap(
            input_pointer,
            input_length as usize,
            output_pointer,
            OUTPUT_SIZE,
        ) {
            return Err(MemoryError::Overlap);
        }
        if input_length == 0 {
            return Ok(operation(&[]));
        }

        // SAFETY: The non-empty range is non-null and was checked against the current linear-memory
        // size. The output range is disjoint, and Wasm execution cannot concurrently mutate memory.
        let input = unsafe {
            std::slice::from_raw_parts(input_pointer as *const u8, input_length as usize)
        };
        Ok(operation(input))
    }

    /// Writes a fixed-size protocol response into a validated guest-memory range.
    pub fn write_fixed<const OUTPUT_SIZE: usize>(
        output_pointer: u32,
        output: &[u8; OUTPUT_SIZE],
    ) -> Result<(), MemoryError> {
        if output_pointer == 0 {
            return Err(MemoryError::Null);
        }
        if !range_in_bounds(output_pointer, OUTPUT_SIZE) {
            return Err(MemoryError::OutOfBounds);
        }
        // SAFETY: The destination range is non-null and within linear memory. `copy` permits an
        // arbitrary caller to target an address overlapping the stack-local source buffer.
        unsafe { std::ptr::copy(output.as_ptr(), output_pointer as *mut u8, output.len()) };
        Ok(())
    }

    /// Writes a bounded JSON output descriptor after proving descriptor/output disjointness.
    pub fn write_json_result(
        descriptor_pointer: u32,
        mut output: Vec<u8>,
        max_output_length: usize,
    ) -> Result<(), MemoryError> {
        if output.len() > max_output_length {
            return Err(MemoryError::TooLarge);
        }
        if descriptor_pointer == 0 {
            return Err(MemoryError::Null);
        }
        if !range_in_bounds(descriptor_pointer, JSON_RESULT_DESCRIPTOR_SIZE) {
            return Err(MemoryError::OutOfBounds);
        }
        let output_pointer =
            u32::try_from(output.as_mut_ptr() as usize).map_err(|_| MemoryError::OutOfBounds)?;
        let output_length = u32::try_from(output.len()).map_err(|_| MemoryError::TooLarge)?;
        if !range_in_bounds(output_pointer, output.len()) {
            return Err(MemoryError::OutOfBounds);
        }
        if ranges_overlap(
            descriptor_pointer,
            JSON_RESULT_DESCRIPTOR_SIZE,
            output_pointer,
            output.len(),
        ) {
            return Err(MemoryError::Overlap);
        }
        let descriptor = super::json_result_descriptor(output_pointer, output_length);
        write_fixed(descriptor_pointer, &descriptor)?;
        std::mem::forget(output);
        Ok(())
    }

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
}

#[cfg(target_arch = "wasm32")]
pub use wasm32::{alloc_bounded, with_input_and_output, write_fixed, write_json_result};

#[cfg(any(test, target_arch = "wasm32"))]
fn ranges_overlap(
    left_pointer: u32,
    left_length: usize,
    right_pointer: u32,
    right_length: usize,
) -> bool {
    if left_length == 0 || right_length == 0 {
        return false;
    }
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

    #[test]
    fn bounded_output_rejects_growth_past_limit_without_partial_write() {
        let mut output = BoundedOutput::new(4);
        output.write_all(b"rust").expect("write at limit");
        assert!(output.write_all(b"!").is_err());
        assert_eq!(output.into_inner(), b"rust");
    }

    #[test]
    fn range_overlap_distinguishes_overlap_adjacency_and_empty_ranges() {
        assert!(ranges_overlap(100, 16, 108, 16));
        assert!(ranges_overlap(108, 16, 100, 16));
        assert!(!ranges_overlap(100, 16, 116, 16));
        assert!(!ranges_overlap(100, 0, 100, 16));
        assert!(!ranges_overlap(100, 16, 100, 0));
    }
}

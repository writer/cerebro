#![deny(unsafe_code)]

mod extraction;
mod normalization;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use extraction::{ABI_VERSION, extract};
#[cfg(target_arch = "wasm32")]
pub(crate) use extraction::{MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};

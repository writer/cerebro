#![deny(unsafe_code)]

mod evaluation;
mod model;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{ABI_VERSION, evaluate};
#[cfg(target_arch = "wasm32")]
pub(crate) use evaluation::{MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
#[cfg(target_arch = "wasm32")]
pub(crate) use model::EvaluationResponse;
pub use model::{EvaluationRequest, Record};

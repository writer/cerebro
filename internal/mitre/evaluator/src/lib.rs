#![deny(unsafe_code)]

mod evaluation;
mod model;
mod normalization;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{ABI_VERSION, evaluate};
#[cfg(target_arch = "wasm32")]
pub(crate) use evaluation::{MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
pub use model::{
    AttackTactic, AttackTechnique, ContextInput, ContextOutput, DefendArtifact, DefendTactic,
    DefendTechnique,
};

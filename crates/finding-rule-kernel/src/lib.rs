#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Closed Rust authority for finding-rule matching and lifecycle decisions.

mod digest;
mod evaluation;
mod model;
#[allow(dead_code, unused_imports)]
mod payload_findings;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{ABI_VERSION, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, evaluate};
pub use model::{
    AURELIUS_DEFINITION_DIGEST, AURELIUS_RULE_ID, COSMO_DEFINITION_DIGEST, COSMO_RULE_ID,
    EvaluationEnvelope, EvaluationResponse, KernelError, Operation, RuleRequest, SCHEMA_VERSION,
    TAILSCALE_DEFINITION_DIGEST, TAILSCALE_RULE_ID,
};

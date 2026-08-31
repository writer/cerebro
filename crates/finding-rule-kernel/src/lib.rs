#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Closed Rust authority for finding-rule matching and lifecycle decisions.
//!
//! The public contract is a content-bound [`EvaluationEnvelope`] and a sealed
//! [`EvaluationResponse`]. Native callers invoke [`evaluate`] directly; Wasm
//! builds additionally export a bounded linear-memory ABI. The kernel owns no
//! credentials, network client, clock, graph reader, or persistence adapter.

mod digest;
mod evaluation;
mod model;
#[allow(dead_code, unused_imports)]
// Payload families share the outer ABI. Some scoped receipt helpers are retained
// only for parity tests, which is why production builds permit unused members.
mod payload_findings;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{ABI_VERSION, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, evaluate};
pub use model::{
    AURELIUS_DEFINITION_DIGEST, AURELIUS_RULE_ID, COSMO_DEFINITION_DIGEST, COSMO_RULE_ID,
    EvaluationEnvelope, EvaluationResponse, KernelError, Operation, RuleRequest, SCHEMA_VERSION,
    TAILSCALE_DEFINITION_DIGEST, TAILSCALE_RULE_ID,
};

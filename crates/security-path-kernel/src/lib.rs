#![deny(unsafe_code)]

//! Deterministic security-path comparison and verification decisions.
//!
//! This crate owns no collection, graph, storage, clock, network, or provider behavior.

mod evaluation;
mod model;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{ABI_VERSION, compare, evaluate, rank_candidate_cuts, verify_observed_absent};
#[cfg(target_arch = "wasm32")]
pub(crate) use evaluation::{MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
pub use model::{
    CandidateEdgeCut, CollectionReceipt, ComparisonDecision, Completeness, EvaluationRequest,
    EvaluationResponse, KernelError, NodeRef, OwnerRef, OwnershipProof, ProofChange, ProofEdge,
    ProvenanceRef, RuntimeCollectionReceipt, SecurityPath, Snapshot, VerificationDecision,
};

#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic security-path comparison and verification decisions.
//!
//! The kernel accepts immutable, content-bound snapshots and returns decisions whose
//! ordering and digests are stable across native and WebAssembly hosts. It answers
//! three questions:
//!
//! - which exposure routes appeared, disappeared, or changed proof;
//! - whether specifically requested routes are absent after a fresh, complete scan;
//! - which proof edges are candidate cuts for the largest number of routes.
//!
//! This crate owns no collection, graph, storage, clock, network, remediation, or
//! provider behavior. Callers remain responsible for producing truthful receipts,
//! persisting inputs and outputs, and treating candidate cuts as proposals rather
//! than proof that a remediation is safe or effective.

mod evaluation;
mod model;
#[cfg(target_arch = "wasm32")]
mod wasm_abi;

pub use evaluation::{
    ABI_VERSION, bind_decision_input, compare, evaluate, rank_candidate_cuts,
    verify_observed_absent,
};
#[cfg(target_arch = "wasm32")]
pub(crate) use evaluation::{MAX_INPUT_BYTES, MAX_OUTPUT_BYTES};
pub use model::{
    CandidateEdgeCut, CollectionReceipt, ComparisonDecision, Completeness, DECISION_INPUT_V1,
    DecisionRequest, DecisionResponse, EvaluationRequest, EvaluationResponse, KernelError, NodeRef,
    OwnerRef, OwnershipProof, ProofChange, ProofEdge, ProvenanceRef, RuntimeCollectionReceipt,
    SecurityPath, Snapshot, VerificationDecision,
};

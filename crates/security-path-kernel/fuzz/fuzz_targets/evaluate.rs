#![no_main]

//! Fuzzes deterministic binding, evaluation, and rejection of JSON decision inputs.
//!
//! Invalid JSON and semantically rejected requests are expected boundary outcomes.
//! The oracle is repeatability: the same bytes must never produce divergent success,
//! rejection, or response values across two evaluations in one kernel build.

use cerebro_security_path_kernel::{
    DecisionRequest, EvaluationRequest, bind_decision_input, evaluate,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A parsed bare request exercises validation plus canonical digest binding. The
    // second bind is safe to expect because it receives an unchanged clone of a
    // request that just passed the same deterministic validation.
    if let Ok(request) = serde_json::from_slice::<DecisionRequest>(data) {
        if let Ok(first_request) = bind_decision_input(request.clone()) {
            let second_request = bind_decision_input(request).expect("same request must bind");
            assert_eq!(evaluate(first_request), evaluate(second_request));
        }
    }
    // A parsed envelope may contain a supported or unsupported schema and a correct
    // or tampered digest. Parsing twice gives evaluate two owned but identical inputs
    // and asserts deterministic acceptance or typed rejection for every combination.
    if let (Ok(first_request), Ok(second_request)) = (
        serde_json::from_slice::<EvaluationRequest>(data),
        serde_json::from_slice::<EvaluationRequest>(data),
    ) {
        assert_eq!(evaluate(first_request), evaluate(second_request));
    }
});

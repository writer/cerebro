#![no_main]

use cerebro_security_path_kernel::{EvaluationRequest, evaluate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(first_request) = serde_json::from_slice::<EvaluationRequest>(data) else {
        return;
    };
    let Ok(second_request) = serde_json::from_slice::<EvaluationRequest>(data) else {
        return;
    };
    assert_eq!(evaluate(first_request), evaluate(second_request));
});

#![no_main]

use cerebro_security_path_kernel::{
    DecisionRequest, EvaluationRequest, bind_decision_input, evaluate,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<DecisionRequest>(data) {
        if let Ok(first_request) = bind_decision_input(request.clone()) {
            let second_request = bind_decision_input(request).expect("same request must bind");
            assert_eq!(evaluate(first_request), evaluate(second_request));
        }
    }
    if let (Ok(first_request), Ok(second_request)) = (
        serde_json::from_slice::<EvaluationRequest>(data),
        serde_json::from_slice::<EvaluationRequest>(data),
    ) {
        assert_eq!(evaluate(first_request), evaluate(second_request));
    }
});

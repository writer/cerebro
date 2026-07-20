#![no_main]

use cerebro_graphagent_staticvalidator::{Decision, validate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let (max_rows, query) = input
        .split_once('\n')
        .and_then(|(maximum, query)| maximum.parse::<u64>().ok().map(|value| (value, query)))
        .unwrap_or((100, input.as_ref()));

    let result = validate(query, max_rows);
    assert_eq!(result, validate(query, max_rows));

    if result.decision == Decision::Allow {
        let raised = validate(query, max_rows.saturating_add(1));
        assert_eq!(raised.decision, Decision::Allow);
        assert_eq!(raised.limit, result.limit);
        assert_eq!(raised.detail, result.detail);
    }
});

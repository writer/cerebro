use std::collections::HashMap;

use crate::source_execution::SourceExecutionError;

use super::users_test_support as support;

#[test]
fn asana_users_rejects_escape_bounds_and_typed_provider_failures() {
    let plan = support::plan();
    let context = support::context("tenant-a", "", 1);
    let metadata = support::metadata();
    let execution = support::plan_page(&plan, &context, &metadata).unwrap();

    for (status, headers, expected) in [
        (
            401,
            HashMap::new(),
            SourceExecutionError::AuthenticationRejected,
        ),
        (
            403,
            HashMap::new(),
            SourceExecutionError::RequiredProviderScopeMissing,
        ),
        (
            429,
            HashMap::from([("retry-after".to_owned(), "30".to_owned())]),
            SourceExecutionError::ProviderRateLimit,
        ),
    ] {
        assert_eq!(
            support::decode_page(&plan, &context, &metadata, &execution, status, b"", headers,),
            Err(expected)
        );
    }
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data": ["#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::MalformedResponse)
    );
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data":[],"next_page":{"offset":"https://escape.example/page"}}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidCursor)
    );
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data":[{"gid":"1"},{"gid":"2"},{"gid":"3"}]}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResultTooLarge)
    );
    let oversized = vec![b' '; usize::try_from(plan.max_response_bytes).unwrap() + 1];
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &oversized,
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResponseTooLarge)
    );
}

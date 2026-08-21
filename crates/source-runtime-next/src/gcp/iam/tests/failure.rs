use std::str::FromStr;

use super::*;
use crate::gcp::iam::{
    cursor::MAX_PROVIDER_CURSOR_BYTES,
    kernel::{MAX_RECORDS_PER_PAGE, MAX_RESPONSE_BYTES},
};

#[test]
fn iam_timestamp_identity_type_and_cursor_selectors_are_fail_closed() {
    let account_kernel = account_kernel();
    let account_request = account_kernel.plan(Some("  ")).unwrap();
    assert_eq!(
        account_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10"
    );
    let blank_next = account_kernel
            .decode(
                &account_request,
                br#"{"accounts":[{"email":"sa@writer-prod.iam.gserviceaccount.com"}],"nextPageToken":"  \t "}"#,
                observed_at(),
            )
            .unwrap();
    assert_eq!(blank_next.next_cursor, None);
    assert_eq!(
        blank_next.records[0].event_id,
        "gcp-service-account-sa@writer-prod.iam.gserviceaccount.com"
    );
    assert_eq!(
        account_kernel
            .decode(
                &account_kernel.plan(None).unwrap(),
                br#"{"accounts":[{"name":"projects/writer-prod/serviceAccounts/name-only"}]}"#,
                observed_at(),
            )
            .unwrap_err(),
        GcpIamError::MissingProviderIdentity
    );
    for body in [
        br#"{"accounts":[{"uniqueId":7}]}"#.as_slice(),
        br#"{"accounts":[{"email":true}]}"#.as_slice(),
        br#"{"accounts":[{"uniqueId":"sa-1","disabled":"false"}]}"#.as_slice(),
    ] {
        assert_eq!(
            account_kernel
                .decode(&account_kernel.plan(None).unwrap(), body, observed_at())
                .unwrap_err(),
            GcpIamError::InvalidResponse
        );
    }

    let key_kernel = key_kernel();
    let key_request = key_kernel.plan(None).unwrap();
    let parsed = key_kernel
            .decode(
                &key_request,
                br#"{"keys":[{"name":"key-1","validAfterTime":"2026-04-23T02:03:04.123456789+01:00"}]}"#,
                observed_at(),
            )
            .unwrap();
    assert_eq!(
        parsed.records[0].occurred_at,
        "2026-04-23T01:03:04.123456789Z"
    );
    for valid_after_time in ["", "not-rfc3339"] {
        let body = serde_json::to_vec(&json!({
            "keys": [{"name": "key-1", "validAfterTime": valid_after_time}]
        }))
        .unwrap();
        let fallback = key_kernel
            .decode(&key_request, &body, observed_at())
            .unwrap();
        assert_eq!(
            fallback.records[0].occurred_at,
            "2026-04-23T01:03:04.123456789Z"
        );
    }
    for body in [
        br#"{"keys":[{"name":false}]}"#.as_slice(),
        br#"{"keys":[{"name":"key-1","disabled":{}}]}"#.as_slice(),
    ] {
        assert_eq!(
            key_kernel
                .decode(&key_request, body, observed_at())
                .unwrap_err(),
            GcpIamError::InvalidResponse
        );
    }
}

#[test]
fn iam_fails_closed_for_config_scope_cursor_and_response_bounds() {
    assert_eq!(
        GcpIamFamily::from_str("unknown").unwrap_err(),
        GcpIamError::InvalidFamily
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            "  ",
            "writer-prod",
            GcpIamFamily::ServiceAccount,
            GcpIamFilters::default(),
            None,
        )
        .unwrap_err(),
        GcpIamError::MissingTenantId
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccountKey,
            GcpIamFilters::default(),
            None,
        )
        .unwrap_err(),
        GcpIamError::MissingServiceAccountEmail
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccount,
            GcpIamFilters::default(),
            Some(201),
        )
        .unwrap_err(),
        GcpIamError::InvalidPageSize
    );
    let kernel = account_kernel();
    assert_eq!(
        kernel.plan(Some("bad\ncursor")).unwrap_err(),
        GcpIamError::InvalidCursor
    );
    assert_eq!(
        kernel
            .plan(Some(&"x".repeat(MAX_PROVIDER_CURSOR_BYTES + 1)))
            .unwrap_err(),
        GcpIamError::InvalidCursor
    );
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel
            .decode(&request, br#"[]"#, observed_at())
            .unwrap_err(),
        GcpIamError::InvalidResponse
    );
    assert_eq!(
        kernel
            .decode(&request, br#"{"accounts":[{}]}"#, observed_at())
            .unwrap_err(),
        GcpIamError::MissingProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &request,
                &vec![b' '; MAX_RESPONSE_BYTES.saturating_add(1)],
                observed_at(),
            )
            .unwrap_err(),
        GcpIamError::ResponseTooLarge
    );
    let too_many = serde_json::to_vec(&serde_json::json!({
        "accounts": (0..=MAX_RECORDS_PER_PAGE)
            .map(|index| serde_json::json!({"uniqueId": index.to_string()}))
            .collect::<Vec<_>>()
    }))
    .unwrap();
    assert_eq!(
        kernel
            .decode(&request, &too_many, observed_at())
            .unwrap_err(),
        GcpIamError::TooManyRecords
    );
    let key_request = key_kernel().plan(None).unwrap();
    assert_eq!(
        kernel
            .decode(&key_request, SERVICE_ACCOUNT_RESPONSE, observed_at())
            .unwrap_err(),
        GcpIamError::RequestScopeMismatch
    );
    for base_url in [
        "http://iam.googleapis.com",
        "https://user@iam.googleapis.com",
        "https://iam.googleapis.com/v1",
        "https://10.0.0.1",
    ] {
        assert_eq!(
            GcpIamKernel::new(
                base_url,
                TENANT_ID,
                "writer-prod",
                GcpIamFamily::ServiceAccount,
                GcpIamFilters::default(),
                None,
            )
            .unwrap_err(),
            GcpIamError::InvalidBaseUrl,
            "base URL {base_url}"
        );
    }
}

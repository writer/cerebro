use reqwest::StatusCode;
use serde_json::Value;

use super::{
    AwsAccountContactError, AwsAccountContactKernel, AwsAccountContactOutcome,
    AwsAccountContactRequest, AwsAccountContactRequestKind,
    model::{MAX_JSON_DEPTH, MAX_RESPONSE_BYTES},
    response::{PRIMARY_CONTACT_STRING_MEMBERS, SECURITY_CONTACT_STRING_MEMBERS},
};

const ACCOUNT_ID: &str = "123456789012";
// These are synthetic, provider-shaped inputs. They are not live captures and
// contain only reserved example contact values; SHA256SUMS binds their bytes.
const PRIMARY_RESPONSE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/aws_account_contact/primary_response.json"
));
const SECURITY_RESPONSE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/testdata/aws_account_contact/security_response.json"
));
const GO_READ_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/aws/testdata/read_account_contact.json"
));

fn kernel(account_id: &str) -> AwsAccountContactKernel {
    AwsAccountContactKernel::new(
        "https://account.us-east-1.amazonaws.com",
        account_id,
        "us-east-1",
    )
    .unwrap()
}

fn security_request(kernel: &AwsAccountContactKernel, body: &[u8]) -> AwsAccountContactRequest {
    let primary = kernel.plan().unwrap();
    let AwsAccountContactOutcome::Request(security) =
        kernel.decode(&primary, StatusCode::OK, None, body).unwrap()
    else {
        panic!("expected security request")
    };
    security
}

fn complete_page(kernel: &AwsAccountContactKernel) -> super::AwsAccountContactPage {
    let security = security_request(kernel, PRIMARY_RESPONSE);
    let AwsAccountContactOutcome::Page(page) = kernel
        .decode(&security, StatusCode::OK, None, SECURITY_RESPONSE)
        .unwrap()
    else {
        panic!("expected completed page")
    };
    page
}

#[test]
fn trusted_host_plan_contains_exact_credential_free_sigv4_requests() {
    let kernel = kernel(ACCOUNT_ID);
    let primary = kernel.plan().unwrap();
    assert_eq!(primary.kind(), AwsAccountContactRequestKind::PrimaryContact);
    assert_eq!(primary.method(), "POST");
    assert_eq!(primary.url().path(), "/getContactInformation");
    assert_eq!(primary.url().query(), None);
    assert_eq!(primary.body(), b"{}");
    assert_eq!(primary.content_type(), "application/json");
    assert_eq!(primary.accept(), "application/json");
    assert_eq!(primary.signing_service(), "account");
    assert_eq!(primary.signing_region(), "us-east-1");

    let security = security_request(&kernel, PRIMARY_RESPONSE);
    assert_eq!(
        security.kind(),
        AwsAccountContactRequestKind::SecurityAlternateContact
    );
    assert_eq!(security.method(), "POST");
    assert_eq!(security.url().path(), "/getAlternateContact");
    assert_eq!(security.body(), br#"{"AlternateContactType":"SECURITY"}"#);
    let debug = format!("{primary:?}{security:?}");
    for prohibited in ["access_key", "secret_key", "session_token", "Authorization"] {
        assert!(!debug.contains(prohibited));
    }
}

#[test]
fn go_semantic_fixture_matches_stable_redacted_output() {
    let page = complete_page(&kernel(ACCOUNT_ID));
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.checkpoint_cursor, ACCOUNT_ID);
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    let fixture: Value = serde_json::from_slice(GO_READ_FIXTURE).unwrap();
    let expected = &fixture[0];
    assert_eq!(record.provider_id, expected["id"]);
    assert_eq!(record.provider_kind, expected["kind"]);
    assert_eq!(record.schema_ref, expected["schema_ref"]);
    assert_eq!(record.payload, expected["payload"]);
    assert_eq!(
        serde_json::to_value(&record.fields).unwrap(),
        expected["attributes"]
    );
    let serialized = format!("{:?}{}", record.fields, record.payload);
    for private_value in [
        "Private Primary",
        "+1-555-0100",
        "security@example.test",
        "Private Security",
        "+1-555-0101",
    ] {
        assert!(!serialized.contains(private_value));
    }
}

#[test]
fn progress_contract_rejects_continuations_and_round_trips_checkpoint() {
    let kernel = kernel(ACCOUNT_ID);
    assert_eq!(
        kernel.plan_with_progress(None, Some(ACCOUNT_ID)).unwrap(),
        kernel.plan().unwrap()
    );
    assert_eq!(
        kernel.plan_with_progress(Some("page-2"), Some(ACCOUNT_ID)),
        Err(AwsAccountContactError::CursorNotSupported)
    );
    assert_eq!(
        kernel.plan_with_progress(Some(""), Some(ACCOUNT_ID)),
        Err(AwsAccountContactError::CursorNotSupported)
    );
    assert_eq!(
        kernel.plan_with_progress(None, Some("210987654321")),
        Err(AwsAccountContactError::InvalidCheckpoint)
    );

    let first = complete_page(&kernel);
    let resumed_request = kernel
        .plan_with_progress(None, Some(first.checkpoint_cursor.as_str()))
        .unwrap();
    let AwsAccountContactOutcome::Request(resumed_security) = kernel
        .decode(&resumed_request, StatusCode::OK, None, PRIMARY_RESPONSE)
        .unwrap()
    else {
        panic!("expected resumed security request")
    };
    let AwsAccountContactOutcome::Page(resumed) = kernel
        .decode(&resumed_security, StatusCode::OK, None, SECURITY_RESPONSE)
        .unwrap()
    else {
        panic!("expected resumed page")
    };
    assert_eq!(resumed, first);
    assert_eq!(resumed.records.len(), 1);
}

#[test]
fn optional_not_found_is_normalized_for_both_operations() {
    let kernel = kernel(ACCOUNT_ID);
    let primary = kernel.plan().unwrap();
    let AwsAccountContactOutcome::Request(security) = kernel
        .decode(
            &primary,
            StatusCode::NOT_FOUND,
            Some("ResourceNotFoundException:http://internal"),
            br#"{"message":"not configured"}"#,
        )
        .unwrap()
    else {
        panic!("expected security request")
    };
    let AwsAccountContactOutcome::Page(page) = kernel
        .decode(
            &security,
            StatusCode::BAD_REQUEST,
            None,
            br#"{"__type":"com.amazonaws.account#ResourceNotFoundException"}"#,
        )
        .unwrap()
    else {
        panic!("expected completed page")
    };
    for field in [
        "primary_contact_configured",
        "security_alternate_contact_present",
        "security_alternate_contact_complete",
        "security_contact_email_present",
        "security_contact_name_present",
        "security_contact_phone_present",
    ] {
        assert_eq!(
            page.records[0].fields.get(field).map(String::as_str),
            Some("false")
        );
    }
}

#[test]
fn null_optional_contacts_are_absent_and_do_not_emit_contact_values() {
    let kernel = kernel(ACCOUNT_ID);
    let security = security_request(&kernel, br#"{"ContactInformation":null}"#);
    let AwsAccountContactOutcome::Page(page) = kernel
        .decode(
            &security,
            StatusCode::OK,
            None,
            br#"{"AlternateContact":null}"#,
        )
        .unwrap()
    else {
        panic!("expected completed page")
    };
    let record = &page.records[0];
    for field in [
        "primary_contact_configured",
        "security_alternate_contact_present",
        "security_alternate_contact_complete",
        "security_contact_email_present",
        "security_contact_name_present",
        "security_contact_phone_present",
    ] {
        assert_eq!(record.fields.get(field).map(String::as_str), Some("false"));
    }
    assert_eq!(
        record.payload["primary_contact"]["configured"],
        Value::Bool(false)
    );
    assert_eq!(
        record.payload["security_contact"]["present"],
        Value::Bool(false)
    );
}

#[test]
fn response_bytes_and_json_recursion_are_bounded_before_decode() {
    let kernel = kernel(ACCOUNT_ID);
    let request = kernel.plan().unwrap();
    let oversized = vec![b' '; MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        kernel.decode(&request, StatusCode::OK, None, &oversized),
        Err(AwsAccountContactError::ResponseTooLarge)
    );

    let too_deep = format!(
        "{}null{}",
        "{\"future\":".repeat(MAX_JSON_DEPTH + 1),
        "}".repeat(MAX_JSON_DEPTH + 1)
    );
    assert_eq!(
        kernel.decode(&request, StatusCode::OK, None, too_deep.as_bytes()),
        Err(AwsAccountContactError::ResponseTooDeep)
    );
    assert_eq!(
        kernel.decode(&request, StatusCode::OK, None, br#"[]"#),
        Err(AwsAccountContactError::InvalidResponse)
    );

    let braces_in_string =
        br#"{"ContactInformation":{"FullName":"{{{{[[[[","PhoneNumber":"+1","CountryCode":"US"}}"#;
    assert!(matches!(
        kernel.decode(&request, StatusCode::OK, None, braces_in_string),
        Ok(AwsAccountContactOutcome::Request(_))
    ));
}

#[test]
fn known_contact_members_reject_wrong_types_and_unknown_members_are_ignored() {
    let kernel = kernel(ACCOUNT_ID);
    let invalid_values = ["null", "17", "true", "[]", "{}"];
    for member in PRIMARY_CONTACT_STRING_MEMBERS {
        for invalid in invalid_values {
            let body = format!(r#"{{"ContactInformation":{{"{member}":{invalid}}}}}"#);
            let request = kernel.plan().unwrap();
            assert_eq!(
                kernel.decode(&request, StatusCode::OK, None, body.as_bytes()),
                Err(AwsAccountContactError::InvalidResponse),
                "primary member {member} accepted {invalid}",
            );
        }
    }

    let security = security_request(&kernel, br#"{}"#);
    for member in SECURITY_CONTACT_STRING_MEMBERS {
        for invalid in invalid_values {
            let body = format!(r#"{{"AlternateContact":{{"{member}":{invalid}}}}}"#);
            assert_eq!(
                kernel.decode(&security, StatusCode::OK, None, body.as_bytes()),
                Err(AwsAccountContactError::InvalidResponse),
                "security member {member} accepted {invalid}",
            );
        }
    }

    let primary = kernel.plan().unwrap();
    let AwsAccountContactOutcome::Request(security) = kernel
        .decode(
            &primary,
            StatusCode::OK,
            None,
            br#"{"ContactInformation":{"FutureMember":{"nested":true}}}"#,
        )
        .unwrap()
    else {
        panic!("expected security request")
    };
    assert!(matches!(
        kernel.decode(
            &security,
            StatusCode::OK,
            None,
            br#"{"AlternateContact":{"FutureMember":["future"]}}"#,
        ),
        Ok(AwsAccountContactOutcome::Page(_))
    ));
}

#[test]
fn auth_scope_rate_limit_and_provider_failures_are_typed_and_redacted() {
    let kernel = kernel(ACCOUNT_ID);
    let request = kernel.plan().unwrap();
    let cases = [
        (
            StatusCode::UNAUTHORIZED,
            Some("UnrecognizedClientException"),
            AwsAccountContactError::AuthenticationRejected {
                status: 401,
                code: Some("UnrecognizedClientException".to_owned()),
            },
        ),
        (
            StatusCode::FORBIDDEN,
            Some("AccessDeniedException"),
            AwsAccountContactError::RequiredScopeMissing {
                status: 403,
                code: Some("AccessDeniedException".to_owned()),
            },
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            Some("TooManyRequestsException"),
            AwsAccountContactError::RateLimited {
                status: 429,
                code: Some("TooManyRequestsException".to_owned()),
            },
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("InternalServerException"),
            AwsAccountContactError::ProviderUnavailable {
                status: 503,
                code: Some("InternalServerException".to_owned()),
            },
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("ValidationException"),
            AwsAccountContactError::UnexpectedProviderStatus {
                status: 400,
                code: Some("ValidationException".to_owned()),
            },
        ),
    ];
    for (status, code, expected) in cases {
        let error = kernel
            .decode(
                &request,
                status,
                code,
                br#"{"message":"secret provider detail"}"#,
            )
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("secret provider detail"));
        assert!(error.operator_action().is_some());
        assert_eq!(
            error.retryable(),
            matches!(
                &error,
                AwsAccountContactError::RateLimited { .. }
                    | AwsAccountContactError::ProviderUnavailable { .. }
            )
        );
    }
}

#[test]
fn stable_identity_is_account_scoped_and_non_aliasing() {
    let first = complete_page(&kernel("123456789012"));
    let second = complete_page(&kernel("210987654321"));
    assert_eq!(
        first.records[0].provider_id,
        "aws-account-contact-123456789012"
    );
    assert_eq!(
        second.records[0].provider_id,
        "aws-account-contact-210987654321"
    );
    assert_ne!(first.records[0].provider_id, second.records[0].provider_id);
    assert_eq!(first.checkpoint_cursor, "123456789012");
    assert_eq!(second.checkpoint_cursor, "210987654321");
}

#[test]
fn rejects_wrong_scope_stage_shapes_and_unsafe_configuration() {
    let first = kernel(ACCOUNT_ID);
    let second = kernel("210987654321");
    let request = first.plan().unwrap();
    assert_eq!(
        second.decode(&request, StatusCode::OK, None, br#"{}"#),
        Err(AwsAccountContactError::RequestScopeMismatch)
    );

    let mut invalid_stage = request;
    invalid_stage.primary_contact_configured = Some(false);
    assert_eq!(
        first.decode(&invalid_stage, StatusCode::OK, None, br#"{}"#),
        Err(AwsAccountContactError::RequestStageMismatch)
    );

    let primary = first.plan().unwrap();
    assert_eq!(
        first.decode(
            &primary,
            StatusCode::OK,
            None,
            br#"{"ContactInformation":"invalid"}"#,
        ),
        Err(AwsAccountContactError::InvalidResponse)
    );
    let security = security_request(&first, br#"{"ContactInformation":null}"#);
    assert_eq!(
        first.decode(
            &security,
            StatusCode::OK,
            None,
            br#"{"AlternateContact":[]}"#,
        ),
        Err(AwsAccountContactError::InvalidResponse)
    );

    assert!(matches!(
        AwsAccountContactKernel::new("http://169.254.169.254", ACCOUNT_ID, "us-east-1"),
        Err(AwsAccountContactError::InvalidBaseUrl)
    ));
    assert!(matches!(
        AwsAccountContactKernel::new(
            "https://account.us-east-1.amazonaws.com/path",
            ACCOUNT_ID,
            "us-east-1"
        ),
        Err(AwsAccountContactError::InvalidBaseUrl)
    ));
    assert!(matches!(
        AwsAccountContactKernel::new(
            "https://account.us-east-1.amazonaws.com",
            "1234",
            "us-east-1"
        ),
        Err(AwsAccountContactError::InvalidAccountId)
    ));
    assert!(matches!(
        AwsAccountContactKernel::new(
            "https://account.us-east-1.amazonaws.com",
            ACCOUNT_ID,
            "US EAST 1"
        ),
        Err(AwsAccountContactError::InvalidSigningRegion)
    ));
}

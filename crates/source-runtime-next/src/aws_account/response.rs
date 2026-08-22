use std::collections::BTreeMap;

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use super::model::{
    AwsAccountContactError, AwsAccountContactPage, AwsAccountContactRecord, FAMILY, MAX_JSON_DEPTH,
    MAX_RESPONSE_BYTES, PROVIDER_KIND, SCHEMA_REF, SECURITY_CONTACT_TYPE,
};

pub(super) const PRIMARY_CONTACT_STRING_MEMBERS: &[&str] = &[
    "AddressLine1",
    "AddressLine2",
    "AddressLine3",
    "City",
    "CompanyName",
    "CountryCode",
    "DistrictOrCounty",
    "FullName",
    "PhoneNumber",
    "PostalCode",
    "StateOrRegion",
    "WebsiteUrl",
];
pub(super) const SECURITY_CONTACT_STRING_MEMBERS: &[&str] = &[
    "AlternateContactType",
    "EmailAddress",
    "Name",
    "PhoneNumber",
    "Title",
];

pub(super) fn decode_provider_response(
    status: StatusCode,
    provider_error_code: Option<&str>,
    body: &[u8],
) -> Result<Option<Value>, AwsAccountContactError> {
    validate_response_bounds(body)?;
    if status.is_success() {
        let response: Value =
            serde_json::from_slice(body).map_err(|_| AwsAccountContactError::InvalidResponse)?;
        if !response.is_object() {
            return Err(AwsAccountContactError::InvalidResponse);
        }
        return Ok(Some(response));
    }
    let code = normalize_error_code(provider_error_code)
        .map(str::to_owned)
        .or_else(|| response_error_code(body));
    if code
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case("ResourceNotFoundException"))
    {
        return Ok(None);
    }
    Err(classify_provider_failure(status, code))
}

fn validate_response_bounds(body: &[u8]) -> Result<(), AwsAccountContactError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AwsAccountContactError::ResponseTooLarge);
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(AwsAccountContactError::ResponseTooDeep);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn classify_provider_failure(status: StatusCode, code: Option<String>) -> AwsAccountContactError {
    if status == StatusCode::UNAUTHORIZED || code.as_deref().is_some_and(authentication_error_code)
    {
        AwsAccountContactError::AuthenticationRejected {
            status: status.as_u16(),
            code,
        }
    } else if status == StatusCode::TOO_MANY_REQUESTS
        || code.as_deref().is_some_and(rate_limit_error_code)
    {
        AwsAccountContactError::RateLimited {
            status: status.as_u16(),
            code,
        }
    } else if status == StatusCode::FORBIDDEN
        || code
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("AccessDeniedException"))
    {
        AwsAccountContactError::RequiredScopeMissing {
            status: status.as_u16(),
            code,
        }
    } else if status.is_server_error() {
        AwsAccountContactError::ProviderUnavailable {
            status: status.as_u16(),
            code,
        }
    } else {
        AwsAccountContactError::UnexpectedProviderStatus {
            status: status.as_u16(),
            code,
        }
    }
}

fn authentication_error_code(code: &str) -> bool {
    [
        "ExpiredTokenException",
        "IncompleteSignature",
        "InvalidSignatureException",
        "UnrecognizedClientException",
    ]
    .into_iter()
    .any(|candidate| code.eq_ignore_ascii_case(candidate))
}

fn rate_limit_error_code(code: &str) -> bool {
    [
        "RequestLimitExceeded",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    ]
    .into_iter()
    .any(|candidate| code.eq_ignore_ascii_case(candidate))
}

fn normalize_error_code(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = value.rsplit('#').next().unwrap_or(value);
            value.split(':').next().unwrap_or(value)
        })
        .filter(|value| {
            value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    #[serde(default, alias = "code", alias = "Code")]
    __type: Option<String>,
}

fn response_error_code(body: &[u8]) -> Option<String> {
    let envelope: ErrorEnvelope = serde_json::from_slice(body).ok()?;
    normalize_error_code(envelope.__type.as_deref()).map(str::to_owned)
}

pub(super) fn optional_object<'a>(
    response: Option<&'a Value>,
    key: &str,
) -> Result<Option<&'a Value>, AwsAccountContactError> {
    let Some(value) = response.and_then(|response| response.get(key)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if !value.is_object() {
        return Err(AwsAccountContactError::InvalidResponse);
    }
    Ok(Some(value))
}

pub(super) fn validate_string_members(
    object: Option<&Value>,
    known_members: &[&str],
) -> Result<(), AwsAccountContactError> {
    let Some(object) = object else {
        return Ok(());
    };
    for member in known_members {
        if object.get(member).is_some_and(|value| !value.is_string()) {
            return Err(AwsAccountContactError::InvalidResponse);
        }
    }
    Ok(())
}

pub(super) fn primary_contact_configured(value: &Value) -> bool {
    ["FullName", "PhoneNumber", "CountryCode"]
        .into_iter()
        .all(|key| populated(value.get(key)))
}

pub(super) fn build_page(
    account_id: &str,
    primary_contact_configured: bool,
    security_contact: Option<&Value>,
) -> AwsAccountContactPage {
    let security_alternate_contact_present = security_contact.is_some();
    let security_contact_email_present =
        security_contact.is_some_and(|value| populated(value.get("EmailAddress")));
    let security_contact_name_present =
        security_contact.is_some_and(|value| populated(value.get("Name")));
    let security_contact_phone_present =
        security_contact.is_some_and(|value| populated(value.get("PhoneNumber")));
    let security_alternate_contact_complete = security_contact_email_present
        && security_contact_name_present
        && security_contact_phone_present;
    let bool_string = |value: bool| value.to_string();
    let fields = BTreeMap::from([
        (
            "account_alternate_contact_security_compliant".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        ("account_id".to_owned(), account_id.to_owned()),
        (
            "account_security_contact_configured".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        ("domain".to_owned(), account_id.to_owned()),
        ("family".to_owned(), FAMILY.to_owned()),
        (
            "primary_contact_configured".to_owned(),
            bool_string(primary_contact_configured),
        ),
        ("resource_id".to_owned(), account_id.to_owned()),
        ("resource_name".to_owned(), account_id.to_owned()),
        ("resource_provider".to_owned(), "aws".to_owned()),
        ("resource_type".to_owned(), "aws_account".to_owned()),
        (
            "security_alternate_contact_complete".to_owned(),
            bool_string(security_alternate_contact_complete),
        ),
        (
            "security_alternate_contact_present".to_owned(),
            bool_string(security_alternate_contact_present),
        ),
        (
            "security_contact_email_present".to_owned(),
            bool_string(security_contact_email_present),
        ),
        (
            "security_contact_name_present".to_owned(),
            bool_string(security_contact_name_present),
        ),
        (
            "security_contact_phone_present".to_owned(),
            bool_string(security_contact_phone_present),
        ),
    ]);
    let payload = json!({
        "account_id": account_id,
        "primary_contact": {
            "configured": primary_contact_configured,
        },
        "security_contact": {
            "alternate_contact_type": SECURITY_CONTACT_TYPE,
            "complete": security_alternate_contact_complete,
            "email_present": security_contact_email_present,
            "name_present": security_contact_name_present,
            "phone_present": security_contact_phone_present,
            "present": security_alternate_contact_present,
        },
    });
    AwsAccountContactPage {
        records: vec![AwsAccountContactRecord {
            family: FAMILY.to_owned(),
            provider_kind: PROVIDER_KIND.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            provider_id: format!("aws-account-contact-{account_id}"),
            fields,
            payload,
        }],
        next_cursor: None,
        checkpoint_cursor: account_id.to_owned(),
    }
}

fn populated(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

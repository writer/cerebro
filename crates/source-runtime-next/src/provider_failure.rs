//! Transient provider-failure classification for source execution.
//!
//! Failure classifications are safe receipt data. They carry no provider body
//! bytes and explicitly state that failed attempts do not advance cursor,
//! checkpoint, append publication, projection, or last-synced state.

use std::{error::Error, fmt, time::Duration};

use reqwest::StatusCode;

use crate::HttpConnectorError;

/// Stable provider failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureKind {
    /// Provider rejected the resolved credential.
    AuthenticationRejected,
    /// Provider authenticated the caller but denied the required scope.
    PermissionDenied,
    /// Provider request timed out.
    Timeout,
    /// Provider DNS resolution failed.
    Dns,
    /// TLS handshake or certificate validation failed.
    Tls,
    /// Provider returned HTTP 5xx.
    Http5xx,
    /// Provider requested a bounded retry.
    RetryAfter,
    /// Caller cancelled execution.
    Cancellation,
    /// Response ended before the declared body was received.
    TruncatedResponse,
    /// Response decompression failed.
    InvalidCompression,
    /// Response exceeded the runtime size limit.
    ResponseSizeLimit,
    /// Provider page is partial or malformed.
    PartialPageResponse,
}

/// Stable retry/quarantine/error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFailureCategory {
    /// Retry the same cursor/checkpoint input later.
    Retry,
    /// Quarantine malformed provider data without advancing progress.
    Quarantine,
    /// Operator-visible provider error without progress advancement.
    Error,
}

/// Safe provider-failure receipt shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderFailureClassification {
    /// Stable failure kind.
    pub kind: ProviderFailureKind,
    /// Stable failure category.
    pub category: ProviderFailureCategory,
    /// Whether retrying the same request may succeed.
    pub retryable: bool,
    /// Bounded retry delay when known.
    pub retry_after: Option<Duration>,
    /// Cursor/checkpoint/projection/append progress must not advance.
    pub advances_progress: bool,
    /// Safe diagnostic code, never provider body text.
    pub diagnostic_code: &'static str,
}

impl fmt::Display for ProviderFailureClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({:?}, retryable={})",
            self.diagnostic_code, self.category, self.retryable
        )
    }
}

impl Error for ProviderFailureClassification {}

/// Classify a provider failure without allowing progress advancement.
pub fn classify_provider_failure(
    kind: ProviderFailureKind,
    retry_after: Option<Duration>,
) -> ProviderFailureClassification {
    let (category, retryable, diagnostic_code) = match kind {
        ProviderFailureKind::AuthenticationRejected => (
            ProviderFailureCategory::Error,
            false,
            "provider_authentication_rejected",
        ),
        ProviderFailureKind::PermissionDenied => (
            ProviderFailureCategory::Error,
            false,
            "provider_permission_denied",
        ),
        ProviderFailureKind::Timeout => (ProviderFailureCategory::Retry, true, "provider_timeout"),
        ProviderFailureKind::Dns => (ProviderFailureCategory::Retry, true, "provider_dns_failure"),
        ProviderFailureKind::Tls => (ProviderFailureCategory::Retry, true, "provider_tls_failure"),
        ProviderFailureKind::Http5xx => (ProviderFailureCategory::Retry, true, "provider_http_5xx"),
        ProviderFailureKind::RetryAfter => {
            (ProviderFailureCategory::Retry, true, "provider_retry_after")
        }
        ProviderFailureKind::Cancellation => {
            (ProviderFailureCategory::Retry, true, "provider_cancelled")
        }
        ProviderFailureKind::TruncatedResponse => (
            ProviderFailureCategory::Retry,
            true,
            "provider_truncated_response",
        ),
        ProviderFailureKind::InvalidCompression => (
            ProviderFailureCategory::Quarantine,
            false,
            "provider_invalid_compression",
        ),
        ProviderFailureKind::ResponseSizeLimit => (
            ProviderFailureCategory::Quarantine,
            false,
            "provider_response_size_limit",
        ),
        ProviderFailureKind::PartialPageResponse => (
            ProviderFailureCategory::Quarantine,
            false,
            "provider_partial_page_response",
        ),
    };
    ProviderFailureClassification {
        kind,
        category,
        retryable,
        retry_after: retry_after.map(bound_retry_after),
        advances_progress: false,
        diagnostic_code,
    }
}

/// Map a connector error into a safe provider-failure classification when it
/// represents provider/runtime transport failure.
pub fn classify_http_connector_failure(
    error: &HttpConnectorError,
) -> Option<ProviderFailureClassification> {
    match error {
        HttpConnectorError::Request(error) if error.is_timeout() => Some(
            classify_provider_failure(ProviderFailureKind::Timeout, None),
        ),
        HttpConnectorError::Request(error) if error.is_connect() => {
            let debug = format!("{error:?}").to_ascii_lowercase();
            let kind = if debug.contains("dns") || debug.contains("resolve") {
                ProviderFailureKind::Dns
            } else if debug.contains("tls") || debug.contains("certificate") {
                ProviderFailureKind::Tls
            } else {
                ProviderFailureKind::Timeout
            };
            Some(classify_provider_failure(kind, None))
        }
        HttpConnectorError::Request(_) => Some(classify_provider_failure(
            ProviderFailureKind::TruncatedResponse,
            None,
        )),
        HttpConnectorError::RedactedRequest => Some(classify_provider_failure(
            ProviderFailureKind::Timeout,
            None,
        )),
        HttpConnectorError::ProviderStatus(status) if status.is_server_error() => Some(
            classify_provider_failure(ProviderFailureKind::Http5xx, None),
        ),
        HttpConnectorError::ProviderStatus(StatusCode::TOO_MANY_REQUESTS) => Some(
            classify_provider_failure(ProviderFailureKind::RetryAfter, None),
        ),
        HttpConnectorError::ProviderStatus(StatusCode::UNAUTHORIZED) => Some(
            classify_provider_failure(ProviderFailureKind::AuthenticationRejected, None),
        ),
        HttpConnectorError::ProviderStatus(StatusCode::FORBIDDEN) => Some(
            classify_provider_failure(ProviderFailureKind::PermissionDenied, None),
        ),
        HttpConnectorError::ProviderStatus(_) => None,
        HttpConnectorError::InvalidResponse(message) if message.contains("exceeds") => Some(
            classify_provider_failure(ProviderFailureKind::ResponseSizeLimit, None),
        ),
        HttpConnectorError::InvalidResponse(_) => Some(classify_provider_failure(
            ProviderFailureKind::PartialPageResponse,
            None,
        )),
        HttpConnectorError::PageLimit => Some(classify_provider_failure(
            ProviderFailureKind::PartialPageResponse,
            None,
        )),
        HttpConnectorError::InvalidConfiguration(_)
        | HttpConnectorError::InvalidUrl(_)
        | HttpConnectorError::Domain(_)
        | HttpConnectorError::MissingProviderAccess
        | HttpConnectorError::CredentialLease(_)
        | HttpConnectorError::EgressDenied(_) => None,
    }
}

fn bound_retry_after(value: Duration) -> Duration {
    const MAX_RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
    value.min(MAX_RETRY_AFTER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_failure_classification_never_advances_progress() {
        for kind in [
            ProviderFailureKind::AuthenticationRejected,
            ProviderFailureKind::PermissionDenied,
            ProviderFailureKind::Timeout,
            ProviderFailureKind::Dns,
            ProviderFailureKind::Tls,
            ProviderFailureKind::Http5xx,
            ProviderFailureKind::RetryAfter,
            ProviderFailureKind::Cancellation,
            ProviderFailureKind::TruncatedResponse,
            ProviderFailureKind::InvalidCompression,
            ProviderFailureKind::ResponseSizeLimit,
            ProviderFailureKind::PartialPageResponse,
        ] {
            let classification = classify_provider_failure(kind, Some(Duration::from_secs(9_999)));
            assert!(!classification.advances_progress, "{kind:?}");
            assert!(classification.diagnostic_code.starts_with("provider_"));
            assert_eq!(classification.retry_after, Some(Duration::from_secs(900)));
        }
    }

    #[test]
    fn provider_failure_redacts_body_diagnostics() {
        let classification = classify_provider_failure(ProviderFailureKind::Http5xx, None);
        let debug = format!("{classification:?}");
        for leaked in [
            "access_token",
            "provider error body",
            "raw_provider_response",
            "secret-sentinel",
        ] {
            assert!(!debug.contains(leaked));
        }
        assert_eq!(classification.category, ProviderFailureCategory::Retry);
        assert!(classification.retryable);
        assert!(!classification.advances_progress);
    }

    #[test]
    fn provider_failure_maps_http_errors_to_no_progress_receipts() {
        let http_5xx = HttpConnectorError::ProviderStatus(StatusCode::BAD_GATEWAY);
        let classification = classify_http_connector_failure(&http_5xx).unwrap();
        assert_eq!(classification.kind, ProviderFailureKind::Http5xx);
        assert_eq!(classification.category, ProviderFailureCategory::Retry);
        assert!(!classification.advances_progress);

        let too_large = HttpConnectorError::InvalidResponse(
            "provider response exceeds the 8-byte limit".to_owned(),
        );
        let classification = classify_http_connector_failure(&too_large).unwrap();
        assert_eq!(classification.kind, ProviderFailureKind::ResponseSizeLimit);
        assert_eq!(classification.category, ProviderFailureCategory::Quarantine);
        assert!(!classification.advances_progress);

        for (status, want) in [
            (
                StatusCode::UNAUTHORIZED,
                ProviderFailureKind::AuthenticationRejected,
            ),
            (StatusCode::FORBIDDEN, ProviderFailureKind::PermissionDenied),
        ] {
            let classification =
                classify_http_connector_failure(&HttpConnectorError::ProviderStatus(status))
                    .unwrap();
            assert_eq!(classification.kind, want);
            assert_eq!(classification.category, ProviderFailureCategory::Error);
            assert!(!classification.retryable);
            assert!(!classification.advances_progress);
        }
    }
}

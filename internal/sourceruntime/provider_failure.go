package sourceruntime

import "time"

// ProviderFailureKind is a stable provider/runtime failure code.
type ProviderFailureKind string

const (
	ProviderFailureTimeout             ProviderFailureKind = "timeout"
	ProviderFailureDNS                 ProviderFailureKind = "dns"
	ProviderFailureTLS                 ProviderFailureKind = "tls"
	ProviderFailureHTTP5xx             ProviderFailureKind = "http_5xx"
	ProviderFailureRetryAfter          ProviderFailureKind = "retry_after"
	ProviderFailureCancellation        ProviderFailureKind = "cancellation"
	ProviderFailureTruncatedResponse   ProviderFailureKind = "truncated_response"
	ProviderFailureInvalidCompression  ProviderFailureKind = "invalid_compression"
	ProviderFailureResponseSizeLimit   ProviderFailureKind = "response_size_limit"
	ProviderFailurePartialPageResponse ProviderFailureKind = "partial_page_response"
)

// ProviderFailureClassification is safe receipt evidence for a failed
// provider attempt. It deliberately carries no provider response body.
type ProviderFailureClassification struct {
	Kind             ProviderFailureKind
	Category         string
	Retryable        bool
	RetryAfter       time.Duration
	AdvancesProgress bool
	DiagnosticCode   string
}

// ClassifyProviderFailure maps transient provider failures into bounded retry
// or quarantine categories without allowing cursor/checkpoint advancement.
func ClassifyProviderFailure(kind ProviderFailureKind, retryAfter time.Duration) ProviderFailureClassification {
	category := "retry"
	retryable := true
	code := "provider_" + string(kind)
	switch kind {
	case ProviderFailureInvalidCompression, ProviderFailureResponseSizeLimit, ProviderFailurePartialPageResponse:
		category = "quarantine"
		retryable = false
	}
	if retryAfter > 15*time.Minute {
		retryAfter = 15 * time.Minute
	}
	if retryAfter < 0 {
		retryAfter = 0
	}
	return ProviderFailureClassification{
		Kind:             kind,
		Category:         category,
		Retryable:        retryable,
		RetryAfter:       retryAfter,
		AdvancesProgress: false,
		DiagnosticCode:   code,
	}
}

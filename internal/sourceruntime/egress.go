package sourceruntime

import (
	"net/url"
	"strings"
	"time"
)

// EgressMode declares whether source execution may contact a provider.
type EgressMode string

const (
	EgressModeFixture EgressMode = "fixture"
	EgressModeParity  EgressMode = "parity"
	EgressModeLive    EgressMode = "live"
)

// EgressPolicy binds provider egress to tenant, family, request intent, and
// an explicit origin allowlist.
type EgressPolicy struct {
	Mode                EgressMode
	TenantID            string
	FamilyID            string
	RequestIntentDigest string
	AllowedOrigins      map[string]struct{}
}

// EgressDecision is a safe, credential-free provider egress decision.
type EgressDecision struct {
	Allowed bool
	Origin  string
	Reason  string
}

// DecideEgress fails closed unless live mode, scope, lease, and origin match.
func DecideEgress(policy EgressPolicy, rawURL string, scope CredentialLeaseScope, lease CredentialLeaseReference, now time.Time) EgressDecision {
	if policy.Mode != EgressModeLive {
		return EgressDecision{Reason: "offline_mode"}
	}
	if scope.TenantID != policy.TenantID || scope.FamilyID != policy.FamilyID || scope.RequestIntentDigest != policy.RequestIntentDigest {
		return EgressDecision{Reason: "context_mismatch"}
	}
	if err := ValidateCredentialLeaseFor(lease, scope, now); err != nil {
		return EgressDecision{Reason: "credential_lease_rejected"}
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return EgressDecision{Reason: "invalid_url"}
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return EgressDecision{Reason: "disallowed_scheme"}
	}
	origin := parsed.Scheme + "://" + parsed.Host
	if _, ok := policy.AllowedOrigins[origin]; !ok {
		return EgressDecision{Reason: "host_not_allowed"}
	}
	return EgressDecision{Allowed: true, Origin: origin}
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}

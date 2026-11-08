package sourcecdk

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/writer/cerebro/internal/sourceconfig"
)

// NormalizeTrustedURL validates and normalizes raw as an absolute URL for a
// source's provider-managed endpoint (its API base_url or an OAuth
// token_url): it rejects user info, a query string, and a fragment
// (wrapping componentsErr, so a source keeps its own sentinel identity for
// that failure), requires https unless allowLoopback permits an http +
// loopback test origin, requires a host, rejects a non-443 port unless the
// host is an allowed loopback test host, and rejects loopback, private, or
// link-local hosts unless allowLoopback explicitly permits them. label names
// the configuration key in returned errors (e.g. "base_url", "url"). The
// normalized form has no trailing slash.
func NormalizeTrustedURL(sourceID, label, raw string, allowLoopback bool, componentsErr error) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s %s: %w", sourceID, label, err)
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("%w: %s %s must not include user info, query, or fragment", componentsErr, sourceID, label)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && IsLoopbackHost(host)
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("%s %s must use https", sourceID, label)
	}
	if host == "" {
		return "", fmt.Errorf("%s %s must include a host", sourceID, label)
	}
	allowCustomPort := allowLoopback && IsLoopbackHost(host)
	if strings.TrimSpace(parsed.Port()) != "" && parsed.Port() != "443" && !allowCustomPort {
		return "", fmt.Errorf("%s %s must not include a custom port", sourceID, label)
	}
	if IsUnsafeHost(host) && (!allowLoopback || !IsLoopbackHost(host)) {
		return "", fmt.Errorf("%s %s must not target loopback, private, or link-local hosts", sourceID, label)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

// RequireTrustedOrigin returns an error unless rawURL's scheme and host
// exactly match trustedOrigin's scheme and host, case-insensitively: the
// "pin to one known provider origin" check a Standard-tier source applies to
// a provider-managed base_url so a misconfigured value cannot silently point
// at an attacker-controlled host while still passing general URL safety
// checks. label names the configuration key and displayName the provider's
// human-readable name in returned errors.
func RequireTrustedOrigin(sourceID, label, displayName, rawURL, trustedOrigin string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse %s %s: %w", sourceID, label, err)
	}
	trusted, err := url.Parse(trustedOrigin)
	if err != nil {
		return fmt.Errorf("parse default %s %s: %w", displayName, label, err)
	}
	if !strings.EqualFold(parsed.Scheme, trusted.Scheme) || !strings.EqualFold(parsed.Host, trusted.Host) {
		return fmt.Errorf("%s %s must use the trusted %s origin", sourceID, label, displayName)
	}
	return nil
}

// RequireTrustedOriginFromDeploymentAllowlist is RequireTrustedOrigin for a
// source with no built-in default origin. It looks up sourceID's trusted
// origins from cfg's sourceconfig.SourceTrustedOriginsKey (deployment-
// controlled, never caller-supplied, parsed by sourceconfig.SourceTrustedOrigins
// from CEREBRO_SOURCE_TRUSTED_ORIGINS) and requires rawURL's scheme and host
// to match one of them. It fails closed, naming CEREBRO_SOURCE_TRUSTED_ORIGINS,
// when the allowlist has no entry for sourceID or a configured entry is
// malformed.
func RequireTrustedOriginFromDeploymentAllowlist(cfg Config, sourceID, label, displayName, rawURL string) error {
	origins, err := sourceconfig.SourceTrustedOrigins(sourceID, ConfigValue(cfg, sourceconfig.SourceTrustedOriginsKey))
	if err != nil {
		return err
	}
	if len(origins) == 0 {
		return fmt.Errorf("%s %s has no trusted origin; configure CEREBRO_SOURCE_TRUSTED_ORIGINS for %s", sourceID, label, sourceID)
	}
	var lastErr error
	for _, origin := range origins {
		if lastErr = RequireTrustedOrigin(sourceID, label, displayName, rawURL, origin); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// RequireIssuerTokenURL validates that configuredTokenURL equals the OAuth
// token endpoint derived by appending tokenPath to issuer, once both are
// normalized as a trusted URL. It lets a source accept a short issuer value
// (e.g. an "okta_issuer" setting) while still rejecting a separately
// configured token_url that silently points somewhere else. issuer must
// already be known non-empty; callers that allow an issuer-less loopback
// test configuration check that before calling. issuerLabel names the
// issuer configuration key in the returned mismatch error.
func RequireIssuerTokenURL(sourceID, issuerLabel, issuer, tokenPath, configuredTokenURL string, allowLoopback bool) error {
	expected, err := NormalizeTrustedURL(sourceID, "url", strings.TrimRight(strings.TrimSpace(issuer), "/")+tokenPath, allowLoopback, ErrInvalidConfig)
	if err != nil {
		return err
	}
	if configuredTokenURL != expected {
		return fmt.Errorf("%s token_url must match %s token endpoint", sourceID, issuerLabel)
	}
	return nil
}

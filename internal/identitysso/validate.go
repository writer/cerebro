// Package identitysso owns web console SSO state: identity provider
// connections, the tenant SSO policy, server-side sessions, and SCIM 2.0
// provisioning. The web server owns the browser protocol and calls these
// endpoints server-to-server; this package never redirects browsers or holds
// secret values.
package identitysso

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/authz"
	"github.com/writer/cerebro/internal/ports"
)

// Connection protocols and statuses.
const (
	ProtocolOIDC = "oidc"
	ProtocolSAML = "saml"

	StatusDraft    = "draft"
	StatusTested   = "tested"
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Limits from the web console SSO contract.
const (
	MaxConnections         = 20
	MaxDomainsPerConn      = 50
	MaxRoleMappings        = 100
	MaxRolesPerMapping     = 20
	MaxSecretRefLength     = 512
	MaxIDPCertificates     = 3
	maxCertificateBytes    = 16 << 10
	maxNameLength          = 128
	maxShortTextLength     = 256
	maxLongTextLength      = 1024
	maxDetailLength        = 2000
	maxOIDCScopes          = 20
	maxSessionClaimValues  = 500
	DefaultLifetimeMinutes = 720
	DefaultIdleMinutes     = 60
	MinLifetimeMinutes     = 15
	MaxLifetimeMinutes     = 43200
	MinIdleMinutes         = 5
	MaxIdleMinutes         = 10080
	MaxNameLength          = maxNameLength
	MaxShortTextLength     = maxShortTextLength
	MaxSubjectLength       = maxSubjectLength
	MaxEmailLength         = maxEmailLength
)

// Defaults applied to omitted protocol fields.
var (
	DefaultOIDCScopes = []string{"openid", "email", "profile", "groups"}
)

const (
	defaultGroupsClaim  = "groups"
	defaultEmailAttr    = "email"
	defaultNameAttr     = "name"
	defaultGroupsAttr   = "groups"
	defaultNameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

// ErrInvalid marks request validation failures that map to HTTP 400.
var ErrInvalid = errors.New("invalid identity sso request")

var (
	envRefPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	awsRegionPattern    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	awsSecretIDPattern  = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]+$`)
	awsSecretARNPattern = regexp.MustCompile(`^arn:aws(-[a-z]+)*:secretsmanager:[a-z]{2}(-[a-z]+)+-[0-9]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$`)
	secretFieldPattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	domainLabelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	oidcScopePattern    = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
	tokenHashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	resourceIDPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	samlURNPattern      = regexp.MustCompile(`^urn:oasis:names:tc:SAML:[0-9.]+:nameid-format:[A-Za-z]+$`)
	claimNamePattern    = regexp.MustCompile(`^[^\s]+$`)
	errFieldTooLong     = errors.New("is too long")
	errFieldRequired    = errors.New("is required")
	errFieldWhitespace  = errors.New("must not contain whitespace")
	errFieldControlChar = errors.New("must not contain control characters")
)

// Invalid builds a validation error that maps to HTTP 400.
func Invalid(format string, args ...any) error {
	return invalid(format, args...)
}

// CheckText validates a free-text field length and rejects control characters.
func CheckText(field string, value string, maxLen int, required bool) error {
	return checkText(field, value, maxLen, required)
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ValidateSecretRef checks that ref is a supported secret reference: env:NAME,
// aws-sm:<region>/<secret-id>, aws-sm:<region>:<secret-id>, or
// aws-sm:<secrets manager ARN>, each aws-sm form with an optional #json-field.
// Only the format is checked; resolution happens in the web server at login time.
func ValidateSecretRef(ref string) error {
	if ref == "" {
		return invalid("secret reference is required")
	}
	if len(ref) > MaxSecretRefLength {
		return invalid("secret reference must be at most %d characters", MaxSecretRefLength)
	}
	if strings.IndexFunc(ref, unicode.IsSpace) >= 0 {
		return invalid("secret reference must not contain whitespace")
	}
	switch {
	case strings.HasPrefix(ref, "env:"):
		if !envRefPattern.MatchString(strings.TrimPrefix(ref, "env:")) {
			return invalid("env: secret reference must name an environment variable")
		}
		return nil
	case strings.HasPrefix(ref, "aws-sm:"):
		body := strings.TrimPrefix(ref, "aws-sm:")
		body, field, hasField := strings.Cut(body, "#")
		if hasField && !secretFieldPattern.MatchString(field) {
			return invalid("aws-sm: secret reference has an invalid json field")
		}
		if strings.HasPrefix(body, "arn:") {
			if !awsSecretARNPattern.MatchString(body) {
				return invalid("aws-sm: secret reference has an invalid secrets manager ARN")
			}
			return nil
		}
		separator := strings.IndexAny(body, "/:")
		if separator < 0 || !awsRegionPattern.MatchString(body[:separator]) {
			return invalid("aws-sm: secret reference must be aws-sm:<region>/<secret-id>")
		}
		secretID := body[separator+1:]
		if secretID == "" || !awsSecretIDPattern.MatchString(secretID) {
			return invalid("aws-sm: secret reference has an invalid secret id")
		}
		return nil
	default:
		return invalid("secret reference must use env: or aws-sm:")
	}
}

// NormalizeDomain lowercases and validates one email domain.
func NormalizeDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", invalid("domain is required")
	}
	if len(domain) > 253 {
		return "", invalid("domain %q is too long", raw)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", invalid("domain %q must contain at least two labels", raw)
	}
	for _, label := range labels {
		if !domainLabelPattern.MatchString(label) {
			return "", invalid("domain %q is not a valid hostname", raw)
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", invalid("domain %q is not a valid hostname", raw)
	}
	return domain, nil
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

// NormalizeDomains normalizes, deduplicates, and bounds connection domains.
func NormalizeDomains(raw []string) ([]string, error) {
	if len(raw) > MaxDomainsPerConn {
		return nil, invalid("at most %d domains are allowed per connection", MaxDomainsPerConn)
	}
	domains := make([]string, 0, len(raw))
	for _, value := range raw {
		domain, err := NormalizeDomain(value)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	return domains, nil
}

// ValidateIdPURL requires an absolute https URL. Plain http is allowed only for
// loopback hosts so local IdP fixtures work.
func ValidateIdPURL(field string, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalid("%s is required", field)
	}
	if len(value) > maxLongTextLength {
		return "", invalid("%s is too long", field)
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" {
		return "", invalid("%s must be an absolute URL", field)
	}
	if parsed.User != nil {
		return "", invalid("%s must not contain credentials", field)
	}
	if parsed.Fragment != "" {
		return "", invalid("%s must not contain a fragment", field)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(parsed.Hostname()) {
			return "", invalid("%s must use https", field)
		}
	default:
		return "", invalid("%s must use https", field)
	}
	return value, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NormalizeCertificate accepts a PEM certificate or bare base64 DER (as found
// in SAML metadata) and returns canonical PEM after confirming it parses.
func NormalizeCertificate(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", invalid("idpCertificates entries must not be empty")
	}
	if len(value) > maxCertificateBytes {
		return "", invalid("idpCertificates entries must be at most %d bytes", maxCertificateBytes)
	}
	var der []byte
	if strings.HasPrefix(value, "-----BEGIN") {
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
			return "", invalid("idpCertificates entries must be a single PEM CERTIFICATE")
		}
		der = block.Bytes
	} else {
		compact := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, value)
		decoded, err := base64.StdEncoding.DecodeString(compact)
		if err != nil {
			return "", invalid("idpCertificates entries must be PEM or base64 DER")
		}
		der = decoded
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return "", invalid("idpCertificates entry is not a valid X.509 certificate")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// NormalizeRoles validates role names against the built-in Cerebro roles.
func NormalizeRoles(field string, raw []string) ([]string, error) {
	if len(raw) > MaxRolesPerMapping {
		return nil, invalid("%s allows at most %d roles", field, MaxRolesPerMapping)
	}
	roles := make([]string, 0, len(raw))
	for _, value := range raw {
		role := strings.ToLower(strings.TrimSpace(value))
		if !authz.IsKnownRole(role) {
			return nil, invalid("%s contains unknown role %q", field, value)
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	return roles, nil
}

func checkText(field string, value string, maxLen int, required bool) error {
	switch {
	case value == "" && required:
		return fmt.Errorf("%w: %s %w", ErrInvalid, field, errFieldRequired)
	case len(value) > maxLen:
		return fmt.Errorf("%w: %s %w", ErrInvalid, field, errFieldTooLong)
	case strings.IndexFunc(value, unicode.IsControl) >= 0:
		return fmt.Errorf("%w: %s %w", ErrInvalid, field, errFieldControlChar)
	}
	return nil
}

func checkToken(field string, value string, maxLen int) error {
	if err := checkText(field, value, maxLen, true); err != nil {
		return err
	}
	if !claimNamePattern.MatchString(value) {
		return fmt.Errorf("%w: %s %w", ErrInvalid, field, errFieldWhitespace)
	}
	return nil
}

// ValidTokenHash reports whether value is a lowercase hex SHA-256 digest.
func ValidTokenHash(value string) bool {
	return tokenHashPattern.MatchString(value)
}

// ValidResourceID reports whether value is a safe server-generated ID.
func ValidResourceID(value string) bool {
	return resourceIDPattern.MatchString(value)
}

// NormalizePolicy applies defaults and validates the session policy ranges.
func NormalizePolicy(policy ports.SSOPolicy) (ports.SSOPolicy, error) {
	if policy.SessionMaxLifetimeMinutes == 0 {
		policy.SessionMaxLifetimeMinutes = DefaultLifetimeMinutes
	}
	if policy.SessionIdleTimeoutMinutes == 0 {
		policy.SessionIdleTimeoutMinutes = DefaultIdleMinutes
	}
	if policy.SessionMaxLifetimeMinutes < MinLifetimeMinutes || policy.SessionMaxLifetimeMinutes > MaxLifetimeMinutes {
		return policy, invalid("sessionMaxLifetimeMinutes must be between %d and %d", MinLifetimeMinutes, MaxLifetimeMinutes)
	}
	if policy.SessionIdleTimeoutMinutes < MinIdleMinutes || policy.SessionIdleTimeoutMinutes > MaxIdleMinutes {
		return policy, invalid("sessionIdleTimeoutMinutes must be between %d and %d", MinIdleMinutes, MaxIdleMinutes)
	}
	if policy.SessionIdleTimeoutMinutes > policy.SessionMaxLifetimeMinutes {
		return policy, invalid("sessionIdleTimeoutMinutes must not exceed sessionMaxLifetimeMinutes")
	}
	policy.UpdatedBy = strings.TrimSpace(policy.UpdatedBy)
	if err := checkText("updatedBy", policy.UpdatedBy, maxShortTextLength, false); err != nil {
		return policy, err
	}
	policy.UpdatedOnBehalfOf = strings.TrimSpace(policy.UpdatedOnBehalfOf)
	if err := checkText("updatedOnBehalfOf", policy.UpdatedOnBehalfOf, maxShortTextLength, false); err != nil {
		return policy, err
	}
	return policy, nil
}

// DefaultPolicy is the effective policy for a tenant that has not saved one.
func DefaultPolicy() ports.SSOPolicy {
	return ports.SSOPolicy{
		SessionMaxLifetimeMinutes: DefaultLifetimeMinutes,
		SessionIdleTimeoutMinutes: DefaultIdleMinutes,
	}
}

func normalizeStringList(field string, raw []string, maxItems int, maxLen int) ([]string, error) {
	if len(raw) > maxItems {
		return nil, invalid("%s allows at most %d entries", field, maxItems)
	}
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if err := checkText(field, value, maxLen, true); err != nil {
			return nil, err
		}
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	return values, nil
}

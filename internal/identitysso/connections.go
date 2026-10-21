package identitysso

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

// Conflict errors map to HTTP 409 with the error code as the body.
var (
	ErrConnectionNotTested = errors.New("connection_not_tested")
	ErrNoActiveConnection  = ports.ErrSSONoActiveConnection
	ErrConnectionInactive  = errors.New("connection_not_active")
	ErrLastActiveEnforced  = ports.ErrSSOLastActiveConnection
	// ErrJITDisabled means a login-time upsert found no directory user and the
	// connection does not allow just-in-time provisioning.
	ErrJITDisabled = errors.New("jit_disabled")
	// ErrSubjectMismatch means the directory user is bound to a different IdP
	// subject on this connection.
	ErrSubjectMismatch = errors.New("subject_mismatch")
)

// Forbidden errors map to HTTP 403 with the error code as the body.
var (
	// ErrUserInactive means the directory user is deactivated.
	ErrUserInactive = errors.New("user_inactive")
	// ErrUserDeprovisioned means the directory user was deleted through SCIM.
	ErrUserDeprovisioned = errors.New("user_deprovisioned")
)

// ConnectionInput is the writable shape of an SSO connection.
type ConnectionInput struct {
	Name            string                 `json:"name"`
	Protocol        string                 `json:"protocol"`
	Status          string                 `json:"status"`
	Domains         []string               `json:"domains"`
	OIDC            *OIDCInput             `json:"oidc"`
	SAML            *SAMLInput             `json:"saml"`
	RoleMappings    []ports.SSORoleMapping `json:"roleMappings"`
	DefaultRoles    []string               `json:"defaultRoles"`
	JITProvisioning bool                   `json:"jitProvisioning"`
	// UpdatedBy is the caller-asserted end user. It is stored as the
	// connection's updatedOnBehalfOf; updatedBy is always the principal.
	UpdatedBy string `json:"updatedBy"`
}

// OIDCInput is the writable OIDC block.
type OIDCInput struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	ClientSecretRef string   `json:"clientSecretRef"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groupsClaim"`
	TrustEmailClaim bool     `json:"trustEmailClaim"`
}

// SAMLInput is the writable SAML block. WantAssertionsSigned is a pointer so
// an omitted value can default to true.
type SAMLInput struct {
	IDPEntityID          string   `json:"idpEntityId"`
	IDPSSOURL            string   `json:"idpSsoUrl"`
	IDPCertificates      []string `json:"idpCertificates"`
	IDPMetadataURL       string   `json:"idpMetadataUrl"`
	WantAssertionsSigned *bool    `json:"wantAssertionsSigned"`
	EmailAttribute       string   `json:"emailAttribute"`
	NameAttribute        string   `json:"nameAttribute"`
	GroupsAttribute      string   `json:"groupsAttribute"`
	NameIDFormat         string   `json:"nameIdFormat"`
}

// TestResultInput records the outcome of an admin test login. Actor is the
// caller-asserted admin who ran the test.
type TestResultInput struct {
	OK     bool   `json:"ok"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

// NormalizeConnectionInput validates input and returns a connection with every
// default applied. ID, tenant, timestamps, and lastTest are left unset.
func NormalizeConnectionInput(input ConnectionInput) (ports.SSOConnection, error) {
	var conn ports.SSOConnection
	conn.Name = strings.TrimSpace(input.Name)
	if err := checkText("name", conn.Name, maxNameLength, true); err != nil {
		return conn, err
	}
	conn.Protocol = strings.ToLower(strings.TrimSpace(input.Protocol))
	switch conn.Protocol {
	case ProtocolOIDC:
		if input.OIDC == nil {
			return conn, invalid("oidc settings are required for protocol oidc")
		}
		if input.SAML != nil {
			return conn, invalid("saml settings must be omitted for protocol oidc")
		}
		oidc, err := normalizeOIDC(*input.OIDC)
		if err != nil {
			return conn, err
		}
		conn.OIDC = &oidc
	case ProtocolSAML:
		if input.SAML == nil {
			return conn, invalid("saml settings are required for protocol saml")
		}
		if input.OIDC != nil {
			return conn, invalid("oidc settings must be omitted for protocol saml")
		}
		saml, err := normalizeSAML(*input.SAML)
		if err != nil {
			return conn, err
		}
		conn.SAML = &saml
	default:
		return conn, invalid("protocol must be oidc or saml")
	}
	conn.Status = strings.ToLower(strings.TrimSpace(input.Status))
	if conn.Status == "" {
		conn.Status = StatusDraft
	}
	switch conn.Status {
	case StatusDraft, StatusTested, StatusActive, StatusDisabled:
	default:
		return conn, invalid("status must be draft, tested, active, or disabled")
	}
	domains, err := NormalizeDomains(input.Domains)
	if err != nil {
		return conn, err
	}
	conn.Domains = domains
	if len(input.RoleMappings) > MaxRoleMappings {
		return conn, invalid("at most %d role mappings are allowed", MaxRoleMappings)
	}
	conn.RoleMappings = make([]ports.SSORoleMapping, 0, len(input.RoleMappings))
	for _, mapping := range input.RoleMappings {
		group := strings.TrimSpace(mapping.Group)
		if err := checkText("roleMappings.group", group, maxShortTextLength, true); err != nil {
			return conn, err
		}
		roles, err := NormalizeRoles("roleMappings.roles", mapping.Roles)
		if err != nil {
			return conn, err
		}
		if len(roles) == 0 {
			return conn, invalid("roleMappings entry for group %q must grant at least one role", group)
		}
		conn.RoleMappings = append(conn.RoleMappings, ports.SSORoleMapping{Group: group, Roles: roles})
	}
	if conn.DefaultRoles, err = NormalizeRoles("defaultRoles", input.DefaultRoles); err != nil {
		return conn, err
	}
	conn.JITProvisioning = input.JITProvisioning
	conn.UpdatedOnBehalfOf = strings.TrimSpace(input.UpdatedBy)
	if err := checkText("updatedBy", conn.UpdatedOnBehalfOf, maxShortTextLength, false); err != nil {
		return conn, err
	}
	return conn, nil
}

func normalizeOIDC(input OIDCInput) (ports.SSOOIDCConfig, error) {
	var oidc ports.SSOOIDCConfig
	issuer, err := ValidateIdPURL("oidc.issuer", input.Issuer)
	if err != nil {
		return oidc, err
	}
	oidc.Issuer = strings.TrimRight(issuer, "/")
	oidc.ClientID = strings.TrimSpace(input.ClientID)
	if err := checkToken("oidc.clientId", oidc.ClientID, maxShortTextLength); err != nil {
		return oidc, err
	}
	oidc.ClientSecretRef = strings.TrimSpace(input.ClientSecretRef)
	if err := ValidateSecretRef(oidc.ClientSecretRef); err != nil {
		return oidc, err
	}
	scopes := input.Scopes
	if len(scopes) == 0 {
		scopes = DefaultOIDCScopes
	}
	if len(scopes) > maxOIDCScopes {
		return oidc, invalid("oidc.scopes allows at most %d entries", maxOIDCScopes)
	}
	oidc.Scopes = make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !oidcScopePattern.MatchString(scope) || len(scope) > maxNameLength {
			return oidc, invalid("oidc.scopes contains invalid scope %q", scope)
		}
		if !containsString(oidc.Scopes, scope) {
			oidc.Scopes = append(oidc.Scopes, scope)
		}
	}
	if !containsString(oidc.Scopes, "openid") {
		return oidc, invalid("oidc.scopes must include openid")
	}
	oidc.GroupsClaim = defaultString(strings.TrimSpace(input.GroupsClaim), defaultGroupsClaim)
	if err := checkToken("oidc.groupsClaim", oidc.GroupsClaim, maxNameLength); err != nil {
		return oidc, err
	}
	oidc.TrustEmailClaim = input.TrustEmailClaim
	return oidc, nil
}

func normalizeSAML(input SAMLInput) (ports.SSOSAMLConfig, error) {
	var saml ports.SSOSAMLConfig
	saml.IDPEntityID = strings.TrimSpace(input.IDPEntityID)
	if err := checkToken("saml.idpEntityId", saml.IDPEntityID, maxLongTextLength); err != nil {
		return saml, err
	}
	ssoURL, err := ValidateIdPURL("saml.idpSsoUrl", input.IDPSSOURL)
	if err != nil {
		return saml, err
	}
	saml.IDPSSOURL = ssoURL
	if strings.TrimSpace(input.IDPMetadataURL) != "" {
		if saml.IDPMetadataURL, err = ValidateIdPURL("saml.idpMetadataUrl", input.IDPMetadataURL); err != nil {
			return saml, err
		}
	}
	if len(input.IDPCertificates) == 0 || len(input.IDPCertificates) > MaxIDPCertificates {
		return saml, invalid("saml.idpCertificates must contain 1 to %d certificates", MaxIDPCertificates)
	}
	saml.IDPCertificates = make([]string, 0, len(input.IDPCertificates))
	for _, raw := range input.IDPCertificates {
		cert, err := NormalizeCertificate(raw)
		if err != nil {
			return saml, err
		}
		if !containsString(saml.IDPCertificates, cert) {
			saml.IDPCertificates = append(saml.IDPCertificates, cert)
		}
	}
	saml.WantAssertionsSigned = input.WantAssertionsSigned == nil || *input.WantAssertionsSigned
	saml.EmailAttribute = defaultString(strings.TrimSpace(input.EmailAttribute), defaultEmailAttr)
	saml.NameAttribute = defaultString(strings.TrimSpace(input.NameAttribute), defaultNameAttr)
	saml.GroupsAttribute = defaultString(strings.TrimSpace(input.GroupsAttribute), defaultGroupsAttr)
	for _, attribute := range [][2]string{
		{"saml.emailAttribute", saml.EmailAttribute},
		{"saml.nameAttribute", saml.NameAttribute},
		{"saml.groupsAttribute", saml.GroupsAttribute},
	} {
		if err := checkToken(attribute[0], attribute[1], maxShortTextLength); err != nil {
			return saml, err
		}
	}
	saml.NameIDFormat = defaultString(strings.TrimSpace(input.NameIDFormat), defaultNameIDFormat)
	if !samlURNPattern.MatchString(saml.NameIDFormat) {
		return saml, invalid("saml.nameIdFormat must be a SAML nameid-format URN")
	}
	return saml, nil
}

// ProtocolChanged reports whether the authentication-relevant settings differ.
func ProtocolChanged(previous ports.SSOConnection, next ports.SSOConnection) bool {
	return previous.Protocol != next.Protocol ||
		!reflect.DeepEqual(previous.OIDC, next.OIDC) ||
		!reflect.DeepEqual(previous.SAML, next.SAML)
}

// PrepareCreate finalizes a new connection. A new connection has never been
// tested, so it may not start as tested or active.
func PrepareCreate(conn ports.SSOConnection, id string, now time.Time) (ports.SSOConnection, error) {
	if conn.Status == StatusTested || conn.Status == StatusActive {
		return conn, ErrConnectionNotTested
	}
	conn.ID = id
	conn.LastTest = nil
	conn.CreatedAt = now
	conn.UpdatedAt = now
	return conn, nil
}

// PrepareUpdate merges a validated input into the stored connection. Changing
// protocol settings discards the previous test result and resets the status to
// draft unless the caller is disabling the connection, so a connection can never
// go active on settings that were not tested.
func PrepareUpdate(previous ports.SSOConnection, next ports.SSOConnection, now time.Time) (ports.SSOConnection, error) {
	next.TenantID = previous.TenantID
	next.ID = previous.ID
	next.CreatedAt = previous.CreatedAt
	next.UpdatedAt = now
	next.LastTest = previous.LastTest
	if ProtocolChanged(previous, next) {
		next.LastTest = nil
		if next.Status != StatusDisabled {
			next.Status = StatusDraft
		}
	}
	if (next.Status == StatusTested || next.Status == StatusActive) && (next.LastTest == nil || !next.LastTest.OK) {
		return next, ErrConnectionNotTested
	}
	return next, nil
}

// ApplyTestResult records a test login. A passing test promotes a draft to
// tested; a failing test demotes tested back to draft. Active and disabled
// connections keep their status. principal is the authenticated caller; the
// body actor is kept separately as the on-behalf-of admin.
func ApplyTestResult(conn ports.SSOConnection, input TestResultInput, principal string, now time.Time) (ports.SSOConnection, error) {
	onBehalfOf := strings.TrimSpace(input.Actor)
	if err := checkText("actor", onBehalfOf, maxShortTextLength, false); err != nil {
		return conn, err
	}
	principal = strings.TrimSpace(principal)
	detail := strings.TrimSpace(input.Detail)
	if len(detail) > maxDetailLength {
		detail = detail[:maxDetailLength]
	}
	conn.LastTest = &ports.SSOConnectionRun{At: now, OK: input.OK, Actor: principal, OnBehalfOf: onBehalfOf, Detail: detail}
	switch {
	case input.OK && conn.Status == StatusDraft:
		conn.Status = StatusTested
	case !input.OK && conn.Status == StatusTested:
		conn.Status = StatusDraft
	}
	conn.UpdatedAt = now
	conn.UpdatedBy = principal
	conn.UpdatedOnBehalfOf = onBehalfOf
	return conn, nil
}

// ConnectionChangeRevokesSessions reports whether replacing previous with next
// invalidates the connection's existing sessions: the connection stops being
// active, or the settings sessions were authorized from (role mappings,
// default roles, or routed domains) change.
func ConnectionChangeRevokesSessions(previous ports.SSOConnection, next ports.SSOConnection) bool {
	if previous.Status == StatusActive && next.Status != StatusActive {
		return true
	}
	return !reflect.DeepEqual(nonNilMappings(previous.RoleMappings), nonNilMappings(next.RoleMappings)) ||
		!slices.Equal(previous.DefaultRoles, next.DefaultRoles) ||
		!slices.Equal(previous.Domains, next.Domains)
}

func nonNilMappings(mappings []ports.SSORoleMapping) []ports.SSORoleMapping {
	if mappings == nil {
		return []ports.SSORoleMapping{}
	}
	return mappings
}

// LeavesNoActiveConnection reports whether replacing (or deleting, when next is
// nil) the connection with ID changedID would leave the tenant without any
// active connection.
func LeavesNoActiveConnection(connections []ports.SSOConnection, changedID string, next *ports.SSOConnection) bool {
	for _, conn := range connections {
		if conn.ID == changedID {
			continue
		}
		if conn.Status == StatusActive {
			return false
		}
	}
	return next == nil || next.Status != StatusActive
}

func defaultString(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

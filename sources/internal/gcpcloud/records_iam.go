package gcpcloud

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/primitives"
)

type ServiceAccountRecord struct {
	Name           string          `json:"name"`
	ProjectID      string          `json:"projectId"`
	UniqueID       string          `json:"uniqueId"`
	Email          string          `json:"email"`
	DisplayName    string          `json:"displayName"`
	Description    string          `json:"description"`
	Disabled       bool            `json:"disabled"`
	OAuth2ClientID string          `json:"oauth2ClientId"`
	Raw            json.RawMessage `json:"-"`
}

type ServiceAccountKeyRecord struct {
	Name            string          `json:"name"`
	PrivateKeyType  string          `json:"privateKeyType"`
	KeyAlgorithm    string          `json:"keyAlgorithm"`
	ValidAfterTime  string          `json:"validAfterTime"`
	ValidBeforeTime string          `json:"validBeforeTime"`
	KeyOrigin       string          `json:"keyOrigin"`
	KeyType         string          `json:"keyType"`
	Disabled        bool            `json:"disabled"`
	Raw             json.RawMessage `json:"-"`
}

type EntityKey struct {
	ID string `json:"id"`
}

type GroupRecord struct {
	Name        string          `json:"name"`
	GroupKey    EntityKey       `json:"groupKey"`
	DisplayName string          `json:"displayName"`
	Description string          `json:"description"`
	Raw         json.RawMessage `json:"-"`
}

type MembershipRecord struct {
	Name               string           `json:"name"`
	PreferredMemberKey EntityKey        `json:"preferredMemberKey"`
	Roles              []MembershipRole `json:"roles"`
	Type               string           `json:"type"`
	Raw                json.RawMessage  `json:"-"`
}

type MembershipRole struct {
	Name string `json:"name"`
}

type RoleAssignmentRecord struct {
	Role   string
	Member string
	Raw    json.RawMessage
}

type ServiceAccountImpersonationRecord struct {
	Role   string
	Member string
	Raw    json.RawMessage
}

type IAMPolicy struct {
	Bindings []IAMBinding `json:"bindings"`
	Etag     string       `json:"etag"`
	Version  int          `json:"version"`
}

type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func (record WorkloadIdentityPoolRecord) CerebroResourceID() string {
	return record.Name
}

func (record WorkloadIdentityProviderRecord) CerebroResourceID() string {
	return record.Name
}

type WorkloadIdentityPoolRecord struct {
	Name                            string          `json:"name"`
	DisplayName                     string          `json:"displayName"`
	Description                     string          `json:"description"`
	State                           string          `json:"state"`
	Disabled                        bool            `json:"disabled"`
	ExpireTime                      string          `json:"expireTime"`
	InlineCertificateIssuanceConfig json.RawMessage `json:"inlineCertificateIssuanceConfig"`
	Raw                             json.RawMessage `json:"-"`
}

type WorkloadIdentityProviderRecord struct {
	Name               string                       `json:"name"`
	DisplayName        string                       `json:"displayName"`
	Description        string                       `json:"description"`
	State              string                       `json:"state"`
	Disabled           bool                         `json:"disabled"`
	ExpireTime         string                       `json:"expireTime"`
	AttributeMapping   map[string]string            `json:"attributeMapping"`
	AttributeCondition string                       `json:"attributeCondition"`
	AWS                WorkloadIdentityProviderAWS  `json:"aws"`
	OIDC               WorkloadIdentityProviderOIDC `json:"oidc"`
	SAML               WorkloadIdentityProviderSAML `json:"saml"`
	X509               json.RawMessage              `json:"x509"`
	PoolName           string                       `json:"-"`
	Raw                json.RawMessage              `json:"-"`
}

type WorkloadIdentityProviderAWS struct {
	AccountID string `json:"accountId"`
}

type WorkloadIdentityProviderOIDC struct {
	IssuerURI        string   `json:"issuerUri"`
	AllowedAudiences []string `json:"allowedAudiences"`
	JwksJSON         string   `json:"jwksJson"`
}

type WorkloadIdentityProviderSAML struct {
	IDPMetadataXML string `json:"idpMetadataXml"`
}

func ServiceAccountEvent(settings Settings, record ServiceAccountRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"display_name":   firstNonEmpty(record.DisplayName, record.Email),
		"domain":         settings.TenantID,
		"email":          record.Email,
		"family":         "service_account",
		"mfa_enrolled":   "false",
		"principal_type": "service_account",
		"status":         disabledStatus(record.Disabled),
		"unique_id":      record.UniqueID,
		"user_id":        firstNonEmpty(record.Email, record.UniqueID, record.Name),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-service-account-"+firstNonEmpty(record.UniqueID, record.Email), "gcp.service_account", "gcp/service_account/v1", payload, attributes)
}

func ServiceAccountKeyEvent(settings Settings, record ServiceAccountKeyRecord) (*primitives.Event, error) {
	attributes := map[string]string{ // #nosec G101 -- service-account key attributes are inventory identifiers, not key material.
		"credential_id":   firstNonEmpty(record.Name, settings.ServiceAccountEmail),
		"credential_type": "gcp_service_account_key",
		"domain":          settings.TenantID,
		"event_type":      "gcp_service_account_key_present",
		"family":          "service_account_key",
		"resource_id":     firstNonEmpty(record.Name, settings.ServiceAccountEmail),
		"resource_type":   "service_account_key",
		"status":          disabledStatus(record.Disabled),
		"subject_email":   settings.ServiceAccountEmail,
		"subject_id":      settings.ServiceAccountEmail,
		"subject_type":    "service_account",
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "service_account_email": settings.ServiceAccountEmail})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.ValidAfterTime != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.ValidAfterTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEventAt(settings, "gcp-service-account-key-"+firstNonEmpty(record.Name, settings.ServiceAccountEmail), "gcp.service_account_key", "gcp/service_account_key/v1", payload, attributes, occurredAt)
}

func GroupEvent(settings Settings, record GroupRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"domain":      settings.TenantID,
		"family":      "group",
		"group_email": emailLike(record.GroupKey.ID),
		"group_id":    firstNonEmpty(record.GroupKey.ID, record.Name),
		"group_name":  firstNonEmpty(record.DisplayName, record.GroupKey.ID),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"customer_id": settings.CustomerID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-group-"+firstNonEmpty(record.GroupKey.ID, record.Name), "gcp.group", "gcp/group/v1", payload, attributes)
}

func GroupMembershipEvent(settings Settings, record MembershipRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.PreferredMemberKey.ID)
	attributes := map[string]string{
		"domain":       settings.TenantID,
		"family":       "group_membership",
		"group_email":  emailLike(settings.GroupKey),
		"group_id":     settings.GroupKey,
		"member_email": memberEmail,
		"member_id":    memberID,
		"member_type":  memberType,
		"role":         membershipRoleName(record.Roles),
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"group_key": settings.GroupKey})
	if err != nil {
		return nil, err
	}
	id := "gcp-group-membership-" + settings.GroupKey + "-" + firstNonEmpty(memberID, record.Name)
	return sourceEvent(settings, id, "gcp.group_membership", "gcp/group_membership/v1", payload, attributes)
}

func RoleAssignmentEvent(settings Settings, record RoleAssignmentRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	attributes := map[string]string{
		"domain":         settings.TenantID,
		"family":         "iam_role_assignment",
		"is_admin":       boolString(iamAdminRole(record.Role)),
		"principal_type": memberType,
		"role_id":        record.Role,
		"role_name":      record.Role,
		"role_type":      "gcp_iam_role",
		"subject_email":  memberEmail,
		"subject_id":     memberID,
		"subject_type":   memberType,
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	id := "gcp-iam-role-assignment-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.iam_role_assignment", "gcp/iam_role_assignment/v1", payload, attributes)
}

func EffectivePermissionEvent(settings Settings, record RoleAssignmentRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	projectResource := "projects/" + settings.ProjectID
	admin := iamAdminRole(record.Role)
	attributes := map[string]string{
		"actions":         record.Role,
		"domain":          settings.TenantID,
		"effect":          "allow",
		"family":          "effective_permission",
		"is_admin":        boolString(admin),
		"permission":      record.Role,
		"privilege_level": privilegeLevel(admin),
		"project_id":      settings.ProjectID,
		"resource_id":     projectResource,
		"resource_name":   settings.ProjectID,
		"resource_type":   "project",
		"role_id":         record.Role,
		"role_name":       record.Role,
		"role_type":       "gcp_iam_role",
		"scope":           projectResource,
		"subject_email":   memberEmail,
		"subject_id":      memberID,
		"subject_type":    memberType,
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	id := "gcp-effective-permission-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.effective_permission", "gcp/effective_permission/v1", payload, attributes)
}

func ServiceAccountImpersonationEvent(settings Settings, record ServiceAccountImpersonationRecord) (*primitives.Event, error) {
	memberType, memberID, memberEmail := parseMember(record.Member)
	attributes := map[string]string{
		"domain":        settings.TenantID,
		"family":        "service_account_impersonation",
		"is_admin":      "true",
		"member":        record.Member,
		"path_type":     "service_account_impersonation",
		"relationship":  "can_impersonate",
		"role_id":       record.Role,
		"role_name":     record.Role,
		"role_type":     "gcp_service_account_iam_role",
		"subject_email": memberEmail,
		"subject_id":    memberID,
		"subject_type":  memberType,
		"target_email":  settings.ServiceAccountEmail,
		"target_id":     settings.ServiceAccountEmail,
		"target_name":   settings.ServiceAccountEmail,
		"target_type":   "service_account",
	}
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID, "service_account_email": settings.ServiceAccountEmail})
	if err != nil {
		return nil, err
	}
	id := "gcp-service-account-impersonation-" + sanitizeEventID(memberID) + "-" + sanitizeEventID(record.Role)
	return sourceEvent(settings, id, "gcp.service_account_impersonation", "gcp/service_account_impersonation/v1", payload, attributes)
}

func WorkloadIdentityPoolEvent(settings Settings, record WorkloadIdentityPoolRecord) (*primitives.Event, error) {
	location := firstNonEmpty(locationFromResourceName(record.Name), settings.Location, "global")
	attributes := cloudResourceAttributes(settings, "workload_identity_pool", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "workload_identity_pool", location, nil)
	attributes["description"] = record.Description
	attributes["disabled"] = boolString(record.Disabled)
	attributes["display_name"] = record.DisplayName
	attributes["expire_time"] = record.ExpireTime
	attributes["pool_id"] = lastPathSegment(record.Name)
	attributes["state"] = record.State
	attributes["status"] = disabledStatus(record.Disabled)
	attributes["inline_certificate_issuance_configured"] = boolString(len(record.InlineCertificateIssuanceConfig) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-workload-identity-pool-"+record.Name, "gcp.workload_identity_pool", "gcp/workload_identity_pool/v1", payload, attributes)
}

func WorkloadIdentityProviderEvent(settings Settings, record WorkloadIdentityProviderRecord) (*primitives.Event, error) {
	providerType := workloadIdentityProviderType(record)
	mappingKeys := workloadIdentityProviderMappingKeys(record.AttributeMapping)
	location := firstNonEmpty(locationFromResourceName(record.Name), locationFromResourceName(record.PoolName), settings.Location, "global")
	poolName := firstNonEmpty(record.PoolName, parentResourceName(record.Name, "providers"))
	attributes := cloudResourceAttributes(settings, "workload_identity_provider", record.Name, firstNonEmpty(record.DisplayName, lastPathSegment(record.Name)), "workload_identity_provider", location, nil)
	attributes["attribute_condition"] = record.AttributeCondition
	attributes["attribute_condition_configured"] = boolString(record.AttributeCondition != "")
	attributes["attribute_mapping_keys"] = strings.Join(mappingKeys, ",")
	attributes["attribute_mappings_count"] = strconv.Itoa(len(record.AttributeMapping))
	attributes["aws_account_id"] = record.AWS.AccountID
	attributes["description"] = record.Description
	attributes["disabled"] = boolString(record.Disabled)
	attributes["display_name"] = record.DisplayName
	attributes["expire_time"] = record.ExpireTime
	attributes["oidc_allowed_audiences"] = strings.Join(record.OIDC.AllowedAudiences, ",")
	attributes["oidc_allowed_audiences_count"] = strconv.Itoa(len(record.OIDC.AllowedAudiences))
	attributes["oidc_issuer_uri"] = record.OIDC.IssuerURI
	attributes["pool_id"] = lastPathSegment(poolName)
	attributes["pool_name"] = poolName
	attributes["provider_id"] = lastPathSegment(record.Name)
	attributes["provider_type"] = providerType
	attributes["saml_metadata_configured"] = boolString(record.SAML.IDPMetadataXML != "")
	attributes["state"] = record.State
	attributes["status"] = disabledStatus(record.Disabled)
	attributes["x509_configured"] = boolString(len(record.X509) != 0)
	payload, err := payloadWithRaw(record.Raw, map[string]any{"pool_name": poolName, "project_id": settings.ProjectID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "gcp-workload-identity-provider-"+record.Name, "gcp.workload_identity_provider", "gcp/workload_identity_provider/v1", payload, attributes)
}

type iamSummary struct {
	Public       bool
	Members      []string
	AdminMembers []string
}

func iamPolicySummary(policy IAMPolicy) iamSummary {
	summary := iamSummary{}
	for _, binding := range policy.Bindings {
		admin := iamAdminRole(binding.Role)
		for _, member := range binding.Members {
			trimmed := strings.TrimSpace(member)
			if trimmed == "" {
				continue
			}
			summary.Members = appendUnique(summary.Members, trimmed)
			if admin {
				summary.AdminMembers = appendUnique(summary.AdminMembers, trimmed)
			}
			if publicPrincipal(trimmed) {
				summary.Public = true
			}
		}
	}
	return summary
}

func iamPolicyRoles(policy IAMPolicy) []string {
	roles := make([]string, 0, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		roles = appendUnique(roles, binding.Role)
	}
	return roles
}

func iamAdminRole(role string) bool {
	normalized := strings.ToLower(strings.TrimSpace(role))
	return strings.Contains(normalized, "admin") || strings.Contains(normalized, "owner") || strings.Contains(normalized, "editor")
}

func workloadIdentityProviderType(record WorkloadIdentityProviderRecord) string {
	switch {
	case record.AWS.AccountID != "":
		return "aws"
	case record.OIDC.IssuerURI != "" || len(record.OIDC.AllowedAudiences) != 0 || record.OIDC.JwksJSON != "":
		return "oidc"
	case record.SAML.IDPMetadataXML != "":
		return "saml"
	case len(record.X509) != 0:
		return "x509"
	default:
		return ""
	}
}

func workloadIdentityProviderMappingKeys(mapping map[string]string) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func parseMember(value string) (string, string, string) {
	trimmed := strings.TrimSpace(value)
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		if publicPrincipal(trimmed) {
			return "public", trimmed, ""
		}
		return "user", trimmed, emailLike(trimmed)
	}
	memberType := strings.ToLower(strings.ReplaceAll(parts[0], "serviceAccount", "service_account"))
	if publicPrincipal(memberType) {
		memberType = "public"
	}
	return memberType, parts[1], emailLike(parts[1])
}

func membershipRoleName(roles []MembershipRole) string {
	if len(roles) == 0 {
		return "member"
	}
	return firstNonEmpty(roles[0].Name, "member")
}

func privilegeLevel(admin bool) string {
	if admin {
		return "admin"
	}
	return "standard"
}

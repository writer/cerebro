package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type authorizationPolicyRecord struct {
	ID                                        string         `json:"id"`
	AllowInvitesFrom                          string         `json:"allowInvitesFrom"`
	AllowedToSignUpEmailBasedSubscriptions    *bool          `json:"allowedToSignUpEmailBasedSubscriptions"`
	AllowedToUseSSPR                          *bool          `json:"allowedToUseSSPR"`
	AllowEmailVerifiedUsersToJoinOrganization *bool          `json:"allowEmailVerifiedUsersToJoinOrganization"`
	BlockMsolPowerShell                       *bool          `json:"blockMsolPowerShell"`
	DefaultUserRolePermissions                map[string]any `json:"defaultUserRolePermissions"`
	GuestUserRoleID                           string         `json:"guestUserRoleId"`
	raw                                       json.RawMessage
}

type userRecord struct {
	ID                string         `json:"id"`
	UserPrincipalName string         `json:"userPrincipalName"`
	Mail              string         `json:"mail"`
	DisplayName       string         `json:"displayName"`
	AccountEnabled    *bool          `json:"accountEnabled"`
	CreatedDateTime   string         `json:"createdDateTime"`
	SignInActivity    signInActivity `json:"signInActivity"`
	raw               json.RawMessage
}

type signInActivity struct {
	LastSignInDateTime string `json:"lastSignInDateTime"`
}

type groupRecord struct {
	ID              string `json:"id"`
	Mail            string `json:"mail"`
	DisplayName     string `json:"displayName"`
	Description     string `json:"description"`
	SecurityEnabled *bool  `json:"securityEnabled"`
	MailEnabled     *bool  `json:"mailEnabled"`
	raw             json.RawMessage
}

type applicationRecord struct {
	ID                  string               `json:"id"`
	AppID               string               `json:"appId"`
	DisplayName         string               `json:"displayName"`
	CreatedDateTime     string               `json:"createdDateTime"`
	PasswordCredentials []passwordCredential `json:"passwordCredentials"`
	KeyCredentials      []keyCredential      `json:"keyCredentials"`
	raw                 json.RawMessage
}

type servicePrincipalRecord struct {
	ID                   string               `json:"id"`
	AppID                string               `json:"appId"`
	DisplayName          string               `json:"displayName"`
	ServicePrincipalType string               `json:"servicePrincipalType"`
	AccountEnabled       *bool                `json:"accountEnabled"`
	PasswordCredentials  []passwordCredential `json:"passwordCredentials"`
	KeyCredentials       []keyCredential      `json:"keyCredentials"`
	raw                  json.RawMessage
}

type passwordCredential struct {
	KeyID               string `json:"keyId"`
	DisplayName         string `json:"displayName"`
	StartDateTime       string `json:"startDateTime"`
	EndDateTime         string `json:"endDateTime"`
	Hint                string `json:"hint"`
	CustomKeyIdentifier string `json:"customKeyIdentifier"`
}

type keyCredential struct {
	KeyID               string `json:"keyId"`
	DisplayName         string `json:"displayName"`
	StartDateTime       string `json:"startDateTime"`
	EndDateTime         string `json:"endDateTime"`
	Type                string `json:"type"`
	Usage               string `json:"usage"`
	CustomKeyIdentifier string `json:"customKeyIdentifier"`
}

type credentialRecord struct {
	OwnerType      string
	OwnerID        string
	OwnerAppID     string
	OwnerName      string
	CredentialID   string
	CredentialName string
	CredentialType string
	StartTime      string
	EndTime        string
	raw            json.RawMessage
}

type directoryRoleAssignmentRecord struct {
	ID               string               `json:"id"`
	PrincipalID      string               `json:"principalId"`
	RoleDefinitionID string               `json:"roleDefinitionId"`
	DirectoryScopeID string               `json:"directoryScopeId"`
	Principal        graphPrincipalRecord `json:"principal"`
	RoleDefinition   directoryRoleDef     `json:"roleDefinition"`
	raw              json.RawMessage
}

type directoryRoleDef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	TemplateID  string `json:"templateId"`
}

type appRoleAssignmentRecord struct {
	ID                   string `json:"id"`
	PrincipalID          string `json:"principalId"`
	PrincipalDisplayName string `json:"principalDisplayName"`
	PrincipalType        string `json:"principalType"`
	ResourceID           string `json:"resourceId"`
	ResourceDisplayName  string `json:"resourceDisplayName"`
	AppRoleID            string `json:"appRoleId"`
	CreatedDateTime      string `json:"createdDateTime"`
	raw                  json.RawMessage
}

type directoryAuditRecord struct {
	ID                  string                `json:"id"`
	ActivityDateTime    string                `json:"activityDateTime"`
	ActivityDisplayName string                `json:"activityDisplayName"`
	OperationType       string                `json:"operationType"`
	Category            string                `json:"category"`
	InitiatedBy         auditInitiatedBy      `json:"initiatedBy"`
	TargetResources     []auditTargetResource `json:"targetResources"`
	raw                 json.RawMessage
}

type auditInitiatedBy struct {
	User auditUser `json:"user"`
	App  auditApp  `json:"app"`
}

type auditUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
}

type auditApp struct {
	AppID              string `json:"appId"`
	DisplayName        string `json:"displayName"`
	ServicePrincipalID string `json:"servicePrincipalId"`
}

type auditTargetResource struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Type              string `json:"type"`
	UserPrincipalName string `json:"userPrincipalName"`
}

func listUsers(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]userRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/users"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure user", func(record *userRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, graphNext(response), err
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/groups"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure group", func(record *groupRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, graphNext(response), err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]graphPrincipalRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	path := "/v1.0/groups/" + url.PathEscape(settings.groupID) + "/members"
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure group member", func(record *graphPrincipalRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listAppRoleAssignments(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]appRoleAssignmentRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	path := "/v1.0/servicePrincipals/" + url.PathEscape(settings.servicePrincipalID) + "/appRoleAssignedTo"
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure app role assignment", func(record *appRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listApplications(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]applicationRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/applications"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure application", func(record *applicationRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listAuthorizationPolicy(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]authorizationPolicyRecord, string, error) {
	var record authorizationPolicyRecord
	if err := getGraphJSON(ctx, source, settings, "/v1.0/policies/authorizationPolicy", nil, &record); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(record.ID) == "" {
		record.ID = "authorizationPolicy"
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	record.raw = append(json.RawMessage(nil), payload...)
	return []authorizationPolicyRecord{record}, "", nil
}

func listServicePrincipals(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]servicePrincipalRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/servicePrincipals"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure service principal", func(record *servicePrincipalRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listCredentials(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]credentialRecord, string, error) {
	if strings.HasPrefix(pageToken, "sp:") {
		principals, next, err := listServicePrincipals(ctx, source, settings, strings.TrimPrefix(pageToken, "sp:"), limit)
		if err != nil {
			return nil, "", err
		}
		return credentialsFromServicePrincipals(principals), prefixedNext("sp", next), nil
	}
	appPageToken := strings.TrimPrefix(pageToken, "app:")
	apps, next, err := listApplications(ctx, source, settings, appPageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records := credentialsFromApplications(apps)
	if next != "" {
		return records, prefixedNext("app", next), nil
	}
	principals, next, err := listServicePrincipals(ctx, source, settings, "", limit)
	if err != nil {
		return nil, "", err
	}
	records = append(records, credentialsFromServicePrincipals(principals)...)
	return records, prefixedNext("sp", next), nil
}

func listDirectoryRoleAssignments(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]directoryRoleAssignmentRecord, string, error) {
	query := graphListQuery(settings, limit)
	query.Set("$expand", "principal,roleDefinition")
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/roleManagement/directory/roleAssignments"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure directory role assignment", func(record *directoryRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listDirectoryAudits(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]directoryAuditRecord, string, error) {
	return listDirectoryAuditsWithCheckpoint(ctx, source, settings, pageToken, limit, nil)
}

func listDirectoryAuditsWithCheckpoint(ctx context.Context, source *Source, settings settings, pageToken string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]directoryAuditRecord, string, error) {
	query := graphListQuery(settings, limit)
	if start, ok := azureCheckpointStart(checkpoint); ok {
		query.Set("$filter", azureCombineFilters(query.Get("$filter"), "activityDateTime ge "+start.Format(time.RFC3339Nano)))
		query.Set("$orderby", "activityDateTime desc")
	}
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, firstNonEmpty(pageToken, "/v1.0/auditLogs/directoryAudits"), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure directory audit", func(record *directoryAuditRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func userEvent(settings settings, record userRecord) (*primitives.Event, error) {
	email := firstNonEmpty(emailLike(record.Mail), emailLike(record.UserPrincipalName))
	attributes := map[string]string{
		"created_at":     record.CreatedDateTime,
		"display_name":   firstNonEmpty(record.DisplayName, record.UserPrincipalName, email),
		"domain":         tenantID(settings),
		"email":          email,
		"family":         familyUser,
		"last_login_at":  record.SignInActivity.LastSignInDateTime,
		"login":          record.UserPrincipalName,
		"principal_type": "user",
		"status":         enabledStatus(record.AccountEnabled),
		"user_id":        firstNonEmpty(record.ID, record.UserPrincipalName, email),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-user-"+firstNonEmpty(record.ID, record.UserPrincipalName, email), "azure.user", "azure/user/v1", payload, attributes, time.Now().UTC())
}

func groupEvent(settings settings, record groupRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"description":      record.Description,
		"domain":           tenantID(settings),
		"family":           familyGroup,
		"group_email":      emailLike(record.Mail),
		"group_id":         firstNonEmpty(record.ID, record.Mail),
		"group_name":       firstNonEmpty(record.DisplayName, record.Mail),
		"mail_enabled":     boolPointerString(record.MailEnabled),
		"security_enabled": boolPointerString(record.SecurityEnabled),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-group-"+firstNonEmpty(record.ID, record.Mail), "azure.group", "azure/group/v1", payload, attributes, time.Now().UTC())
}

func groupMembershipEvent(settings settings, record graphPrincipalRecord) (*primitives.Event, error) {
	memberType := azurePrincipalType(record.ODataType, record)
	memberEmail := firstNonEmpty(emailLike(record.Mail), emailLike(record.UserPrincipalName))
	attributes := map[string]string{
		"domain":       tenantID(settings),
		"family":       familyGroupMember,
		"group_id":     settings.groupID,
		"member_email": memberEmail,
		"member_id":    firstNonEmpty(record.ID, record.AppID, record.UserPrincipalName, record.Mail),
		"member_name":  firstNonEmpty(record.DisplayName, record.UserPrincipalName, record.AppID),
		"member_type":  memberType,
		"role":         "member",
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"group_id": settings.groupID})
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("azure-group-membership-%s-%s", settings.groupID, firstNonEmpty(record.ID, record.UserPrincipalName, record.AppID))
	return sourceEvent(settings, id, "azure.group_membership", "azure/group_membership/v1", payload, attributes, time.Now().UTC())
}

func appRoleAssignmentEvent(settings settings, record appRoleAssignmentRecord) (*primitives.Event, error) {
	subjectType := azurePrincipalType(record.PrincipalType, graphPrincipalRecord{})
	subjectEmail := ""
	if subjectType == "user" {
		subjectEmail = emailLike(record.PrincipalDisplayName)
	}
	attributes := map[string]string{
		"domain":        tenantID(settings),
		"family":        familyAppRoleAssignment,
		"is_admin":      "true",
		"path_type":     "app_role_assignment",
		"relationship":  "assigned_to",
		"role_id":       record.AppRoleID,
		"role_name":     record.AppRoleID,
		"role_type":     "azure_app_role",
		"subject_email": subjectEmail,
		"subject_id":    record.PrincipalID,
		"subject_login": subjectEmail,
		"subject_name":  record.PrincipalDisplayName,
		"subject_type":  subjectType,
		"target_id":     firstNonEmpty(record.ResourceID, settings.servicePrincipalID),
		"target_name":   record.ResourceDisplayName,
		"target_type":   "service_principal",
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID, "service_principal_id": settings.servicePrincipalID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.CreatedDateTime != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.CreatedDateTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "azure-app-role-assignment-"+firstNonEmpty(record.ID, record.PrincipalID+"-"+record.AppRoleID), "azure.app_role_assignment", "azure/app_role_assignment/v1", payload, attributes, occurredAt)
}

func applicationEvent(settings settings, record applicationRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"app_id":         firstNonEmpty(record.AppID, record.ID),
		"app_name":       record.DisplayName,
		"application_id": firstNonEmpty(record.AppID, record.ID),
		"client_id":      record.AppID,
		"created_at":     record.CreatedDateTime,
		"domain":         tenantID(settings),
		"family":         familyApplication,
		"object_id":      record.ID,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-application-"+firstNonEmpty(record.AppID, record.ID), "azure.application", "azure/application/v1", payload, attributes, time.Now().UTC())
}

func servicePrincipalEvent(settings settings, record servicePrincipalRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"app_id":                 record.AppID,
		"display_name":           firstNonEmpty(record.DisplayName, record.AppID),
		"domain":                 tenantID(settings),
		"family":                 familyServicePrincipal,
		"login":                  record.AppID,
		"principal_type":         "service_principal",
		"service_principal_type": record.ServicePrincipalType,
		"status":                 enabledStatus(record.AccountEnabled),
		"user_id":                firstNonEmpty(record.ID, record.AppID),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-service-principal-"+firstNonEmpty(record.ID, record.AppID), "azure.service_principal", "azure/service_principal/v1", payload, attributes, time.Now().UTC())
}

func credentialEvent(settings settings, record credentialRecord) (*primitives.Event, error) {
	attributes := map[string]string{
		"app_id":          record.OwnerAppID,
		"credential_id":   firstNonEmpty(record.CredentialID, record.OwnerID),
		"credential_name": record.CredentialName,
		"credential_type": record.CredentialType,
		"domain":          tenantID(settings),
		"event_type":      "azure_credential_present",
		"expires_at":      record.EndTime,
		"family":          familyCredential,
		"resource_id":     firstNonEmpty(record.CredentialID, record.OwnerID),
		"resource_type":   "credential",
		"status":          credentialStatus(record.EndTime),
		"subject_id":      firstNonEmpty(record.OwnerID, record.OwnerAppID),
		"subject_name":    record.OwnerName,
		"subject_type":    record.OwnerType,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID, "owner_type": record.OwnerType, "owner_id": record.OwnerID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.StartTime != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.StartTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "azure-credential-"+firstNonEmpty(record.CredentialID, record.OwnerID), "azure.credential", "azure/credential/v1", payload, attributes, occurredAt)
}

func authorizationPolicyEvent(settings settings, record authorizationPolicyRecord) (*primitives.Event, error) {
	permissions := mapFromAny(record.DefaultUserRolePermissions)
	attributes := map[string]string{
		"allow_email_verified_users_to_join": strconv.FormatBool(boolPtrValue(record.AllowEmailVerifiedUsersToJoinOrganization)),
		"allow_invites_from":                 record.AllowInvitesFrom,
		"allowed_to_sign_up_email":           strconv.FormatBool(boolPtrValue(record.AllowedToSignUpEmailBasedSubscriptions)),
		"allowed_to_use_sspr":                strconv.FormatBool(boolPtrValue(record.AllowedToUseSSPR)),
		"block_msol_powershell":              strconv.FormatBool(boolPtrValue(record.BlockMsolPowerShell)),
		"default_user_can_create_apps":       stringFromAny(permissions["allowedToCreateApps"]),
		"default_user_can_create_groups":     stringFromAny(permissions["allowedToCreateSecurityGroups"]),
		"default_user_can_read_bitlocker":    stringFromAny(permissions["allowedToReadBitlockerKeysForOwnedDevice"]),
		"domain":                             tenantID(settings),
		"family":                             familyAuthorizationPolicy,
		"guest_user_role_id":                 record.GuestUserRoleID,
		"resource_id":                        firstNonEmpty(record.ID, "authorizationPolicy"),
		"resource_name":                      "authorizationPolicy",
		"resource_provider":                  "azure",
		"resource_type":                      "authorization_policy",
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-authorization-policy-"+firstNonEmpty(record.ID, "authorizationPolicy"), "azure.authorization_policy", "azure/authorization_policy/v1", payload, attributes, time.Now().UTC())
}

func directoryRoleAssignmentEvent(settings settings, record directoryRoleAssignmentRecord) (*primitives.Event, error) {
	principal := record.Principal
	roleID := firstNonEmpty(record.RoleDefinition.ID, record.RoleDefinitionID)
	roleName := firstNonEmpty(record.RoleDefinition.DisplayName, roleID)
	subjectType := azurePrincipalType(principal.ODataType, principal)
	if subjectType == "user" && strings.TrimSpace(principal.ID) == "" {
		subjectType = "unknown"
	}
	attributes := map[string]string{
		"domain":        tenantID(settings),
		"family":        familyDirectoryRoleAssign,
		"is_admin":      boolString(isAdminRole(roleName)),
		"role_id":       roleID,
		"role_name":     roleName,
		"role_type":     "azure_directory_role",
		"scope":         record.DirectoryScopeID,
		"subject_email": firstNonEmpty(emailLike(principal.Mail), emailLike(principal.UserPrincipalName)),
		"subject_id":    firstNonEmpty(record.PrincipalID, principal.ID, principal.AppID, principal.UserPrincipalName),
		"subject_name":  firstNonEmpty(principal.DisplayName, principal.UserPrincipalName, principal.AppID),
		"subject_type":  subjectType,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	id := firstNonEmpty(record.ID, record.PrincipalID+"-"+roleID)
	return sourceEvent(settings, "azure-directory-role-assignment-"+id, "azure.directory_role_assignment", "azure/directory_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func directoryAuditEvent(settings settings, record directoryAuditRecord) (*primitives.Event, error) {
	target := auditTargetResource{}
	if len(record.TargetResources) != 0 {
		target = record.TargetResources[0]
	}
	actorID := firstNonEmpty(record.InitiatedBy.User.ID, record.InitiatedBy.User.UserPrincipalName, record.InitiatedBy.App.ServicePrincipalID, record.InitiatedBy.App.AppID)
	actorEmail := emailLike(record.InitiatedBy.User.UserPrincipalName)
	actorName := firstNonEmpty(record.InitiatedBy.User.DisplayName, record.InitiatedBy.User.UserPrincipalName, record.InitiatedBy.App.DisplayName, record.InitiatedBy.App.AppID)
	attributes := map[string]string{
		"actor_alternate_id": firstNonEmpty(record.InitiatedBy.User.UserPrincipalName, record.InitiatedBy.App.AppID),
		"actor_email":        actorEmail,
		"actor_id":           actorID,
		"actor_name":         actorName,
		"domain":             tenantID(settings),
		"event_name":         record.ActivityDisplayName,
		"event_type":         firstNonEmpty(record.ActivityDisplayName, record.OperationType),
		"family":             familyDirectoryAudit,
		"resource_id":        firstNonEmpty(target.ID, target.UserPrincipalName, target.DisplayName),
		"resource_name":      firstNonEmpty(target.DisplayName, target.UserPrincipalName, target.ID),
		"resource_type":      firstNonEmpty(target.Type, record.Category, "directory_resource"),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"tenant_id": settings.tenantID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.ActivityDateTime != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.ActivityDateTime); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "azure-directory-audit-"+firstNonEmpty(record.ID, record.ActivityDisplayName), "azure.directory_audit", "azure/directory_audit/v1", payload, attributes, occurredAt)
}

func credentialsFromApplications(records []applicationRecord) []credentialRecord {
	credentials := make([]credentialRecord, 0)
	for _, app := range records {
		ownerID := firstNonEmpty(app.AppID, app.ID)
		credentials = append(credentials, credentialsFromPasswords("application", ownerID, app.AppID, app.DisplayName, app.PasswordCredentials)...)
		credentials = append(credentials, credentialsFromKeys("application", ownerID, app.AppID, app.DisplayName, app.KeyCredentials)...)
	}
	return credentials
}

func credentialsFromServicePrincipals(records []servicePrincipalRecord) []credentialRecord {
	credentials := make([]credentialRecord, 0)
	for _, principal := range records {
		ownerID := firstNonEmpty(principal.ID, principal.AppID)
		credentials = append(credentials, credentialsFromPasswords("service_principal", ownerID, principal.AppID, principal.DisplayName, principal.PasswordCredentials)...)
		credentials = append(credentials, credentialsFromKeys("service_principal", ownerID, principal.AppID, principal.DisplayName, principal.KeyCredentials)...)
	}
	return credentials
}

func credentialsFromPasswords(ownerType string, ownerID string, appID string, ownerName string, passwords []passwordCredential) []credentialRecord {
	credentials := make([]credentialRecord, 0, len(passwords))
	for _, password := range passwords {
		credentialID := firstNonEmpty(password.KeyID, ownerID+":password")
		raw, _ := json.Marshal(map[string]any{"keyId": password.KeyID, "displayName": password.DisplayName, "startDateTime": password.StartDateTime, "endDateTime": password.EndDateTime, "hint": password.Hint})
		credentials = append(credentials, credentialRecord{OwnerType: ownerType, OwnerID: ownerID, OwnerAppID: appID, OwnerName: ownerName, CredentialID: credentialID, CredentialName: password.DisplayName, CredentialType: "azure_" + ownerType + "_password", StartTime: password.StartDateTime, EndTime: password.EndDateTime, raw: raw})
	}
	return credentials
}

func credentialsFromKeys(ownerType string, ownerID string, appID string, ownerName string, keys []keyCredential) []credentialRecord {
	credentials := make([]credentialRecord, 0, len(keys))
	for _, key := range keys {
		credentialID := firstNonEmpty(key.KeyID, ownerID+":key")
		raw, _ := json.Marshal(map[string]any{"keyId": key.KeyID, "displayName": key.DisplayName, "startDateTime": key.StartDateTime, "endDateTime": key.EndDateTime, "type": key.Type, "usage": key.Usage})
		credentials = append(credentials, credentialRecord{OwnerType: ownerType, OwnerID: ownerID, OwnerAppID: appID, OwnerName: ownerName, CredentialID: credentialID, CredentialName: key.DisplayName, CredentialType: "azure_" + ownerType + "_key", StartTime: key.StartDateTime, EndTime: key.EndDateTime, raw: raw})
	}
	return credentials
}

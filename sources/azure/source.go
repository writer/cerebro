package azure

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultFamily             = familyDirectoryAudit
	defaultPageSize           = 10
	maxPageSize               = 200
	familyActivityLog         = "activity_log"
	familyAppRoleAssignment   = "app_role_assignment"
	familyApplication         = "application"
	familyCredential          = "credential"
	familyDirectoryAudit      = "directory_audit"
	familyDirectoryRoleAssign = "directory_role_assignment"
	familyGroup               = "group"
	familyGroupMember         = "group_membership"
	familyIAMRoleAssign       = "iam_role_assignment"
	familyResourceExposure    = "resource_exposure"
	familyServicePrincipal    = "service_principal"
	familyUser                = "user"
)

// Source reads Azure Entra ID inventory, Azure RBAC, and audit/activity logs.
type Source struct {
	spec     *cerebrov1.SourceSpec
	client   *http.Client
	families *sourcecdk.FamilyEngine[settings]
}

type settings struct {
	family             string
	tenantID           string
	subscriptionID     string
	groupID            string
	servicePrincipalID string
	token              string
	graphToken         string
	armToken           string
	baseURL            string
	graphBaseURL       string
	armBaseURL         string
	filter             string
	perPage            int
}

type graphPage struct {
	Value        []json.RawMessage `json:"value"`
	ODataNext    string            `json:"@odata.nextLink"`
	NextPageLink string            `json:"nextLink"`
}

type armPage struct {
	Value []json.RawMessage `json:"value"`
	Next  string            `json:"nextLink"`
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

type graphPrincipalRecord struct {
	ODataType         string   `json:"@odata.type"`
	ID                string   `json:"id"`
	UserPrincipalName string   `json:"userPrincipalName"`
	Mail              string   `json:"mail"`
	DisplayName       string   `json:"displayName"`
	AppID             string   `json:"appId"`
	ServiceNames      []string `json:"servicePrincipalNames"`
	raw               json.RawMessage
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

type armRoleAssignmentRecord struct {
	ID         string                `json:"id"`
	Name       string                `json:"name"`
	Type       string                `json:"type"`
	Properties armRoleAssignmentProp `json:"properties"`
	RoleName   string
	raw        json.RawMessage
}

type armRoleAssignmentProp struct {
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	Scope            string `json:"scope"`
	CreatedOn        string `json:"createdOn"`
	UpdatedOn        string `json:"updatedOn"`
}

type armRoleDefinitionRecord struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties armRoleDefinition `json:"properties"`
}

type armRoleDefinition struct {
	RoleName string `json:"roleName"`
	Type     string `json:"type"`
}

type nsgRecord struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Location   string        `json:"location"`
	Type       string        `json:"type"`
	Properties nsgProperties `json:"properties"`
	raw        json.RawMessage
}

type nsgProperties struct {
	SecurityRules        []nsgRule `json:"securityRules"`
	DefaultSecurityRules []nsgRule `json:"defaultSecurityRules"`
}

type nsgRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Properties nsgRuleProperties `json:"properties"`
}

type nsgRuleProperties struct {
	Access                   string `json:"access"`
	Direction                string `json:"direction"`
	Protocol                 string `json:"protocol"`
	SourceAddressPrefix      string `json:"sourceAddressPrefix"`
	SourcePortRange          string `json:"sourcePortRange"`
	DestinationPortRange     string `json:"destinationPortRange"`
	DestinationAddressPrefix string `json:"destinationAddressPrefix"`
	Priority                 int    `json:"priority"`
}

type azureResourceExposure struct {
	NetworkSecurityGroup nsgRecord
	Rule                 nsgRule
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

type activityLogRecord struct {
	ID                string         `json:"id"`
	EventTimestamp    string         `json:"eventTimestamp"`
	Caller            string         `json:"caller"`
	ResourceID        string         `json:"resourceId"`
	ResourceGroupName string         `json:"resourceGroupName"`
	OperationName     localizedValue `json:"operationName"`
	ResourceProvider  localizedValue `json:"resourceProviderName"`
	Category          localizedValue `json:"category"`
	Authorization     activityAuth   `json:"authorization"`
	SubscriptionID    string         `json:"subscriptionId"`
	raw               json.RawMessage
}

type localizedValue struct {
	Value          string `json:"value"`
	LocalizedValue string `json:"localizedValue"`
}

type activityAuth struct {
	Action string `json:"action"`
	Scope  string `json:"scope"`
}

type azureFamilyOptions[T any] struct {
	Name     string
	Label    string
	List     func(context.Context, *Source, settings, string, int) ([]T, string, error)
	Event    func(settings, T) (*primitives.Event, error)
	URN      func(settings, T) (string, error)
	Discover func(context.Context, *Source, settings) ([]sourcecdk.URN, error)
}

// New constructs the live Azure source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, client: &http.Client{Timeout: 30 * time.Second}}
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

// Spec returns static source metadata.
func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that the configured Azure family is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

// Discover returns Azure resource URNs for the configured family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

// Read returns one page of normalized Azure events.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family },
		azureFamily(s, azureFamilyOptions[activityLogRecord]{
			Name:  familyActivityLog,
			Label: "azure activity logs",
			List:  listActivityLogs,
			Event: activityLogEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := azureCheck(ctx, source, settings, listActivityLogs, "azure activity logs"); err != nil {
					return nil, err
				}
				return parseAzureURNs(fmt.Sprintf("urn:cerebro:%s:azure_subscription:%s", tenantID(settings), settings.subscriptionID))
			},
		}),
		azureFamily(s, azureFamilyOptions[appRoleAssignmentRecord]{
			Name:  familyAppRoleAssignment,
			Label: "azure app role assignments",
			List:  listAppRoleAssignments,
			Event: appRoleAssignmentEvent,
			URN: func(settings settings, assignment appRoleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_app_role_assignment:%s", tenantID(settings), firstNonEmpty(assignment.ID, assignment.PrincipalID+":"+assignment.AppRoleID)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[applicationRecord]{
			Name:  familyApplication,
			Label: "azure applications",
			List:  listApplications,
			Event: applicationEvent,
			URN: func(settings settings, app applicationRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_application:%s", tenantID(settings), firstNonEmpty(app.AppID, app.ID)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[credentialRecord]{
			Name:  familyCredential,
			Label: "azure application and service principal credentials",
			List:  listCredentials,
			Event: credentialEvent,
			URN: func(settings settings, credential credentialRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_credential:%s", tenantID(settings), firstNonEmpty(credential.CredentialID, credential.OwnerID)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[directoryAuditRecord]{
			Name:  familyDirectoryAudit,
			Label: "azure directory audits",
			List:  listDirectoryAudits,
			Event: directoryAuditEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := azureCheck(ctx, source, settings, listDirectoryAudits, "azure directory audits"); err != nil {
					return nil, err
				}
				return parseAzureURNs(fmt.Sprintf("urn:cerebro:%s:azure_tenant:%s", tenantID(settings), tenantID(settings)))
			},
		}),
		azureFamily(s, azureFamilyOptions[directoryRoleAssignmentRecord]{
			Name:  familyDirectoryRoleAssign,
			Label: "azure directory role assignments",
			List:  listDirectoryRoleAssignments,
			Event: directoryRoleAssignmentEvent,
			URN: func(settings settings, assignment directoryRoleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_directory_role_assignment:%s", tenantID(settings), firstNonEmpty(assignment.ID, assignment.PrincipalID+":"+assignment.RoleDefinitionID)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[groupRecord]{
			Name:  familyGroup,
			Label: "azure groups",
			List:  listGroups,
			Event: groupEvent,
			URN: func(settings settings, group groupRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_group:%s", tenantID(settings), firstNonEmpty(group.ID, group.Mail)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[graphPrincipalRecord]{
			Name:  familyGroupMember,
			Label: "azure group memberships",
			List:  listGroupMemberships,
			Event: groupMembershipEvent,
			URN: func(settings settings, member graphPrincipalRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_group_membership:%s:%s", tenantID(settings), settings.groupID, firstNonEmpty(member.ID, member.UserPrincipalName, member.Mail)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armRoleAssignmentRecord]{
			Name:  familyIAMRoleAssign,
			Label: "azure rbac role assignments",
			List:  listIAMRoleAssignments,
			Event: iamRoleAssignmentEvent,
			URN: func(settings settings, assignment armRoleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_iam_role_assignment:%s", tenantID(settings), firstNonEmpty(assignment.ID, assignment.Name)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[azureResourceExposure]{
			Name:  familyResourceExposure,
			Label: "azure resource exposures",
			List:  listResourceExposures,
			Event: resourceExposureEvent,
			URN: func(settings settings, exposure azureResourceExposure) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_resource_exposure:%s", tenantID(settings), firstNonEmpty(exposure.Rule.ID, exposure.Rule.Name)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[servicePrincipalRecord]{
			Name:  familyServicePrincipal,
			Label: "azure service principals",
			List:  listServicePrincipals,
			Event: servicePrincipalEvent,
			URN: func(settings settings, principal servicePrincipalRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_service_principal:%s", tenantID(settings), firstNonEmpty(principal.ID, principal.AppID)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[userRecord]{
			Name:  familyUser,
			Label: "azure users",
			List:  listUsers,
			Event: userEvent,
			URN: func(settings settings, user userRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_user:%s", tenantID(settings), firstNonEmpty(user.ID, user.UserPrincipalName, user.Mail)), nil
			},
		}),
	)
}

func azureFamily[T any](source *Source, options azureFamilyOptions[T]) sourcecdk.Family[settings] {
	return sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			return azureCheck(ctx, source, settings, options.List, options.Label)
		},
		Discover: func(ctx context.Context, settings settings) ([]sourcecdk.URN, error) {
			if options.Discover != nil {
				return options.Discover(ctx, source, settings)
			}
			records, _, err := options.List(ctx, source, settings, "", settings.perPage)
			if err != nil {
				return nil, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			return azureURNsFor(settings, records, options.URN)
		},
		Read: func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
			records, next, err := options.List(ctx, source, settings, strings.TrimSpace(cursor.GetOpaque()), settings.perPage)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return azurePullFromRecords(records, next, build)
		},
	}
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:             configValue(cfg, "family"),
		tenantID:           configValue(cfg, "tenant_id"),
		subscriptionID:     configValue(cfg, "subscription_id"),
		groupID:            configValue(cfg, "group_id"),
		servicePrincipalID: configValue(cfg, "service_principal_id"),
		token:              configValue(cfg, "token"),
		graphToken:         configValue(cfg, "graph_token"),
		armToken:           configValue(cfg, "arm_token"),
		baseURL:            strings.TrimRight(configValue(cfg, "base_url"), "/"),
		graphBaseURL:       strings.TrimRight(configValue(cfg, "graph_base_url"), "/"),
		armBaseURL:         strings.TrimRight(configValue(cfg, "arm_base_url"), "/"),
		filter:             configValue(cfg, "filter"),
		perPage:            defaultPageSize,
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse azure per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("azure per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	if settings.tenantID == "" {
		return settings, fmt.Errorf("azure tenant_id is required")
	}
	switch settings.family {
	case familyActivityLog, familyIAMRoleAssign, familyResourceExposure:
		if settings.subscriptionID == "" {
			return settings, fmt.Errorf("azure subscription_id is required when family=%q", settings.family)
		}
		if armToken(settings) == "" {
			return settings, fmt.Errorf("azure arm_token or token is required when family=%q", settings.family)
		}
	case familyApplication, familyCredential, familyDirectoryAudit, familyDirectoryRoleAssign, familyGroup, familyServicePrincipal, familyUser:
		if graphToken(settings) == "" {
			return settings, fmt.Errorf("azure graph_token or token is required when family=%q", settings.family)
		}
	case familyGroupMember:
		if settings.groupID == "" {
			return settings, fmt.Errorf("azure group_id is required when family=%q", familyGroupMember)
		}
		if graphToken(settings) == "" {
			return settings, fmt.Errorf("azure graph_token or token is required when family=%q", settings.family)
		}
	case familyAppRoleAssignment:
		if settings.servicePrincipalID == "" {
			return settings, fmt.Errorf("azure service_principal_id is required when family=%q", familyAppRoleAssignment)
		}
		if graphToken(settings) == "" {
			return settings, fmt.Errorf("azure graph_token or token is required when family=%q", settings.family)
		}
	default:
		return settings, fmt.Errorf("azure family must be one of activity_log, app_role_assignment, application, credential, directory_audit, directory_role_assignment, group, group_membership, iam_role_assignment, resource_exposure, service_principal, or user")
	}
	return settings, nil
}

func listUsers(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]userRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/users"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure user", func(record *userRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, graphNext(response), err
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/groups"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure group", func(record *groupRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	return records, graphNext(response), err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]graphPrincipalRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	path := "/v1.0/groups/" + url.PathEscape(settings.groupID) + "/members"
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure group member", func(record *graphPrincipalRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listAppRoleAssignments(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]appRoleAssignmentRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	path := "/v1.0/servicePrincipals/" + url.PathEscape(settings.servicePrincipalID) + "/appRoleAssignedTo"
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure app role assignment", func(record *appRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listApplications(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]applicationRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/applications"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure application", func(record *applicationRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listServicePrincipals(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]servicePrincipalRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/servicePrincipals"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure service principal", func(record *servicePrincipalRecord, raw json.RawMessage) {
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
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/roleManagement/directory/roleAssignments"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure directory role assignment", func(record *directoryRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listDirectoryAudits(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]directoryAuditRecord, string, error) {
	query := graphListQuery(settings, limit)
	var response graphPage
	if err := getGraphJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, "/v1.0/auditLogs/directoryAudits"), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure directory audit", func(record *directoryAuditRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, graphNext(response), err
}

func listIAMRoleAssignments(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]armRoleAssignmentRecord, string, error) {
	query := url.Values{"api-version": {"2022-04-01"}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/Microsoft.Authorization/roleAssignments"
	if err := getARMJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure rbac role assignment", func(record *armRoleAssignmentRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	for i := range records {
		records[i].RoleName = firstNonEmpty(records[i].RoleName, resolveARMRoleName(ctx, source, settings, records[i].Properties.RoleDefinitionID))
	}
	return records, response.Next, nil
}

func listResourceExposures(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]azureResourceExposure, string, error) {
	query := url.Values{"api-version": {"2023-09-01"}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/Microsoft.Network/networkSecurityGroups"
	if err := getARMJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	nsgs, err := decodeAzureRecords(response.Value, "azure network security group", func(record *nsgRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
	if err != nil {
		return nil, "", err
	}
	exposures := make([]azureResourceExposure, 0)
	for _, nsg := range nsgs {
		for _, rule := range append(nsg.Properties.SecurityRules, nsg.Properties.DefaultSecurityRules...) {
			if nsgRulePublicIngress(rule) {
				exposures = append(exposures, azureResourceExposure{NetworkSecurityGroup: nsg, Rule: rule})
			}
		}
	}
	return exposures, response.Next, nil
}

func listActivityLogs(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]activityLogRecord, string, error) {
	query := url.Values{"api-version": {"2015-04-01"}}
	if settings.filter != "" {
		query.Set("$filter", settings.filter)
	}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/microsoft.insights/eventtypes/management/values"
	if err := getARMJSON(ctx, source, settings, http.MethodGet, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), nil, &response); err != nil {
		return nil, "", err
	}
	records, err := decodeAzureRecords(response.Value, "azure activity log", func(record *activityLogRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.Next, err
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
	attributes := map[string]string{
		"domain":       tenantID(settings),
		"family":       familyAppRoleAssignment,
		"is_admin":     "true",
		"path_type":    "app_role_assignment",
		"relationship": "assigned_to",
		"role_id":      record.AppRoleID,
		"role_name":    record.AppRoleID,
		"role_type":    "azure_app_role",
		"subject_id":   record.PrincipalID,
		"subject_name": record.PrincipalDisplayName,
		"subject_type": subjectType,
		"target_id":    firstNonEmpty(record.ResourceID, settings.servicePrincipalID),
		"target_name":  record.ResourceDisplayName,
		"target_type":  "service_principal",
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

func iamRoleAssignmentEvent(settings settings, record armRoleAssignmentRecord) (*primitives.Event, error) {
	roleName := firstNonEmpty(record.RoleName, record.Properties.RoleDefinitionID)
	attributes := map[string]string{
		"domain":             tenantID(settings),
		"family":             familyIAMRoleAssign,
		"is_admin":           boolString(isAdminRole(roleName)),
		"role_assignment_id": firstNonEmpty(record.ID, record.Name),
		"role_id":            firstNonEmpty(record.Properties.RoleDefinitionID, roleName),
		"role_name":          roleName,
		"role_type":          "azure_rbac_role",
		"scope":              record.Properties.Scope,
		"subject_id":         record.Properties.PrincipalID,
		"subject_type":       azurePrincipalType(record.Properties.PrincipalType, graphPrincipalRecord{}),
		"subscription_id":    settings.subscriptionID,
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"subscription_id": settings.subscriptionID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-iam-role-assignment-"+firstNonEmpty(record.Name, record.ID), "azure.iam_role_assignment", "azure/iam_role_assignment/v1", payload, attributes, time.Now().UTC())
}

func resourceExposureEvent(settings settings, record azureResourceExposure) (*primitives.Event, error) {
	rule := record.Rule
	nsg := record.NetworkSecurityGroup
	resourceID := firstNonEmpty(nsg.ID, nsg.Name)
	ruleID := firstNonEmpty(rule.ID, rule.Name)
	attributes := map[string]string{
		"action":            strings.ToLower(rule.Properties.Access),
		"direction":         strings.ToLower(rule.Properties.Direction),
		"domain":            tenantID(settings),
		"exposed_to":        "public_internet",
		"exposure_id":       ruleID,
		"exposure_type":     "public_network_ingress",
		"external_exposure": "true",
		"family":            familyResourceExposure,
		"internet_exposed":  "true",
		"location":          nsg.Location,
		"port_range":        firstNonEmpty(rule.Properties.DestinationPortRange, "all"),
		"protocol":          rule.Properties.Protocol,
		"public":            "true",
		"resource_id":       resourceID,
		"resource_name":     firstNonEmpty(nsg.Name, resourceID),
		"resource_provider": "azure",
		"resource_type":     "network_security_group",
		"rule_id":           ruleID,
		"rule_name":         rule.Name,
		"scope":             settings.subscriptionID,
		"source_cidr":       rule.Properties.SourceAddressPrefix,
		"subscription_id":   settings.subscriptionID,
	}
	payload, err := payloadWithRaw(nsg.raw, map[string]any{"subscription_id": settings.subscriptionID, "rule": rule})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, "azure-resource-exposure-"+firstNonEmpty(ruleID, resourceID), "azure.resource_exposure", "azure/resource_exposure/v1", payload, attributes, time.Now().UTC())
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

func activityLogEvent(settings settings, record activityLogRecord) (*primitives.Event, error) {
	resourceID := firstNonEmpty(record.ResourceID, record.Authorization.Scope, settings.subscriptionID)
	attributes := map[string]string{
		"actor_alternate_id": record.Caller,
		"actor_email":        emailLike(record.Caller),
		"actor_id":           record.Caller,
		"domain":             tenantID(settings),
		"event_name":         firstNonEmpty(record.OperationName.Value, record.OperationName.LocalizedValue, record.Authorization.Action),
		"event_type":         firstNonEmpty(record.Authorization.Action, record.OperationName.Value, record.OperationName.LocalizedValue),
		"family":             familyActivityLog,
		"resource_id":        resourceID,
		"resource_name":      resourceID,
		"resource_group":     record.ResourceGroupName,
		"resource_type":      firstNonEmpty(record.ResourceProvider.Value, record.Category.Value, "azure_resource"),
		"scope":              record.Authorization.Scope,
		"subscription_id":    firstNonEmpty(record.SubscriptionID, settings.subscriptionID),
	}
	payload, err := payloadWithRaw(record.raw, map[string]any{"subscription_id": settings.subscriptionID})
	if err != nil {
		return nil, err
	}
	occurredAt := time.Now().UTC()
	if record.EventTimestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, record.EventTimestamp); err == nil {
			occurredAt = parsed.UTC()
		}
	}
	return sourceEvent(settings, "azure-activity-log-"+firstNonEmpty(record.ID, record.OperationName.Value), "azure.activity_log", "azure/activity_log/v1", payload, attributes, occurredAt)
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: tenantID(settings), SourceId: "azure", Kind: kind, OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: schemaRef, Payload: payload, Attributes: attributes}, nil
}

func getGraphJSON(ctx context.Context, source *Source, settings settings, method string, requestPath string, query url.Values, body any, target any) error {
	return getJSON(ctx, source, graphBaseURL(settings), graphToken(settings), method, requestPath, query, body, target)
}

func getARMJSON(ctx context.Context, source *Source, settings settings, method string, requestPath string, query url.Values, body any, target any) error {
	return getJSON(ctx, source, armBaseURL(settings), armToken(settings), method, requestPath, query, body, target)
}

func getJSON(ctx context.Context, source *Source, baseURL string, token string, method string, requestPath string, query url.Values, body any, target any) error {
	endpoint := requestPath
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimRight(baseURL, "/") + requestPath
	}
	if encoded := query.Encode(); encoded != "" {
		separator := "?"
		if strings.Contains(endpoint, "?") {
			separator = "&"
		}
		endpoint += separator + encoded
	}
	var requestBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s request: %w", requestPath, err)
		}
		requestBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, requestBody)
	if err != nil {
		return fmt.Errorf("build request %s: %w", requestPath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := http.DefaultClient
	if source != nil && source.client != nil {
		client = source.client
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", requestPath, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("azure API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(content)))
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func decodeAzureRecords[T any](rawRecords []json.RawMessage, label string, setRaw func(*T, json.RawMessage)) ([]T, error) {
	records := make([]T, 0, len(rawRecords))
	for _, raw := range rawRecords {
		var record T
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, raw)
		}
		records = append(records, record)
	}
	return records, nil
}

func azurePullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error)) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		if next == "" {
			return sourcecdk.Pull{}, nil
		}
		return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: events[len(events)-1].OccurredAt, CursorOpaque: firstNonEmpty(next, events[len(events)-1].GetId())}}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func azureCheck[T any](ctx context.Context, source *Source, settings settings, list func(context.Context, *Source, settings, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, source, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, tenantID(settings), err)
	}
	return nil
}

func azureURNsFor[T any](settings settings, records []T, render func(settings, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return parseAzureURNs(values...)
}

func parseAzureURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func payloadWithRaw(raw json.RawMessage, values map[string]any) ([]byte, error) {
	payload := map[string]any{}
	for key, value := range values {
		payload[key] = value
	}
	if len(raw) != 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, err
		}
		payload["raw"] = decoded
	}
	return json.Marshal(payload)
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

func resolveARMRoleName(ctx context.Context, source *Source, settings settings, roleDefinitionID string) string {
	if strings.TrimSpace(roleDefinitionID) == "" {
		return ""
	}
	path := roleDefinitionID
	if strings.HasPrefix(path, armBaseURL(settings)) {
		path = strings.TrimPrefix(path, armBaseURL(settings))
	}
	query := url.Values{"api-version": {"2022-04-01"}}
	var record armRoleDefinitionRecord
	if err := getARMJSON(ctx, source, settings, http.MethodGet, path, query, nil, &record); err != nil {
		return ""
	}
	return record.Properties.RoleName
}

func graphListQuery(settings settings, limit int) url.Values {
	query := url.Values{"$top": {strconv.Itoa(limit)}}
	addQuery(query, "$filter", settings.filter)
	return query
}

func queryForPageToken(pageToken string, query url.Values) url.Values {
	if strings.TrimSpace(pageToken) != "" {
		return nil
	}
	return query
}

func graphNext(response graphPage) string {
	return firstNonEmpty(response.ODataNext, response.NextPageLink)
}

func prefixedNext(prefix string, next string) string {
	if strings.TrimSpace(next) == "" {
		return ""
	}
	return prefix + ":" + next
}

func graphToken(settings settings) string {
	return firstNonEmpty(settings.graphToken, settings.token)
}

func armToken(settings settings) string {
	return firstNonEmpty(settings.armToken, settings.token)
}

func graphBaseURL(settings settings) string {
	return firstNonEmpty(settings.graphBaseURL, settings.baseURL, "https://graph.microsoft.com")
}

func armBaseURL(settings settings) string {
	return firstNonEmpty(settings.armBaseURL, settings.baseURL, "https://management.azure.com")
}

func tenantID(settings settings) string {
	return settings.tenantID
}

func azurePrincipalType(raw string, record graphPrincipalRecord) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(value, "#microsoft.graph.")
	switch {
	case strings.Contains(value, "serviceprincipal") || strings.Contains(value, "service_principal") || strings.EqualFold(raw, "ServicePrincipal") || strings.TrimSpace(record.AppID) != "":
		return "service_principal"
	case strings.Contains(value, "group") || strings.EqualFold(raw, "Group"):
		return "group"
	case strings.Contains(value, "application") || strings.EqualFold(raw, "Application"):
		return "application"
	case strings.Contains(value, "user") || strings.EqualFold(raw, "User"):
		return "user"
	default:
		return "user"
	}
}

func isAdminRole(value string) bool {
	role := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	return strings.Contains(role, "globaladministrator") ||
		strings.Contains(role, "privilegedroleadministrator") ||
		strings.Contains(role, "applicationadministrator") ||
		strings.Contains(role, "cloudapplicationadministrator") ||
		strings.Contains(role, "authenticationadministrator") ||
		strings.Contains(role, "useraccessadministrator") ||
		strings.Contains(role, "owner") ||
		strings.Contains(role, "contributor") ||
		strings.Contains(role, "admin")
}

func nsgRulePublicIngress(rule nsgRule) bool {
	return strings.EqualFold(rule.Properties.Access, "Allow") &&
		strings.EqualFold(rule.Properties.Direction, "Inbound") &&
		azurePublicSource(rule.Properties.SourceAddressPrefix)
}

func azurePublicSource(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "*" ||
		strings.EqualFold(trimmed, "Internet") ||
		trimmed == "0.0.0.0/0" ||
		trimmed == "::/0"
}

func enabledStatus(value *bool) string {
	if value == nil || *value {
		return "ACTIVE"
	}
	return "DISABLED"
}

func boolPointerString(value *bool) string {
	if value == nil {
		return ""
	}
	return boolString(*value)
}

func credentialStatus(endTime string) string {
	if strings.TrimSpace(endTime) == "" {
		return "ACTIVE"
	}
	parsed, err := time.Parse(time.RFC3339Nano, endTime)
	if err != nil || parsed.After(time.Now().UTC()) {
		return "ACTIVE"
	}
	return "EXPIRED"
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func addQuery(query url.Values, key string, value string) {
	if strings.TrimSpace(value) != "" {
		query.Set(key, strings.TrimSpace(value))
	}
}

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
}

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
}

func sanitizeEventID(value string) string {
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	return strings.Trim(value, "-")
}

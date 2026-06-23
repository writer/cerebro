package azure

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/azurearm"
	"github.com/writer/cerebro/sources/internal/textutil"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultFamily             = familyDirectoryAudit
	defaultPageSize           = 10
	azureCheckpointLookback   = 2 * time.Minute
	maxPageSize               = 200
	familyActivityLog         = "activity_log"
	familyAuthorizationPolicy = "authorization_policy"
	familyAppRoleAssignment   = "app_role_assignment"
	familyApplication         = "application"
	familyAssetMetadata       = "asset_metadata"
	familyAKSCluster          = "aks_cluster"
	familyAKSNodePool         = "aks_node_pool"
	familyAppService          = "app_service"
	familyContainerRegistry   = "container_registry"
	familyCosmosAccount       = "cosmos_account"
	familyCredential          = "credential"
	familyDirectoryAudit      = "directory_audit"
	familyDirectoryRoleAssign = "directory_role_assignment"
	familyEffectivePermission = "effective_permission"
	familyFunctionApp         = "function_app"
	familyGroup               = "group"
	familyGroupMember         = "group_membership"
	familyIAMRoleAssign       = "iam_role_assignment"
	familyKeyVault            = "key_vault"
	familyKeyVaultKey         = "key_vault_key"
	familyKeyVaultSecret      = "key_vault_secret"
	familyMySQLServer         = "mysql_server"
	familyManagedDisk         = "managed_disk"
	familyNetworkSecurityGrp  = "network_security_group"
	familyPublicIPAddress     = "public_ip_address"
	familyResourceExposure    = "resource_exposure"
	familyServicePrincipal    = "service_principal"
	familySQLDatabase         = "sql_database"
	familySQLServer           = "sql_server"
	familyStorageAccount      = "storage_account"
	familyStorageContainer    = "storage_container"
	familyStorageQueue        = "storage_queue"
	familySubnet              = "subnet"
	familyUser                = "user"
	familyVirtualMachine      = "virtual_machine"
	familyVirtualNetwork      = "virtual_network"
)

var azureARMChildDefinitions = []azureARMChildDefinition{
	{Name: familyAKSNodePool, Label: "azure aks node pools", ParentProvider: "Microsoft.ContainerService/managedClusters", ParentAPIVersion: "2024-05-01", ChildPath: "agentPools", ChildAPIVersion: "2024-05-01", Kind: "azure.aks_node_pool", SchemaRef: "azure/aks_node_pool/v1"},
	{Name: "cognitive_services_deployment", Label: "azure cognitive services deployments", ParentProvider: "Microsoft.CognitiveServices/accounts", ParentAPIVersion: "2023-05-01", ChildPath: "deployments", ChildAPIVersion: "2023-05-01", Kind: "azure.cognitive_services_deployment", SchemaRef: "azure/cognitive_services_deployment/v1"},
	{Name: "cosmos_postgresql_firewall_rule", Label: "azure cosmos db for postgresql firewall rules", ParentProvider: "Microsoft.DBforPostgreSQL/serverGroupsv2", ParentAPIVersion: "2023-03-02-preview", ChildPath: "firewallRules", ChildAPIVersion: "2023-03-02-preview", Kind: "azure.cosmos_postgresql_firewall_rule", SchemaRef: "azure/cosmos_postgresql_firewall_rule/v1"},
	{Name: "diagnostic_setting_resource", Label: "azure resource diagnostic settings", ParentProvider: "", ParentAPIVersion: "2021-04-01", ChildPath: "providers/Microsoft.Insights/diagnosticSettings", ChildAPIVersion: "2021-05-01-preview", Kind: "azure.diagnostic_setting_resource", SchemaRef: "azure/diagnostic_setting_resource/v1", Optional: true},
	{Name: "machine_learning_compute", Label: "azure machine learning computes", ParentProvider: "Microsoft.MachineLearningServices/workspaces", ParentAPIVersion: "2024-04-01", ChildPath: "computes", ChildAPIVersion: "2024-04-01", Kind: "azure.machine_learning_compute", SchemaRef: "azure/machine_learning_compute/v1"},
	{Name: "postgresql_firewall_rule", Label: "azure postgresql firewall rules", ParentProvider: "Microsoft.DBforPostgreSQL/flexibleServers", ParentAPIVersion: "2023-06-01-preview", ChildPath: "firewallRules", ChildAPIVersion: "2023-06-01-preview", Kind: "azure.postgresql_firewall_rule", SchemaRef: "azure/postgresql_firewall_rule/v1"},
	{Name: "server_vulnerability_subassessment", Label: "azure security subassessments", ParentProvider: "Microsoft.Security/assessments", ParentAPIVersion: "2020-01-01", ChildPath: "subAssessments", ChildAPIVersion: "2019-01-01-preview", Kind: "azure.server_vulnerability_subassessment", SchemaRef: "azure/server_vulnerability_subassessment/v1"},
	{Name: "sql_managed_instance_tde", Label: "azure sql managed instance encryption protectors", ParentProvider: "Microsoft.Sql/managedInstances", ParentAPIVersion: "2022-05-01-preview", ChildPath: "encryptionProtector/current", ChildAPIVersion: "2022-05-01-preview", Kind: "azure.sql_managed_instance_tde", SchemaRef: "azure/sql_managed_instance_tde/v1", Singleton: true},
	{Name: familyStorageContainer, Label: "azure storage containers", ParentProvider: "Microsoft.Storage/storageAccounts", ParentAPIVersion: "2023-01-01", ChildPath: "blobServices/default/containers", ChildAPIVersion: "2023-01-01", Kind: "azure.storage_container", SchemaRef: "azure/storage_container/v1"},
	{Name: familyStorageQueue, Label: "azure storage queues", ParentProvider: "Microsoft.Storage/storageAccounts", ParentAPIVersion: "2023-01-01", ChildPath: "queueServices/default/queues", ChildAPIVersion: "2023-01-01", Kind: "azure.storage_queue", SchemaRef: "azure/storage_queue/v1"},
	{Name: "synapse_sql_pool", Label: "azure synapse sql pools", ParentProvider: "Microsoft.Synapse/workspaces", ParentAPIVersion: "2021-06-01", ChildPath: "sqlPools", ChildAPIVersion: "2021-06-01", Kind: "azure.synapse_sql_pool", SchemaRef: "azure/synapse_sql_pool/v1"},
	{Name: "virtual_machine_extension", Label: "azure virtual machine extensions", ParentProvider: "Microsoft.Compute/virtualMachines", ParentAPIVersion: "2024-07-01", ChildPath: "extensions", ChildAPIVersion: "2024-07-01", Kind: "azure.virtual_machine_extension", SchemaRef: "azure/virtual_machine_extension/v1"},
	{Name: "virtual_machine_scale_set_instance", Label: "azure virtual machine scale set instances", ParentProvider: "Microsoft.Compute/virtualMachineScaleSets", ParentAPIVersion: "2024-07-01", ChildPath: "virtualMachines", ChildAPIVersion: "2024-07-01", Kind: "azure.virtual_machine_scale_set_instance", SchemaRef: "azure/virtual_machine_scale_set_instance/v1"},
}

// Source reads Azure Entra ID inventory, Azure RBAC, and audit/activity logs.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	families             *sourcecdk.FamilyEngine[settings]
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
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

type armTypedResourceRecord struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Type       string              `json:"type"`
	Kind       string              `json:"kind"`
	Location   string              `json:"location"`
	Tags       map[string]string   `json:"tags"`
	Identity   armResourceIdentity `json:"identity"`
	SKU        armResourceSKU      `json:"sku"`
	HTTPSOnly  *bool               `json:"httpsOnly"`
	Properties map[string]any      `json:"properties"`
	raw        json.RawMessage
}

type armResourceIdentity struct {
	Type                   string                             `json:"type"`
	PrincipalID            string                             `json:"principalId"`
	TenantID               string                             `json:"tenantId"`
	UserAssignedIdentities map[string]armUserAssignedIdentity `json:"userAssignedIdentities"`
}

type armUserAssignedIdentity struct {
	PrincipalID string `json:"principalId"`
	ClientID    string `json:"clientId"`
}

type armResourceSKU struct {
	Name string `json:"name"`
	Tier string `json:"tier"`
}

type azureSQLDatabaseRecord struct {
	Database armTypedResourceRecord
	Server   armTypedResourceRecord
}

type azureKeyVaultChildRecord struct {
	Resource armTypedResourceRecord
	Vault    armTypedResourceRecord
}

type azureARMChildDefinition struct {
	Name             string
	Label            string
	ParentProvider   string
	ParentAPIVersion string
	ChildPath        string
	ChildAPIVersion  string
	Kind             string
	SchemaRef        string
	Optional         bool
	Singleton        bool
}

type azureARMChildRecord struct {
	Resource armTypedResourceRecord
	Parent   armTypedResourceRecord
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
	Name               string
	Label              string
	List               func(context.Context, *Source, settings, string, int) ([]T, string, error)
	ListWithCheckpoint func(context.Context, *Source, settings, string, int, *cerebrov1.SourceCheckpoint) ([]T, string, error)
	Check              func(context.Context, *Source, settings, string, int) ([]T, string, error)
	Event              func(settings, T) (*primitives.Event, error)
	URN                func(settings, T) (string, error)
	Discover           func(context.Context, *Source, settings) ([]sourcecdk.URN, error)
}

// New constructs the live Azure source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	source := &Source{spec: spec, lookupIPAddrs: net.DefaultResolver.LookupIPAddr}
	source.client = source.safeClient()
	source.families, err = source.newFamilyEngine()
	if err != nil {
		return nil, err
	}
	return source, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func (s *Source) Spec() *cerebrov1.SourceSpec { return s.spec }

func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	return s.families.Check(ctx, cfg)
}

func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	return s.families.Discover(ctx, cfg)
}

func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.families.Read(ctx, cfg, cursor)
}

// ReadWithCheckpoint lets Azure audit families apply provider-side watermark filters and stop once they reach the durable runtime watermark.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	return s.families.ReadWithCheckpoint(ctx, cfg, cursor, checkpoint)
}

func (s *Source) newFamilyEngine() (*sourcecdk.FamilyEngine[settings], error) {
	families := []sourcecdk.Family[settings]{
		azureFamily(s, azureFamilyOptions[activityLogRecord]{
			Name:               familyActivityLog,
			Label:              "azure activity logs",
			List:               listActivityLogs,
			ListWithCheckpoint: listActivityLogsWithCheckpoint,
			Event:              activityLogEvent,
			Discover: func(ctx context.Context, source *Source, settings settings) ([]sourcecdk.URN, error) {
				if err := azureCheck(ctx, source, settings, listActivityLogs, "azure activity logs"); err != nil {
					return nil, err
				}
				return parseAzureURNs(fmt.Sprintf("urn:cerebro:%s:azure_subscription:%s", tenantID(settings), settings.subscriptionID))
			},
		}),
		azureFamily(s, azureFamilyOptions[authorizationPolicyRecord]{
			Name:  familyAuthorizationPolicy,
			Label: "azure authorization policy",
			List:  listAuthorizationPolicy,
			Event: authorizationPolicyEvent,
			URN: func(settings settings, policy authorizationPolicyRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_authorization_policy:%s", tenantID(settings), firstNonEmpty(policy.ID, "authorizationPolicy")), nil
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
		azureFamily(s, azureFamilyOptions[armResourceRecord]{
			Name:  familyAssetMetadata,
			Label: "azure asset metadata",
			List:  listAssetMetadata,
			Event: assetMetadataEvent,
			URN: func(settings settings, asset armResourceRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_asset_metadata:%s", tenantID(settings), firstNonEmpty(asset.ID, asset.Name)), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyAKSCluster,
			Label: "azure aks clusters",
			List:  listAKSClusters,
			Event: aksClusterEvent,
			URN: func(settings settings, cluster armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyAKSCluster, cluster), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyAppService,
			Label: "azure app services",
			List:  listAppServices,
			Event: appServiceEvent,
			URN: func(settings settings, app armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyAppService, app), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyContainerRegistry,
			Label: "azure container registries",
			List:  listContainerRegistries,
			Event: containerRegistryEvent,
			URN: func(settings settings, registry armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyContainerRegistry, registry), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyCosmosAccount,
			Label: "azure cosmos db accounts",
			List:  listCosmosAccounts,
			Event: cosmosAccountEvent,
			URN: func(settings settings, account armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyCosmosAccount, account), nil
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
			Name:               familyDirectoryAudit,
			Label:              "azure directory audits",
			List:               listDirectoryAudits,
			ListWithCheckpoint: listDirectoryAuditsWithCheckpoint,
			Event:              directoryAuditEvent,
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
		azureFamily(s, azureFamilyOptions[armRoleAssignmentRecord]{
			Name:  familyEffectivePermission,
			Label: "azure effective permissions",
			List:  listIAMRoleAssignments,
			Check: listIAMRoleAssignmentsBase,
			Event: effectivePermissionEvent,
			URN: func(settings settings, assignment armRoleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_effective_permission:%s", tenantID(settings), firstNonEmpty(assignment.ID, assignment.Name)), nil
			},
			Discover: func(ctx context.Context, source *Source, cfg settings) ([]sourcecdk.URN, error) {
				records, _, err := listIAMRoleAssignmentsBase(ctx, source, cfg, "", cfg.perPage)
				if err != nil {
					return nil, fmt.Errorf("lookup azure effective permissions for %s: %w", tenantID(cfg), err)
				}
				return azureURNsFor(cfg, records, func(cfg settings, assignment armRoleAssignmentRecord) (string, error) {
					return fmt.Sprintf("urn:cerebro:%s:azure_effective_permission:%s", tenantID(cfg), firstNonEmpty(assignment.ID, assignment.Name)), nil
				})
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
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyFunctionApp,
			Label: "azure function apps",
			List:  listFunctionApps,
			Event: functionAppEvent,
			URN: func(settings settings, app armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyFunctionApp, app), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armRoleAssignmentRecord]{
			Name:  familyIAMRoleAssign,
			Label: "azure rbac role assignments",
			List:  listIAMRoleAssignments,
			Check: listIAMRoleAssignmentsBase,
			Event: iamRoleAssignmentEvent,
			URN: func(settings settings, assignment armRoleAssignmentRecord) (string, error) {
				return fmt.Sprintf("urn:cerebro:%s:azure_iam_role_assignment:%s", tenantID(settings), firstNonEmpty(assignment.ID, assignment.Name)), nil
			},
			Discover: func(ctx context.Context, source *Source, cfg settings) ([]sourcecdk.URN, error) {
				records, _, err := listIAMRoleAssignmentsBase(ctx, source, cfg, "", cfg.perPage)
				if err != nil {
					return nil, fmt.Errorf("lookup azure rbac role assignments for %s: %w", tenantID(cfg), err)
				}
				return azureURNsFor(cfg, records, func(cfg settings, assignment armRoleAssignmentRecord) (string, error) {
					return fmt.Sprintf("urn:cerebro:%s:azure_iam_role_assignment:%s", tenantID(cfg), firstNonEmpty(assignment.ID, assignment.Name)), nil
				})
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyKeyVault,
			Label: "azure key vaults",
			List:  listKeyVaults,
			Event: keyVaultEvent,
			URN: func(settings settings, vault armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyKeyVault, vault), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[azureKeyVaultChildRecord]{
			Name:  familyKeyVaultKey,
			Label: "azure key vault keys",
			List:  listKeyVaultKeys,
			Event: keyVaultKeyEvent,
			URN: func(settings settings, key azureKeyVaultChildRecord) (string, error) {
				return azureTypedResourceURN(settings, familyKeyVaultKey, key.Resource), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[azureKeyVaultChildRecord]{
			Name:  familyKeyVaultSecret,
			Label: "azure key vault secrets",
			List:  listKeyVaultSecrets,
			Event: keyVaultSecretEvent,
			URN: func(settings settings, secret azureKeyVaultChildRecord) (string, error) {
				return azureTypedResourceURN(settings, familyKeyVaultSecret, secret.Resource), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{Name: familyVirtualNetwork, Label: "azure virtual networks", List: listVirtualNetworks, Event: virtualNetworkEvent, URN: func(settings settings, network armTypedResourceRecord) (string, error) {
			return azureTypedResourceURN(settings, familyVirtualNetwork, network), nil
		}}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{Name: familyNetworkSecurityGrp, Label: "azure network security groups", List: listNetworkSecurityGroups, Event: networkSecurityGroupEvent, URN: func(settings settings, group armTypedResourceRecord) (string, error) {
			return azureTypedResourceURN(settings, familyNetworkSecurityGrp, group), nil
		}}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{Name: familyPublicIPAddress, Label: "azure public ip addresses", List: listPublicIPAddresses, Event: publicIPAddressEvent, URN: func(settings settings, address armTypedResourceRecord) (string, error) {
			return azureTypedResourceURN(settings, familyPublicIPAddress, address), nil
		}}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{Name: familyManagedDisk, Label: "azure managed disks", List: listManagedDisks, Event: managedDiskEvent, URN: func(settings settings, disk armTypedResourceRecord) (string, error) {
			return azureTypedResourceURN(settings, familyManagedDisk, disk), nil
		}}),
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
		azureFamily(s, azureFamilyOptions[azureSQLDatabaseRecord]{
			Name:  familySQLDatabase,
			Label: "azure sql databases",
			List:  listSQLDatabases,
			Event: sqlDatabaseEvent,
			URN: func(settings settings, database azureSQLDatabaseRecord) (string, error) {
				return azureTypedResourceURN(settings, familySQLDatabase, database.Database), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familySQLServer,
			Label: "azure sql servers",
			List:  listSQLServers,
			Event: sqlServerEvent,
			URN: func(settings settings, server armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familySQLServer, server), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyStorageAccount,
			Label: "azure storage accounts",
			List:  listStorageAccounts,
			Event: storageAccountEvent,
			URN: func(settings settings, account armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyStorageAccount, account), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familyMySQLServer,
			Label: "azure mysql flexible servers",
			List: func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
				return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.DBforMySQL/flexibleServers", "2023-06-30", "azure mysql flexible server")
			},
			Event: func(settings settings, server armTypedResourceRecord) (*primitives.Event, error) {
				return genericARMResourceEvent(settings, server, familyMySQLServer, "azure.mysql_server", "azure/mysql_server/v1")
			},
			URN: func(settings settings, server armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familyMySQLServer, server), nil
			},
		}),
		azureFamily(s, azureFamilyOptions[armTypedResourceRecord]{
			Name:  familySubnet,
			Label: "azure subnets",
			List:  listSubnets,
			Event: func(settings settings, subnet armTypedResourceRecord) (*primitives.Event, error) {
				return genericARMResourceEvent(settings, subnet, familySubnet, "azure.subnet", "azure/subnet/v1")
			},
			URN: func(settings settings, subnet armTypedResourceRecord) (string, error) {
				return azureTypedResourceURN(settings, familySubnet, subnet), nil
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
		azureFamily(s, azureFamilyOptions[azureVMRecord]{
			Name:  familyVirtualMachine,
			Label: "azure virtual machines",
			List:  listVirtualMachines,
			Event: virtualMachineEvent,
			URN: func(settings settings, vm azureVMRecord) (string, error) {
				return azureTypedResourceURN(settings, familyVirtualMachine, vm.Resource), nil
			},
		}),
	}
	for _, definition := range azureARMChildDefinitions {
		definition := definition
		families = append(families, azureFamily(s, azureFamilyOptions[azureARMChildRecord]{
			Name:  definition.Name,
			Label: definition.Label,
			List: func(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]azureARMChildRecord, string, error) {
				return listAzureARMChildResources(ctx, source, settings, pageToken, limit, definition)
			},
			Event: func(settings settings, record azureARMChildRecord) (*primitives.Event, error) {
				return azureARMChildResourceEvent(settings, record, definition)
			},
			URN: func(settings settings, record azureARMChildRecord) (string, error) {
				return azureTypedResourceURN(settings, definition.Name, record.Resource), nil
			},
		}))
	}
	families = append(families, azurearm.Families(s, func(settings settings) int { return settings.perPage }, func(ctx context.Context, source *Source, settings settings, pageToken string, limit int, definition azurearm.Definition) ([]armTypedResourceRecord, string, error) {
		return listARMTypedResources(ctx, source, settings, pageToken, definition.ProviderPath, definition.APIVersion, definition.Label)
	}, func(settings settings, record armTypedResourceRecord, definition azurearm.Definition) (*primitives.Event, error) {
		return genericARMResourceEvent(settings, record, definition.Name, definition.Kind, definition.SchemaRef)
	}, func(settings settings, record armTypedResourceRecord, definition azurearm.Definition) (string, error) {
		return azureTypedResourceURN(settings, definition.Name, record), nil
	})...)
	return sourcecdk.NewFamilyEngine(parseSettings, func(settings settings) string { return settings.family }, families...)
}

func azureFamily[T any](source *Source, options azureFamilyOptions[T]) sourcecdk.Family[settings] {
	family := sourcecdk.Family[settings]{
		Name: options.Name,
		Check: func(ctx context.Context, settings settings) error {
			checkList := options.List
			if options.Check != nil {
				checkList = options.Check
			}
			return azureCheck(ctx, source, settings, checkList, options.Label)
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
	if options.ListWithCheckpoint != nil {
		family.ReadWithCheckpoint = func(ctx context.Context, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
			readCheckpoint := sourcecdk.IncrementalCheckpointForCursor("azure", options.Name, cursor, checkpoint)
			records, next, err := options.ListWithCheckpoint(ctx, source, settings, sourcecdk.CursorToken(cursor), settings.perPage, readCheckpoint)
			if err != nil {
				return sourcecdk.Pull{}, fmt.Errorf("lookup %s for %s: %w", options.Label, tenantID(settings), err)
			}
			build := func(record T) (*primitives.Event, error) { return options.Event(settings, record) }
			return sourcecdk.IncrementalPullFromRecords("azure", options.Name, records, next, readCheckpoint, build)
		}
	}
	return family
}

func parseSettings(cfg sourcecdk.Config) (settings, error) {
	settings := settings{
		family:             sourcecdk.ConfigValue(cfg, "family"),
		tenantID:           sourcecdk.ConfigValue(cfg, "tenant_id"),
		subscriptionID:     sourcecdk.ConfigValue(cfg, "subscription_id"),
		groupID:            sourcecdk.ConfigValue(cfg, "group_id"),
		servicePrincipalID: sourcecdk.ConfigValue(cfg, "service_principal_id"),
		token:              sourcecdk.ConfigValue(cfg, "token"),
		graphToken:         sourcecdk.ConfigValue(cfg, "graph_token"),
		armToken:           sourcecdk.ConfigValue(cfg, "arm_token"),
		baseURL:            strings.TrimRight(sourcecdk.ConfigValue(cfg, "base_url"), "/"),
		graphBaseURL:       strings.TrimRight(sourcecdk.ConfigValue(cfg, "graph_base_url"), "/"),
		armBaseURL:         strings.TrimRight(sourcecdk.ConfigValue(cfg, "arm_base_url"), "/"),
		filter:             sourcecdk.ConfigValue(cfg, "filter"),
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
	case familyActivityLog, "activity_log_alert", familyAKSCluster, familyAKSNodePool, familyAppService, "application_container", "application_gateway", "application_insight", familyAssetMetadata, "cognitive_services_account", "cognitive_services_deployment", familyContainerRegistry, familyCosmosAccount, "cosmos_postgresql", "cosmos_postgresql_firewall_rule", "databricks_workspace", "defender_config", "diagnostic_setting", "diagnostic_setting_resource", familyEffectivePermission, familyFunctionApp, familyIAMRoleAssign, familyKeyVault, familyKeyVaultKey, familyKeyVaultSecret, "load_balancer", "log_alert", "machine_learning_compute", "machine_learning_workspace", familyManagedDisk, "metric_alert_rule", familyMySQLServer, familyNetworkSecurityGrp, "policy_assignment", "postgresql_firewall_rule", "postgresql_server", familyPublicIPAddress, familyResourceExposure, "role", "route_table", "security_contact", "security_setting", "server_vulnerability", "server_vulnerability_subassessment", familySQLDatabase, "sql_managed_instance", "sql_managed_instance_tde", "sql_server_on_virtual_machine", familySQLServer, familyStorageAccount, familyStorageContainer, familyStorageQueue, familySubnet, "synapse_sql_pool", familyVirtualMachine, "virtual_machine_extension", "virtual_machine_scale_set", "virtual_machine_scale_set_instance", familyVirtualNetwork:
		if settings.subscriptionID == "" {
			return settings, fmt.Errorf("azure subscription_id is required when family=%q", settings.family)
		}
		if armToken(settings) == "" {
			return settings, fmt.Errorf("azure arm_token or token is required when family=%q", settings.family)
		}
	case familyApplication, familyAuthorizationPolicy, familyCredential, familyDirectoryAudit, familyDirectoryRoleAssign, familyGroup, familyServicePrincipal, familyUser:
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
		return settings, fmt.Errorf("azure family must be one of activity_log, activity_log_alert, aks_cluster, app_role_assignment, app_service, application, application_container, application_gateway, application_insight, asset_metadata, cognitive_services_account, container_registry, cosmos_account, cosmos_postgresql, credential, databricks_workspace, defender_config, diagnostic_setting, directory_audit, directory_role_assignment, effective_permission, function_app, group, group_membership, iam_role_assignment, key_vault, key_vault_key, key_vault_secret, load_balancer, log_alert, machine_learning_workspace, managed_disk, metric_alert_rule, network_security_group, postgresql_server, public_ip_address, resource_exposure, role, route_table, security_contact, server_vulnerability, service_principal, sql_database, sql_managed_instance, sql_server, sql_server_on_virtual_machine, storage_account, subnet, user, virtual_machine, virtual_machine_scale_set, or virtual_network")
	}
	return settings, nil
}

func listManagedDisks(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Compute/disks", "2024-03-02", "azure managed disk")
}

func listAKSClusters(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.ContainerService/managedClusters", "2024-05-01", "azure aks cluster")
}

func listWebSites(ctx context.Context, source *Source, settings settings, pageToken string) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Web/sites", "2023-12-01", "azure web site")
}

func listAppServices(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	sites, next, err := listWebSites(ctx, source, settings, pageToken)
	if err != nil {
		return nil, "", err
	}
	filtered := make([]armTypedResourceRecord, 0, len(sites))
	for _, site := range sites {
		if !azureSiteIsFunctionApp(site) {
			filtered = append(filtered, site)
		}
	}
	return filtered, next, nil
}

func listFunctionApps(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	sites, next, err := listWebSites(ctx, source, settings, pageToken)
	if err != nil {
		return nil, "", err
	}
	filtered := make([]armTypedResourceRecord, 0, len(sites))
	for _, site := range sites {
		if azureSiteIsFunctionApp(site) {
			filtered = append(filtered, site)
		}
	}
	return filtered, next, nil
}

func listStorageAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Storage/storageAccounts", "2023-01-01", "azure storage account")
}

func listSQLServers(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.Sql/servers", "2022-05-01-preview", "azure sql server")
}

func listSQLDatabases(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]azureSQLDatabaseRecord, string, error) {
	if strings.HasPrefix(pageToken, "db:") {
		serverID, nextToken, ok := parseNestedPageToken(strings.TrimPrefix(pageToken, "db:"))
		if !ok {
			return nil, "", fmt.Errorf("invalid azure sql database cursor")
		}
		server, found := getARMTypedResourceByID(ctx, source, settings, serverID, "2022-05-01-preview")
		if !found {
			return nil, "", fmt.Errorf("lookup azure sql server %s", serverID)
		}
		return listSQLDatabasesForServer(ctx, source, settings, server, nextToken)
	}
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("azure", familySQLDatabase, pageToken)
	if err != nil {
		return nil, "", err
	}
	records := make([]azureSQLDatabaseRecord, 0)
	servers, nextServers, err := listSQLServers(ctx, source, settings, parentToken, limit)
	if err != nil {
		return nil, "", err
	}
	for index := startIndex; index < len(servers); index++ {
		server := servers[index]
		databases, nextDatabases, err := listSQLDatabasesForServer(ctx, source, settings, server, childToken)
		if err != nil {
			return nil, "", err
		}
		records = append(records, databases...)
		if nextDatabases != "" {
			return records, sourcecdk.EncodeChildPageCursor("azure", familySQLDatabase, parentToken, index, nextDatabases), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("azure", familySQLDatabase, parentToken, nextServers, index+1, len(servers)), nil
		}
	}
	return records, nextServers, nil
}

func listSQLDatabasesForServer(ctx context.Context, source *Source, settings settings, server armTypedResourceRecord, pageToken string) ([]azureSQLDatabaseRecord, string, error) {
	query := url.Values{"api-version": {"2022-05-01-preview"}}
	var response armPage
	path := strings.TrimRight(server.ID, "/") + "/databases"
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	databases, err := sourcecdk.DecodeRecords(response.Value, "azure sql database", func(record *armTypedResourceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]azureSQLDatabaseRecord, 0, len(databases))
	for _, database := range databases {
		database = inheritAzureResourceContext(database, server)
		records = append(records, azureSQLDatabaseRecord{Database: database, Server: server})
	}
	return records, response.Next, nil
}

func listKeyVaults(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.KeyVault/vaults", "2023-07-01", "azure key vault")
}

func listKeyVaultKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]azureKeyVaultChildRecord, string, error) {
	return listKeyVaultChildren(ctx, source, settings, pageToken, limit, "keys", "azure key vault key")
}

func listKeyVaultSecrets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]azureKeyVaultChildRecord, string, error) {
	return listKeyVaultChildren(ctx, source, settings, pageToken, limit, "secrets", "azure key vault secret")
}

func listKeyVaultChildren(ctx context.Context, source *Source, settings settings, pageToken string, limit int, childPath string, label string) ([]azureKeyVaultChildRecord, string, error) {
	if strings.HasPrefix(pageToken, childPath+":") {
		vaultID, nextToken, ok := parseNestedPageToken(strings.TrimPrefix(pageToken, childPath+":"))
		if !ok {
			return nil, "", fmt.Errorf("invalid azure key vault %s cursor", childPath)
		}
		vault, found := getARMTypedResourceByID(ctx, source, settings, vaultID, "2023-07-01")
		if !found {
			return nil, "", fmt.Errorf("lookup azure key vault %s", vaultID)
		}
		return listKeyVaultChildrenForVault(ctx, source, settings, vault, nextToken, childPath, label)
	}
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("azure", childPath, pageToken)
	if err != nil {
		return nil, "", err
	}
	records := make([]azureKeyVaultChildRecord, 0)
	vaults, nextVaults, err := listKeyVaults(ctx, source, settings, parentToken, limit)
	if err != nil {
		return nil, "", err
	}
	for index := startIndex; index < len(vaults); index++ {
		vault := vaults[index]
		children, nextChildren, err := listKeyVaultChildrenForVault(ctx, source, settings, vault, childToken, childPath, label)
		if err != nil {
			return nil, "", err
		}
		records = append(records, children...)
		if nextChildren != "" {
			return records, sourcecdk.EncodeChildPageCursor("azure", childPath, parentToken, index, nextChildren), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("azure", childPath, parentToken, nextVaults, index+1, len(vaults)), nil
		}
	}
	return records, nextVaults, nil
}

func listKeyVaultChildrenForVault(ctx context.Context, source *Source, settings settings, vault armTypedResourceRecord, pageToken string, childPath string, label string) ([]azureKeyVaultChildRecord, string, error) {
	query := url.Values{"api-version": {"2023-07-01"}}
	var response armPage
	path := strings.TrimRight(vault.ID, "/") + "/" + childPath
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	children, err := sourcecdk.DecodeRecords(response.Value, label, func(record *armTypedResourceRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]azureKeyVaultChildRecord, 0, len(children))
	for _, child := range children {
		child = inheritAzureResourceContext(child, vault)
		records = append(records, azureKeyVaultChildRecord{Resource: child, Vault: vault})
	}
	return records, response.Next, nil
}

func listAzureARMChildResources(ctx context.Context, source *Source, settings settings, pageToken string, limit int, definition azureARMChildDefinition) ([]azureARMChildRecord, string, error) {
	parentToken, startIndex, childToken, _, err := sourcecdk.DecodeChildPageCursor("azure", definition.Name, pageToken)
	if err != nil {
		return nil, "", err
	}
	parents, nextParents, err := listAzureARMChildParents(ctx, source, settings, parentToken, limit, definition)
	if err != nil {
		return nil, "", err
	}
	records := make([]azureARMChildRecord, 0)
	for index := startIndex; index < len(parents); index++ {
		parent := parents[index]
		children, nextChildren, err := listAzureARMChildrenForParent(ctx, source, settings, parent, childToken, definition)
		if err != nil {
			return nil, "", err
		}
		records = append(records, children...)
		if nextChildren != "" {
			return records, sourcecdk.EncodeChildPageCursor("azure", definition.Name, parentToken, index, nextChildren), nil
		}
		childToken = ""
		if len(records) != 0 {
			return records, sourcecdk.NextChildPageCursor("azure", definition.Name, parentToken, nextParents, index+1, len(parents)), nil
		}
	}
	return records, nextParents, nil
}

func listAzureARMChildParents(ctx context.Context, source *Source, settings settings, pageToken string, limit int, definition azureARMChildDefinition) ([]armTypedResourceRecord, string, error) {
	if strings.TrimSpace(definition.ParentProvider) == "" {
		records, next, err := listAssetMetadata(ctx, source, settings, pageToken, limit)
		if err != nil {
			return nil, "", err
		}
		parents := make([]armTypedResourceRecord, 0, len(records))
		for _, record := range records {
			parents = append(parents, armTypedResourceRecord{ID: record.ID, Name: record.Name, Type: record.Type, Location: record.Location, Tags: record.Tags, raw: record.raw})
		}
		return parents, next, nil
	}
	return listARMTypedResources(ctx, source, settings, pageToken, definition.ParentProvider, definition.ParentAPIVersion, definition.Label+" parents")
}

func listAzureARMChildrenForParent(ctx context.Context, source *Source, settings settings, parent armTypedResourceRecord, pageToken string, definition azureARMChildDefinition) ([]azureARMChildRecord, string, error) {
	query := url.Values{"api-version": {definition.ChildAPIVersion}}
	path := strings.TrimRight(parent.ID, "/") + "/" + strings.Trim(definition.ChildPath, "/")
	if definition.Singleton {
		var raw json.RawMessage
		if err := getARMJSON(ctx, source, settings, path, query, &raw); err != nil {
			return nil, "", err
		}
		var child armTypedResourceRecord
		if err := json.Unmarshal(raw, &child); err != nil {
			return nil, "", err
		}
		child = inheritAzureResourceContext(child, parent)
		child.raw = append(json.RawMessage(nil), raw...)
		return []azureARMChildRecord{{Resource: child, Parent: parent}}, "", nil
	}
	var response armPage
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		if definition.Optional && optionalAzureARMChildErr(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	children, err := sourcecdk.DecodeRecords(response.Value, definition.Label, func(record *armTypedResourceRecord, raw json.RawMessage) {
		*record = inheritAzureResourceContext(*record, parent)
		record.raw = append(json.RawMessage(nil), raw...)
	})
	if err != nil {
		return nil, "", err
	}
	records := make([]azureARMChildRecord, 0, len(children))
	for _, child := range children {
		records = append(records, azureARMChildRecord{Resource: child, Parent: parent})
	}
	return records, response.Next, nil
}

func optionalAzureARMChildErr(err error) bool {
	message := fmt.Sprint(err)
	lower := strings.ToLower(message)
	return strings.Contains(message, "azure API returned 404") ||
		(strings.Contains(message, "azure API returned 400") && strings.Contains(lower, "diagnostic"))
}

func listCosmosAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.DocumentDB/databaseAccounts", "2024-05-15", "azure cosmos db account")
}

func listContainerRegistries(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]armTypedResourceRecord, string, error) {
	return listARMTypedResources(ctx, source, settings, pageToken, "Microsoft.ContainerRegistry/registries", "2023-07-01", "azure container registry")
}

func listResourceExposures(ctx context.Context, source *Source, settings settings, pageToken string, _ int) ([]azureResourceExposure, string, error) {
	query := url.Values{"api-version": {"2023-09-01"}}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/Microsoft.Network/networkSecurityGroups"
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	nsgs, err := sourcecdk.DecodeRecords(response.Value, "azure network security group", func(record *nsgRecord, raw json.RawMessage) { record.raw = append(json.RawMessage(nil), raw...) })
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
	return listActivityLogsWithCheckpoint(ctx, source, settings, pageToken, 0, nil)
}

func listActivityLogsWithCheckpoint(ctx context.Context, source *Source, settings settings, pageToken string, _ int, checkpoint *cerebrov1.SourceCheckpoint) ([]activityLogRecord, string, error) {
	query := url.Values{"api-version": {"2015-04-01"}}
	if settings.filter != "" {
		query.Set("$filter", settings.filter)
	}
	if start, ok := azureCheckpointStart(checkpoint); ok {
		query.Set("$filter", azureCombineFilters(query.Get("$filter"), fmt.Sprintf("eventTimestamp ge '%s'", start.Format(time.RFC3339Nano))))
	}
	var response armPage
	path := "/subscriptions/" + url.PathEscape(settings.subscriptionID) + "/providers/microsoft.insights/eventtypes/management/values"
	if err := getARMJSON(ctx, source, settings, firstNonEmpty(pageToken, path), queryForPageToken(pageToken, query), &response); err != nil {
		return nil, "", err
	}
	records, err := sourcecdk.DecodeRecords(response.Value, "azure activity log", func(record *activityLogRecord, raw json.RawMessage) {
		record.raw = append(json.RawMessage(nil), raw...)
	})
	return records, response.Next, err
}

func genericARMResourceEvent(settings settings, record armTypedResourceRecord, family string, kind string, schemaRef string) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, family)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, azurearm.ResourceAttributes(family, record.Kind, kind, azurearm.Properties(record.Properties)))
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(family, record), kind, schemaRef, payload, attributes, time.Now().UTC())
}

func azureARMChildResourceEvent(settings settings, record azureARMChildRecord, definition azureARMChildDefinition) (*primitives.Event, error) {
	event, err := genericARMResourceEvent(settings, record.Resource, definition.Name, definition.Kind, definition.SchemaRef)
	if err != nil {
		return nil, err
	}
	setAttributes(event.Attributes, map[string]string{
		"parent_resource_id":   record.Parent.ID,
		"parent_resource_name": record.Parent.Name,
		"parent_resource_type": record.Parent.Type,
	})
	return event, nil
}

func managedDiskEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyManagedDisk)
	setAttributes(attributes, map[string]string{"disk_size_gb": propertyString(record, "diskSizeGB"), "disk_state": propertyString(record, "diskState"), "os_type": propertyString(record, "osType"), "creation_data_source_id": propertyString(record, "creationData", "sourceResourceId"), "network_access_policy": propertyString(record, "networkAccessPolicy"), "public_network_access": propertyString(record, "publicNetworkAccess"), "encryption_type": propertyString(record, "encryption", "type"), "disk_encryption_set_id": propertyString(record, "encryption", "diskEncryptionSetId")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyManagedDisk, record), "azure.managed_disk", "azure/managed_disk/v1", payload, attributes, time.Now().UTC())
}

func aksClusterEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyAKSCluster)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"kubernetes_version": propertyString(record, "kubernetesVersion"), "dns_prefix": propertyString(record, "dnsPrefix"), "public_host": firstNonEmpty(propertyString(record, "fqdn"), propertyString(record, "privateFQDN")), "public_network_access": propertyString(record, "publicNetworkAccess"), "private_cluster_enabled": propertyBoolString(record, "apiServerAccessProfile", "enablePrivateCluster"), "network_plugin": propertyString(record, "networkProfile", "networkPlugin"), "network_policy": propertyString(record, "networkProfile", "networkPolicy"), "subnet_ids": strings.Join(aksSubnetIDs(record), ","), "public_ip_ids": strings.Join(aksOutboundPublicIPIDs(record), ",")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyAKSCluster, record), "azure.aks_cluster", "azure/aks_cluster/v1", payload, attributes, time.Now().UTC())
}

func appServiceEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	return webSiteEvent(settings, record, familyAppService, "azure.app_service", "azure/app_service/v1")
}

func functionAppEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	return webSiteEvent(settings, record, familyFunctionApp, "azure.function_app", "azure/function_app/v1")
}

func webSiteEvent(settings settings, record armTypedResourceRecord, family string, kind string, schemaRef string) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, family)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"kind": record.Kind, "enabled": propertyBoolString(record, "enabled"), "https_only": propertyBoolString(record, "httpsOnly"), "min_tls_version": firstNonEmpty(propertyString(record, "siteConfig", "minTlsVersion"), propertyString(record, "siteConfig", "minimumTlsVersion")), "public_network_access": propertyString(record, "publicNetworkAccess"), "public_host": propertyString(record, "defaultHostName"), "host_names": strings.Join(propertyStringSlice(record, "hostNames"), ","), "subnet_ids": propertyString(record, "virtualNetworkSubnetId"), "server_farm_id": propertyString(record, "serverFarmId"), "runtime": firstNonEmpty(propertyString(record, "siteConfig", "linuxFxVersion"), propertyString(record, "siteConfig", "windowsFxVersion"), propertyString(record, "siteConfig", "netFrameworkVersion")), "outbound_ip_addresses": propertyString(record, "outboundIpAddresses")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(family, record), kind, schemaRef, payload, attributes, time.Now().UTC())
}

func storageAccountEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyStorageAccount)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"sku": firstNonEmpty(record.SKU.Name, record.SKU.Tier), "public_network_access": propertyString(record, "publicNetworkAccess"), "allow_blob_public_access": propertyBoolString(record, "allowBlobPublicAccess"), "allow_shared_key_access": propertyBoolString(record, "allowSharedKeyAccess"), "https_only": propertyBoolString(record, "supportsHttpsTrafficOnly"), "min_tls_version": propertyString(record, "minimumTlsVersion"), "encryption_key_source": propertyString(record, "encryption", "keySource"), "blob_encryption_enabled": propertyBoolString(record, "encryption", "services", "blob", "enabled"), "file_encryption_enabled": propertyBoolString(record, "encryption", "services", "file", "enabled"), "public_host": firstNonEmpty(propertyString(record, "primaryEndpoints", "blob"), propertyString(record, "primaryEndpoints", "web"))})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyStorageAccount, record), "azure.storage_account", "azure/storage_account/v1", payload, attributes, time.Now().UTC())
}

func sqlServerEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familySQLServer)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"public_network_access": propertyString(record, "publicNetworkAccess"), "min_tls_version": propertyString(record, "minimalTlsVersion"), "public_host": propertyString(record, "fullyQualifiedDomainName"), "state": propertyString(record, "state"), "primary_user_assigned_identity_id": propertyString(record, "primaryUserAssignedIdentityId")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familySQLServer, record), "azure.sql_server", "azure/sql_server/v1", payload, attributes, time.Now().UTC())
}

func sqlDatabaseEvent(settings settings, record azureSQLDatabaseRecord) (*primitives.Event, error) {
	database := record.Database
	attributes := azureResourceAttributes(settings, database, familySQLDatabase)
	setAttributes(attributes, map[string]string{"server_id": record.Server.ID, "server_name": record.Server.Name, "public_host": propertyString(record.Server, "fullyQualifiedDomainName"), "status": propertyString(database, "status"), "collation": propertyString(database, "collation"), "max_size_bytes": propertyString(database, "maxSizeBytes"), "zone_redundant": propertyBoolString(database, "zoneRedundant"), "read_scale": propertyString(database, "readScale"), "backup_storage_redundancy": firstNonEmpty(propertyString(database, "currentBackupStorageRedundancy"), propertyString(database, "requestedBackupStorageRedundancy")), "earliest_restore_date": propertyString(database, "earliestRestoreDate")})
	payload, err := payloadWithRaw(database.raw, map[string]any{"tenant_id": settings.tenantID, "subscription_id": settings.subscriptionID, "server_id": record.Server.ID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familySQLDatabase, database), "azure.sql_database", "azure/sql_database/v1", payload, attributes, time.Now().UTC())
}

func keyVaultEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyKeyVault)
	setAttributes(attributes, map[string]string{"tenant_id": firstNonEmpty(propertyString(record, "tenantId"), settings.tenantID), "public_network_access": propertyString(record, "publicNetworkAccess"), "soft_delete_enabled": propertyBoolString(record, "enableSoftDelete"), "purge_protection_enabled": propertyBoolString(record, "enablePurgeProtection"), "soft_delete_retention_days": propertyString(record, "softDeleteRetentionInDays"), "rbac_authorization_enabled": propertyBoolString(record, "enableRbacAuthorization"), "enabled_for_disk_encryption": propertyBoolString(record, "enabledForDiskEncryption"), "network_default_action": propertyString(record, "networkAcls", "defaultAction"), "public_host": propertyString(record, "vaultUri")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyKeyVault, record), "azure.key_vault", "azure/key_vault/v1", payload, attributes, time.Now().UTC())
}

func keyVaultKeyEvent(settings settings, record azureKeyVaultChildRecord) (*primitives.Event, error) {
	return keyVaultChildEvent(settings, record, familyKeyVaultKey, "azure.key_vault_key", "azure/key_vault_key/v1")
}

func keyVaultSecretEvent(settings settings, record azureKeyVaultChildRecord) (*primitives.Event, error) {
	return keyVaultChildEvent(settings, record, familyKeyVaultSecret, "azure.key_vault_secret", "azure/key_vault_secret/v1")
}

func keyVaultChildEvent(settings settings, record azureKeyVaultChildRecord, family string, kind string, schemaRef string) (*primitives.Event, error) {
	resource := record.Resource
	attributes := azureResourceAttributes(settings, resource, family)
	setAttribute(attributes, "vault_id", record.Vault.ID)
	setAttribute(attributes, "vault_name", record.Vault.Name)
	setAttribute(attributes, "enabled", propertyBoolString(resource, "attributes", "enabled"))
	setAttribute(attributes, "expires_at", unixTimeString(propertyString(resource, "attributes", "exp")))
	setAttribute(attributes, "not_before", unixTimeString(propertyString(resource, "attributes", "nbf")))
	setAttribute(attributes, "created_at", unixTimeString(propertyString(resource, "attributes", "created")))
	setAttribute(attributes, "updated_at", unixTimeString(propertyString(resource, "attributes", "updated")))
	setAttribute(attributes, "recovery_level", propertyString(resource, "attributes", "recoveryLevel"))
	setAttribute(attributes, "content_type", propertyString(resource, "contentType"))
	setAttribute(attributes, "key_type", propertyString(resource, "kty"))
	setAttribute(attributes, "key_ops", strings.Join(propertyStringSlice(resource, "keyOps"), ","))
	setAttribute(attributes, "soft_delete_enabled", propertyBoolString(record.Vault, "enableSoftDelete"))
	setAttribute(attributes, "purge_protection_enabled", propertyBoolString(record.Vault, "enablePurgeProtection"))
	payload, err := payloadWithRaw(resource.raw, map[string]any{"tenant_id": settings.tenantID, "subscription_id": settings.subscriptionID, "vault_id": record.Vault.ID})
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(family, resource), kind, schemaRef, payload, attributes, time.Now().UTC())
}

func cosmosAccountEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyCosmosAccount)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"public_network_access": propertyString(record, "publicNetworkAccess"), "public_host": propertyString(record, "documentEndpoint"), "min_tls_version": propertyString(record, "minimalTlsVersion"), "local_auth_disabled": propertyBoolString(record, "disableLocalAuth"), "multiple_write_locations_enabled": propertyBoolString(record, "enableMultipleWriteLocations"), "free_tier_enabled": propertyBoolString(record, "enableFreeTier"), "default_consistency_level": propertyString(record, "consistencyPolicy", "defaultConsistencyLevel"), "locations": strings.Join(cosmosLocationNames(record), ","), "private_endpoint_connection_count": strconv.Itoa(len(propertyArray(record, "privateEndpointConnections")))})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyCosmosAccount, record), "azure.cosmos_account", "azure/cosmos_account/v1", payload, attributes, time.Now().UTC())
}

func containerRegistryEvent(settings settings, record armTypedResourceRecord) (*primitives.Event, error) {
	attributes := azureResourceAttributes(settings, record, familyContainerRegistry)
	addAzureIdentityAttributes(attributes, record.Identity)
	setAttributes(attributes, map[string]string{"sku": firstNonEmpty(record.SKU.Name, record.SKU.Tier), "public_network_access": propertyString(record, "publicNetworkAccess"), "public_host": propertyString(record, "loginServer"), "admin_user_enabled": propertyBoolString(record, "adminUserEnabled"), "network_default_action": propertyString(record, "networkRuleSet", "defaultAction"), "quarantine_policy_status": propertyString(record, "policies", "quarantinePolicy", "status"), "trust_policy_status": propertyString(record, "policies", "trustPolicy", "status"), "retention_policy_status": propertyString(record, "policies", "retentionPolicy", "status"), "retention_policy_days": propertyString(record, "policies", "retentionPolicy", "days"), "encryption_status": propertyString(record, "encryption", "status"), "encryption_key_vault_key_id": propertyString(record, "encryption", "keyVaultProperties", "keyIdentifier")})
	payload, err := payloadWithRaw(record.raw, azureResourcePayload(settings))
	if err != nil {
		return nil, err
	}
	return sourceEvent(settings, azureResourceEventID(familyContainerRegistry, record), "azure.container_registry", "azure/container_registry/v1", payload, attributes, time.Now().UTC())
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

func azureTypedResourceURN(settings settings, family string, record armTypedResourceRecord) string {
	return fmt.Sprintf("urn:cerebro:%s:azure_%s:%s", tenantID(settings), family, firstNonEmpty(record.ID, record.Name))
}

func azureResourceEventID(family string, record armTypedResourceRecord) string {
	return "azure-" + strings.ReplaceAll(family, "_", "-") + "-" + firstNonEmpty(record.ID, record.Name, record.Type)
}

func azureResourcePayload(settings settings) map[string]any {
	return map[string]any{"tenant_id": settings.tenantID, "subscription_id": settings.subscriptionID}
}

func azureResourceAttributes(settings settings, record armTypedResourceRecord, family string) map[string]string {
	tags := record.Tags
	resourceID := firstNonEmpty(record.ID, record.Name)
	provider := firstNonEmpty(azurearm.ProviderFromType(record.Type), azurearm.ProviderFromID(record.ID), "azure")
	attributes := map[string]string{
		"cloud_provider":    "azure",
		"domain":            tenantID(settings),
		"env":               tagLookup(tags, "env", "environment", "stage"),
		"environment":       tagLookup(tags, "environment", "env", "stage"),
		"family":            family,
		"location":          record.Location,
		"owner":             tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"provider":          provider,
		"region":            record.Location,
		"resource_group":    azurearm.ResourceGroupFromID(resourceID),
		"resource_id":       resourceID,
		"resource_name":     firstNonEmpty(record.Name, resourceID),
		"resource_provider": provider,
		"resource_type":     firstNonEmpty(record.Type, family),
		"source_provider":   "azure",
		"subscription_id":   settings.subscriptionID,
		"team":              tagLookup(tags, "team", "squad", "group"),
		"tenant_id":         settings.tenantID,
	}
	if record.SKU.Name != "" || record.SKU.Tier != "" {
		attributes["sku"] = firstNonEmpty(record.SKU.Name, record.SKU.Tier)
	}
	trimEmptyAttributes(attributes)
	return attributes
}

func addAzureIdentityAttributes(attributes map[string]string, identity armResourceIdentity) {
	setAttribute(attributes, "identity_type", identity.Type)
	setAttribute(attributes, "identity_principal_id", identity.PrincipalID)
	setAttribute(attributes, "identity_tenant_id", identity.TenantID)
	identityIDs := make([]string, 0, len(identity.UserAssignedIdentities))
	principalIDs := make([]string, 0, len(identity.UserAssignedIdentities))
	for identityID, assigned := range identity.UserAssignedIdentities {
		if strings.TrimSpace(identityID) != "" {
			identityIDs = append(identityIDs, identityID)
		}
		if strings.TrimSpace(assigned.PrincipalID) != "" {
			principalIDs = append(principalIDs, assigned.PrincipalID)
		}
	}
	setAttribute(attributes, "user_assigned_identity_ids", strings.Join(uniqueStrings(identityIDs), ","))
	setAttribute(attributes, "user_assigned_principal_ids", strings.Join(uniqueStrings(principalIDs), ","))
}

func setAttribute(attributes map[string]string, key string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		delete(attributes, key)
		return
	}
	attributes[key] = value
}

func setAttributes(attributes map[string]string, values map[string]string) {
	for key, value := range values {
		setAttribute(attributes, key, value)
	}
}

func getARMTypedResourceByID(ctx context.Context, source *Source, settings settings, resourceID string, apiVersion string) (armTypedResourceRecord, bool) {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return armTypedResourceRecord{}, false
	}
	path := resourceID
	if strings.HasPrefix(path, armBaseURL(settings)) {
		path = strings.TrimPrefix(path, armBaseURL(settings))
	}
	query := url.Values{"api-version": {apiVersion}}
	var record armTypedResourceRecord
	if err := getARMJSON(ctx, source, settings, path, query, &record); err != nil {
		return armTypedResourceRecord{}, false
	}
	if record.ID == "" {
		record.ID = resourceID
	}
	return record, true
}

func inheritAzureResourceContext(child armTypedResourceRecord, parent armTypedResourceRecord) armTypedResourceRecord {
	if child.Location == "" {
		child.Location = parent.Location
	}
	if len(child.Tags) == 0 {
		child.Tags = parent.Tags
	}
	return child
}

func azureSiteIsFunctionApp(record armTypedResourceRecord) bool {
	return strings.Contains(strings.ToLower(record.Kind), "functionapp")
}

func azureNetworkInterfaceIDs(record armTypedResourceRecord) []string {
	interfaces := propertyArray(record, "networkProfile", "networkInterfaces")
	values := make([]string, 0, len(interfaces))
	for _, item := range interfaces {
		if iface := mapFromAny(item); iface != nil {
			values = append(values, stringFromAny(iface["id"]))
		}
	}
	return uniqueStrings(values)
}

func azureNICSubnetIDs(record armTypedResourceRecord) []string {
	configs := propertyArray(record, "ipConfigurations")
	values := make([]string, 0, len(configs))
	for _, item := range configs {
		config := mapFromAny(item)
		if config == nil {
			continue
		}
		properties := mapFromAny(config["properties"])
		subnet := mapFromAny(properties["subnet"])
		values = append(values, stringFromAny(subnet["id"]))
	}
	return uniqueStrings(values)
}

func azureNICNSGIDs(record armTypedResourceRecord) []string {
	values := []string{propertyString(record, "networkSecurityGroup", "id")}
	configs := propertyArray(record, "ipConfigurations")
	for _, item := range configs {
		config := mapFromAny(item)
		if config == nil {
			continue
		}
		properties := mapFromAny(config["properties"])
		nsg := mapFromAny(properties["networkSecurityGroup"])
		values = append(values, stringFromAny(nsg["id"]))
	}
	return uniqueStrings(values)
}

func azureNICPublicIPIDs(record armTypedResourceRecord) []string {
	configs := propertyArray(record, "ipConfigurations")
	values := make([]string, 0, len(configs))
	for _, item := range configs {
		config := mapFromAny(item)
		if config == nil {
			continue
		}
		properties := mapFromAny(config["properties"])
		publicIP := mapFromAny(properties["publicIPAddress"])
		values = append(values, stringFromAny(publicIP["id"]))
	}
	return uniqueStrings(values)
}

func azurePublicIPHosts(record armTypedResourceRecord) []string {
	if fqdn := propertyString(record, "dnsSettings", "fqdn"); fqdn != "" {
		return []string{fqdn}
	}
	return uniqueStrings([]string{propertyString(record, "ipAddress")})
}

func azureChildResourceIDs(record armTypedResourceRecord, keys ...string) []string {
	return azureChildResourceValues(record, "id", keys...)
}

func azureChildResourceNames(record armTypedResourceRecord, keys ...string) []string {
	return azureChildResourceValues(record, "name", keys...)
}

func azureChildResourceValues(record armTypedResourceRecord, field string, keys ...string) []string {
	items := propertyArray(record, keys...)
	values := make([]string, 0, len(items))
	for _, item := range items {
		if child := mapFromAny(item); child != nil {
			values = append(values, stringFromAny(child[field]))
		}
	}
	return uniqueStrings(values)
}

func aksSubnetIDs(record armTypedResourceRecord) []string {
	pools := propertyArray(record, "agentPoolProfiles")
	values := make([]string, 0, len(pools))
	for _, item := range pools {
		pool := mapFromAny(item)
		if pool != nil {
			values = append(values, stringFromAny(pool["vnetSubnetID"]))
		}
	}
	return uniqueStrings(values)
}

func aksOutboundPublicIPIDs(record armTypedResourceRecord) []string {
	profile := mapFromAny(nestedValue(record.Properties, "networkProfile", "loadBalancerProfile"))
	values := make([]string, 0)
	for _, key := range []string{"effectiveOutboundIPs", "outboundIPs"} {
		for _, item := range arrayFromAny(profile[key]) {
			ip := mapFromAny(item)
			if ip != nil {
				values = append(values, stringFromAny(ip["id"]))
			}
		}
	}
	return uniqueStrings(values)
}

func cosmosLocationNames(record armTypedResourceRecord) []string {
	locations := propertyArray(record, "locations")
	values := make([]string, 0, len(locations))
	for _, item := range locations {
		location := mapFromAny(item)
		if location != nil {
			values = append(values, firstNonEmpty(stringFromAny(location["locationName"]), stringFromAny(location["documentEndpoint"])))
		}
	}
	return uniqueStrings(values)
}

func propertyString(record armTypedResourceRecord, keys ...string) string {
	return stringFromAny(nestedValue(record.Properties, keys...))
}

func propertyBoolString(record armTypedResourceRecord, keys ...string) string {
	value := nestedValue(record.Properties, keys...)
	switch typed := value.(type) {
	case bool:
		return boolString(typed)
	case string:
		if strings.TrimSpace(typed) == "" {
			return ""
		}
		if strings.EqualFold(typed, "true") || strings.EqualFold(typed, "false") {
			return strings.ToLower(typed)
		}
		return typed
	default:
		return ""
	}
}

func propertyStringSlice(record armTypedResourceRecord, keys ...string) []string {
	items := propertyArray(record, keys...)
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, stringFromAny(item))
	}
	return uniqueStrings(values)
}

func propertyArray(record armTypedResourceRecord, keys ...string) []any {
	return arrayFromAny(nestedValue(record.Properties, keys...))
}

func nestedValue(values map[string]any, keys ...string) any {
	if len(keys) == 0 {
		return values
	}
	var current any = values
	for _, key := range keys {
		currentMap := mapFromAny(current)
		if currentMap == nil {
			return nil
		}
		current = currentMap[key]
	}
	return current
}

func mapFromAny(value any) map[string]any {
	if value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func arrayFromAny(value any) []any {
	if value == nil {
		return nil
	}
	if typed, ok := value.([]any); ok {
		return typed
	}
	return nil
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return boolString(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func unixTimeString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func parseNestedPageToken(value string) (string, string, bool) {
	parentID, next, ok := strings.Cut(value, "|")
	return parentID, next, ok && strings.TrimSpace(parentID) != "" && strings.TrimSpace(next) != ""
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func sourceEvent(settings settings, id string, kind string, schemaRef string, payload []byte, attributes map[string]string, occurredAt time.Time) (*primitives.Event, error) {
	trimEmptyAttributes(attributes)
	return &primitives.Event{Id: sanitizeEventID(id), TenantId: tenantID(settings), SourceId: "azure", Kind: kind, OccurredAt: timestamppb.New(occurredAt.UTC()), SchemaRef: schemaRef, Payload: payload, Attributes: attributes}, nil
}

func getGraphJSON(ctx context.Context, source *Source, settings settings, requestPath string, query url.Values, target any) error {
	return getJSON(ctx, source, graphBaseURL(settings), graphToken(settings), http.MethodGet, requestPath, query, nil, target)
}

func getARMJSON(ctx context.Context, source *Source, settings settings, requestPath string, query url.Values, target any) error {
	return getJSON(ctx, source, armBaseURL(settings), armToken(settings), http.MethodGet, requestPath, query, nil, target)
}

func getJSON(ctx context.Context, source *Source, baseURL string, token string, method string, requestPath string, query url.Values, body any, target any) error {
	normalizedBaseURL, _, err := sourcehttp.NormalizeBaseURL("azure", baseURL, source != nil && source.allowLoopbackBaseURL)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSpace(requestPath)
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		endpoint, err = sourcehttp.SameOriginAbsoluteURL("azure", normalizedBaseURL, endpoint)
		if err != nil {
			return err
		}
	} else {
		path, err := sourcehttp.NormalizeRequestPath("azure", endpoint)
		if err != nil {
			return err
		}
		endpoint = normalizedBaseURL + path
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
	client := sourcehttp.NewClient(sourcehttp.ClientOptions{SourceID: "azure"})
	if source != nil && source.client != nil {
		client = source.client
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", requestPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	content, err := sourcehttp.ReadLimitedBody(resp.Body)
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

func (s *Source) safeClient() *http.Client {
	return sourcehttp.NewClient(sourcehttp.ClientOptions{
		SourceID:      "azure",
		Timeout:       30 * time.Second,
		AllowLoopback: s != nil && s.allowLoopbackBaseURL,
		LookupIPAddrs: lookupIPAddrs(s),
	})
}

func lookupIPAddrs(source *Source) func(context.Context, string) ([]net.IPAddr, error) {
	if source != nil && source.lookupIPAddrs != nil {
		return source.lookupIPAddrs
	}
	return net.DefaultResolver.LookupIPAddr
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

func resolveAzurePrincipal(ctx context.Context, source *Source, settings settings, principalID string, principalType string) (graphPrincipalRecord, bool) {
	principalID = strings.TrimSpace(principalID)
	if principalID == "" || graphToken(settings) == "" {
		return graphPrincipalRecord{}, false
	}
	var path string
	switch azurePrincipalType(principalType, graphPrincipalRecord{}) {
	case "user":
		path = "/v1.0/users/" + url.PathEscape(principalID)
	case "group":
		path = "/v1.0/groups/" + url.PathEscape(principalID)
	case "service_principal", "application":
		path = "/v1.0/servicePrincipals/" + url.PathEscape(principalID)
	default:
		path = "/v1.0/directoryObjects/" + url.PathEscape(principalID)
	}
	var record graphPrincipalRecord
	if err := getGraphJSON(ctx, source, settings, path, nil, &record); err != nil {
		return graphPrincipalRecord{}, false
	}
	if strings.TrimSpace(record.ID) == "" {
		record.ID = principalID
	}
	return record, true
}

func graphListQuery(settings settings, limit int) url.Values {
	query := url.Values{"$top": {strconv.Itoa(limit)}}
	sourcecdk.AddQueryParam(query, "$filter", settings.filter)
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

func azureCheckpointStart(checkpoint *cerebrov1.SourceCheckpoint) (time.Time, bool) {
	if checkpoint == nil || checkpoint.GetWatermark() == nil {
		return time.Time{}, false
	}
	watermark := checkpoint.GetWatermark().AsTime().UTC()
	if watermark.IsZero() {
		return time.Time{}, false
	}
	return watermark.Add(-azureCheckpointLookback), true
}

func azureCombineFilters(existing string, incremental string) string {
	existing = strings.TrimSpace(existing)
	incremental = strings.TrimSpace(incremental)
	switch {
	case existing == "":
		return incremental
	case incremental == "":
		return existing
	default:
		return "(" + existing + ") and " + incremental
	}
}

func graphToken(settings settings) string { return firstNonEmpty(settings.graphToken, settings.token) }

func armToken(settings settings) string { return firstNonEmpty(settings.armToken, settings.token) }

func graphBaseURL(settings settings) string {
	return firstNonEmpty(settings.graphBaseURL, settings.baseURL, "https://graph.microsoft.com")
}

func armBaseURL(settings settings) string {
	return firstNonEmpty(settings.armBaseURL, settings.baseURL, "https://management.azure.com")
}

func tenantID(settings settings) string { return settings.tenantID }

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

func privilegeLevel(admin bool) string {
	if admin {
		return "admin"
	}
	return "standard"
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

func boolString(value bool) string { return strconv.FormatBool(value) }

func boolPtrValue(value *bool) bool { return value != nil && *value }

func emailLike(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "@") {
		return strings.ToLower(trimmed)
	}
	return ""
}

func tagLookup(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}
	normalized := map[string]string{}
	for key, value := range tags {
		normalized[normalizeTagKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeTagKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeTagKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func criticalityFromTags(tags map[string]string) string {
	for _, value := range tags {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "critical", "high", "tier0", "tier_0", "tier-0", "crown_jewel", "crown-jewel":
			return "critical"
		}
	}
	return ""
}

func crownJewelFromTags(tags map[string]string) bool {
	for _, key := range []string{"crown_jewel", "crown-jewel", "tier0", "tier_0", "business_critical"} {
		if value := strings.ToLower(tagLookup(tags, key)); value == "true" || value == "yes" || value == "1" || value == "critical" {
			return true
		}
	}
	return strings.EqualFold(criticalityFromTags(tags), "critical")
}

func firstNonEmpty(values ...string) string { return textutil.FirstNonEmpty(values...) }

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

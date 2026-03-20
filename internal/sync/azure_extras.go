package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

const (
	azureManagementScope               = "https://management.azure.com/.default"
	azureGraphScope                    = "https://graph.microsoft.com/.default"
	azureAKSManagedClustersAPIVersion  = "2023-08-01"
	azurePolicyAssignmentsAPIVersion   = "2022-06-01"
	azureDefenderAssessmentsAPIVersion = "2020-01-01"
)

var azureManagementHTTPClient = &http.Client{Timeout: 30 * time.Second}
var azureGraphHTTPClient = &http.Client{Timeout: 30 * time.Second}

type azureManagedClusterListResponse struct {
	Value    []azureManagedCluster `json:"value"`
	NextLink string                `json:"nextLink"`
}

type azureManagedCluster struct {
	ID         *string                        `json:"id"`
	Name       *string                        `json:"name"`
	Location   *string                        `json:"location"`
	Tags       map[string]string              `json:"tags"`
	Identity   map[string]interface{}         `json:"identity"`
	Properties *azureManagedClusterProperties `json:"properties"`
}

type azureManagedClusterProperties struct {
	KubernetesVersion *string                        `json:"kubernetesVersion"`
	DNSPrefix         *string                        `json:"dnsPrefix"`
	ProvisioningState *string                        `json:"provisioningState"`
	FQDN              *string                        `json:"fqdn"`
	NodeResourceGroup *string                        `json:"nodeResourceGroup"`
	APIServerAccess   *azureManagedClusterAPIAccess  `json:"apiServerAccessProfile"`
	NetworkProfile    *azureManagedClusterNetwork    `json:"networkProfile"`
	AgentPoolProfiles []azureManagedClusterAgentPool `json:"agentPoolProfiles"`
}

type azureManagedClusterAPIAccess struct {
	EnablePrivateCluster *bool    `json:"enablePrivateCluster"`
	AuthorizedIPRanges   []string `json:"authorizedIPRanges"`
}

type azureManagedClusterNetwork struct {
	NetworkPlugin *string `json:"networkPlugin"`
	NetworkPolicy *string `json:"networkPolicy"`
	OutboundType  *string `json:"outboundType"`
}

type azureManagedClusterAgentPool struct {
	Name                *string `json:"name"`
	Count               *int32  `json:"count"`
	VMSize              *string `json:"vmSize"`
	Mode                *string `json:"mode"`
	OSType              *string `json:"osType"`
	OrchestratorVersion *string `json:"orchestratorVersion"`
}

type azureRoleAssignmentListResponse struct {
	Value    []azureRoleAssignment `json:"value"`
	NextLink string                `json:"nextLink"`
}

type azureRoleAssignment struct {
	ID         *string                        `json:"id"`
	Name       *string                        `json:"name"`
	Properties *azureRoleAssignmentProperties `json:"properties"`
}

type azureRoleAssignmentProperties struct {
	Scope                      *string `json:"scope"`
	RoleDefinitionID           *string `json:"roleDefinitionId"`
	PrincipalID                *string `json:"principalId"`
	PrincipalType              *string `json:"principalType"`
	Condition                  *string `json:"condition"`
	ConditionVersion           *string `json:"conditionVersion"`
	Description                *string `json:"description"`
	CanDelegate                *bool   `json:"canDelegate"`
	CreatedOn                  *string `json:"createdOn"`
	UpdatedOn                  *string `json:"updatedOn"`
	CreatedBy                  *string `json:"createdBy"`
	UpdatedBy                  *string `json:"updatedBy"`
	DelegatedManagedIdentityID *string `json:"delegatedManagedIdentityResourceId"`
}

type azurePolicyAssignmentListResponse struct {
	Value    []azurePolicyAssignment `json:"value"`
	NextLink string                  `json:"nextLink"`
}

type azurePolicyAssignment struct {
	ID         *string                          `json:"id"`
	Name       *string                          `json:"name"`
	Type       *string                          `json:"type"`
	Location   *string                          `json:"location"`
	Identity   map[string]interface{}           `json:"identity"`
	Properties *azurePolicyAssignmentProperties `json:"properties"`
}

type azurePolicyAssignmentProperties struct {
	DisplayName           *string                  `json:"displayName"`
	Description           *string                  `json:"description"`
	PolicyDefinitionID    *string                  `json:"policyDefinitionId"`
	Scope                 *string                  `json:"scope"`
	EnforcementMode       *string                  `json:"enforcementMode"`
	NotScopes             []string                 `json:"notScopes"`
	Metadata              map[string]interface{}   `json:"metadata"`
	Parameters            map[string]interface{}   `json:"parameters"`
	NonComplianceMessages []map[string]interface{} `json:"nonComplianceMessages"`
	Overrides             []map[string]interface{} `json:"overrides"`
	ResourceSelectors     []map[string]interface{} `json:"resourceSelectors"`
}

type azureGraphServicePrincipalListResponse struct {
	Value    []azureGraphServicePrincipal `json:"value"`
	NextLink string                       `json:"@odata.nextLink"`
}

type azureGraphServicePrincipal struct {
	ID                        *string `json:"id"`
	AppID                     *string `json:"appId"`
	DisplayName               *string `json:"displayName"`
	ServicePrincipalType      *string `json:"servicePrincipalType"`
	AccountEnabled            *bool   `json:"accountEnabled"`
	AppOwnerOrganizationID    *string `json:"appOwnerOrganizationId"`
	AppRoleAssignmentRequired *bool   `json:"appRoleAssignmentRequired"`
	PublisherName             *string `json:"publisherName"`
	VerifiedPublisher         *struct {
		DisplayName         *string `json:"displayName"`
		VerifiedPublisherID *string `json:"verifiedPublisherId"`
		AddedDateTime       *string `json:"addedDateTime"`
	} `json:"verifiedPublisher"`
	CreatedDateTime *string  `json:"createdDateTime"`
	Tags            []string `json:"tags"`
}

type azureDefenderAssessmentListResponse struct {
	Value    []azureDefenderAssessment `json:"value"`
	NextLink string                    `json:"nextLink"`
}

type azureDefenderAssessment struct {
	ID         *string                            `json:"id"`
	Name       *string                            `json:"name"`
	Type       *string                            `json:"type"`
	Properties *azureDefenderAssessmentProperties `json:"properties"`
}

type azureDefenderAssessmentProperties struct {
	DisplayName            *string                `json:"displayName"`
	Description            *string                `json:"description"`
	Status                 *azureDefenderStatus   `json:"status"`
	ResourceDetails        map[string]interface{} `json:"resourceDetails"`
	Metadata               map[string]interface{} `json:"metadata"`
	AdditionalData         map[string]interface{} `json:"additionalData"`
	Links                  map[string]interface{} `json:"links"`
	RemediationDescription *string                `json:"remediationDescription"`
}

type azureDefenderStatus struct {
	Code        *string `json:"code"`
	Cause       *string `json:"cause"`
	Description *string `json:"description"`
}

func (e *AzureSyncEngine) azureFunctionAppTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_functions_apps",
		Columns: []string{
			"id", "name", "location", "resource_group", "kind", "state", "https_only",
			"client_cert_enabled", "identity", "tags", "subscription_id", "site_config",
			"auth_level", "http_trigger",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			client, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := client.NewListPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, app := range page.Value {
					if !isFunctionApp(app.Kind) {
						continue
					}

					row := map[string]interface{}{
						"_cq_id":          ptrStr(app.ID),
						"id":              ptrStr(app.ID),
						"name":            ptrStr(app.Name),
						"location":        ptrStr(app.Location),
						"resource_group":  resourceGroupFromID(ptrStr(app.ID)),
						"kind":            ptrStr(app.Kind),
						"subscription_id": subscriptionID,
						"tags":            app.Tags,
					}

					if app.Properties != nil {
						row["state"] = ptrStr(app.Properties.State)
						row["https_only"] = app.Properties.HTTPSOnly
						row["client_cert_enabled"] = app.Properties.ClientCertEnabled
						if app.Properties.SiteConfig != nil {
							row["site_config"] = map[string]interface{}{
								"http20_enabled":  app.Properties.SiteConfig.Http20Enabled,
								"ftps_state":      app.Properties.SiteConfig.FtpsState,
								"min_tls_version": app.Properties.SiteConfig.MinTLSVersion,
							}
						}
					}
					if app.Identity != nil {
						row["identity"] = app.Identity
					}

					authLevel, httpTrigger, err := fetchFunctionAppAuth(ctx, client, row["resource_group"].(string), ptrStr(app.Name))
					if err == nil {
						if authLevel != "" {
							row["auth_level"] = authLevel
						}
						row["http_trigger"] = httpTrigger
					}

					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureAKSClusterTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_aks_clusters",
		Columns: []string{
			"id",
			"name",
			"location",
			"resource_group",
			"kubernetes_version",
			"provisioning_state",
			"dns_prefix",
			"fqdn",
			"node_resource_group",
			"private_cluster_enabled",
			"authorized_ip_ranges",
			"network_plugin",
			"network_policy",
			"outbound_type",
			"agent_pool_count",
			"agent_pools",
			"identity",
			"tags",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			clusters, err := listAzureManagedClusters(ctx, cred, subscriptionID)
			if err != nil {
				return nil, err
			}

			results := make([]map[string]interface{}, 0, len(clusters))
			for _, cluster := range clusters {
				clusterID := ptrStr(cluster.ID)
				row := map[string]interface{}{
					"_cq_id":          clusterID,
					"id":              clusterID,
					"name":            ptrStr(cluster.Name),
					"location":        ptrStr(cluster.Location),
					"resource_group":  resourceGroupFromID(clusterID),
					"subscription_id": subscriptionID,
					"tags":            cluster.Tags,
				}

				if len(cluster.Identity) > 0 {
					row["identity"] = cluster.Identity
				}

				if cluster.Properties != nil {
					row["kubernetes_version"] = ptrStr(cluster.Properties.KubernetesVersion)
					row["provisioning_state"] = ptrStr(cluster.Properties.ProvisioningState)
					row["dns_prefix"] = ptrStr(cluster.Properties.DNSPrefix)
					row["fqdn"] = ptrStr(cluster.Properties.FQDN)
					row["node_resource_group"] = ptrStr(cluster.Properties.NodeResourceGroup)
					row["agent_pool_count"] = len(cluster.Properties.AgentPoolProfiles)
					row["agent_pools"] = serializeAKSAgentPools(cluster.Properties.AgentPoolProfiles)

					if cluster.Properties.APIServerAccess != nil {
						if cluster.Properties.APIServerAccess.EnablePrivateCluster != nil {
							row["private_cluster_enabled"] = *cluster.Properties.APIServerAccess.EnablePrivateCluster
						}
						if len(cluster.Properties.APIServerAccess.AuthorizedIPRanges) > 0 {
							row["authorized_ip_ranges"] = cluster.Properties.APIServerAccess.AuthorizedIPRanges
						}
					}

					if cluster.Properties.NetworkProfile != nil {
						row["network_plugin"] = ptrStr(cluster.Properties.NetworkProfile.NetworkPlugin)
						row["network_policy"] = ptrStr(cluster.Properties.NetworkProfile.NetworkPolicy)
						row["outbound_type"] = ptrStr(cluster.Properties.NetworkProfile.OutboundType)
					}
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureAKSNodePoolTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_aks_node_pools",
		Columns: []string{
			"id",
			"cluster_id",
			"cluster_name",
			"name",
			"location",
			"resource_group",
			"node_resource_group",
			"count",
			"vm_size",
			"mode",
			"os_type",
			"orchestrator_version",
			"subscription_id",
			"tags",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			clusters, err := listAzureManagedClusters(ctx, cred, subscriptionID)
			if err != nil {
				return nil, err
			}

			results := make([]map[string]interface{}, 0)
			for _, cluster := range clusters {
				clusterID := ptrStr(cluster.ID)
				resourceGroup := resourceGroupFromID(clusterID)
				nodeResourceGroup := ""
				if cluster.Properties == nil {
					continue
				}
				nodeResourceGroup = ptrStr(cluster.Properties.NodeResourceGroup)
				for _, pool := range cluster.Properties.AgentPoolProfiles {
					poolID := strings.TrimSpace(clusterID)
					if poolName := ptrStr(pool.Name); poolID != "" && poolName != "" {
						poolID += "/agentPools/" + poolName
					}
					row := map[string]interface{}{
						"_cq_id":               poolID,
						"id":                   poolID,
						"cluster_id":           clusterID,
						"cluster_name":         ptrStr(cluster.Name),
						"name":                 ptrStr(pool.Name),
						"location":             ptrStr(cluster.Location),
						"resource_group":       resourceGroup,
						"node_resource_group":  nodeResourceGroup,
						"vm_size":              ptrStr(pool.VMSize),
						"mode":                 ptrStr(pool.Mode),
						"os_type":              ptrStr(pool.OSType),
						"orchestrator_version": ptrStr(pool.OrchestratorVersion),
						"subscription_id":      subscriptionID,
						"tags":                 cluster.Tags,
					}
					if pool.Count != nil {
						row["count"] = *pool.Count
					}
					results = append(results, row)
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureRBACRoleAssignmentTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_rbac_role_assignments",
		Columns: []string{
			"id",
			"name",
			"scope",
			"resource_group",
			"role_definition_id",
			"principal_id",
			"principal_type",
			"condition",
			"condition_version",
			"description",
			"can_delegate",
			"created_on",
			"updated_on",
			"created_by",
			"updated_by",
			"delegated_managed_identity_id",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			assignments, err := listAzureRoleAssignments(ctx, cred, subscriptionID)
			if err != nil {
				return nil, err
			}

			results := make([]map[string]interface{}, 0, len(assignments))
			for _, assignment := range assignments {
				assignmentID := ptrStr(assignment.ID)
				row := map[string]interface{}{
					"_cq_id":          assignmentID,
					"id":              assignmentID,
					"name":            ptrStr(assignment.Name),
					"resource_group":  resourceGroupFromID(assignmentID),
					"subscription_id": subscriptionID,
				}

				if assignment.Properties != nil {
					row["scope"] = ptrStr(assignment.Properties.Scope)
					row["role_definition_id"] = ptrStr(assignment.Properties.RoleDefinitionID)
					row["principal_id"] = ptrStr(assignment.Properties.PrincipalID)
					row["principal_type"] = ptrStr(assignment.Properties.PrincipalType)
					row["condition"] = ptrStr(assignment.Properties.Condition)
					row["condition_version"] = ptrStr(assignment.Properties.ConditionVersion)
					row["description"] = ptrStr(assignment.Properties.Description)
					row["created_on"] = ptrStr(assignment.Properties.CreatedOn)
					row["updated_on"] = ptrStr(assignment.Properties.UpdatedOn)
					row["created_by"] = ptrStr(assignment.Properties.CreatedBy)
					row["updated_by"] = ptrStr(assignment.Properties.UpdatedBy)
					row["delegated_managed_identity_id"] = ptrStr(assignment.Properties.DelegatedManagedIdentityID)
					if assignment.Properties.CanDelegate != nil {
						row["can_delegate"] = *assignment.Properties.CanDelegate
					}
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azurePolicyAssignmentTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_policy_assignments",
		Columns: []string{
			"id",
			"name",
			"assignment_type",
			"location",
			"display_name",
			"description",
			"scope",
			"resource_group",
			"policy_definition_id",
			"enforcement_mode",
			"not_scopes",
			"identity",
			"metadata",
			"parameters",
			"non_compliance_messages",
			"overrides",
			"resource_selectors",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			assignments, err := listAzurePolicyAssignments(ctx, cred, subscriptionID)
			if err != nil {
				return nil, err
			}

			results := make([]map[string]interface{}, 0, len(assignments))
			for _, assignment := range assignments {
				assignmentID := ptrStr(assignment.ID)
				row := map[string]interface{}{
					"_cq_id":          assignmentID,
					"id":              assignmentID,
					"name":            ptrStr(assignment.Name),
					"assignment_type": ptrStr(assignment.Type),
					"location":        ptrStr(assignment.Location),
					"resource_group":  resourceGroupFromID(assignmentID),
					"subscription_id": subscriptionID,
				}

				if len(assignment.Identity) > 0 {
					row["identity"] = assignment.Identity
				}

				if assignment.Properties != nil {
					row["display_name"] = ptrStr(assignment.Properties.DisplayName)
					row["description"] = ptrStr(assignment.Properties.Description)
					row["scope"] = ptrStr(assignment.Properties.Scope)
					row["policy_definition_id"] = ptrStr(assignment.Properties.PolicyDefinitionID)
					row["enforcement_mode"] = ptrStr(assignment.Properties.EnforcementMode)
					if len(assignment.Properties.NotScopes) > 0 {
						row["not_scopes"] = assignment.Properties.NotScopes
					}
					if len(assignment.Properties.Metadata) > 0 {
						row["metadata"] = assignment.Properties.Metadata
					}
					if len(assignment.Properties.Parameters) > 0 {
						row["parameters"] = assignment.Properties.Parameters
					}
					if len(assignment.Properties.NonComplianceMessages) > 0 {
						row["non_compliance_messages"] = assignment.Properties.NonComplianceMessages
					}
					if len(assignment.Properties.Overrides) > 0 {
						row["overrides"] = assignment.Properties.Overrides
					}
					if len(assignment.Properties.ResourceSelectors) > 0 {
						row["resource_selectors"] = assignment.Properties.ResourceSelectors
					}
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureGraphServicePrincipalTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_graph_service_principals",
		Columns: []string{
			"id",
			"app_id",
			"display_name",
			"service_principal_type",
			"account_enabled",
			"app_owner_organization_id",
			"app_role_assignment_required",
			"publisher_name",
			"verified_publisher_display_name",
			"verified_publisher_id",
			"verified_publisher_added_datetime",
			"created_date_time",
			"tags",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			servicePrincipals, err := listAzureGraphServicePrincipals(ctx, cred)
			if err != nil {
				if isAzureGraphPermissionError(err) {
					return []map[string]interface{}{}, nil
				}
				return nil, err
			}

			results := make([]map[string]interface{}, 0, len(servicePrincipals))
			for _, principal := range servicePrincipals {
				principalID := ptrStr(principal.ID)
				if principalID == "" {
					continue
				}

				row := map[string]interface{}{
					"_cq_id":                    azureScopedResourceID(subscriptionID, principalID),
					"id":                        principalID,
					"app_id":                    ptrStr(principal.AppID),
					"display_name":              ptrStr(principal.DisplayName),
					"service_principal_type":    ptrStr(principal.ServicePrincipalType),
					"app_owner_organization_id": ptrStr(principal.AppOwnerOrganizationID),
					"publisher_name":            ptrStr(principal.PublisherName),
					"created_date_time":         ptrStr(principal.CreatedDateTime),
					"subscription_id":           subscriptionID,
				}
				if principal.VerifiedPublisher != nil {
					row["verified_publisher_display_name"] = ptrStr(principal.VerifiedPublisher.DisplayName)
					row["verified_publisher_id"] = ptrStr(principal.VerifiedPublisher.VerifiedPublisherID)
					row["verified_publisher_added_datetime"] = ptrStr(principal.VerifiedPublisher.AddedDateTime)
				}

				if principal.AccountEnabled != nil {
					row["account_enabled"] = *principal.AccountEnabled
				}
				if principal.AppRoleAssignmentRequired != nil {
					row["app_role_assignment_required"] = *principal.AppRoleAssignmentRequired
				}
				if len(principal.Tags) > 0 {
					row["tags"] = principal.Tags
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureDefenderAssessmentTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_defender_assessments",
		Columns: []string{
			"id",
			"name",
			"assessment_type",
			"display_name",
			"description",
			"status_code",
			"status_cause",
			"status_description",
			"resource_id",
			"resource_source",
			"severity",
			"remediation_description",
			"metadata",
			"additional_data",
			"links",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			assessments, err := listAzureDefenderAssessments(ctx, cred, subscriptionID)
			if err != nil {
				return nil, err
			}

			results := make([]map[string]interface{}, 0, len(assessments))
			for _, assessment := range assessments {
				assessmentID := ptrStr(assessment.ID)
				row := map[string]interface{}{
					"_cq_id":          assessmentID,
					"id":              assessmentID,
					"name":            ptrStr(assessment.Name),
					"assessment_type": ptrStr(assessment.Type),
					"subscription_id": subscriptionID,
				}

				if assessment.Properties != nil {
					row["display_name"] = ptrStr(assessment.Properties.DisplayName)
					row["description"] = ptrStr(assessment.Properties.Description)
					row["remediation_description"] = ptrStr(assessment.Properties.RemediationDescription)

					if assessment.Properties.Status != nil {
						row["status_code"] = ptrStr(assessment.Properties.Status.Code)
						row["status_cause"] = ptrStr(assessment.Properties.Status.Cause)
						row["status_description"] = ptrStr(assessment.Properties.Status.Description)
					}

					if len(assessment.Properties.ResourceDetails) > 0 {
						row["resource_id"] = mapStringAnyFold(assessment.Properties.ResourceDetails, "id", "resourceId")
						row["resource_source"] = mapStringAnyFold(assessment.Properties.ResourceDetails, "source")
					}

					if len(assessment.Properties.Metadata) > 0 {
						row["metadata"] = assessment.Properties.Metadata
						row["severity"] = mapStringAnyFold(assessment.Properties.Metadata, "severity")
					}

					if len(assessment.Properties.AdditionalData) > 0 {
						row["additional_data"] = assessment.Properties.AdditionalData
					}

					if len(assessment.Properties.Links) > 0 {
						row["links"] = assessment.Properties.Links
					}
				}

				results = append(results, row)
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureStorageContainerTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_storage_containers",
		Columns: []string{
			"id", "name", "account_name", "resource_group", "public_access",
			"immutability_policy", "has_immutability_policy", "legal_hold",
			"metadata", "last_modified", "lease_status", "lease_state",
			"subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			accountsClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}
			containersClient, err := armstorage.NewBlobContainersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			accountsPager := accountsClient.NewListPager(nil)
			for accountsPager.More() {
				page, err := accountsPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, account := range page.Value {
					accountName := ptrStr(account.Name)
					resourceGroup := resourceGroupFromID(ptrStr(account.ID))
					if accountName == "" || resourceGroup == "" {
						continue
					}

					containersPager := containersClient.NewListPager(resourceGroup, accountName, nil)
					for containersPager.More() {
						containerPage, err := containersPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, container := range containerPage.Value {
							row := map[string]interface{}{
								"_cq_id":          ptrStr(container.ID),
								"id":              ptrStr(container.ID),
								"name":            ptrStr(container.Name),
								"account_name":    accountName,
								"resource_group":  resourceGroup,
								"subscription_id": subscriptionID,
							}

							if container.Properties != nil {
								row["public_access"] = ptrToStringValue(container.Properties.PublicAccess)
								row["metadata"] = container.Properties.Metadata
								row["last_modified"] = container.Properties.LastModifiedTime
								row["lease_status"] = container.Properties.LeaseStatus
								row["lease_state"] = container.Properties.LeaseState
								row["legal_hold"] = container.Properties.LegalHold
								row["immutability_policy"] = container.Properties.ImmutabilityPolicy
								row["has_immutability_policy"] = container.Properties.ImmutabilityPolicy != nil
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureStorageBlobTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_storage_blobs",
		Columns: []string{
			"id", "name", "container_name", "account_name", "resource_group",
			"content_length", "content_type", "etag", "last_modified", "blob_type",
			"access_tier", "metadata", "snapshot", "version_id", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			accountsClient, err := armstorage.NewAccountsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}
			containersClient, err := armstorage.NewBlobContainersClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			accountsPager := accountsClient.NewListPager(nil)
			for accountsPager.More() {
				page, err := accountsPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, account := range page.Value {
					accountName := ptrStr(account.Name)
					resourceGroup := resourceGroupFromID(ptrStr(account.ID))
					if accountName == "" || resourceGroup == "" {
						continue
					}

					serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)
					blobClient, err := azblob.NewClient(serviceURL, cred, nil)
					if err != nil {
						return nil, err
					}

					containersPager := containersClient.NewListPager(resourceGroup, accountName, nil)
					for containersPager.More() {
						containerPage, err := containersPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, container := range containerPage.Value {
							containerName := ptrStr(container.Name)
							if containerName == "" {
								continue
							}

							pager := blobClient.NewListBlobsFlatPager(containerName, nil)
							for pager.More() {
								resp, err := pager.NextPage(ctx)
								if err != nil {
									return nil, err
								}
								for _, item := range resp.Segment.BlobItems {
									blobName := ptrStr(item.Name)
									blobID := fmt.Sprintf("%s%s/%s", serviceURL, containerName, blobName)
									row := map[string]interface{}{
										"_cq_id":          blobID,
										"id":              blobID,
										"name":            blobName,
										"container_name":  containerName,
										"account_name":    accountName,
										"resource_group":  resourceGroup,
										"subscription_id": subscriptionID,
										"metadata":        item.Metadata,
										"snapshot":        ptrStr(item.Snapshot),
										"version_id":      ptrStr(item.VersionID),
									}

									if item.Properties != nil {
										row["content_length"] = item.Properties.ContentLength
										row["content_type"] = ptrStr(item.Properties.ContentType)
										row["etag"] = ptrToStringValue(item.Properties.ETag)
										row["last_modified"] = item.Properties.LastModified
										row["blob_type"] = item.Properties.BlobType
										row["access_tier"] = item.Properties.AccessTier
									}

									results = append(results, row)
								}
							}
						}
					}
				}
			}

			return results, nil
		},
	}
}

func (e *AzureSyncEngine) azureKeyVaultKeyTable() AzureTableSpec {
	return AzureTableSpec{
		Name: "azure_keyvault_keys",
		Columns: []string{
			"id", "name", "vault_uri", "attributes", "tags", "managed", "subscription_id",
		},
		Fetch: func(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]map[string]interface{}, error) {
			vaultClient, err := armkeyvault.NewVaultsClient(subscriptionID, cred, nil)
			if err != nil {
				return nil, err
			}

			var results []map[string]interface{}
			pager := vaultClient.NewListBySubscriptionPager(nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, vault := range page.Value {
					vaultURI := ""
					if vault.Properties != nil {
						vaultURI = ptrStr(vault.Properties.VaultURI)
					}
					if vaultURI == "" {
						continue
					}

					keyClient, err := azkeys.NewClient(vaultURI, cred, nil)
					if err != nil {
						return nil, err
					}

					keyPager := keyClient.NewListKeyPropertiesPager(nil)
					for keyPager.More() {
						keyPage, err := keyPager.NextPage(ctx)
						if err != nil {
							return nil, err
						}
						for _, key := range keyPage.Value {
							keyID := ""
							keyName := ""
							if key.KID != nil {
								keyID = string(*key.KID)
								keyName = key.KID.Name()
							}
							row := map[string]interface{}{
								"_cq_id":          keyID,
								"id":              keyID,
								"name":            keyName,
								"vault_uri":       vaultURI,
								"tags":            key.Tags,
								"managed":         key.Managed,
								"subscription_id": subscriptionID,
							}
							if key.Attributes != nil {
								row["attributes"] = map[string]interface{}{
									"enabled":    key.Attributes.Enabled,
									"created":    key.Attributes.Created,
									"updated":    key.Attributes.Updated,
									"not_before": key.Attributes.NotBefore,
									"expires":    key.Attributes.Expires,
								}
							}

							results = append(results, row)
						}
					}
				}
			}

			return results, nil
		},
	}
}

func listAzureManagedClusters(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]azureManagedCluster, error) {
	token, err := azureManagementToken(ctx, cred)
	if err != nil {
		return nil, err
	}

	nextURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.ContainerService/managedClusters?api-version=%s", subscriptionID, azureAKSManagedClustersAPIVersion)
	clusters := make([]azureManagedCluster, 0)
	for nextURL != "" {
		var page azureManagedClusterListResponse
		if err := fetchAzureManagementPage(ctx, token, nextURL, &page); err != nil {
			return nil, fmt.Errorf("list AKS clusters: %w", err)
		}

		clusters = append(clusters, page.Value...)
		nextURL = strings.TrimSpace(page.NextLink)
	}

	return clusters, nil
}

func listAzureRoleAssignments(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]azureRoleAssignment, error) {
	token, err := azureManagementToken(ctx, cred)
	if err != nil {
		return nil, err
	}

	nextURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subscriptionID)
	assignments := make([]azureRoleAssignment, 0)
	for nextURL != "" {
		var page azureRoleAssignmentListResponse
		if err := fetchAzureManagementPage(ctx, token, nextURL, &page); err != nil {
			return nil, fmt.Errorf("list role assignments: %w", err)
		}

		assignments = append(assignments, page.Value...)
		nextURL = strings.TrimSpace(page.NextLink)
	}

	return assignments, nil
}

func listAzurePolicyAssignments(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]azurePolicyAssignment, error) {
	token, err := azureManagementToken(ctx, cred)
	if err != nil {
		return nil, err
	}

	nextURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/policyAssignments?api-version=%s", subscriptionID, azurePolicyAssignmentsAPIVersion)
	assignments := make([]azurePolicyAssignment, 0)
	for nextURL != "" {
		var page azurePolicyAssignmentListResponse
		if err := fetchAzureManagementPage(ctx, token, nextURL, &page); err != nil {
			return nil, fmt.Errorf("list policy assignments: %w", err)
		}

		assignments = append(assignments, page.Value...)
		nextURL = strings.TrimSpace(page.NextLink)
	}

	return assignments, nil
}

func listAzureGraphServicePrincipals(ctx context.Context, cred *azidentity.DefaultAzureCredential) ([]azureGraphServicePrincipal, error) {
	token, err := azureGraphToken(ctx, cred)
	if err != nil {
		return nil, err
	}

	nextURL := "https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,appRoleAssignmentRequired,publisherName,verifiedPublisher,createdDateTime,tags"
	servicePrincipals := make([]azureGraphServicePrincipal, 0)
	for nextURL != "" {
		var page azureGraphServicePrincipalListResponse
		if err := fetchAzureGraphPage(ctx, token, nextURL, &page); err != nil {
			return nil, fmt.Errorf("list graph service principals: %w", err)
		}

		servicePrincipals = append(servicePrincipals, page.Value...)
		nextURL = strings.TrimSpace(page.NextLink)
	}

	return servicePrincipals, nil
}

func listAzureDefenderAssessments(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) ([]azureDefenderAssessment, error) {
	token, err := azureManagementToken(ctx, cred)
	if err != nil {
		return nil, err
	}

	nextURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/providers/Microsoft.Security/assessments?api-version=%s", subscriptionID, azureDefenderAssessmentsAPIVersion)
	assessments := make([]azureDefenderAssessment, 0)
	for nextURL != "" {
		var page azureDefenderAssessmentListResponse
		if err := fetchAzureManagementPage(ctx, token, nextURL, &page); err != nil {
			return nil, fmt.Errorf("list defender assessments: %w", err)
		}

		assessments = append(assessments, page.Value...)
		nextURL = strings.TrimSpace(page.NextLink)
	}

	return assessments, nil
}

func azureManagementToken(ctx context.Context, cred *azidentity.DefaultAzureCredential) (string, error) {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureManagementScope}})
	if err != nil {
		return "", fmt.Errorf("acquire Azure management token: %w", err)
	}
	return token.Token, nil
}

func azureGraphToken(ctx context.Context, cred *azidentity.DefaultAzureCredential) (string, error) {
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureGraphScope}})
	if err != nil {
		return "", fmt.Errorf("acquire Azure Graph token: %w", err)
	}
	return token.Token, nil
}

func fetchAzureManagementPage(ctx context.Context, token, requestURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := azureManagementHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request management endpoint: %w", err)
	}

	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read response body: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close response body: %w", closeErr)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func fetchAzureGraphPage(ctx context.Context, token, requestURL string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := azureGraphHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request graph endpoint: %w", err)
	}

	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read response body: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close response body: %w", closeErr)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func serializeAKSAgentPools(pools []azureManagedClusterAgentPool) []map[string]interface{} {
	if len(pools) == 0 {
		return nil
	}

	serialized := make([]map[string]interface{}, 0, len(pools))
	for _, pool := range pools {
		var count interface{}
		if pool.Count != nil {
			count = *pool.Count
		}

		entry := map[string]interface{}{
			"name":                 ptrStr(pool.Name),
			"count":                count,
			"vm_size":              ptrStr(pool.VMSize),
			"mode":                 ptrStr(pool.Mode),
			"os_type":              ptrStr(pool.OSType),
			"orchestrator_version": ptrStr(pool.OrchestratorVersion),
		}
		serialized = append(serialized, entry)
	}

	return serialized
}

func mapStringAnyFold(values map[string]interface{}, keys ...string) string {
	if len(values) == 0 || len(keys) == 0 {
		return ""
	}

	for _, key := range keys {
		for existingKey, value := range values {
			if !strings.EqualFold(strings.TrimSpace(existingKey), strings.TrimSpace(key)) {
				continue
			}
			resolved := strings.TrimSpace(toString(value))
			if resolved != "" {
				return resolved
			}
		}
	}

	return ""
}

func isAzureGraphPermissionError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "authorization_requestdenied") ||
		strings.Contains(message, "insufficient privileges") ||
		strings.Contains(message, "insufficientprivileges") ||
		strings.Contains(message, "forbidden") ||
		strings.Contains(message, "status 401") ||
		strings.Contains(message, "status 403")
}

func azureScopedResourceID(subscriptionID, resourceID string) string {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "" {
		return ""
	}

	subscriptionID = strings.TrimSpace(subscriptionID)
	if subscriptionID == "" {
		return resourceID
	}

	return subscriptionID + ":" + resourceID
}

func isFunctionApp(kind *string) bool {
	if kind == nil {
		return false
	}
	return strings.Contains(strings.ToLower(*kind), "functionapp")
}

func fetchFunctionAppAuth(ctx context.Context, client *armappservice.WebAppsClient, resourceGroup, name string) (string, bool, error) {
	if resourceGroup == "" || name == "" {
		return "", false, nil
	}

	pager := client.NewListFunctionsPager(resourceGroup, name, nil)
	var authLevel string
	var httpTrigger bool

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", false, err
		}
		for _, fn := range page.Value {
			level, hasHTTP := parseFunctionBindings(fn.Properties)
			if hasHTTP {
				httpTrigger = true
				if level != "" {
					if authLevel == "" || strings.EqualFold(level, "anonymous") {
						authLevel = strings.ToLower(level)
					}
				}
			}
		}
	}

	return authLevel, httpTrigger, nil
}

func parseFunctionBindings(properties *armappservice.FunctionEnvelopeProperties) (string, bool) {
	if properties == nil || properties.Config == nil {
		return "", false
	}

	configBytes, err := json.Marshal(properties.Config)
	if err != nil {
		return "", false
	}
	var config map[string]interface{}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return "", false
	}

	bindingsValue, ok := config["bindings"]
	if !ok {
		return "", false
	}
	bindings, ok := bindingsValue.([]interface{})
	if !ok {
		return "", false
	}

	var authLevel string
	var httpTrigger bool
	for _, binding := range bindings {
		bindingMap, ok := binding.(map[string]interface{})
		if !ok {
			continue
		}
		bindingType, _ := bindingMap["type"].(string)
		if strings.EqualFold(bindingType, "httpTrigger") {
			httpTrigger = true
			if level, ok := bindingMap["authLevel"].(string); ok {
				authLevel = level
			}
		}
	}

	return authLevel, httpTrigger
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ptrToStringValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

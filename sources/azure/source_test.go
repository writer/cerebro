package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "azure" {
		t.Fatalf("Spec().Id = %q, want azure", source.Spec().Id)
	}
}

func TestCheckRequiresTenantAndToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want missing tenant_id error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant-1"})); err == nil {
		t.Fatal("Check() error = nil, want missing token error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant-1", "token": "test-token", "family": familyActivityLog})); err == nil {
		t.Fatal("Check() error = nil, want missing subscription_id error")
	}
}

func TestNewFixtureReplaysAzureFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyActivityLog, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.activity_log"},
		{family: familyAKSCluster, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.aks_cluster"},
		{family: familyAppRoleAssignment, config: map[string]string{"service_principal_id": "sp-resource-1"}, kind: "azure.app_role_assignment"},
		{family: familyAppService, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.app_service"},
		{family: familyApplication, kind: "azure.application"},
		{family: familyAssetMetadata, config: map[string]string{"subscription_id": "sub-1"}, kind: "asset.data_sensitivity"},
		{family: "cognitive_services_account", config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.cognitive_services_account"},
		{family: familyContainerRegistry, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.container_registry"},
		{family: familyCosmosAccount, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.cosmos_account"},
		{family: familyCredential, kind: "azure.credential"},
		{family: familyDirectoryAudit, kind: "azure.directory_audit"},
		{family: familyDirectoryRoleAssign, kind: "azure.directory_role_assignment"},
		{family: familyEffectivePermission, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.effective_permission"},
		{family: familyFunctionApp, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.function_app"},
		{family: familyGroup, kind: "azure.group"},
		{family: familyGroupMember, config: map[string]string{"group_id": "group-1"}, kind: "azure.group_membership"},
		{family: familyIAMRoleAssign, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.iam_role_assignment"},
		{family: familyKeyVault, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.key_vault"},
		{family: familyKeyVaultKey, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.key_vault_key"},
		{family: familyKeyVaultSecret, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.key_vault_secret"},
		{family: familyManagedDisk, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.managed_disk"},
		{family: familyNetworkSecurityGrp, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.network_security_group"},
		{family: familyPublicIPAddress, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.public_ip_address"},
		{family: familyResourceExposure, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.resource_exposure"},
		{family: familyServicePrincipal, kind: "azure.service_principal"},
		{family: familySQLDatabase, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.sql_database"},
		{family: familySQLServer, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.sql_server"},
		{family: familyStorageAccount, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.storage_account"},
		{family: familyUser, kind: "azure.user"},
		{family: familyVirtualMachine, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.virtual_machine"},
		{family: familyVirtualNetwork, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.virtual_network"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"tenant_id": "tenant-1", "family": tt.family, "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
		})
	}
}

func TestReadLiveAzureGraphIdentityPreview(t *testing.T) {
	server := httptest.NewServer(newAzureAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: familyUser, kind: "azure.user", attr: "email", want: "admin@writer.com"},
		{family: familyGroup, kind: "azure.group", attr: "group_email", want: "security@writer.com"},
		{family: familyGroupMember, config: map[string]string{"group_id": "group-1"}, kind: "azure.group_membership", attr: "member_type", want: "service_principal"},
		{family: familyApplication, kind: "azure.application", attr: "app_id", want: "app-client-1"},
		{family: familyServicePrincipal, kind: "azure.service_principal", attr: "principal_type", want: "service_principal"},
		{family: familyDirectoryRoleAssign, kind: "azure.directory_role_assignment", attr: "is_admin", want: "true"},
		{family: familyDirectoryAudit, kind: "azure.directory_audit", attr: "actor_email", want: "admin@writer.com"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "tenant-1", "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestReadLiveAzureCredentialPreview(t *testing.T) {
	server := httptest.NewServer(newAzureAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyCredential, "tenant_id": "tenant-1", "token": "test-token"}), nil)
	if err != nil {
		t.Fatalf("Read(credential) error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["credential_type"]; got != "azure_application_password" {
		t.Fatalf("credential_type = %q, want azure_application_password", got)
	}
	if got := pull.Events[1].Attributes["credential_type"]; got != "azure_service_principal_key" {
		t.Fatalf("credential_type = %q, want azure_service_principal_key", got)
	}
}

func TestReadLiveAzureARMPreview(t *testing.T) {
	server := httptest.NewServer(newAzureAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: familyIAMRoleAssign, kind: "azure.iam_role_assignment", attr: "role_name", want: "Owner"},
		{family: familyEffectivePermission, kind: "azure.effective_permission", attr: "privilege_level", want: "admin"},
		{family: familyAssetMetadata, kind: "asset.data_sensitivity", attr: "data_classification", want: "restricted"},
		{family: familyVirtualMachine, kind: "azure.virtual_machine", attr: "public_host", want: "vm1.eastus.cloudapp.azure.com"},
		{family: familyVirtualNetwork, kind: "azure.virtual_network", attr: "address_prefixes", want: "10.0.0.0/16"},
		{family: familyNetworkSecurityGrp, kind: "azure.network_security_group", attr: "security_rule_names", want: "AllowHTTPS"},
		{family: familyPublicIPAddress, kind: "azure.public_ip_address", attr: "public_host", want: "vm1.eastus.cloudapp.azure.com"},
		{family: familyManagedDisk, kind: "azure.managed_disk", attr: "disk_state", want: "Attached"},
		{family: familyAKSCluster, kind: "azure.aks_cluster", attr: "public_host", want: "aks-prod.eastus.azmk8s.io"},
		{family: familyAppService, kind: "azure.app_service", attr: "https_only", want: "true"},
		{family: familyFunctionApp, kind: "azure.function_app", attr: "https_only", want: "true"},
		{family: familyFunctionApp, kind: "azure.function_app", attr: "runtime", want: "NODE|18-lts"},
		{family: familyStorageAccount, kind: "azure.storage_account", attr: "min_tls_version", want: "TLS1_2"},
		{family: familySQLServer, kind: "azure.sql_server", attr: "public_network_access", want: "Enabled"},
		{family: familySQLDatabase, kind: "azure.sql_database", attr: "backup_storage_redundancy", want: "Geo"},
		{family: familyKeyVault, kind: "azure.key_vault", attr: "purge_protection_enabled", want: "true"},
		{family: familyKeyVaultKey, kind: "azure.key_vault_key", attr: "recovery_level", want: "Recoverable+Purgeable"},
		{family: familyKeyVaultSecret, kind: "azure.key_vault_secret", attr: "content_type", want: "connection-string"},
		{family: familyCosmosAccount, kind: "azure.cosmos_account", attr: "local_auth_disabled", want: "true"},
		{family: "cognitive_services_account", kind: "azure.cognitive_services_account", attr: "kind", want: "OpenAI"},
		{family: "cognitive_services_account", kind: "azure.cognitive_services_account", attr: "public_network_access", want: "Enabled"},
		{family: familyContainerRegistry, kind: "azure.container_registry", attr: "admin_user_enabled", want: "false"},
		{family: familyActivityLog, kind: "azure.activity_log", attr: "actor_email", want: "admin@writer.com"},
		{family: familyResourceExposure, kind: "azure.resource_exposure", attr: "internet_exposed", want: "true"},
		{family: familyAppRoleAssignment, config: map[string]string{"service_principal_id": "sp-resource-1"}, kind: "azure.app_role_assignment", attr: "relationship", want: "assigned_to"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"base_url": server.URL, "family": tt.family, "subscription_id": "sub-1", "tenant_id": "tenant-1", "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestListSQLDatabasesDrainsServerAndDatabasePages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Sql/servers":
			if r.URL.Query().Get("page") == "2" {
				writeJSON(t, w, map[string]any{"value": []map[string]any{azureSQLServerPayload("sql-b")}})
				return
			}
			writeJSON(t, w, map[string]any{
				"value":    []map[string]any{azureSQLServerPayload("sql-a")},
				"nextLink": serverURL(r) + "/subscriptions/sub-1/providers/Microsoft.Sql/servers?page=2",
			})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-a/databases":
			if r.URL.Query().Get("page") == "2" {
				writeJSON(t, w, map[string]any{"value": []map[string]any{azureSQLDatabasePayload("sql-a", "db-a2")}})
				return
			}
			writeJSON(t, w, map[string]any{
				"value":    []map[string]any{azureSQLDatabasePayload("sql-a", "db-a1")},
				"nextLink": serverURL(r) + "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-a/databases?page=2",
			})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-b/databases":
			writeJSON(t, w, map[string]any{"value": []map[string]any{azureSQLDatabasePayload("sql-b", "db-b1")}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, settings := newAzurePaginationTestSource(t, server, familySQLDatabase)

	records, next, err := listSQLDatabases(context.Background(), source, settings, "", 1)
	if err != nil {
		t.Fatalf("listSQLDatabases: %v", err)
	}
	if next != "" {
		t.Fatalf("next = %q, want empty after draining nested pages", next)
	}
	if got, want := len(records), 3; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}
	if records[0].Database.Name != "db-a1" || records[1].Database.Name != "db-a2" || records[2].Database.Name != "db-b1" {
		t.Fatalf("database order = %q, %q, %q", records[0].Database.Name, records[1].Database.Name, records[2].Database.Name)
	}
}

func TestListKeyVaultChildrenDrainsVaultAndChildPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults":
			if r.URL.Query().Get("page") == "2" {
				writeJSON(t, w, map[string]any{"value": []map[string]any{azureKeyVaultPayload("kv-b")}})
				return
			}
			writeJSON(t, w, map[string]any{
				"value":    []map[string]any{azureKeyVaultPayload("kv-a")},
				"nextLink": serverURL(r) + "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults?page=2",
			})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-a/keys":
			if r.URL.Query().Get("page") == "2" {
				writeJSON(t, w, map[string]any{"value": []map[string]any{azureKeyVaultKeyPayload("kv-a", "key-a2")}})
				return
			}
			writeJSON(t, w, map[string]any{
				"value":    []map[string]any{azureKeyVaultKeyPayload("kv-a", "key-a1")},
				"nextLink": serverURL(r) + "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-a/keys?page=2",
			})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-b/keys":
			writeJSON(t, w, map[string]any{"value": []map[string]any{azureKeyVaultKeyPayload("kv-b", "key-b1")}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, settings := newAzurePaginationTestSource(t, server, familyKeyVaultKey)

	records, next, err := listKeyVaultKeys(context.Background(), source, settings, "", 1)
	if err != nil {
		t.Fatalf("listKeyVaultKeys: %v", err)
	}
	if next != "" {
		t.Fatalf("next = %q, want empty after draining nested pages", next)
	}
	if got, want := len(records), 3; got != want {
		t.Fatalf("len(records) = %d, want %d", got, want)
	}
	if records[0].Resource.Name != "key-a1" || records[1].Resource.Name != "key-a2" || records[2].Resource.Name != "key-b1" {
		t.Fatalf("key order = %q, %q, %q", records[0].Resource.Name, records[1].Resource.Name, records[2].Resource.Name)
	}
}

func TestAzureAppRoleAssignmentDerivesUserPrincipalEmail(t *testing.T) {
	event, err := appRoleAssignmentEvent(settings{tenantID: "tenant-1"}, appRoleAssignmentRecord{
		ID:                   "app-role-assignment-1",
		PrincipalID:          "user-1",
		PrincipalDisplayName: "admin@writer.com",
		PrincipalType:        "User",
		ResourceID:           "sp-resource-1",
		ResourceDisplayName:  "Graph API",
		AppRoleID:            "role-1",
	})
	if err != nil {
		t.Fatalf("appRoleAssignmentEvent() error = %v", err)
	}
	if got := event.Attributes["subject_email"]; got != "admin@writer.com" {
		t.Fatalf("subject_email = %q, want admin@writer.com", got)
	}
	if got := event.Attributes["subject_login"]; got != "admin@writer.com" {
		t.Fatalf("subject_login = %q, want admin@writer.com", got)
	}
}

func TestReadAzureIAMRoleAssignmentResolvesPrincipalEmail(t *testing.T) {
	server := httptest.NewServer(newAzureAPIHandler(t))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":        server.URL,
		"family":          familyIAMRoleAssign,
		"subscription_id": "sub-1",
		"tenant_id":       "tenant-1",
		"token":           "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(%s) error = %v", familyIAMRoleAssign, err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["subject_email"]; got != "admin@writer.com" {
		t.Fatalf("subject_email = %q, want admin@writer.com", got)
	}
}

func TestListAzureIAMRoleAssignmentsCachesResolvedMetadata(t *testing.T) {
	var roleDefinitionLookups int
	var principalLookups int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			writeJSON(t, w, map[string]any{"value": []map[string]any{
				{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-1", "name": "ra-1", "properties": map[string]any{"principalId": "user-1", "principalType": "User", "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "scope": "/subscriptions/sub-1"}},
				{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-2", "name": "ra-2", "properties": map[string]any{"principalId": "user-1", "principalType": "User", "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "scope": "/subscriptions/sub-1"}},
			}})
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role":
			roleDefinitionLookups++
			writeJSON(t, w, map[string]any{"properties": map[string]any{"roleName": "Owner"}})
		case "/v1.0/users/user-1":
			principalLookups++
			writeJSON(t, w, map[string]any{"@odata.type": "#microsoft.graph.user", "id": "user-1", "userPrincipalName": "admin@writer.com", "mail": "admin@writer.com"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	settings := settings{baseURL: server.URL, tenantID: "tenant-1", subscriptionID: "sub-1", token: "test-token"}

	baseRecords, _, err := listIAMRoleAssignmentsBase(context.Background(), source, settings, "", 10)
	if err != nil {
		t.Fatalf("listIAMRoleAssignmentsBase() error = %v", err)
	}
	if len(baseRecords) != 2 {
		t.Fatalf("len(baseRecords) = %d, want 2", len(baseRecords))
	}
	if roleDefinitionLookups != 0 || principalLookups != 0 {
		t.Fatalf("base list made enrichment calls: role=%d principal=%d", roleDefinitionLookups, principalLookups)
	}

	records, _, err := listIAMRoleAssignments(context.Background(), source, settings, "", 10)
	if err != nil {
		t.Fatalf("listIAMRoleAssignments() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(records))
	}
	if roleDefinitionLookups != 1 {
		t.Fatalf("role definition lookups = %d, want 1", roleDefinitionLookups)
	}
	if principalLookups != 1 {
		t.Fatalf("principal lookups = %d, want 1", principalLookups)
	}
}

func newLiveTestSource() (*Source, error) {
	source, err := New()
	if err != nil {
		return nil, err
	}
	source.allowLoopbackBaseURL = true
	source.client = source.safeClient()
	return source, nil
}

func newAzureAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
			return
		}
		switch r.URL.Path {
		case "/v1.0/users":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "user-1", "userPrincipalName": "admin@writer.com", "mail": "admin@writer.com", "displayName": "Admin", "accountEnabled": true, "createdDateTime": "2026-04-23T00:00:00Z", "signInActivity": map[string]any{"lastSignInDateTime": "2026-04-24T00:00:00Z"}}}})
		case "/v1.0/users/user-1":
			writeJSON(t, w, map[string]any{"@odata.type": "#microsoft.graph.user", "id": "user-1", "userPrincipalName": "admin@writer.com", "mail": "admin@writer.com", "displayName": "Admin"})
		case "/v1.0/groups":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "group-1", "mail": "security@writer.com", "displayName": "Security", "securityEnabled": true, "mailEnabled": true}}})
		case "/v1.0/groups/group-1/members":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-1", "appId": "app-client-1", "displayName": "Prod App"}}})
		case "/v1.0/servicePrincipals/sp-resource-1/appRoleAssignedTo":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "app-role-assignment-1", "principalId": "sp-1", "principalDisplayName": "Prod App", "principalType": "ServicePrincipal", "resourceId": "sp-resource-1", "resourceDisplayName": "Graph API", "appRoleId": "role-1", "createdDateTime": "2026-04-23T00:00:00Z"}}})
		case "/v1.0/applications":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "app-object-1", "appId": "app-client-1", "displayName": "Prod App", "createdDateTime": "2026-04-23T00:00:00Z", "passwordCredentials": []map[string]any{{"keyId": "app-password-1", "displayName": "deploy secret", "startDateTime": "2026-04-23T00:00:00Z", "endDateTime": "2027-04-23T00:00:00Z"}}}}})
		case "/v1.0/servicePrincipals":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "sp-1", "appId": "app-client-1", "displayName": "Prod App", "servicePrincipalType": "Application", "accountEnabled": true, "keyCredentials": []map[string]any{{"keyId": "sp-key-1", "displayName": "certificate", "startDateTime": "2026-04-23T00:00:00Z", "endDateTime": "2027-04-23T00:00:00Z", "type": "AsymmetricX509Cert", "usage": "Verify"}}}}})
		case "/v1.0/roleManagement/directory/roleAssignments":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "dir-role-assignment-1", "principalId": "user-1", "roleDefinitionId": "global-admin", "directoryScopeId": "/", "principal": map[string]any{"@odata.type": "#microsoft.graph.user", "id": "user-1", "userPrincipalName": "admin@writer.com", "mail": "admin@writer.com", "displayName": "Admin"}, "roleDefinition": map[string]any{"id": "global-admin", "displayName": "Global Administrator"}}}})
		case "/v1.0/auditLogs/directoryAudits":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "audit-1", "activityDateTime": "2026-04-23T00:00:00Z", "activityDisplayName": "Update conditional access policy", "operationType": "Update", "category": "Policy", "initiatedBy": map[string]any{"user": map[string]any{"id": "user-1", "userPrincipalName": "admin@writer.com", "displayName": "Admin"}}, "targetResources": []map[string]any{{"id": "policy-1", "displayName": "Require MFA", "type": "conditional_access_policy"}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-1", "name": "ra-1", "type": "Microsoft.Authorization/roleAssignments", "properties": map[string]any{"principalId": "user-1", "principalType": "User", "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "scope": "/subscriptions/sub-1"}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role":
			writeJSON(t, w, map[string]any{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "name": "owner-role", "properties": map[string]any{"roleName": "Owner", "type": "BuiltInRole"}})
		case "/subscriptions/sub-1/resources":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/data", "name": "data", "type": "Microsoft.Storage/storageAccounts", "location": "eastus", "tags": map[string]string{"data_classification": "restricted", "owner": "security@writer.com", "tier": "critical", "pii": "true", "env": "prod"}}}})
		case "/subscriptions/sub-1/providers/Microsoft.CognitiveServices/accounts":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.CognitiveServices/accounts/openai-prod", "name": "openai-prod", "type": "Microsoft.CognitiveServices/accounts", "kind": "OpenAI", "location": "eastus", "sku": map[string]any{"name": "S0", "tier": "Standard"}, "identity": map[string]any{"type": "SystemAssigned", "principalId": "openai-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "ai@writer.com", "team": "ai", "env": "prod"}, "properties": map[string]any{"publicNetworkAccess": "Enabled", "provisioningState": "Succeeded", "customSubDomainName": "openai-prod"}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Compute/virtualMachines":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm1", "name": "vm1", "type": "Microsoft.Compute/virtualMachines", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "vm-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "platform@writer.com", "team": "platform", "env": "prod"}, "properties": map[string]any{"hardwareProfile": map[string]any{"vmSize": "Standard_D2s_v5"}, "osProfile": map[string]any{"computerName": "vm1", "adminUsername": "azureuser"}, "storageProfile": map[string]any{"osDisk": map[string]any{"osType": "Linux"}}, "securityProfile": map[string]any{"encryptionAtHost": true}, "diagnosticsProfile": map[string]any{"bootDiagnostics": map[string]any{"enabled": true}}, "networkProfile": map[string]any{"networkInterfaces": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/vm1-nic"}}}}}}})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/vm1-nic":
			writeJSON(t, w, map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/vm1-nic", "name": "vm1-nic", "type": "Microsoft.Network/networkInterfaces", "location": "eastus", "properties": map[string]any{"networkSecurityGroup": map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg"}, "ipConfigurations": []map[string]any{{"name": "ipconfig1", "properties": map[string]any{"subnet": map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/web"}, "publicIPAddress": map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/vm1-pip"}}}}}})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/vm1-pip":
			writeJSON(t, w, map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/vm1-pip", "name": "vm1-pip", "type": "Microsoft.Network/publicIPAddresses", "location": "eastus", "properties": map[string]any{"ipAddress": "203.0.113.10", "dnsSettings": map[string]any{"fqdn": "vm1.eastus.cloudapp.azure.com"}}})
		case "/subscriptions/sub-1/providers/Microsoft.Network/virtualNetworks":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet", "name": "prod-vnet", "type": "Microsoft.Network/virtualNetworks", "location": "eastus", "tags": map[string]string{"env": "prod"}, "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []string{"10.0.0.0/16"}}, "enableDdosProtection": true, "subnets": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/web", "name": "web"}}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Network/publicIPAddresses":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/vm1-pip", "name": "vm1-pip", "type": "Microsoft.Network/publicIPAddresses", "location": "eastus", "sku": map[string]string{"name": "Standard"}, "properties": map[string]any{"ipAddress": "203.0.113.10", "publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4", "dnsSettings": map[string]any{"fqdn": "vm1.eastus.cloudapp.azure.com"}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Compute/disks":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/disks/vm1-osdisk", "name": "vm1-osdisk", "type": "Microsoft.Compute/disks", "location": "eastus", "sku": map[string]string{"name": "Premium_LRS"}, "properties": map[string]any{"diskSizeGB": 128, "diskState": "Attached", "osType": "Linux", "networkAccessPolicy": "DenyAll", "publicNetworkAccess": "Disabled", "encryption": map[string]any{"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/diskEncryptionSets/prod"}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.ContainerService/managedClusters":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.ContainerService/managedClusters/aks-prod", "name": "aks-prod", "type": "Microsoft.ContainerService/managedClusters", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "aks-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "platform@writer.com", "team": "platform", "env": "prod"}, "properties": map[string]any{"kubernetesVersion": "1.30.0", "dnsPrefix": "aks-prod", "fqdn": "aks-prod.eastus.azmk8s.io", "publicNetworkAccess": "Enabled", "apiServerAccessProfile": map[string]any{"enablePrivateCluster": false}, "networkProfile": map[string]any{"networkPlugin": "azure", "networkPolicy": "azure", "loadBalancerProfile": map[string]any{"effectiveOutboundIPs": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/publicIPAddresses/aks-egress"}}}}, "agentPoolProfiles": []map[string]any{{"name": "system", "vnetSubnetID": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/aks"}}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Web/sites":
			writeJSON(t, w, map[string]any{"value": []map[string]any{
				{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Web/sites/web-prod", "name": "web-prod", "type": "Microsoft.Web/sites", "kind": "app,linux,container", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "web-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "app@writer.com", "team": "app", "env": "prod"}, "properties": map[string]any{"enabled": true, "httpsOnly": true, "defaultHostName": "web-prod.azurewebsites.net", "hostNames": []string{"web.writer.com", "web-prod.azurewebsites.net"}, "publicNetworkAccess": "Enabled", "virtualNetworkSubnetId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/web", "serverFarmId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Web/serverfarms/asp-prod", "siteConfig": map[string]any{"minTlsVersion": "1.2", "linuxFxVersion": "DOCKER|writer/web:latest"}}},
				{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Web/sites/fn-prod", "name": "fn-prod", "type": "Microsoft.Web/sites", "kind": "functionapp,linux", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "fn-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "app@writer.com", "team": "app", "env": "prod"}, "properties": map[string]any{"enabled": true, "httpsOnly": true, "defaultHostName": "fn-prod.azurewebsites.net", "hostNames": []string{"fn-prod.azurewebsites.net"}, "publicNetworkAccess": "Disabled", "virtualNetworkSubnetId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/functions", "serverFarmId": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Web/serverfarms/asp-prod", "siteConfig": map[string]any{"minTlsVersion": "1.2", "linuxFxVersion": "NODE|18-lts"}}},
			}})
		case "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/dataprod", "name": "dataprod", "type": "Microsoft.Storage/storageAccounts", "location": "eastus", "sku": map[string]any{"name": "Standard_GRS", "tier": "Standard"}, "identity": map[string]any{"type": "SystemAssigned", "principalId": "storage-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "data@writer.com", "team": "data", "env": "prod"}, "properties": map[string]any{"allowBlobPublicAccess": false, "allowSharedKeyAccess": false, "publicNetworkAccess": "Disabled", "minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": true, "primaryEndpoints": map[string]any{"blob": "https://dataprod.blob.core.windows.net/"}, "encryption": map[string]any{"keySource": "Microsoft.Keyvault", "services": map[string]any{"blob": map[string]any{"enabled": true}, "file": map[string]any{"enabled": true}}}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Sql/servers":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod", "name": "sql-prod", "type": "Microsoft.Sql/servers", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "sql-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "data@writer.com", "team": "data", "env": "prod"}, "properties": map[string]any{"publicNetworkAccess": "Enabled", "minimalTlsVersion": "1.2", "fullyQualifiedDomainName": "sql-prod.database.windows.net", "state": "Ready"}}}})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod/databases":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/sql-prod/databases/appdb", "name": "appdb", "type": "Microsoft.Sql/servers/databases", "location": "eastus", "tags": map[string]string{"owner": "data@writer.com", "team": "data", "env": "prod"}, "properties": map[string]any{"status": "Online", "collation": "SQL_Latin1_General_CP1_CI_AS", "maxSizeBytes": 1073741824, "zoneRedundant": true, "readScale": "Disabled", "currentBackupStorageRedundancy": "Geo", "earliestRestoreDate": "2026-04-23T00:00:00Z"}}}})
		case "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod", "name": "kv-prod", "type": "Microsoft.KeyVault/vaults", "location": "eastus", "tags": map[string]string{"owner": "security@writer.com", "team": "security", "env": "prod"}, "properties": map[string]any{"tenantId": "tenant-1", "publicNetworkAccess": "Disabled", "enableSoftDelete": true, "enablePurgeProtection": true, "softDeleteRetentionInDays": 90, "enableRbacAuthorization": true, "enabledForDiskEncryption": true, "vaultUri": "https://kv-prod.vault.azure.net/", "networkAcls": map[string]any{"defaultAction": "Deny"}}}}})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod/keys":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod/keys/signing-key", "name": "signing-key", "type": "Microsoft.KeyVault/vaults/keys", "properties": map[string]any{"kty": "RSA", "keyOps": []string{"sign", "verify"}, "attributes": map[string]any{"enabled": true, "exp": 1818979200, "created": 1776902400, "updated": 1776902400, "recoveryLevel": "Recoverable+Purgeable"}}}}})
		case "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod/secrets":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/kv-prod/secrets/db-connection", "name": "db-connection", "type": "Microsoft.KeyVault/vaults/secrets", "properties": map[string]any{"contentType": "connection-string", "attributes": map[string]any{"enabled": true, "created": 1776902400, "updated": 1776902400, "recoveryLevel": "Recoverable+Purgeable"}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.DocumentDB/databaseAccounts":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.DocumentDB/databaseAccounts/cosmos-prod", "name": "cosmos-prod", "type": "Microsoft.DocumentDB/databaseAccounts", "location": "eastus", "identity": map[string]any{"type": "SystemAssigned", "principalId": "cosmos-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "data@writer.com", "team": "data", "env": "prod"}, "properties": map[string]any{"publicNetworkAccess": "Disabled", "documentEndpoint": "https://cosmos-prod.documents.azure.com:443/", "minimalTlsVersion": "Tls12", "disableLocalAuth": true, "enableMultipleWriteLocations": false, "enableFreeTier": false, "consistencyPolicy": map[string]any{"defaultConsistencyLevel": "Session"}, "locations": []map[string]any{{"locationName": "East US"}}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.ContainerRegistry/registries":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.ContainerRegistry/registries/acrprod", "name": "acrprod", "type": "Microsoft.ContainerRegistry/registries", "location": "eastus", "sku": map[string]any{"name": "Premium", "tier": "Premium"}, "identity": map[string]any{"type": "SystemAssigned", "principalId": "acr-principal-1", "tenantId": "tenant-1"}, "tags": map[string]string{"owner": "platform@writer.com", "team": "platform", "env": "prod"}, "properties": map[string]any{"loginServer": "acrprod.azurecr.io", "publicNetworkAccess": "Disabled", "adminUserEnabled": false, "networkRuleSet": map[string]any{"defaultAction": "Deny"}, "policies": map[string]any{"quarantinePolicy": map[string]any{"status": "enabled"}, "trustPolicy": map[string]any{"status": "enabled"}, "retentionPolicy": map[string]any{"status": "enabled", "days": 30}}, "encryption": map[string]any{"status": "enabled", "keyVaultProperties": map[string]any{"keyIdentifier": "https://kv-prod.vault.azure.net/keys/acr"}}}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Network/networkSecurityGroups":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg", "name": "web-nsg", "location": "eastus", "type": "Microsoft.Network/networkSecurityGroups", "properties": map[string]any{"securityRules": []map[string]any{{"id": "nsg-rule-1", "name": "AllowHTTPS", "properties": map[string]any{"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "sourceAddressPrefix": "Internet", "destinationPortRange": "443", "priority": 100}}}}}}})
		case "/subscriptions/sub-1/providers/microsoft.insights/eventtypes/management/values":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "activity-1", "eventTimestamp": "2026-04-23T00:00:00Z", "caller": "admin@writer.com", "resourceId": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm1", "resourceGroupName": "prod", "operationName": map[string]any{"value": "Microsoft.Compute/virtualMachines/write", "localizedValue": "Create or Update Virtual Machine"}, "resourceProviderName": map[string]any{"value": "Microsoft.Compute"}, "category": map[string]any{"value": "Administrative"}, "authorization": map[string]any{"action": "Microsoft.Compute/virtualMachines/write", "scope": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm1"}, "subscriptionId": "sub-1"}}})
		default:
			http.NotFound(w, r)
		}
	})
}

func newAzurePaginationTestSource(t *testing.T, server *httptest.Server, family string) (*Source, settings) {
	t.Helper()
	source, err := newLiveTestSource()
	if err != nil {
		t.Fatalf("newLiveTestSource: %v", err)
	}
	source.client = server.Client()
	return source, settings{
		armBaseURL:     server.URL,
		armToken:       "test-token",
		family:         family,
		perPage:        1,
		subscriptionID: "sub-1",
		tenantID:       "tenant-1",
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func azureSQLServerPayload(name string) map[string]any {
	return map[string]any{
		"id":       "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/" + name,
		"name":     name,
		"type":     "Microsoft.Sql/servers",
		"location": "eastus",
		"properties": map[string]any{
			"fullyQualifiedDomainName": name + ".database.windows.net",
			"publicNetworkAccess":      "Enabled",
		},
	}
}

func azureSQLDatabasePayload(serverName string, name string) map[string]any {
	return map[string]any{
		"id":       "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Sql/servers/" + serverName + "/databases/" + name,
		"name":     name,
		"type":     "Microsoft.Sql/servers/databases",
		"location": "eastus",
		"properties": map[string]any{
			"currentBackupStorageRedundancy": "Geo",
			"status":                         "Online",
		},
	}
}

func azureKeyVaultPayload(name string) map[string]any {
	return map[string]any{
		"id":       "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/" + name,
		"name":     name,
		"type":     "Microsoft.KeyVault/vaults",
		"location": "eastus",
		"properties": map[string]any{
			"enablePurgeProtection": true,
			"vaultUri":              "https://" + name + ".example.com/",
		},
	}
}

func azureKeyVaultKeyPayload(vaultName string, name string) map[string]any {
	return map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/" + vaultName + "/keys/" + name,
		"name": name,
		"type": "Microsoft.KeyVault/vaults/keys",
		"properties": map[string]any{
			"attributes": map[string]any{"enabled": true, "recoveryLevel": "Recoverable+Purgeable"},
			"kty":        "RSA",
		},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

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
		{family: familyAppRoleAssignment, config: map[string]string{"service_principal_id": "sp-resource-1"}, kind: "azure.app_role_assignment"},
		{family: familyApplication, kind: "azure.application"},
		{family: familyCredential, kind: "azure.credential"},
		{family: familyDirectoryAudit, kind: "azure.directory_audit"},
		{family: familyDirectoryRoleAssign, kind: "azure.directory_role_assignment"},
		{family: familyGroup, kind: "azure.group"},
		{family: familyGroupMember, config: map[string]string{"group_id": "group-1"}, kind: "azure.group_membership"},
		{family: familyIAMRoleAssign, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.iam_role_assignment"},
		{family: familyResourceExposure, config: map[string]string{"subscription_id": "sub-1"}, kind: "azure.resource_exposure"},
		{family: familyServicePrincipal, kind: "azure.service_principal"},
		{family: familyUser, kind: "azure.user"},
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
	source, err := New()
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
	source, err := New()
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
	source, err := New()
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
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/ra-1", "name": "ra-1", "type": "Microsoft.Authorization/roleAssignments", "properties": map[string]any{"principalId": "sp-1", "principalType": "ServicePrincipal", "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "scope": "/subscriptions/sub-1"}}}})
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role":
			writeJSON(t, w, map[string]any{"id": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-role", "name": "owner-role", "properties": map[string]any{"roleName": "Owner", "type": "BuiltInRole"}})
		case "/subscriptions/sub-1/providers/Microsoft.Network/networkSecurityGroups":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Network/networkSecurityGroups/web-nsg", "name": "web-nsg", "location": "eastus", "type": "Microsoft.Network/networkSecurityGroups", "properties": map[string]any{"securityRules": []map[string]any{{"id": "nsg-rule-1", "name": "AllowHTTPS", "properties": map[string]any{"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "sourceAddressPrefix": "Internet", "destinationPortRange": "443", "priority": 100}}}}}}})
		case "/subscriptions/sub-1/providers/microsoft.insights/eventtypes/management/values":
			writeJSON(t, w, map[string]any{"value": []map[string]any{{"id": "activity-1", "eventTimestamp": "2026-04-23T00:00:00Z", "caller": "admin@writer.com", "resourceId": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm1", "resourceGroupName": "prod", "operationName": map[string]any{"value": "Microsoft.Compute/virtualMachines/write", "localizedValue": "Create or Update Virtual Machine"}, "resourceProviderName": map[string]any{"value": "Microsoft.Compute"}, "category": map[string]any{"value": "Administrative"}, "authorization": map[string]any{"action": "Microsoft.Compute/virtualMachines/write", "scope": "/subscriptions/sub-1/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm1"}, "subscriptionId": "sub-1"}}})
		default:
			http.NotFound(w, r)
		}
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

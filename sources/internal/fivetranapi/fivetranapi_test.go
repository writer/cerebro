package fivetranapi

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestFamiliesUseVerifiedProviderRESTPaths(t *testing.T) {
	wantPaths := map[string]string{
		FamilyUsers:                          "/v1/users",
		FamilyUserConnectionMemberships:      "/v1/users/{userId}/connections",
		FamilyUserGroupMemberships:           "/v1/users/{userId}/groups",
		FamilyGroups:                         "/v1/groups",
		FamilyGroupUsers:                     "/v1/groups/{groupId}/users",
		FamilyGroupConnections:               "/v1/groups/{groupId}/connections",
		FamilyTeams:                          "/v1/teams",
		FamilyTeamUsers:                      "/v1/teams/{teamId}/users",
		FamilyTeamGroups:                     "/v1/teams/{teamId}/groups",
		FamilyTeamConnections:                "/v1/teams/{teamId}/connections",
		FamilyRoles:                          "/v1/roles",
		FamilyDestinations:                   "/v1/destinations",
		FamilyDestinationCertificates:        "/v1/destinations/{destinationId}/certificates",
		FamilyDestinationFingerprints:        "/v1/destinations/{destinationId}/fingerprints",
		FamilyConnections:                    "/v1/connections",
		FamilyConnectionCertificates:         "/v1/connections/{connectionId}/certificates",
		FamilyConnectionFingerprints:         "/v1/connections/{connectionId}/fingerprints",
		FamilyLogServices:                    "/v1/external-logging",
		FamilyWebhooks:                       "/v1/webhooks",
		FamilyPrivateLinks:                   "/v1/private-links",
		FamilyProxyAgents:                    "/v1/proxy",
		FamilyProxyAgentConnections:          "/v1/proxy/{agentId}/connections",
		FamilyHybridDeploymentAgents:         "/v1/hybrid-deployment-agents",
		FamilyConnectorMetadata:              "/v1/metadata/connector-types",
		FamilyConnectorSDKPackages:           "/v1/connector-sdk/packages",
		FamilySystemKeys:                     "/v1/system-keys",
		FamilyExternalSecretsManagers:        "/v1/external-secrets-managers",
		FamilyExternalSecretsManagerEntities: "/v1/external-secrets-managers-entities",
		FamilyTransformations:                "/v1/transformations",
		FamilyTransformationProjects:         "/v1/transformation-projects",
		FamilyTransformationPackageMetadata:  "/v1/transformations/package-metadata",
	}
	families := Families()
	if len(families) != len(wantPaths) {
		t.Fatalf("families = %d, want %d", len(families), len(wantPaths))
	}
	for _, family := range families {
		wantPath, ok := wantPaths[family.Name]
		if !ok {
			t.Fatalf("unexpected family %q", family.Name)
		}
		if family.Path != wantPath {
			t.Fatalf("%s path = %q, want %q", family.Name, family.Path, wantPath)
		}
		if !reflect.DeepEqual(family.ListKeys, []string{"data.items"}) {
			t.Fatalf("%s list keys = %#v, want data.items", family.Name, family.ListKeys)
		}
		if !reflect.DeepEqual(family.NextCursorKeys, []string{"data.next_cursor"}) {
			t.Fatalf("%s next cursor keys = %#v, want data.next_cursor", family.Name, family.NextCursorKeys)
		}
		if family.CursorParam != "cursor" {
			t.Fatalf("%s cursor param = %q, want cursor", family.Name, family.CursorParam)
		}
		if !reflect.DeepEqual(family.PageSizeParams, []string{"limit"}) {
			t.Fatalf("%s page size params = %#v, want limit", family.Name, family.PageSizeParams)
		}
	}
}

func TestPathParamValuesUsesConfiguredFanoutIDs(t *testing.T) {
	cfg := sourcecdk.NewConfig(map[string]string{
		"user_ids":        "user_1,user_2",
		"group_ids":       "group_1",
		"team_ids":        "team_1",
		"connection_ids":  "connection_1",
		"destination_ids": "destination_1",
		"proxy_agent_ids": "proxy_agent_1",
	})
	tests := []struct {
		family    string
		wantParam string
		wantIDs   []string
	}{
		{FamilyUserConnectionMemberships, "userId", []string{"user_1", "user_2"}},
		{FamilyGroupUsers, "groupId", []string{"group_1"}},
		{FamilyTeamConnections, "teamId", []string{"team_1"}},
		{FamilyConnectionCertificates, "connectionId", []string{"connection_1"}},
		{FamilyDestinationFingerprints, "destinationId", []string{"destination_1"}},
		{FamilyProxyAgentConnections, "agentId", []string{"proxy_agent_1"}},
	}
	for _, test := range tests {
		t.Run(test.family, func(t *testing.T) {
			param, ids := PathParamValues(cfg, test.family)
			if param != test.wantParam {
				t.Fatalf("param = %q, want %q", param, test.wantParam)
			}
			if !reflect.DeepEqual(ids, test.wantIDs) {
				t.Fatalf("ids = %#v, want %#v", ids, test.wantIDs)
			}
		})
	}
}

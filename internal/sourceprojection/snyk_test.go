package sourceprojection

import (
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSnykGoProjectionFailsClosedForRustAuthoritativeFamilies(t *testing.T) {
	for _, kind := range []string{
		"snyk.groups",
		"snyk.orgs",
		"snyk.projects",
		"snyk.targets",
		"snyk.assets",
		"snyk.findings",
		"snyk.vulnerabilities",
		"snyk.org_memberships",
		"snyk.service_accounts",
		"snyk.audit_logs",
		"snyk.collections",
		"snyk.cloud_environments",
		"snyk.cloud_resources",
		"snyk.cloud_scans",
		"snyk.group_memberships",
		"snyk.group_service_accounts",
		"snyk.group_audit_logs",
		"snyk.asset_project_relationships",
		"snyk.asset_target_relationships",
	} {
		t.Run(kind, func(t *testing.T) {
			entities, links, err := ProjectEvent(&cerebrov1.EventEnvelope{
				Id:       "event-1",
				TenantId: "tenant",
				SourceId: "snyk",
				Kind:     kind,
			})
			if !errors.Is(err, errSnykRustProjectionRequired) {
				t.Fatalf("ProjectEvent() error = %v", err)
			}
			if len(entities) != 0 || len(links) != 0 {
				t.Fatalf("Go projection produced entities=%d links=%d", len(entities), len(links))
			}
		})
	}
}

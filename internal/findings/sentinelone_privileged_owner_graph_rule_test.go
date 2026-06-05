package findings

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestSentinelOneInfectedPrivilegedOwnerRuleEvaluateRowsBuildsFinding(t *testing.T) {
	rule := newSentinelOneInfectedPrivilegedOwnerRule().(*sentinelOneInfectedPrivilegedOwnerRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	row := sentinelOnePrivilegedOwnerRow(time.Now().UTC())

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", got)
	}
	finding := findings[0]
	if finding.RuleID != sentinelOneInfectedPrivilegedOwnerRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, sentinelOneInfectedPrivilegedOwnerRuleID)
	}
	if finding.Severity != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", finding.Severity)
	}
	if got := finding.Attributes["principal_urn"]; got != "urn:cerebro:writer:okta.user:alice" {
		t.Fatalf("principal_urn = %q", got)
	}
	if got := finding.Attributes["privileged_relations"]; got != grcOverlayAccessEdgeRelationCanAdmin {
		t.Fatalf("privileged_relations = %q, want %q", got, grcOverlayAccessEdgeRelationCanAdmin)
	}
}

func TestSentinelOneInfectedPrivilegedOwnerRuleRequiresInfectionFreshOwnerAndPrivilege(t *testing.T) {
	rule := newSentinelOneInfectedPrivilegedOwnerRule().(*sentinelOneInfectedPrivilegedOwnerRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "threat"}}
	now := time.Now().UTC()

	clean := sentinelOnePrivilegedOwnerRow(now)
	clean.Values["agent_attributes_json"] = sentinelOneTestJSON(map[string]string{"agent_id": "agent-1", "computer_name": "mac-1", "is_infected": "false", "active_threats": "0"})
	clean.Values["threats"] = []any{}

	staleOwner := sentinelOnePrivilegedOwnerRow(now)
	staleOwner.Values["owned_attributes_json"] = sentinelOneTestJSON(map[string]string{"at": now.Add(-90 * 24 * time.Hour).Format(time.RFC3339), "match_type": "sentinelone_owner_email"})

	noPrivilege := sentinelOnePrivilegedOwnerRow(now)
	noPrivilege.Values["privilege_edges"] = []any{map[string]any{
		"relation":        grcOverlayAccessEdgeRelationCanPerform,
		"resource_urn":    "urn:cerebro:writer:cloud_resource:read-only",
		"resource_type":   "cloud.resource",
		"resource_label":  "ReadOnly",
		"attributes_json": sentinelOneTestJSON(map[string]string{"permission": "read"}),
	}}

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{clean, staleOwner, noPrivilege})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0: %#v", len(findings), findings)
	}
}

func TestSentinelOneInfectedPrivilegedOwnerRuleSupportsRelevantRuntimes(t *testing.T) {
	rule := newSentinelOneInfectedPrivilegedOwnerRule().(*sentinelOneInfectedPrivilegedOwnerRule)
	withFamily := func(sourceID, family string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{SourceId: sourceID, Config: map[string]string{"family": family}}
	}
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"sentinelone agent":                {withFamily("sentinelone", "agent"), true},
		"sentinelone threat":               {withFamily("sentinelone", "threat"), true},
		"okta admin role":                  {withFamily("okta", "admin_role"), true},
		"google workspace role assignment": {withFamily("google_workspace", "role_assignment"), true},
		"aws effective permission":         {withFamily("aws", "effective_permission"), true},
		"azure directory role assignment":  {withFamily("azure", "directory_role_assignment"), true},
		"sentinelone application":          {withFamily("sentinelone", "application"), false},
		"github dependabot":                {withFamily("github", "dependabot_alert"), false},
		"nil runtime":                      {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rule.SupportsRuntime(tc.runtime); got != tc.want {
				t.Fatalf("SupportsRuntime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func sentinelOnePrivilegedOwnerRow(now time.Time) ports.CypherRow {
	row := sentinelOneInfectionRow("agent-1", "mac-1", map[string]string{
		"agent_id":       "agent-1",
		"computer_name":  "mac-1",
		"is_infected":    "true",
		"active_threats": "1",
	}, []map[string]string{
		{"threat_id": "threat-1", "threat_name": "malware-a", "incident_status": "unresolved", "mitigation_status": "not_mitigated", "classification": "Malware"},
	})
	row.Values["owned_attributes_json"] = sentinelOneTestJSON(map[string]string{"at": now.Format(time.RFC3339), "match_type": "sentinelone_owner_email"})
	row.Values["identity_urn"] = "urn:cerebro:writer:identity:email:alice@writer.com"
	row.Values["identity_label"] = "alice@writer.com"
	row.Values["principal_urn"] = "urn:cerebro:writer:okta.user:alice"
	row.Values["principal_label"] = "alice@writer.com"
	row.Values["principal_entity_type"] = grcOverlayEntityTypeOktaUser
	row.Values["principal_identity_attributes_json"] = deprovisionedOktaRuleEmailIdentityAttrs(now)
	row.Values["privilege_edges"] = []any{map[string]any{
		"relation":        grcOverlayAccessEdgeRelationCanAdmin,
		"resource_urn":    "urn:cerebro:writer:okta_admin_role:super-admin",
		"resource_type":   "okta.admin_role",
		"resource_label":  "Super Admin",
		"attributes_json": "{}",
	}}
	return row
}

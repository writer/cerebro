package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestGRCInactiveIdentityActiveAccessRuleQueryScopesByTenant(t *testing.T) {
	rule := newGRCInactiveIdentityActiveAccessRule().(*grcInactiveIdentityActiveAccessRule)
	request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-grc-person", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "person"}})
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	if !strings.Contains(request.Query, "source_id: 'grc'") {
		t.Fatalf("query must scope GRC subject nodes to the provider-neutral grc source:\n%s", request.Query)
	}
	if !strings.Contains(request.Query, "access_edges") || !strings.Contains(request.Query, "collect(DISTINCT") {
		t.Fatalf("query must collapse active access fan-out before LIMIT:\n%s", request.Query)
	}
	if request.RowLimit != grcOverlayQueryRowLimit {
		t.Fatalf("RowLimit = %d, want %d", request.RowLimit, grcOverlayQueryRowLimit)
	}
}

func TestGRCOverlayIdentityRulesSupportRelevantRuntimes(t *testing.T) {
	rule := newGRCInactiveIdentityActiveAccessRule().(*grcInactiveIdentityActiveAccessRule)
	withFamily := func(sourceID, family string) *cerebrov1.SourceRuntime {
		return &cerebrov1.SourceRuntime{SourceId: sourceID, Config: map[string]string{"family": family}}
	}
	cases := map[string]struct {
		runtime *cerebrov1.SourceRuntime
		want    bool
	}{
		"grc person":                  {withFamily("grc", "person"), true},
		"grc user":                    {withFamily("grc", "user"), true},
		"github audit":                {withFamily("github", "audit"), true},
		"okta user":                   {withFamily("okta", "user"), true},
		"google role assignment":      {withFamily("google_workspace", "role_assignment"), true},
		"aws iam role assignment":     {withFamily("aws", "iam_role_assignment"), true},
		"gcp service impersonation":   {withFamily("gcp", "service_account_impersonation"), true},
		"azure directory role":        {withFamily("azure", "directory_role_assignment"), true},
		"grc vendor unrelated":        {withFamily("grc", "vendor"), false},
		"github dependabot unrelated": {withFamily("github", "dependabot_alert"), false},
		"sentinelone unrelated":       {withFamily("sentinelone", "activity"), false},
		"missing family":              {&cerebrov1.SourceRuntime{SourceId: "grc"}, false},
		"nil runtime":                 {nil, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rule.SupportsRuntime(tc.runtime); got != tc.want {
				t.Fatalf("SupportsRuntime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGRCInactiveIdentityActiveAccessRuleEvaluateRowsEmits(t *testing.T) {
	rule := newGRCInactiveIdentityActiveAccessRule().(*grcInactiveIdentityActiveAccessRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-person", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "person"}}
	row := grcInactiveAccessRow(map[string]string{
		"source_system":     "vanta",
		"person_id":         "person-1",
		"employment_status": "TERMINATED",
	}, grcOverlayBridgeAttrs(time.Now().UTC().Add(-time.Hour)), grcOverlayBridgeAttrs(time.Now().UTC().Add(-time.Hour)), []any{
		grcOverlayAccessMap(grcOverlayAccessEdgeRelationCanAdmin, "urn:cerebro:writer:github_org:writer", "github.org", "writer", "{}"),
	})

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if got := finding.RuleID; got != grcInactiveIdentityActiveAccessRuleID {
		t.Fatalf("RuleID = %q, want %q", got, grcInactiveIdentityActiveAccessRuleID)
	}
	if got := finding.Severity; got != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", got)
	}
	if got := finding.Attributes["access_count"]; got != "1" {
		t.Fatalf("access_count = %q, want 1", got)
	}
}

func TestGRCInactiveIdentityActiveAccessRuleSuppressesCurrentAndStaleBridge(t *testing.T) {
	rule := newGRCInactiveIdentityActiveAccessRule().(*grcInactiveIdentityActiveAccessRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-person", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "person"}}
	fresh := grcOverlayBridgeAttrs(time.Now().UTC().Add(-time.Hour))
	stale := grcOverlayBridgeAttrs(time.Now().UTC().Add(-90 * 24 * time.Hour))
	accesses := []any{grcOverlayAccessMap(grcOverlayAccessEdgeRelationCanAdmin, "urn:cerebro:writer:github_org:writer", "github.org", "writer", "{}")}
	rows := []ports.CypherRow{
		grcInactiveAccessRow(map[string]string{"source_system": "vanta", "employment_status": "CURRENT"}, fresh, fresh, accesses),
		grcInactiveAccessRow(map[string]string{"source_system": "vanta", "employment_status": "TERMINATED"}, fresh, stale, accesses),
	}

	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0", len(findings))
	}
}

func TestGRCPrivilegedAccountMissingPersonRuleEvaluateRowsEmitsWithoutFreshBridge(t *testing.T) {
	rule := newGRCPrivilegedAccountMissingPersonRule().(*grcPrivilegedAccountMissingPersonRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-iam-role-assignment", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "iam_role_assignment"}}
	row := grcPrivilegedMissingPersonRow(nil)

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if got := finding.RuleID; got != grcPrivilegedAccountMissingPersonRuleID {
		t.Fatalf("RuleID = %q, want %q", got, grcPrivilegedAccountMissingPersonRuleID)
	}
	if got := finding.Attributes["privilege_count"]; got != "1" {
		t.Fatalf("privilege_count = %q, want 1", got)
	}
}

func TestGRCPrivilegedAccountMissingPersonRuleFreshBridgeSuppresses(t *testing.T) {
	rule := newGRCPrivilegedAccountMissingPersonRule().(*grcPrivilegedAccountMissingPersonRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-aws-iam-role-assignment", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "iam_role_assignment"}}
	fresh := grcOverlayBridgeAttrs(time.Now().UTC().Add(-time.Hour))
	bridges := []any{map[string]any{
		"grc_subject_urn":                    "urn:cerebro:writer:person:vanta:person-1",
		"grc_subject_label":                  "alice@writer.com",
		"identity_urn":                       "urn:cerebro:writer:identity:email:alice@writer.com",
		"identity_label":                     "alice@writer.com",
		"grc_identity_attributes_json":       fresh,
		"principal_identity_attributes_json": fresh,
	}}
	row := grcPrivilegedMissingPersonRow(bridges)

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0", len(findings))
	}
}

func TestGRCOverdueVulnerabilityLiveOnAssetsRuleQueryScopesByTenant(t *testing.T) {
	rule := newGRCOverdueVulnerabilityLiveOnAssetsRule().(*grcOverdueVulnerabilityLiveOnAssetsRule)
	request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-grc-vulnerability", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "vulnerability"}})
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	if !strings.Contains(request.Query, "affected_by") || !strings.Contains(request.Query, "source_id, '') <> 'grc'") {
		t.Fatalf("query must join canonical vulnerabilities to non-GRC affected_by evidence:\n%s", request.Query)
	}
}

func TestGRCOverdueVulnerabilityLiveOnAssetsRuleEvaluateRowsEmits(t *testing.T) {
	rule := newGRCOverdueVulnerabilityLiveOnAssetsRule().(*grcOverdueVulnerabilityLiveOnAssetsRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-vulnerability", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "vulnerability"}}
	row := grcVulnerabilityAssetRow(map[string]string{
		"source_system":     "vanta",
		"name":              "CVE-2026-4242",
		"severity":          "CRITICAL",
		"remediate_by_date": "2020-01-01T00:00:00Z",
	}, []any{
		grcOverlayAssetMap("urn:cerebro:writer:sentinelone_endpoint:endpoint-1", "sentinelone.endpoint", "prod-macbook", "sentinelone"),
	})

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if got := finding.RuleID; got != grcOverdueVulnerabilityLiveOnAssetsRuleID {
		t.Fatalf("RuleID = %q, want %q", got, grcOverdueVulnerabilityLiveOnAssetsRuleID)
	}
	if got := finding.Severity; got != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL", got)
	}
	if got := finding.Attributes["asset_count"]; got != "1" {
		t.Fatalf("asset_count = %q, want 1", got)
	}
}

func TestGRCOverdueVulnerabilityLiveOnAssetsRuleSuppressesFutureDeadlineAndGRCOnlyAssets(t *testing.T) {
	rule := newGRCOverdueVulnerabilityLiveOnAssetsRule().(*grcOverdueVulnerabilityLiveOnAssetsRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-vulnerability", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "vulnerability"}}
	rows := []ports.CypherRow{
		grcVulnerabilityAssetRow(map[string]string{
			"source_system":     "vanta",
			"name":              "CVE-2026-4242",
			"severity":          "HIGH",
			"remediate_by_date": "2999-01-01T00:00:00Z",
		}, []any{grcOverlayAssetMap("urn:cerebro:writer:sentinelone_endpoint:endpoint-1", "sentinelone.endpoint", "prod-macbook", "sentinelone")}),
		grcVulnerabilityAssetRow(map[string]string{
			"source_system":     "vanta",
			"name":              "CVE-2026-4243",
			"severity":          "HIGH",
			"remediate_by_date": "2020-01-01T00:00:00Z",
		}, []any{grcOverlayAssetMap("urn:cerebro:writer:package:grc:openssl", "package", "openssl", "grc")}),
	}

	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0", len(findings))
	}
}

func TestGRCFailingControlOpenOperationalFindingsRuleQueryMatchesControlRefs(t *testing.T) {
	rule := newGRCFailingControlOpenOperationalFindingsRule().(*grcFailingControlOpenOperationalFindingsRule)
	request := rule.QueryFor(&cerebrov1.SourceRuntime{Id: "writer-grc-control-test", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "control_test"}})
	if request.Query == "" {
		t.Fatal("QueryFor() returned empty query for populated runtime")
	}
	if got := request.Params["tenant_id"]; got != "writer" {
		t.Fatalf("Params[tenant_id] = %v, want writer", got)
	}
	if !strings.Contains(request.Query, "has_finding") || !strings.Contains(request.Query, "CONTAINS toUpper(control_label)") {
		t.Fatalf("query must join failing controls to open non-GRC finding control refs:\n%s", request.Query)
	}
}

func TestGRCFailingControlOpenOperationalFindingsRuleEvaluateRowsEmits(t *testing.T) {
	rule := newGRCFailingControlOpenOperationalFindingsRule().(*grcFailingControlOpenOperationalFindingsRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-control-test", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "control_test"}}
	row := grcFailingControlRow(map[string]string{
		"source_system": "vanta",
		"test_id":       "test-1",
		"status":        "FAIL",
	}, map[string]string{
		"source_system":       "vanta",
		"framework_name":      "SOC 2",
		"control_external_id": "CC6.2",
		"control_id":          "control-1",
	}, []any{
		grcOverlayOperationalFindingMap("urn:cerebro:writer:finding:github-shadow", "Active GitHub Identity With No Linked Okta Identity", "urn:cerebro:writer:github_user:alice", "github.user", "alice", map[string]string{
			"rule_id":      "identity-github-active-without-okta-link",
			"severity":     "CRITICAL",
			"control_refs": "SOC 2:CC6.2",
		}),
	})

	findings, err := rule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{row})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if got := finding.RuleID; got != grcFailingControlOpenOperationalFindingsID {
		t.Fatalf("RuleID = %q, want %q", got, grcFailingControlOpenOperationalFindingsID)
	}
	if got := finding.Severity; got != "CRITICAL" {
		t.Fatalf("Severity = %q, want CRITICAL from linked operational finding", got)
	}
	if got := finding.Attributes["operational_count"]; got != "1" {
		t.Fatalf("operational_count = %q, want 1", got)
	}
	if len(finding.ControlRefs) != 1 || finding.ControlRefs[0].FrameworkName != "SOC 2" || finding.ControlRefs[0].ControlID != "CC6.2" {
		t.Fatalf("ControlRefs = %#v, want SOC 2:CC6.2", finding.ControlRefs)
	}
}

func TestGRCFailingControlOpenOperationalFindingsRuleSuppressesPassingAndGRCFindings(t *testing.T) {
	rule := newGRCFailingControlOpenOperationalFindingsRule().(*grcFailingControlOpenOperationalFindingsRule)
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc-control-test", SourceId: "grc", TenantId: "writer", Config: map[string]string{"family": "control_test"}}
	rows := []ports.CypherRow{
		grcFailingControlRow(map[string]string{"source_system": "vanta", "status": "PASS"}, map[string]string{"control_external_id": "CC6.2"}, []any{
			grcOverlayOperationalFindingMap("urn:cerebro:writer:finding:github-shadow", "shadow", "urn:cerebro:writer:github_user:alice", "github.user", "alice", map[string]string{"rule_id": "identity-github-active-without-okta-link", "severity": "HIGH"}),
		}),
		grcFailingControlRow(map[string]string{"source_system": "vanta", "status": "FAIL"}, map[string]string{"control_external_id": "CC6.2"}, []any{
			grcOverlayOperationalFindingMap("urn:cerebro:writer:finding:grc-signal", "grc signal", "urn:cerebro:writer:evidence:vanta:control_test:test-1", "evidence", "test-1", map[string]string{"rule_id": "grc-control-test-needs-attention", "severity": "MEDIUM"}),
		}),
	}

	findings, err := rule.EvaluateRows(context.Background(), runtime, rows)
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("EvaluateRows() returned %d findings, want 0", len(findings))
	}
}

func grcInactiveAccessRow(grcAttrs map[string]string, grcIdentityJSON string, principalIdentityJSON string, accesses []any) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"grc_subject_urn":                    "urn:cerebro:writer:person:vanta:person-1",
		"grc_subject_label":                  "alice@writer.com",
		"grc_subject_type":                   "person",
		"grc_attributes_json":                grcOverlayJSON(grcAttrs),
		"identity_urn":                       "urn:cerebro:writer:identity:email:alice@writer.com",
		"identity_label":                     "alice@writer.com",
		"principal_urn":                      "urn:cerebro:writer:github_user:alice",
		"principal_label":                    "alice",
		"principal_entity_type":              "github.user",
		"principal_attributes_json":          "{}",
		"grc_identity_attributes_json":       grcIdentityJSON,
		"principal_identity_attributes_json": principalIdentityJSON,
		"access_edges":                       accesses,
	}}
}

func grcPrivilegedMissingPersonRow(bridges []any) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"principal_urn":             "urn:cerebro:writer:aws_user:alice@writer.com",
		"principal_label":           "alice@writer.com",
		"principal_entity_type":     "aws.user",
		"principal_attributes_json": "{}",
		"privilege_edges": []any{
			grcOverlayAccessMap(grcOverlayAccessEdgeRelationCanAdmin, "urn:cerebro:writer:aws_admin_role:AdministratorAccess", "aws.admin_role", "AdministratorAccess", "{}"),
		},
		"grc_bridges": bridges,
	}}
}

func grcVulnerabilityAssetRow(vulnerabilityAttrs map[string]string, assets []any) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"vulnerability_urn":             "urn:cerebro:writer:vulnerability:cve-2026-4242",
		"vulnerability_label":           "CVE-2026-4242",
		"vulnerability_attributes_json": grcOverlayJSON(vulnerabilityAttrs),
		"assets":                        assets,
	}}
}

func grcFailingControlRow(testAttrs map[string]string, controlAttrs map[string]string, operationalFindings []any) ports.CypherRow {
	return ports.CypherRow{Values: map[string]any{
		"control_test_urn":        "urn:cerebro:writer:evidence:vanta:control_test:test-1",
		"control_test_label":      "Control test 1",
		"test_attributes_json":    grcOverlayJSON(testAttrs),
		"control_urn":             "urn:cerebro:writer:policy:vanta:control:control-1",
		"control_label":           firstNonEmpty(controlAttrs["control_external_id"], controlAttrs["control_id"], "CC6.2"),
		"control_attributes_json": grcOverlayJSON(controlAttrs),
		"operational_findings":    operationalFindings,
	}}
}

func grcOverlayAccessMap(relation string, resourceURN string, resourceType string, resourceLabel string, attributesJSON string) map[string]any {
	return map[string]any{
		"relation":        relation,
		"resource_urn":    resourceURN,
		"resource_type":   resourceType,
		"resource_label":  resourceLabel,
		"attributes_json": attributesJSON,
	}
}

func grcOverlayAssetMap(assetURN string, assetType string, assetLabel string, sourceID string) map[string]any {
	return map[string]any{
		"asset_urn":       assetURN,
		"asset_type":      assetType,
		"asset_label":     assetLabel,
		"source_id":       sourceID,
		"attributes_json": "{}",
	}
}

func grcOverlayOperationalFindingMap(findingURN string, findingLabel string, resourceURN string, resourceType string, resourceLabel string, attrs map[string]string) map[string]any {
	return map[string]any{
		"finding_urn":             findingURN,
		"finding_label":           findingLabel,
		"finding_attributes_json": grcOverlayJSON(attrs),
		"resource_urn":            resourceURN,
		"resource_type":           resourceType,
		"resource_label":          resourceLabel,
		"link_attributes_json":    "{}",
	}
}

func grcOverlayBridgeAttrs(at time.Time) string {
	attrs := map[string]string{
		"confidence":      "0.95",
		"identifier_type": "email",
		"match_type":      "exact_email",
	}
	if !at.IsZero() {
		attrs["at"] = at.UTC().Format(time.RFC3339)
	}
	return grcOverlayJSON(attrs)
}

func grcOverlayJSON(values map[string]string) string {
	encoded, err := json.Marshal(values)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

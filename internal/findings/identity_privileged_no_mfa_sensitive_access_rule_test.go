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

func TestIdentityPrivilegedNoMfaPlusSensitiveAccessGraphRuleEmits(t *testing.T) {
	rule := newIdentityPrivilegedNoMFAAccessRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access does not implement GraphRule")
	}
	if _, ok := rule.(CounterEventRule); ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access must not remain an audit-event CounterEventRule")
	}
	assertIdentityDurableMetadata(t, rule, []string{"user"})

	for _, runtime := range []*cerebrov1.SourceRuntime{
		{Id: "example-okta-user", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}},
		{Id: "example-google-workspace-user", SourceId: "google_workspace", TenantId: "writer", Config: map[string]string{"family": "user"}},
		{Id: "example-azure-iam-role-assignment", SourceId: "azure", TenantId: "writer", Config: map[string]string{"family": "iam_role_assignment"}},
		{Id: "example-aws-iam-role-assignment", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "iam_role_assignment"}},
		{Id: "example-gcp-service-account", SourceId: "gcp", TenantId: "writer", Config: map[string]string{"family": "service_account"}},
		{Id: "example-asset-crown-jewel", SourceId: "asset", TenantId: "writer", Config: map[string]string{"family": "crown_jewel"}},
		{Id: "example-asset-data-sensitivity", SourceId: "asset", TenantId: "writer", Config: map[string]string{"family": "data_sensitivity"}},
	} {
		if !graphRule.SupportsRuntime(runtime) {
			t.Fatalf("SupportsRuntime(%s/%s) = false, want true", runtime.GetSourceId(), runtime.GetConfig()["family"])
		}
	}
	if graphRule.SupportsRuntime(&cerebrov1.SourceRuntime{Id: "example-okta-audit", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "audit"}}) {
		t.Fatal("SupportsRuntime(okta/audit) = true, want false for graph-anchored state rule")
	}

	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-user", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}}
	query := graphRule.QueryFor(runtime)
	if query.RowLimit != 250 || query.Params["tenant_id"] != "writer" || query.Params["row_limit"] != int64(250) {
		t.Fatalf("QueryFor() = %#v, want tenant-scoped row_limit=250", query)
	}
	for _, fragment := range []string{
		"LIMIT $row_limit",
		"access.relation IN ['acted_on','assigned_to','can_admin','can_perform']",
		"marker.entity_type = 'asset.tag'",
		"marker.entity_type = 'data.classification'",
		"'crown_jewel'",
		"'confidential','restricted','regulated','pii','phi','pci'",
		"'okta.user','google_workspace.user','gcp.service_account'",
	} {
		if !strings.Contains(query.Query, fragment) {
			t.Fatalf("QueryFor() missing fragment %q:\n%s", fragment, query.Query)
		}
	}

	findings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{
		identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
			"is_admin":     "true",
			"mfa_enrolled": "false",
		}, nil),
	})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("len(findings) = %d, want 1", got)
	}
	finding := findings[0]
	if finding.RuleID != identityPrivilegedNoMFAAccessRuleID || finding.Severity != "HIGH" || finding.Status != findingStatusOpen {
		t.Fatalf("finding = %#v", finding)
	}
	if got, want := finding.Fingerprint, hashFindingFingerprint(identityPrivilegedNoMFAAccessRuleID, "urn:cerebro:writer:okta_user:00u-admin"); got != want {
		t.Fatalf("Fingerprint = %q, want stable user fingerprint %q", got, want)
	}
	if len(finding.EventIDs) != 0 {
		t.Fatalf("EventIDs = %#v, want none for graph-derived finding", finding.EventIDs)
	}
	if got := finding.Attributes["user"]; got != "urn:cerebro:writer:okta_user:00u-admin" {
		t.Fatalf("attributes[user] = %q, want user URN", got)
	}
	if got := finding.Attributes["sensitive_resource_count"]; got != "1" {
		t.Fatalf("sensitive_resource_count = %q, want 1", got)
	}
	if len(finding.GraphEvidenceRows) != 1 {
		t.Fatalf("len(GraphEvidenceRows) = %d, want 1", len(finding.GraphEvidenceRows))
	}
	assertFindingResourceURN(t, finding.ResourceURNs, "urn:cerebro:writer:okta_user:00u-admin")
	assertFindingResourceURN(t, finding.ResourceURNs, "urn:cerebro:writer:asset:prod-customer-db")
	assertFindingResourceURN(t, finding.ResourceURNs, "urn:cerebro:writer:data_classification:restricted")

	delegatedFindings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{
		identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
			"is_admin":           "false",
			"is_delegated_admin": "true",
			"mfa_enrolled":       "false",
		}, map[string]any{
			"sensitivity_relation":    "tagged_as",
			"sensitivity_urn":         "urn:cerebro:writer:asset_tag:crown_jewel",
			"sensitivity_entity_type": "asset.tag",
			"sensitivity_label":       "crown_jewel",
		}),
	})
	if err != nil {
		t.Fatalf("EvaluateRows(delegated admin crown jewel) error = %v", err)
	}
	if got := len(delegatedFindings); got != 1 {
		t.Fatalf("len(delegatedFindings) = %d, want 1 for delegated-admin crown-jewel access", got)
	}
	if got := delegatedFindings[0].Attributes["is_delegated_admin"]; got != "true" {
		t.Fatalf("delegated finding is_delegated_admin = %q, want true", got)
	}
}

func TestIdentityPrivilegedNoMfaSensitiveAccess_PrefilterCoversAllMFAFlags(t *testing.T) {
	rule := newIdentityPrivilegedNoMFAAccessRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access does not implement GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "example-google-workspace-user", SourceId: "google_workspace", TenantId: "writer", Config: map[string]string{"family": "user"}}
	query := graphRule.QueryFor(runtime)
	if !strings.Contains(query.Query, "user.mfa_disabled = true") {
		t.Fatalf("QueryFor() missing sargable MFA predicate:\n%s", query.Query)
	}

	for _, tc := range []struct {
		name  string
		attrs map[string]string
	}{
		{
			name: "google workspace enrolled but 2sv not enforced",
			attrs: map[string]string{
				"is_admin":           "true",
				"mfa_enrolled":       "true",
				"is_enforced_in_2sv": "false",
			},
		},
		{
			name: "generic mfa enrolled but mfa not enforced",
			attrs: map[string]string{
				"is_admin":     "true",
				"mfa_enrolled": "true",
				"mfa_enforced": "false",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{
				identityPrivilegedNoMFASensitiveAccessRow(t, tc.attrs, nil),
			})
			if err != nil {
				t.Fatalf("EvaluateRows() error = %v", err)
			}
			if got := len(findings); got != 1 {
				t.Fatalf("EvaluateRows() returned %d findings, want 1", got)
			}
		})
	}
}

func TestIdentityPrivilegedNoMfaSensitiveAccess_IncludesCanPerform(t *testing.T) {
	rule := newIdentityPrivilegedNoMFAAccessRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access does not implement GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "example-aws-iam-role-assignment", SourceId: "aws", TenantId: "writer", Config: map[string]string{"family": "iam_role_assignment"}}
	query := graphRule.QueryFor(runtime)
	if !strings.Contains(query.Query, "can_perform") {
		t.Fatalf("QueryFor() missing can_perform access relation:\n%s", query.Query)
	}
	findings, err := graphRule.EvaluateRows(context.Background(), runtime, []ports.CypherRow{
		identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
			"is_admin":     "true",
			"mfa_enrolled": "false",
		}, map[string]any{"access_relation": "can_perform"}),
	})
	if err != nil {
		t.Fatalf("EvaluateRows() error = %v", err)
	}
	if got := len(findings); got != 1 {
		t.Fatalf("EvaluateRows() returned %d findings, want 1 for can_perform-only path", got)
	}
	if got := findings[0].Attributes["access_relations"]; got != "can_perform" {
		t.Fatalf("access_relations = %q, want can_perform", got)
	}
}

func TestIdentityPrivilegedNoMfaSensitiveAccess_ActedOnRecencyBound(t *testing.T) {
	rule := newIdentityPrivilegedNoMFAAccessRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access does not implement GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-user", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}}
	query := graphRule.QueryFor(runtime)
	if _, ok := query.Params["acted_on_since"]; !ok {
		t.Fatalf("QueryFor() params missing acted_on_since recency cutoff: %#v", query.Params)
	}
	for _, fragment := range []string{"access.relation <> 'acted_on'", "$acted_on_since"} {
		if !strings.Contains(query.Query, fragment) {
			t.Fatalf("QueryFor() missing acted_on recency guard fragment %q:\n%s", fragment, query.Query)
		}
	}

	baseAttrs := map[string]string{
		"is_admin":     "true",
		"mfa_enrolled": "false",
	}
	staleRows := []ports.CypherRow{
		identityPrivilegedNoMFASensitiveAccessRow(t, baseAttrs, map[string]any{
			"access_relation":        "acted_on",
			"access_attributes_json": identityPrivilegedNoMFAAccessAttrs(t, time.Now().UTC().Add(-91*24*time.Hour)),
		}),
	}
	staleFindings, err := graphRule.EvaluateRows(context.Background(), runtime, staleRows)
	if err != nil {
		t.Fatalf("EvaluateRows(stale acted_on) error = %v", err)
	}
	if got := len(staleFindings); got != 0 {
		t.Fatalf("EvaluateRows(stale acted_on) returned %d findings, want 0", got)
	}

	freshRows := []ports.CypherRow{
		identityPrivilegedNoMFASensitiveAccessRow(t, baseAttrs, map[string]any{
			"access_relation":        "acted_on",
			"access_attributes_json": identityPrivilegedNoMFAAccessAttrs(t, time.Now().UTC().Add(-1*time.Hour)),
		}),
	}
	freshFindings, err := graphRule.EvaluateRows(context.Background(), runtime, freshRows)
	if err != nil {
		t.Fatalf("EvaluateRows(fresh acted_on) error = %v", err)
	}
	if got := len(freshFindings); got != 1 {
		t.Fatalf("EvaluateRows(fresh acted_on) returned %d findings, want 1", got)
	}
}

func TestIdentityPrivilegedNoMfaPlusSensitiveAccessGraphRuleRemediationMatrix(t *testing.T) {
	rule := newIdentityPrivilegedNoMFAAccessRule()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatal("identity-privileged-no-mfa-plus-sensitive-access does not implement GraphRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "example-okta-user", SourceId: "okta", TenantId: "writer", Config: map[string]string{"family": "user"}}
	openRows := []ports.CypherRow{identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
		"is_admin":     "true",
		"mfa_enrolled": "false",
	}, nil)}
	openFindings, err := graphRule.EvaluateRows(context.Background(), runtime, openRows)
	if err != nil || len(openFindings) != 1 {
		t.Fatalf("EvaluateRows(open) = (%v, %v), want one finding", openFindings, err)
	}
	openFinding := openFindings[0]

	for _, tc := range []struct {
		name      string
		graphRows []ports.CypherRow
	}{
		{
			name: "remove sensitive-access tag",
			graphRows: []ports.CypherRow{identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
				"is_admin":     "true",
				"mfa_enrolled": "false",
			}, map[string]any{"sensitivity_label": "public"})},
		},
		{
			name: "flip mfa_enrolled",
			graphRows: []ports.CypherRow{identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
				"is_admin":     "true",
				"mfa_enrolled": "true",
			}, nil)},
		},
		{
			name: "remove privilege",
			graphRows: []ports.CypherRow{identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
				"is_admin":           "false",
				"is_delegated_admin": "false",
				"mfa_enrolled":       "false",
			}, nil)},
		},
		{
			name: "revoke access edge",
			graphRows: []ports.CypherRow{identityPrivilegedNoMFASensitiveAccessRow(t, map[string]string{
				"is_admin":     "true",
				"mfa_enrolled": "false",
			}, map[string]any{"access_relation": "member_of"})},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubFindingStore{findings: map[string]*ports.FindingRecord{openFinding.ID: cloneFinding(openFinding)}}
			graphStore := &stubGraphStore{cypherRows: tc.graphRows}
			registry, err := NewRegistry(rule)
			if err != nil {
				t.Fatalf("NewRegistry() error = %v", err)
			}
			service := NewWithRegistry(newGraphRuleStubRuntimeStore(runtime), &stubReplayer{}, store, store, store, store, registry).WithGraphQueryStore(graphStore)
			result, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{RuntimeID: runtime.GetId()})
			if err != nil {
				t.Fatalf("EvaluateSourceRuntimeGraphRules() error = %v", err)
			}
			if got := len(result.Evaluations); got != 1 {
				t.Fatalf("len(Evaluations) = %d, want 1", got)
			}
			if got := len(result.Evaluations[0].Findings); got != 0 {
				t.Fatalf("len(emitted findings) = %d, want 0 after %s", got, tc.name)
			}
			persisted := store.findings[openFinding.ID]
			if persisted == nil {
				t.Fatalf("persisted finding %q missing", openFinding.ID)
			}
			if got := persisted.Status; got != findingStatusResolved {
				t.Fatalf("status after %s = %q, want %q", tc.name, got, findingStatusResolved)
			}
			if got := persisted.StatusReason; got != "graph_rule_no_longer_matches" {
				t.Fatalf("status reason after %s = %q, want graph_rule_no_longer_matches", tc.name, got)
			}
			if store.updateStatusCallCount != 1 {
				t.Fatalf("updateStatusCallCount after %s = %d, want 1", tc.name, store.updateStatusCallCount)
			}
		})
	}
}

func identityPrivilegedNoMFASensitiveAccessRow(t *testing.T, userAttributes map[string]string, overrides map[string]any) ports.CypherRow {
	t.Helper()
	values := map[string]any{
		"user_urn":                    "urn:cerebro:writer:okta_user:00u-admin",
		"user_entity_type":            "okta.user",
		"user_label":                  "admin@writer.com",
		"user_attributes_json":        identityPrivilegedNoMFAMustJSON(t, userAttributes),
		"resource_urn":                "urn:cerebro:writer:asset:prod-customer-db",
		"resource_entity_type":        "asset.database",
		"resource_label":              "prod-customer-db",
		"access_relation":             "can_admin",
		"access_attributes_json":      `{"role":"owner"}`,
		"sensitivity_relation":        "has_classification",
		"sensitivity_urn":             "urn:cerebro:writer:data_classification:restricted",
		"sensitivity_entity_type":     "data.classification",
		"sensitivity_label":           "restricted",
		"sensitivity_attributes_json": `{"label":"restricted"}`,
	}
	for key, value := range overrides {
		values[key] = value
	}
	return ports.CypherRow{Values: values}
}

func identityPrivilegedNoMFAMustJSON(t *testing.T, values map[string]string) string {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal(%v) error = %v", values, err)
	}
	return string(encoded)
}

func identityPrivilegedNoMFAAccessAttrs(t *testing.T, observedAt time.Time) string {
	t.Helper()
	return identityPrivilegedNoMFAMustJSON(t, map[string]string{
		"action":      "admin.access_resource",
		"event_id":    "example-acted-on",
		"observed_at": observedAt.UTC().Format(time.RFC3339),
	})
}

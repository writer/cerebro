package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	rulepackAuditClassConvert = "CONVERT_TO_CURRENT_STATE"
	rulepackAuditClassKeep    = "KEEP_AS_IS"
	rulepackAuditClassRetire  = "RETIRE"
)

type rulepackAuditClassification struct {
	RuleID                string `json:"rule_id"`
	Classification        string `json:"classification"`
	BulkCloseoutThreshold string `json:"bulk_closeout_threshold"`
	Source                string `json:"source"`
}

func TestRulepackAllRulesDeclareLifecycle(t *testing.T) {
	classifications := loadRulepackAuditClassifications(t)
	metadataByID := rulepackAuditMetadataByID(t)
	if got, want := len(metadataByID), len(classifications); got != want {
		t.Fatalf("BuiltinRuleMetadata count = %d, want %d from rule classification plan", got, want)
	}
	validKinds := map[LifecycleKind]struct{}{
		LifecycleDurableState:  {},
		LifecycleAuditEvidence: {},
		LifecycleTTLEvidence:   {},
		LifecycleRetired:       {},
	}
	rows := make([]string, 0, len(metadataByID))
	for _, entry := range classifications {
		definition, ok := metadataByID[entry.RuleID]
		if !ok {
			t.Fatalf("classification rule %q missing from BuiltinRuleMetadata", entry.RuleID)
		}
		if _, ok := validKinds[definition.Lifecycle.Kind]; !ok {
			t.Fatalf("rule %q Lifecycle.Kind = %q, want one of durable_state|audit_evidence|ttl_evidence|retired",
				entry.RuleID, definition.Lifecycle.Kind)
		}
		if err := definition.Validate(); err != nil {
			t.Fatalf("RuleDefinition.Validate(%q) error = %v", entry.RuleID, err)
		}
		rows = append(rows, fmt.Sprintf("%s=%s/%s", entry.RuleID, definition.Lifecycle.Kind, definition.Lifecycle.Anchor))
	}
	t.Logf("rule lifecycle table: %s", strings.Join(rows, ", "))
}

func TestNoConvertRuleUsesEventIdOrMatchedAtFingerprint(t *testing.T) {
	metadataByID := rulepackAuditMetadataByID(t)
	convertRules := rulepackAuditRulesByClass(t, rulepackAuditClassConvert)
	if got, want := len(convertRules), 17; got != want {
		t.Fatalf("CONVERT_TO_CURRENT_STATE rule count = %d, want %d", got, want)
	}
	rows := make([]string, 0, len(convertRules))
	for _, entry := range convertRules {
		definition := metadataByID[entry.RuleID]
		if len(definition.FingerprintFields) == 0 {
			t.Fatalf("convert rule %q has empty FingerprintFields", entry.RuleID)
		}
		if field := prohibitedFingerprintField(definition.FingerprintFields); field != "" {
			t.Fatalf("convert rule %q FingerprintFields = %v, prohibited field %q present",
				entry.RuleID, definition.FingerprintFields, field)
		}
		rows = append(rows, fmt.Sprintf("%s:%s", entry.RuleID, strings.Join(definition.FingerprintFields, "|")))
	}
	t.Logf("convert fingerprint fields: %s", strings.Join(rows, ", "))
}

func TestCloseoutSelectorCoversAllRetiredAndConvertRules(t *testing.T) {
	targets := append(rulepackAuditRulesByClass(t, rulepackAuditClassConvert), rulepackAuditRulesByClass(t, rulepackAuditClassRetire)...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].RuleID < targets[j].RuleID })
	if got, want := len(targets), 28; got != want {
		t.Fatalf("CONVERT+RETIRE closeout target count = %d, want %d", got, want)
	}
	for i, entry := range targets {
		entry := entry
		t.Run(entry.RuleID, func(t *testing.T) {
			olderThan := rulepackAuditThresholdDuration(t, entry.BulkCloseoutThreshold)
			fx := newCloseoutFixture(t)
			staleID := "stale-" + strings.ReplaceAll(entry.RuleID, "-", "_")
			recentID := "recent-" + strings.ReplaceAll(entry.RuleID, "-", "_")
			now := time.Now().UTC()
			fx.seedFindingWithRule(staleID, entry.RuleID, findingStatusOpen, now.Add(-olderThan-time.Hour), nil)
			fx.seedFindingWithRule(recentID, entry.RuleID, findingStatusOpen, now.Add(-olderThan+time.Hour), nil)

			req := fx.request(fmt.Sprintf("run-xcut-%02d", i), true)
			req.Selector.RuleIDs = []string{entry.RuleID}
			req.Selector.OlderThan = olderThan
			result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
			if err != nil {
				t.Fatalf("TombstoneFindingsBulk dry-run error = %v", err)
			}
			if result.ProposedCount != 1 || len(result.Proposed) != 1 {
				t.Fatalf("ProposedCount=%d len(Proposed)=%d, want exactly one stale candidate", result.ProposedCount, len(result.Proposed))
			}
			proposed := result.Proposed[0]
			if proposed.ID != staleID {
				t.Fatalf("proposed finding id = %q, want %q", proposed.ID, staleID)
			}
			if proposed.RuleID != entry.RuleID {
				t.Fatalf("proposed rule id = %q, want %q", proposed.RuleID, entry.RuleID)
			}
			run, err := fx.closeout.GetCloseoutRun(context.Background(), req.RunID)
			if err != nil {
				t.Fatalf("GetCloseoutRun(%q): %v", req.RunID, err)
			}
			var selector CloseoutSelector
			if err := json.Unmarshal(run.SelectorJSON, &selector); err != nil {
				t.Fatalf("unmarshal selector_json: %v", err)
			}
			if selector.OlderThan != olderThan {
				t.Fatalf("selector OlderThan = %s, want %s for threshold %q",
					selector.OlderThan, olderThan, entry.BulkCloseoutThreshold)
			}
		})
	}
}

func TestCloseoutRuleIDFilesMatchRulepackClassification(t *testing.T) {
	classifications := loadRulepackAuditClassifications(t)
	expectedByThreshold := map[string][]string{}
	for _, entry := range classifications {
		switch entry.Classification {
		case rulepackAuditClassConvert, rulepackAuditClassRetire:
		default:
			continue
		}
		if entry.BulkCloseoutThreshold != ">24h" && entry.BulkCloseoutThreshold != ">7d" {
			t.Fatalf("closeout target %q has unsupported threshold %q", entry.RuleID, entry.BulkCloseoutThreshold)
		}
		expectedByThreshold[entry.BulkCloseoutThreshold] = append(expectedByThreshold[entry.BulkCloseoutThreshold], entry.RuleID)
	}

	assertCloseoutRuleIDFile(t, "ops/closeout/rule-ids-24h.txt", expectedByThreshold[">24h"])
	assertCloseoutRuleIDFile(t, "ops/closeout/rule-ids-7d.txt", expectedByThreshold[">7d"])
}

func TestConvertRulesReplaySingleOpenRow(t *testing.T) {
	metadataByID := rulepackAuditMetadataByID(t)
	convertRules := rulepackAuditRulesByClass(t, rulepackAuditClassConvert)
	fixtures := rulepackConvertReplayFixtures()
	if got, want := len(fixtures), len(convertRules); got != want {
		t.Fatalf("convert replay fixture count = %d, want %d", got, want)
	}
	registry := Builtin()
	for _, entry := range convertRules {
		entry := entry
		t.Run(entry.RuleID, func(t *testing.T) {
			definition := metadataByID[entry.RuleID]
			if field := prohibitedFingerprintField(definition.FingerprintFields); field != "" {
				t.Fatalf("convert rule %q FingerprintFields = %v, prohibited field %q present",
					entry.RuleID, definition.FingerprintFields, field)
			}
			if len(definition.FingerprintFields) == 0 {
				t.Fatalf("convert rule %q has empty FingerprintFields", entry.RuleID)
			}
			rule, ok := registry.Get(entry.RuleID)
			if !ok {
				t.Fatalf("Builtin registry missing convert rule %q", entry.RuleID)
			}
			fixture, ok := fixtures[entry.RuleID]
			if !ok {
				t.Fatalf("missing replay fixture for convert rule %q", entry.RuleID)
			}
			if len(fixture.graphRows) != 0 {
				assertRulepackConvertGraphReplaySingleOpenRow(t, rule, definition, fixture)
				return
			}
			assertRulepackConvertEventReplaySingleOpenRow(t, rule, definition, fixture)
		})
	}
}

type rulepackConvertReplayFixture struct {
	runtime    *cerebrov1.SourceRuntime
	kind       string
	attributes map[string]string
	graphRows  []ports.CypherRow
}

func rulepackConvertReplayFixtures() map[string]rulepackConvertReplayFixture {
	staleLogin := time.Now().UTC().Add(-120 * 24 * time.Hour).Format(time.RFC3339Nano)
	return map[string]rulepackConvertReplayFixture{
		cloudEffectiveAdminPermissionRuleID: {
			runtime: rulepackConvertRuntime("aws", "effective_permission"),
			kind:    "aws.effective_permission",
			attributes: map[string]string{
				"actions":       "*",
				"domain":        "123456789012",
				"effect":        "allow",
				"resource_id":   "123456789012",
				"resource_type": "account",
				"subject_email": "admin@writer.com",
				"subject_id":    "admin@writer.com",
				"subject_type":  "user",
			},
		},
		cloudPrivilegePathGrantedRuleID: {
			runtime: rulepackConvertRuntime("aws", "iam_role_trust"),
			kind:    "aws.iam_role_trust",
			attributes: map[string]string{
				"domain":       "123456789012",
				"family":       "iam_role_trust",
				"path_type":    "assume_role_trust",
				"relationship": "can_assume",
				"subject_id":   "arn:aws:iam::999999999999:role/ExternalAdmin",
				"subject_type": "role",
				"target_id":    "arn:aws:iam::123456789012:role/AdminRole",
				"target_type":  "role",
			},
		},
		cloudPublicResourceExposureRuleID: {
			runtime: rulepackConvertRuntime("aws", "resource_exposure"),
			kind:    "aws.resource_exposure",
			attributes: map[string]string{
				"domain":           "123456789012",
				"exposed_to":       "public_internet",
				"exposure_type":    "public_network_ingress",
				"family":           "resource_exposure",
				"internet_exposed": "true",
				"resource_id":      "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
				"resource_name":    "prod-web",
				"resource_type":    "security_group",
				"source_cidr":      "0.0.0.0/0",
			},
		},
		dataSensitiveAssetRiskRuleID: {
			runtime: rulepackConvertRuntime("asset", "crown_jewel"),
			kind:    "asset.crown_jewel",
			attributes: map[string]string{
				"contains_secrets":    "true",
				"crown_jewel":         "true",
				"data_classification": "restricted",
				"internet_exposed":    "true",
				"resource_id":         "prod-secrets",
				"resource_name":       "Production Secrets",
				"resource_type":       "secret_store",
				"source_provider":     "aws",
			},
		},
		githubCodeSecurityControlsDisabledRuleID: {
			runtime: rulepackConvertRuntime("github", "audit"),
			kind:    "github.audit",
			attributes: map[string]string{
				"action":                    "dependabot_alerts.disable",
				"dependabot_alerts_enabled": "false",
				"org":                       "writer",
				"repo":                      "writer/cerebro",
				"resource_type":             "dependabot_alerts",
			},
		},
		githubSecretScanningAlertCreatedRuleID: {
			runtime: rulepackConvertRuntime("github", "audit"),
			kind:    "github.audit",
			attributes: map[string]string{
				"action":                      "secret_scanning_alert.create",
				"html_url":                    "https://github.com/writer/cerebro/security/secret-scanning/12",
				"number":                      "12",
				"repo":                        "writer/cerebro",
				"secret_scanning_alert.state": "open",
				"secret_type":                 "github_personal_access_token",
			},
		},
		identityAdminPrivilegeGrantedRuleID: {
			runtime: rulepackConvertRuntime("google_workspace", "role_assignment"),
			kind:    "google_workspace.role_assignment",
			attributes: map[string]string{
				"domain":        "writer.com",
				"role_id":       "super-admin",
				"role_name":     "Super Admin",
				"subject_email": "admin@writer.com",
				"subject_id":    "1001",
				"subject_type":  "user",
			},
		},
		identityAPIOrOAuthCredentialCreatedRuleID: {
			runtime: rulepackConvertRuntime("aws", "access_key"),
			kind:    "aws.access_key",
			attributes: map[string]string{
				"credential_id":   "AKIAEXAMPLE",
				"credential_type": "aws_access_key",
				"domain":          "123456789012",
				"status":          "ACTIVE",
				"subject_email":   "dev@writer.com",
				"subject_id":      "AIDADEV",
				"subject_type":    "user",
			},
		},
		identityAuthControlLifecycleTamperingRuleID: {
			runtime: rulepackConvertRuntime("okta", "audit"),
			kind:    "okta.audit",
			attributes: map[string]string{
				"actor_email":           "admin@writer.com",
				"auth_control_weakened": "true",
				"domain":                "writer.okta.com",
				"event_type":            "policy.lifecycle.update",
				"outcome_result":        "SUCCESS",
				"policy_id":             "pol-sign-on",
				"resource_id":           "pol-sign-on",
				"resource_type":         "policy",
			},
		},
		identityExternalGroupMemberRuleID: {
			runtime: rulepackConvertRuntime("okta", "group_membership"),
			kind:    "okta.group_membership",
			attributes: map[string]string{
				"domain":         "writer.okta.com",
				"group_id":       "grp-security",
				"group_name":     "Security",
				"member_email":   "external@gmail.com",
				"member_status":  "ACTIVE",
				"member_type":    "user",
				"member_user_id": "00u-external",
			},
		},
		identityMFAFactorResetOrDisabledRuleID: {
			runtime: rulepackConvertRuntime("google_workspace", "user"),
			kind:    "google_workspace.user",
			attributes: map[string]string{
				"domain":        "writer.com",
				"email":         "admin@writer.com",
				"is_admin":      "true",
				"mfa_enforced":  "false",
				"mfa_enrolled":  "false",
				"primary_email": "admin@writer.com",
				"user_id":       "1001",
			},
		},
		oktaPolicyRuleLifecycleTamperingRuleID: {
			runtime: rulepackConvertRuntime("okta", "policy_rule"),
			kind:    "okta.policy_rule",
			attributes: map[string]string{
				"domain":             "writer.okta.com",
				"name":               "Require MFA",
				"policy_id":          "pol-1",
				"policy_rule_id":     "rul-1",
				"policy_rule_status": "INACTIVE",
				"policy_type":        "OKTA_SIGN_ON",
				"resource_id":        "rul-1",
				"resource_type":      "PolicyRule",
				"status":             "INACTIVE",
			},
		},
		identityPrivilegedAccountWithoutMFARuleID: {
			runtime: rulepackConvertRuntime("google_workspace", "user"),
			kind:    "google_workspace.user",
			attributes: map[string]string{
				"domain":        "writer.com",
				"email":         "admin@writer.com",
				"is_admin":      "true",
				"mfa_enrolled":  "false",
				"primary_email": "admin@writer.com",
				"user_id":       "1001",
			},
		},
		identityPrivilegedNoMFAAccessRuleID: {
			runtime:   rulepackConvertRuntime("okta", "user"),
			graphRows: rulepackPrivilegedNoMFAAccessRows(),
		},
		identityStalePrivilegedAccountRuleID: {
			runtime: rulepackConvertRuntime("google_workspace", "user"),
			kind:    "google_workspace.user",
			attributes: map[string]string{
				"domain":        "writer.com",
				"email":         "admin@writer.com",
				"is_admin":      "true",
				"last_login_at": staleLogin,
				"primary_email": "admin@writer.com",
				"user_id":       "1001",
			},
		},
		sentinelOneProtectionControlTamperingRuleID: {
			runtime: rulepackConvertRuntime("sentinelone", "agent"),
			kind:    sentinelOneAgentEntityType,
			attributes: map[string]string{
				"agent_id":         "agent-99",
				"computer_name":    "host-99",
				"control_type":     "firewall",
				"firewall_enabled": "false",
			},
		},
		vulnViewActionableExternalFindingRuleID: {
			runtime: rulepackConvertRuntime("vulnview", "vulnerability"),
			kind:    "vulnview.vulnerability",
			attributes: map[string]string{
				"asset_urn":              "urn:cerebro:writer:external_asset:admin.writer.com",
				"external_id":            "scan-1:exposed-panel:admin.writer.com",
				"host":                   "admin.writer.com",
				"name":                   "Exposed Admin Panel",
				"severity":               "high",
				"target_id":              "admin.writer.com",
				"template_id":            "exposed-panel",
				"vulnview_finding_state": "open",
				"vulnview_status":        "open",
			},
		},
	}
}

func rulepackConvertRuntime(sourceID string, family string) *cerebrov1.SourceRuntime {
	sourceID = strings.TrimSpace(sourceID)
	family = strings.TrimSpace(family)
	return &cerebrov1.SourceRuntime{
		Id:       "example-" + strings.ReplaceAll(sourceID, "_", "-") + "-" + strings.ReplaceAll(family, "_", "-"),
		SourceId: sourceID,
		TenantId: "writer",
		Config:   map[string]string{"family": family},
	}
}

func rulepackPrivilegedNoMFAAccessRows() []ports.CypherRow {
	rows := make([]ports.CypherRow, 0, 3)
	for i, resource := range []struct {
		urn   string
		label string
		kind  string
	}{
		{urn: "urn:cerebro:writer:asset:prod-customer-db", label: "prod-customer-db", kind: "asset.database"},
		{urn: "urn:cerebro:writer:asset:prod-secrets", label: "prod-secrets", kind: "asset.secret_store"},
		{urn: "urn:cerebro:writer:asset:prod-warehouse", label: "prod-warehouse", kind: "asset.warehouse"},
	} {
		rows = append(rows, ports.CypherRow{Values: map[string]any{
			"access_attributes_json":      fmt.Sprintf(`{"role":"owner","event_id":"graph-event-%d","matched_at":"2026-05-23T12:%02d:00Z"}`, i, i),
			"access_relation":             "can_admin",
			"resource_entity_type":        resource.kind,
			"resource_label":              resource.label,
			"resource_urn":                resource.urn,
			"sensitivity_attributes_json": `{"label":"restricted"}`,
			"sensitivity_entity_type":     "data.classification",
			"sensitivity_label":           "restricted",
			"sensitivity_relation":        "has_classification",
			"sensitivity_urn":             "urn:cerebro:writer:data_classification:restricted",
			"user_attributes_json":        `{"is_admin":"true","mfa_enrolled":"false"}`,
			"user_entity_type":            "okta.user",
			"user_label":                  "admin@writer.com",
			"user_urn":                    "urn:cerebro:writer:okta_user:00u-admin",
		}})
	}
	return rows
}

func assertRulepackConvertEventReplaySingleOpenRow(t *testing.T, rule Rule, definition RuleDefinition, fixture rulepackConvertReplayFixture) {
	t.Helper()
	if fixture.runtime == nil {
		t.Fatal("event replay fixture runtime is required")
	}
	events := rulepackConvertReplayEvents(definition.ID, fixture, 4)
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", definition.ID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{events: events[:3]}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{fixture.runtime.GetId(): fixture.runtime}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)
	firstResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: fixture.runtime.GetId(),
		RuleIDs:   []string{definition.ID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q first replay) error = %v", definition.ID, err)
	}
	firstEvaluation := rulepackSingleEvaluation(t, firstResult, definition.ID)
	if got, want := len(firstEvaluation.Findings), 3; got != want {
		t.Fatalf("first replay emitted %d findings, want %d (one per fixture event)", got, want)
	}
	firstFingerprint := assertRulepackStableEmittedFingerprints(t, firstEvaluation.Findings)
	firstOpen := rulepackSingleOpenFindingRow(t, store, definition.ID, fixture.runtime.GetId())
	if got := strings.TrimSpace(firstOpen.Fingerprint); got != firstFingerprint {
		t.Fatalf("first persisted fingerprint = %q, want emitted %q", got, firstFingerprint)
	}
	assertRulepackEventRowProgression(t, definition, firstEvaluation.Findings[0], firstOpen, events[2])
	assertRulepackEvidenceCoversEventIDs(t, store, firstOpen.ID, events[:3])

	replayer.events = events[3:]
	secondResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: fixture.runtime.GetId(),
		RuleIDs:   []string{definition.ID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q second replay) error = %v", definition.ID, err)
	}
	if replayer.calls != 2 {
		t.Fatalf("Replay calls = %d, want 2", replayer.calls)
	}
	secondEvaluation := rulepackSingleEvaluation(t, secondResult, definition.ID)
	if got, want := len(secondEvaluation.Findings), 1; got != want {
		t.Fatalf("second replay emitted %d findings, want %d equivalent finding", got, want)
	}
	if got := assertRulepackStableEmittedFingerprints(t, secondEvaluation.Findings); got != firstFingerprint {
		t.Fatalf("second replay fingerprint = %q, want stable %q", got, firstFingerprint)
	}
	finalOpen := rulepackSingleOpenFindingRow(t, store, definition.ID, fixture.runtime.GetId())
	if finalOpen.ID != firstOpen.ID {
		t.Fatalf("final open finding ID = %q, want same row %q", finalOpen.ID, firstOpen.ID)
	}
	if got := strings.TrimSpace(finalOpen.Fingerprint); got != firstFingerprint {
		t.Fatalf("final fingerprint = %q, want stable %q", got, firstFingerprint)
	}
	assertRulepackEventRowProgression(t, definition, firstEvaluation.Findings[0], finalOpen, events[3])
	assertRulepackEvidenceCoversEventIDs(t, store, finalOpen.ID, events)
}

func rulepackConvertReplayEvents(ruleID string, fixture rulepackConvertReplayFixture, count int) []*cerebrov1.EventEnvelope {
	baseTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	events := make([]*cerebrov1.EventEnvelope, 0, count)
	for i := 0; i < count; i++ {
		observedAt := baseTime.Add(time.Duration(i) * time.Minute)
		eventID := fmt.Sprintf("%s-replay-%02d", ruleID, i)
		attributes := cloneStringMap(fixture.attributes)
		if attributes == nil {
			attributes = map[string]string{}
		}
		attributes["event_id"] = eventID
		attributes["matched_at"] = observedAt.Format(time.RFC3339Nano)
		attributes["family"] = eventFamilyForKind(fixture.kind)
		attributes[ports.EventAttributeSourceRuntimeID] = fixture.runtime.GetId()
		events = append(events, &cerebrov1.EventEnvelope{
			Id:         eventID,
			TenantId:   fixture.runtime.GetTenantId(),
			SourceId:   fixture.runtime.GetSourceId(),
			Kind:       fixture.kind,
			OccurredAt: timestamppb.New(observedAt),
			SchemaRef:  strings.ReplaceAll(fixture.kind, ".", "/") + "/v1",
			Attributes: attributes,
		})
	}
	return events
}

func rulepackSingleEvaluation(t *testing.T, result *EvaluateRulesResult, ruleID string) *RuleEvaluationResult {
	t.Helper()
	if result == nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) returned nil result", ruleID)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) returned %d evaluations, want 1", ruleID, got)
	}
	evaluation := result.Evaluations[0]
	if evaluation == nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) returned nil evaluation", ruleID)
	}
	if got := strings.TrimSpace(evaluation.Rule.GetId()); got != ruleID {
		t.Fatalf("evaluation rule id = %q, want %q", got, ruleID)
	}
	return evaluation
}

func assertRulepackStableEmittedFingerprints(t *testing.T, findings []*ports.FindingRecord) string {
	t.Helper()
	if len(findings) == 0 {
		t.Fatal("no emitted findings")
	}
	fingerprint := strings.TrimSpace(findings[0].Fingerprint)
	if fingerprint == "" {
		t.Fatalf("first emitted finding %q has empty fingerprint", findings[0].ID)
	}
	for i, finding := range findings {
		if finding == nil {
			t.Fatalf("emitted finding %d is nil", i)
		}
		if got := strings.TrimSpace(finding.Fingerprint); got != fingerprint {
			t.Fatalf("emitted finding %d fingerprint = %q, want stable %q", i, got, fingerprint)
		}
	}
	return fingerprint
}

func rulepackSingleOpenFindingRow(t *testing.T, store *stubFindingStore, ruleID string, runtimeID string) *ports.FindingRecord {
	t.Helper()
	openRows := rulepackOpenFindingRows(store, ruleID, runtimeID)
	if got := len(openRows); got != 1 {
		t.Fatalf("open persisted rows for rule %q runtime %q = %d, want exactly 1: %#v", ruleID, runtimeID, got, openRows)
	}
	return openRows[0]
}

func rulepackOpenFindingRows(store *stubFindingStore, ruleID string, runtimeID string) []*ports.FindingRecord {
	if store == nil {
		return nil
	}
	findings := make([]*ports.FindingRecord, 0, len(store.findings))
	for _, finding := range store.findings {
		if finding == nil {
			continue
		}
		if strings.TrimSpace(finding.RuleID) != strings.TrimSpace(ruleID) {
			continue
		}
		if strings.TrimSpace(runtimeID) != "" && strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(runtimeID) {
			continue
		}
		if finding.Tombstoned || strings.TrimSpace(finding.Status) != findingStatusOpen {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func assertRulepackEventRowProgression(t *testing.T, definition RuleDefinition, baseline *ports.FindingRecord, final *ports.FindingRecord, latest *cerebrov1.EventEnvelope) {
	t.Helper()
	if baseline == nil || final == nil || latest == nil {
		t.Fatal("baseline, final finding, and latest event are required")
	}
	if got, want := final.LastObservedAt.UTC(), latest.GetOccurredAt().AsTime().UTC(); !got.Equal(want) {
		t.Fatalf("LastObservedAt = %s, want latest event observed_at %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	if got := strings.TrimSpace(final.Attributes["event_id"]); got != latest.GetId() {
		t.Fatalf("final Attributes[event_id] = %q, want latest event id %q", got, latest.GetId())
	}
	if want := strings.TrimSpace(latest.GetAttributes()["matched_at"]); want != "" {
		if got := strings.TrimSpace(final.Attributes["matched_at"]); got != "" && got != want {
			t.Fatalf("final Attributes[matched_at] = %q, want latest matched_at %q", got, want)
		}
	}
	for _, field := range definition.FingerprintFields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		expected := strings.TrimSpace(baseline.Attributes[field])
		if expected == "" {
			continue
		}
		if got := strings.TrimSpace(final.Attributes[field]); got != expected {
			t.Fatalf("final anchor attribute %q = %q, want preserved %q", field, got, expected)
		}
	}
}

func assertRulepackEvidenceCoversEventIDs(t *testing.T, store *stubFindingStore, findingID string, events []*cerebrov1.EventEnvelope) {
	t.Helper()
	evidence := rulepackEvidenceForFinding(store, findingID)
	if got, wantAtLeast := len(evidence), len(events); got < wantAtLeast {
		t.Fatalf("evidence rows for finding %q = %d, want at least %d to preserve replayed audit events", findingID, got, wantAtLeast)
	}
	seen := map[string]struct{}{}
	for _, record := range evidence {
		if record.GetFindingId() != findingID {
			t.Fatalf("evidence FindingId = %q, want %q", record.GetFindingId(), findingID)
		}
		if len(record.GetEventIds()) == 0 {
			t.Fatalf("evidence %q has no EventIds", record.GetId())
		}
		if strings.TrimSpace(record.GetAttributes()["event_id"]) == "" {
			t.Fatalf("evidence %q Attributes[event_id] is empty", record.GetId())
		}
		for _, eventID := range record.GetEventIds() {
			seen[strings.TrimSpace(eventID)] = struct{}{}
		}
	}
	for _, event := range events {
		if _, ok := seen[strings.TrimSpace(event.GetId())]; !ok {
			t.Fatalf("evidence for finding %q does not preserve event id %q; saw %v", findingID, event.GetId(), sortedRulepackKeys(seen))
		}
	}
}

func rulepackEvidenceForFinding(store *stubFindingStore, findingID string) []*cerebrov1.FindingEvidence {
	if store == nil {
		return nil
	}
	evidence := make([]*cerebrov1.FindingEvidence, 0, len(store.evidence))
	for _, record := range store.evidence {
		if record == nil || strings.TrimSpace(record.GetFindingId()) != strings.TrimSpace(findingID) {
			continue
		}
		evidence = append(evidence, cloneFindingEvidence(record))
	}
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].GetId() < evidence[j].GetId()
	})
	return evidence
}

func sortedRulepackKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func assertRulepackConvertGraphReplaySingleOpenRow(t *testing.T, rule Rule, definition RuleDefinition, fixture rulepackConvertReplayFixture) {
	t.Helper()
	graphRule, ok := rule.(GraphRule)
	if !ok {
		t.Fatalf("convert rule %q has graph fixture but does not implement GraphRule", definition.ID)
	}
	if len(fixture.graphRows) < 3 {
		t.Fatalf("graph fixture for %q has %d rows, want at least 3 rows for one durable user anchor", definition.ID, len(fixture.graphRows))
	}
	registry, err := NewRegistry(graphRule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", definition.ID, err)
	}
	store := &stubFindingStore{}
	graphStore := &stubGraphStore{cypherRows: fixture.graphRows}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{fixture.runtime.GetId(): fixture.runtime}},
		&stubReplayer{},
		store,
		store,
		store,
		store,
		registry,
	).WithGraphQueryStore(graphStore)

	firstResult, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{
		RuntimeID: fixture.runtime.GetId(),
		RuleIDs:   []string{definition.ID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(%q first replay) error = %v", definition.ID, err)
	}
	firstEvaluation := rulepackSingleGraphEvaluation(t, firstResult, definition.ID)
	if got, want := int(firstEvaluation.RowsRead), len(fixture.graphRows); got != want {
		t.Fatalf("graph RowsRead = %d, want %d", got, want)
	}
	if got := len(firstEvaluation.Findings); got != 1 {
		t.Fatalf("first graph replay emitted %d findings, want one grouped finding for one durable user anchor", got)
	}
	firstFingerprint := strings.TrimSpace(firstEvaluation.Findings[0].Fingerprint)
	if firstFingerprint == "" {
		t.Fatal("first graph finding has empty fingerprint")
	}
	firstOpen := rulepackSingleOpenFindingRow(t, store, definition.ID, fixture.runtime.GetId())
	if got := strings.TrimSpace(firstOpen.Fingerprint); got != firstFingerprint {
		t.Fatalf("first graph persisted fingerprint = %q, want emitted %q", got, firstFingerprint)
	}
	assertRulepackGraphEvidence(t, store, firstOpen.ID, len(fixture.graphRows), 1)
	firstObserved := firstOpen.LastObservedAt

	secondResult, err := service.EvaluateSourceRuntimeGraphRules(context.Background(), EvaluateGraphRulesRequest{
		RuntimeID: fixture.runtime.GetId(),
		RuleIDs:   []string{definition.ID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(%q second replay) error = %v", definition.ID, err)
	}
	secondEvaluation := rulepackSingleGraphEvaluation(t, secondResult, definition.ID)
	if got := len(secondEvaluation.Findings); got != 1 {
		t.Fatalf("second graph replay emitted %d findings, want one equivalent finding", got)
	}
	if got := strings.TrimSpace(secondEvaluation.Findings[0].Fingerprint); got != firstFingerprint {
		t.Fatalf("second graph fingerprint = %q, want stable %q", got, firstFingerprint)
	}
	finalOpen := rulepackSingleOpenFindingRow(t, store, definition.ID, fixture.runtime.GetId())
	if finalOpen.ID != firstOpen.ID {
		t.Fatalf("final graph finding ID = %q, want same row %q", finalOpen.ID, firstOpen.ID)
	}
	if finalOpen.LastObservedAt.Before(firstObserved) {
		t.Fatalf("final graph LastObservedAt = %s, want not before first replay %s", finalOpen.LastObservedAt.Format(time.RFC3339Nano), firstObserved.Format(time.RFC3339Nano))
	}
	if got := strings.TrimSpace(finalOpen.Attributes["user"]); got == "" {
		t.Fatalf("final graph Attributes[user] = empty, want durable user anchor preserved")
	}
	assertRulepackGraphEvidence(t, store, finalOpen.ID, len(fixture.graphRows), 2)
}

func rulepackSingleGraphEvaluation(t *testing.T, result *EvaluateGraphRulesResult, ruleID string) *GraphRuleEvaluationResult {
	t.Helper()
	if result == nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(%q) returned nil result", ruleID)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(%q) returned %d evaluations, want 1", ruleID, got)
	}
	evaluation := result.Evaluations[0]
	if evaluation == nil {
		t.Fatalf("EvaluateSourceRuntimeGraphRules(%q) returned nil evaluation", ruleID)
	}
	if got := strings.TrimSpace(evaluation.Rule.GetId()); got != ruleID {
		t.Fatalf("graph evaluation rule id = %q, want %q", got, ruleID)
	}
	return evaluation
}

func assertRulepackGraphEvidence(t *testing.T, store *stubFindingStore, findingID string, wantGraphRows int, wantRunIDsAtLeast int) {
	t.Helper()
	evidence := rulepackEvidenceForFinding(store, findingID)
	if len(evidence) != 1 {
		t.Fatalf("graph evidence rows for finding %q = %d, want one merged evidence row", findingID, len(evidence))
	}
	record := evidence[0]
	if got := len(record.GetGraphRows()); got != wantGraphRows {
		t.Fatalf("graph evidence row count = %d, want %d", got, wantGraphRows)
	}
	if got := len(record.GetRunIds()); got < wantRunIDsAtLeast {
		t.Fatalf("graph evidence RunIds = %v, want at least %d run id(s)", record.GetRunIds(), wantRunIDsAtLeast)
	}
	if record.GetLastObservedAt() == nil || record.GetLastObservedAt().AsTime().IsZero() {
		t.Fatalf("graph evidence %q LastObservedAt is empty", record.GetId())
	}
}

func TestKeepAsIsRulesUnchanged(t *testing.T) {
	metadataByID := rulepackAuditMetadataByID(t)
	keepRules := rulepackAuditRulesByClass(t, rulepackAuditClassKeep)
	if got, want := len(keepRules), 50; got != want {
		t.Fatalf("KEEP_AS_IS rule count = %d, want %d", got, want)
	}
	for _, entry := range keepRules {
		definition := metadataByID[entry.RuleID]
		if definition.Lifecycle.Kind != LifecycleDurableState {
			t.Fatalf("KEEP_AS_IS rule %q Lifecycle.Kind = %q, want %q",
				entry.RuleID, definition.Lifecycle.Kind, LifecycleDurableState)
		}
		switch definition.Lifecycle.Anchor {
		case AnchorGraphAnchored, AnchorSourceState:
		default:
			t.Fatalf("KEEP_AS_IS rule %q Lifecycle.Anchor = %q, want graph_anchored or source_state",
				entry.RuleID, definition.Lifecycle.Anchor)
		}
		if field := prohibitedKeepAsIsFingerprintField(definition.FingerprintFields); field != "" {
			t.Fatalf("KEEP_AS_IS rule %q FingerprintFields = %v, prohibited field %q present",
				entry.RuleID, definition.FingerprintFields, field)
		}
	}
}

func TestEventRuleEvaluateRequiresLifecycle(t *testing.T) {
	definition := RuleDefinition{
		ID:                 "test-missing-lifecycle",
		Name:               "Missing Lifecycle Test",
		SourceID:           "github",
		EventKinds:         []string{"github.audit"},
		OutputKind:         "finding.test_missing_lifecycle",
		Severity:           "MEDIUM",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"test"},
		References:         []string{"https://example.com"},
		FalsePositives:     []string{"test"},
		Runbook:            "test",
		RequiredAttributes: []string{"action"},
		FingerprintFields:  []string{"repo"},
		ControlRefs:        []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}},
	}
	rule := newEventRule(eventRuleConfig{
		definition: definition,
		match:      eventKindMatcher("github.audit"),
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return &ports.FindingRecord{ID: "f-1", RuleID: definition.ID, Status: findingStatusOpen}, nil
		},
	})
	_, err := rule.Evaluate(context.Background(),
		&cerebrov1.SourceRuntime{Id: "example-github-audit", SourceId: "github", TenantId: "writer"},
		&cerebrov1.EventEnvelope{
			Id:         "event-1",
			TenantId:   "writer",
			SourceId:   "github",
			Kind:       "github.audit",
			OccurredAt: timestamppb.New(time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)),
			Attributes: map[string]string{"action": "repo.access", "repo": "writer/cerebro"},
		},
	)
	if err == nil {
		t.Fatal("Evaluate() error = nil, want missing lifecycle validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "lifecycle") {
		t.Fatalf("Evaluate() error = %v, want message mentioning lifecycle", err)
	}
}

func loadRulepackAuditClassifications(t *testing.T) []rulepackAuditClassification {
	t.Helper()
	for _, path := range rulepackAuditPlanningCandidates(t) {
		payload, err := os.ReadFile(path) // #nosec G304 -- optional local audit classification fixture path is generated by the test helper.
		if err != nil {
			continue
		}
		var document struct {
			Rules []rulepackAuditClassification `json:"rules"`
		}
		if err := json.Unmarshal(payload, &document); err != nil {
			t.Fatalf("unmarshal %s: %v", path, err)
		}
		if len(document.Rules) == 0 {
			t.Fatalf("classification file %s contains no rules", path)
		}
		return document.Rules
	}
	t.Log("classification JSON not found near worktree; using embedded fallback table")
	return fallbackRulepackAuditClassifications()
}

func rulepackAuditPlanningCandidates(t *testing.T) []string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		return nil
	}
	var candidates []string
	for dir := wd; ; dir = filepath.Dir(dir) {
		candidates = append(candidates, filepath.Join(dir, "_planning", "01-per-rule-classification.json"))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return candidates
}

func assertCloseoutRuleIDFile(t *testing.T, relPath string, expected []string) {
	t.Helper()
	path := repoRelativePath(t, relPath)
	payload, err := os.ReadFile(path) // #nosec G304 -- repository-relative rule ID file path is supplied by the test case.
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	actual := parseCloseoutRuleIDFile(t, string(payload))
	sort.Strings(expected)
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("%s rule IDs mismatch\nactual:\n%s\n\nexpected:\n%s", relPath, strings.Join(actual, "\n"), strings.Join(expected, "\n"))
	}
}

func parseCloseoutRuleIDFile(t *testing.T, payload string) []string {
	t.Helper()
	seen := map[string]struct{}{}
	var out []string
	for lineNumber, line := range strings.Split(payload, "\n") {
		text := strings.TrimSpace(line)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if _, ok := seen[text]; ok {
			t.Fatalf("duplicate rule id %q on line %d", text, lineNumber+1)
		}
		seen[text] = struct{}{}
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

func repoRelativePath(t *testing.T, relPath string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, relPath)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	t.Fatalf("could not find %s from %s", relPath, wd)
	return ""
}

func fallbackRulepackAuditClassifications() []rulepackAuditClassification {
	return []rulepackAuditClassification{
		{RuleID: "cloud-effective-admin-permission", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "cloud-privilege-path-granted", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "cloud-public-exposure-privileged-principal", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "cloud"},
		{RuleID: "cloud-current-public-exposure-review-needed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "cloud"},
		{RuleID: "cloud-exposed-privileged-compute-role", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "cloud"},
		{RuleID: "cloud-public-resource-exposure", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "cloudflare-zone-protection-paused", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "cloudflare"},
		{RuleID: "data-sensitive-asset-risk", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "asset"},
		{RuleID: "email-domain-authentication-misconfigured", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "email_domain_health"},
		{RuleID: "evidence-cas-unresolved-linkage", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "evidence_cas"},
		{RuleID: "github-app-integration-installed", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-code-security-controls-disabled", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-dependabot-open-alert", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "github-org-auth-control-modified", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-org-ip-allow-list-modified", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-organization-owner-added", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-personal-access-token-created", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-private-repository-forking-enabled", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-repository-collaborator-added", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-repository-ruleset-modified", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-secret-scanning-alert-created", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-self-hosted-runner-review-needed", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "github-org-owner-role-review-needed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "github-programmatic-credential-review-needed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "github-webhook-modified", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "github"},
		{RuleID: "grc-control-test-needs-attention", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-failing-control-open-operational-findings", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-failing-control-test-unhealthy-integration", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-control-missing-evidence-coverage", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-document-needs-owner-or-upload", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-inactive-identity-active-access", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-isolated-target-enrichment-gap", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-overdue-vulnerability-live-on-assets", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-privileged-account-missing-person", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-source-integration-concentrated-open-findings", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-vendor-review-overdue", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-vulnerability-sla-overdue", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "kandji-endpoint-disk-encryption-disabled", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "kandji"},
		{RuleID: "identity-admin-privilege-granted", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-api-token-or-oauth-app-created", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-auth-control-lifecycle-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-external-or-personal-group-member", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-github-active-without-okta-link", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "identity-mfa-factor-reset-or-disabled", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-okta-authenticator-weak-factor-enabled", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "identity"},
		{RuleID: "identity-okta-deprovisioned-active-cloud-access", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "okta"},
		{RuleID: "identity-okta-oauth-public-client-review-needed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "identity"},
		{RuleID: "identity-okta-threat-insight-not-blocking", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "identity"},
		{RuleID: "identity-okta-deprovisioned-active-in-github", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "okta"},
		{RuleID: "identity-okta-policy-rule-lifecycle-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "okta"},
		{RuleID: "identity-privileged-account-without-mfa", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-privileged-no-mfa-plus-sensitive-access", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-stale-privileged-account", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "finding-isolated-open-anchor", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "graph"},
		{RuleID: "graph-aws-ec2-eni-link-missing", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "graph"},
		{RuleID: "graph-orphan-nonfinding-node", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "graph"},
		{RuleID: "graph-resource-multiple-open-findings", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "graph"},
		{RuleID: "panopticon-curated-case", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "panopticon"},
		{RuleID: "runtime-active-threat-evidence", Classification: "TTL_EVIDENCE_ONLY", BulkCloseoutThreshold: ">24h", Source: "runtime"},
		{RuleID: "security-reviewer-reported-finding", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "security_reviewer"},
		{RuleID: "sentinelone-agent-detect-only-mode", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-agent-not-up-to-date", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-agent-stale", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-endpoint-active-infection", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-infected-endpoint-privileged-owner", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-mitigation-failed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-protection-control-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "sentinelone"},
		{RuleID: "sentinelone-risky-exclusion", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-unmitigated-threat", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "trivy-image-vulnerability-active", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "trivy"},
		{RuleID: "tailscale-tailnet-device-approval-disabled", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "tailscale"},
		{RuleID: "kolide-host-failing-compliance-checks", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "kolide"},
		{RuleID: "duo-active-user-mfa-not-enforced", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "duo"},
		{RuleID: "openai-orphaned-privileged-api-key", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "openai"},
		{RuleID: "slack-privileged-user-without-mfa", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "slack"},
		{RuleID: "pagerduty-service-without-escalation-policy", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "pagerduty"},
		{RuleID: "trusted-endpoint-active-trust-gate-failure", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "trusted_endpoint"},
		{RuleID: "vulnview-actionable-external-finding", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "vulnview"},
		{RuleID: "vulnview-external-asset-concentrated-signal", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "vulnview"},
	}
}

func rulepackAuditRulesByClass(t *testing.T, classes ...string) []rulepackAuditClassification {
	t.Helper()
	classSet := make(map[string]struct{}, len(classes))
	for _, class := range classes {
		classSet[class] = struct{}{}
	}
	var out []rulepackAuditClassification
	for _, entry := range loadRulepackAuditClassifications(t) {
		if _, ok := classSet[entry.Classification]; ok {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func rulepackAuditMetadataByID(t *testing.T) map[string]RuleDefinition {
	t.Helper()
	out := map[string]RuleDefinition{}
	for _, definition := range BuiltinRuleMetadata() {
		if policyRuleMetadata(definition) {
			continue
		}
		if definition.ID == "" {
			t.Fatal("BuiltinRuleMetadata returned empty rule ID")
		}
		if _, exists := out[definition.ID]; exists {
			t.Fatalf("duplicate BuiltinRuleMetadata ID %q", definition.ID)
		}
		out[definition.ID] = definition
	}
	return out
}

func prohibitedFingerprintField(fields []string) string {
	for _, field := range fields {
		normalized := strings.ToLower(strings.TrimSpace(field))
		if normalized == "event_id" || normalized == "matched_at" {
			return field
		}
	}
	return ""
}

func prohibitedKeepAsIsFingerprintField(fields []string) string {
	for _, field := range fields {
		if strings.EqualFold(strings.TrimSpace(field), "event_id") {
			return field
		}
	}
	return ""
}

func rulepackAuditThresholdDuration(t *testing.T, threshold string) time.Duration {
	t.Helper()
	value := strings.TrimPrefix(strings.TrimSpace(threshold), ">")
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil {
			t.Fatalf("parse threshold %q: %v", threshold, err)
		}
		return time.Duration(days) * 24 * time.Hour
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		t.Fatalf("parse threshold %q: %v", threshold, err)
	}
	if duration <= 0 {
		t.Fatalf("threshold %q parsed to non-positive duration %s", threshold, duration)
	}
	return duration
}

func eventFamilyForKind(kind string) string {
	parts := strings.Split(strings.TrimSpace(kind), ".")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}
	return "audit"
}

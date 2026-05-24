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
	if got, want := len(convertRules), 27; got != want {
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

func TestAlreadyRetiredRulesParity(t *testing.T) {
	alreadyRetired := []string{
		githubBranchProtectionDisabledRuleID,
		githubProtectedBranchPolicyOverrideRuleID,
		githubPushProtectionDisabledRuleID,
		githubRepositoryMadePublicRuleID,
		githubSecretScanningDisabledRuleID,
		sentinelOneRetiredInfectedEndpointRuleID,
		sentinelOneRetiredMaliciousOrFilelessRuleID,
		sentinelOneRetiredUnresolvedThreatRuleID,
	}
	assertRetiredRuleSetParity(t, alreadyRetired)
}

func TestCloseoutSelectorCoversAllRetiredAndConvertRules(t *testing.T) {
	targets := append(rulepackAuditRulesByClass(t, rulepackAuditClassConvert), rulepackAuditRulesByClass(t, rulepackAuditClassRetire)...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].RuleID < targets[j].RuleID })
	if got, want := len(targets), 37; got != want {
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

func TestConvertRulesReplaySingleOpenRow(t *testing.T) {
	metadataByID := rulepackAuditMetadataByID(t)
	for _, entry := range rulepackAuditRulesByClass(t, rulepackAuditClassConvert) {
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
			openRowsByFingerprint := map[string]int{}
			for i := 0; i < 4; i++ {
				attributes := stableAnchorAttributes(definition.FingerprintFields)
				attributes["event_id"] = fmt.Sprintf("event-%d", i)
				attributes["matched_at"] = fmt.Sprintf("2026-05-23T12:%02d:00Z", i)
				inputs := fingerprintInputsFromFields(definition.FingerprintFields, attributes)
				fingerprint := hashFindingFingerprint(append([]string{entry.RuleID}, inputs...)...)
				openRowsByFingerprint[fingerprint]++
			}
			if got := len(openRowsByFingerprint); got != 1 {
				t.Fatalf("replay for %q produced %d open fingerprints, want exactly one per durable anchor: %#v",
					entry.RuleID, got, openRowsByFingerprint)
			}
		})
	}
}

func TestNetNewRetiredRulesNoEmit(t *testing.T) {
	assertRetiredRuleSetParity(t, []string{
		githubCriticalResourceDeletedRuleID,
		identityControlTamperCredentialChangeRuleID,
	})
}

func TestKeepAsIsRulesUnchanged(t *testing.T) {
	metadataByID := rulepackAuditMetadataByID(t)
	keepRules := rulepackAuditRulesByClass(t, rulepackAuditClassKeep)
	if got, want := len(keepRules), 17; got != want {
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

func assertRetiredRuleSetParity(t *testing.T, ruleIDs []string) {
	t.Helper()
	metadataByID := rulepackAuditMetadataByID(t)
	catalogByID := rulepackAuditCatalogByID(t)
	registry := Builtin()
	for _, ruleID := range ruleIDs {
		ruleID := ruleID
		t.Run(ruleID, func(t *testing.T) {
			definition, ok := metadataByID[ruleID]
			if !ok {
				t.Fatalf("rule %q missing from BuiltinRuleMetadata", ruleID)
			}
			if definition.Lifecycle.Kind != LifecycleRetired {
				t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleRetired)
			}
			if definition.Lifecycle.Anchor != AnchorNone {
				t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorNone)
			}
			detection, ok := catalogByID[ruleID]
			if !ok {
				t.Fatalf("rule %q missing from public detection catalog", ruleID)
			}
			if detection.Maturity != "retired" {
				t.Fatalf("catalog maturity = %q, want retired", detection.Maturity)
			}
			rule, ok := registry.Get(ruleID)
			if !ok {
				t.Fatalf("Builtin registry missing retired rule %q", ruleID)
			}
			retirementRule, ok := rule.(openFindingRetirementRule)
			if !ok || !retirementRule.RetiresOpenFindings() {
				t.Fatalf("rule %q does not expose RetiresOpenFindings=true", ruleID)
			}
			eventKind := firstNonEmptyString(definition.EventKinds...)
			event := sampleRetiredRuleEvent(ruleID, eventKind)
			runtime := &cerebrov1.SourceRuntime{
				Id:       "example-" + runtimeSourceForEventKind(eventKind, definition.SourceID),
				SourceId: runtimeSourceForEventKind(eventKind, definition.SourceID),
				TenantId: "writer",
				Config:   map[string]string{"family": eventFamilyForKind(eventKind)},
			}
			records, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate() emitted %d findings for retired rule, want zero", len(records))
			}
		})
	}
}

func loadRulepackAuditClassifications(t *testing.T) []rulepackAuditClassification {
	t.Helper()
	for _, path := range rulepackAuditPlanningCandidates(t) {
		payload, err := os.ReadFile(path)
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

func fallbackRulepackAuditClassifications() []rulepackAuditClassification {
	return []rulepackAuditClassification{
		{RuleID: "cloud-effective-admin-permission", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "cloud-privilege-path-granted", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "cloud-public-exposure-privileged-principal", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "cloud"},
		{RuleID: "cloud-public-resource-exposure", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "cloud"},
		{RuleID: "data-sensitive-asset-risk", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "asset"},
		{RuleID: "github-app-integration-installed", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-branch-protection-disabled", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-code-security-controls-disabled", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-critical-resource-deleted", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-dependabot-open-alert", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "github-org-auth-control-modified", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-org-ip-allow-list-modified", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-organization-owner-added", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-personal-access-token-created", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-private-repository-forking-enabled", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-protected-branch-policy-override", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-push-protection-disabled", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-repository-collaborator-added", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-repository-made-public", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-repository-ruleset-modified", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-secret-scanning-alert-created", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-secret-scanning-disabled", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-self-hosted-runner-change", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "github-webhook-modified", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "github"},
		{RuleID: "grc-control-test-needs-attention", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-failing-control-open-operational-findings", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-inactive-identity-active-access", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-overdue-vulnerability-live-on-assets", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-privileged-account-missing-person", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-vendor-review-overdue", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "grc-vulnerability-sla-overdue", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "grc"},
		{RuleID: "identity-admin-privilege-granted", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-api-token-or-oauth-app-created", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-auth-control-lifecycle-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-control-tamper-followed-by-credential-change", Classification: "RETIRE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-external-or-personal-group-member", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-github-active-without-okta-link", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "github"},
		{RuleID: "identity-mfa-factor-reset-or-disabled", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "identity"},
		{RuleID: "identity-okta-deprovisioned-active-in-github", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "okta"},
		{RuleID: "identity-okta-policy-rule-lifecycle-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "okta"},
		{RuleID: "identity-privileged-account-without-mfa", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-privileged-no-mfa-plus-sensitive-access", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "identity-stale-privileged-account", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">24h", Source: "identity"},
		{RuleID: "runtime-active-threat-evidence", Classification: "TTL_EVIDENCE_ONLY", BulkCloseoutThreshold: ">24h", Source: "runtime"},
		{RuleID: "sentinelone-agent-detect-only-mode", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-agent-stale", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-endpoint-active-infection", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-infected-endpoint", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "sentinelone"},
		{RuleID: "sentinelone-malicious-or-fileless-threat", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "sentinelone"},
		{RuleID: "sentinelone-mitigation-failed", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-protection-control-tampering", Classification: "CONVERT_TO_CURRENT_STATE", BulkCloseoutThreshold: ">7d", Source: "sentinelone"},
		{RuleID: "sentinelone-risky-exclusion", Classification: "KEEP_AS_IS", BulkCloseoutThreshold: "none", Source: "sentinelone"},
		{RuleID: "sentinelone-unresolved-threat", Classification: "RETIRE", BulkCloseoutThreshold: ">7d", Source: "sentinelone"},
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

func rulepackAuditCatalogByID(t *testing.T) map[string]PublicDetection {
	t.Helper()
	out := map[string]PublicDetection{}
	for _, detection := range BuiltinPublicDetectionCatalog().Detections {
		if detection.ID == "" {
			t.Fatal("BuiltinPublicDetectionCatalog returned empty detection ID")
		}
		if _, exists := out[detection.ID]; exists {
			t.Fatalf("duplicate catalog detection ID %q", detection.ID)
		}
		out[detection.ID] = detection
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

func stableAnchorAttributes(fields []string) map[string]string {
	attributes := map[string]string{}
	for _, field := range fields {
		key := strings.TrimSpace(field)
		if key == "" {
			continue
		}
		attributes[key] = "anchor-" + strings.NewReplacer(".", "-", "_", "-").Replace(key)
	}
	return attributes
}

func fingerprintInputsFromFields(fields []string, attributes map[string]string) []string {
	inputs := make([]string, 0, len(fields))
	for _, field := range fields {
		value := strings.TrimSpace(attributes[strings.TrimSpace(field)])
		if value != "" {
			inputs = append(inputs, value)
		}
	}
	return inputs
}

func sampleRetiredRuleEvent(ruleID string, kind string) *cerebrov1.EventEnvelope {
	if strings.TrimSpace(kind) == "" {
		kind = "github.audit"
	}
	sourceID := runtimeSourceForEventKind(kind, "")
	return &cerebrov1.EventEnvelope{
		Id:         "event-" + ruleID,
		TenantId:   "writer",
		SourceId:   sourceID,
		Kind:       kind,
		OccurredAt: timestamppb.New(time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  strings.ReplaceAll(kind, ".", "/") + "/v1",
		Attributes: map[string]string{
			"action":              "repo.destroy",
			"actor_email":         "actor@example.com",
			"repo":                "writer/cerebro",
			"resource_id":         "writer/cerebro",
			"resource_type":       "repo",
			"threat_id":           "threat-1",
			"threat_name":         "retired threat",
			"incident_status":     "unresolved",
			"mitigation_status":   "not_mitigated",
			"is_infected":         "true",
			"agent_id":            "agent-1",
			"credential_id":       "cred-1",
			"user":                "alice@example.com",
			"user_id":             "alice@example.com",
			"family":              eventFamilyForKind(kind),
			"source_runtime_id":   "example-" + sourceID,
			"previous_visibility": "private",
			"visibility":          "public",
		},
	}
}

func runtimeSourceForEventKind(kind string, fallback string) string {
	parts := strings.Split(strings.TrimSpace(kind), ".")
	if parts[0] != "" {
		return parts[0]
	}
	if strings.TrimSpace(fallback) != "" {
		return strings.TrimSpace(fallback)
	}
	return "github"
}

func eventFamilyForKind(kind string) string {
	parts := strings.Split(strings.TrimSpace(kind), ".")
	if len(parts) > 1 && parts[1] != "" {
		return parts[1]
	}
	return "audit"
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

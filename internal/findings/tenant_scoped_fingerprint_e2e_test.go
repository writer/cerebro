package findings_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/statestore/postgres"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	tenantScopedGitHubAuditRuleID     = "github-repository-collaborator-added"
	tenantScopedDependabotRuleID      = "github-dependabot-open-alert"
	tenantScopedSentinelOneRuleID     = "sentinelone-protection-control-tampering"
	tenantScopedIdentityUserRuleID    = "identity-privileged-account-without-mfa"
	tenantScopedIdentityAdminRuleID   = "identity-admin-privilege-granted"
	tenantScopedIdentityAuthRuleID    = "identity-auth-control-lifecycle-tampering"
	tenantScopedIdentityTokenRuleID   = "identity-api-token-or-oauth-app-created"
	tenantScopedIdentityGroupRuleID   = "identity-external-or-personal-group-member"
	tenantScopedFindingStatusOpen     = "open"
	tenantScopedFindingStatusResolved = "resolved"
)

var tenantScopedBaseTime = time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

type tenantScopedFingerprintCase struct {
	name     string
	ruleID   string
	sourceID string
	family   string
	event    *cerebrov1.EventEnvelope
}

func TestGitHubAuditFingerprint_TenantScoped(t *testing.T) {
	if tenantScopedRuleRetired(t, tenantScopedGitHubAuditRuleID) {
		t.Skip("github repository collaborator audit rule is retired")
	}
	store := tenantScopedPostgresStore(t)
	tc := githubAuditTenantScopedCase()
	first, second := runTenantScopedFingerprintPair(t, store, tc)
	if first.Fingerprint == second.Fingerprint {
		t.Fatalf("GitHub audit fingerprints are equal across tenants: %q", first.Fingerprint)
	}
	if got, want := first.Fingerprint, tenantScopedHash(tc.ruleID, first.TenantID, "writer/cerebro", "octocat"); got != want {
		t.Fatalf("tenant A fingerprint = %q, want %q", got, want)
	}
}

func TestSentinelOneProtectionControlTamperingFingerprint_TenantScoped(t *testing.T) {
	store := tenantScopedPostgresStore(t)
	tc := sentinelOneTenantScopedCase()
	first, second := runTenantScopedFingerprintPair(t, store, tc)
	if first.Fingerprint == second.Fingerprint {
		t.Fatalf("SentinelOne fingerprints are equal across tenants: %q", first.Fingerprint)
	}
	if got, want := first.Fingerprint, tenantScopedHash(tc.ruleID, first.TenantID, "agent-99", "firewall"); got != want {
		t.Fatalf("tenant A fingerprint = %q, want %q", got, want)
	}
}

func TestIdentityFingerprintHelpers_TenantScoped_Integration(t *testing.T) {
	store := tenantScopedPostgresStore(t)
	for _, tc := range identityTenantScopedCases() {
		t.Run(tc.name, func(t *testing.T) {
			first, second := runTenantScopedFingerprintPair(t, store, tc)
			if first.Fingerprint == second.Fingerprint {
				t.Fatalf("%s fingerprints are equal across tenants: %q", tc.name, first.Fingerprint)
			}
		})
	}
}

func TestGitHubDependabotAlertFingerprint_TenantScoped(t *testing.T) {
	rule := mustBuiltinRule(t, tenantScopedDependabotRuleID)
	metadataRule, ok := rule.(findings.MetadataRule)
	if !ok {
		t.Fatal("github-dependabot-open-alert does not expose RuleMetadata")
	}
	fields := metadataRule.RuleMetadata().FingerprintFields
	if len(fields) == 0 || strings.TrimSpace(fields[0]) != "tenant_id" {
		t.Fatalf("FingerprintFields = %v, want tenant_id as first field", fields)
	}

	store := tenantScopedPostgresStore(t)
	tc := githubDependabotTenantScopedCase()
	first, second := runTenantScopedFingerprintPair(t, store, tc)
	if first.Fingerprint == second.Fingerprint {
		t.Fatalf("Dependabot fingerprints are equal across tenants: %q", first.Fingerprint)
	}
	if got, want := first.Fingerprint, tenantScopedHash(tc.ruleID, first.TenantID, "writer/cerebro", "7"); got != want {
		t.Fatalf("tenant A fingerprint = %q, want %q", got, want)
	}
}

func TestIdentityUserAnchor_ProviderScoped(t *testing.T) {
	store := tenantScopedPostgresStore(t)
	ctx := context.Background()
	tenantID := tenantScopedTestTenant("identity-anchor")
	oktaRuntime := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID("identity-anchor-okta", tenantID),
		SourceId: "okta",
		TenantId: tenantID,
		Config:   map[string]string{"family": "user"},
	}
	googleRuntime := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID("identity-anchor-google", tenantID),
		SourceId: "google_workspace",
		TenantId: tenantID,
		Config:   map[string]string{"family": "user"},
	}
	rule := mustBuiltinRule(t, tenantScopedIdentityUserRuleID)
	registry, err := findings.NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q): %v", tenantScopedIdentityUserRuleID, err)
	}
	replayer := &stubReplayer{}
	service := findings.NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			oktaRuntime.GetId():   oktaRuntime,
			googleRuntime.GetId(): googleRuntime,
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	oktaOpen := tenantScopedEvent("provider-okta-open", tenantID, "okta", "okta.user", map[string]string{
		"email":        "admin@example.com",
		"is_admin":     "true",
		"mfa_enrolled": "false",
		"status":       "ACTIVE",
		"user_id":      "00u-okta-admin",
	}, tenantScopedBaseTime)
	replayer.events = []*cerebrov1.EventEnvelope{withRuntimeID(oktaOpen, oktaRuntime.GetId())}
	openResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: oktaRuntime.GetId(),
		RuleIDs:   []string{tenantScopedIdentityUserRuleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(okta open): %v", err)
	}
	if len(openResult.Evaluations) != 1 || len(openResult.Evaluations[0].Findings) != 1 {
		t.Fatalf("okta open result = %#v, want one finding", openResult)
	}
	oktaFinding := openResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(oktaFinding.Status); got != tenantScopedFindingStatusOpen {
		t.Fatalf("okta finding status = %q, want open", got)
	}

	googleMFAEnabled := tenantScopedEvent("provider-google-mfa-enabled", tenantID, "google_workspace", "google_workspace.user", map[string]string{
		"email":         "admin@example.com",
		"is_admin":      "true",
		"mfa_enrolled":  "true",
		"primary_email": "admin@example.com",
		"user_id":       "google-admin-1001",
	}, tenantScopedBaseTime.Add(time.Minute))
	replayer.events = []*cerebrov1.EventEnvelope{withRuntimeID(googleMFAEnabled, googleRuntime.GetId())}
	if _, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: googleRuntime.GetId(),
		RuleIDs:   []string{tenantScopedIdentityUserRuleID},
	}); err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(google close): %v", err)
	}
	after, err := store.GetFinding(ctx, oktaFinding.ID)
	if err != nil {
		t.Fatalf("reload okta finding %q: %v", oktaFinding.ID, err)
	}
	if got := strings.TrimSpace(after.Status); got != tenantScopedFindingStatusOpen {
		t.Fatalf("Okta finding status after Google Workspace MFA event = %q, want open", got)
	}
}

func TestIdentityAdminPrivilegeAnchor_ProviderScoped(t *testing.T) {
	store := tenantScopedPostgresStore(t)
	ctx := context.Background()
	tenantID := tenantScopedTestTenant("identity-admin-anchor")
	oktaRuntime := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID("identity-admin-anchor-okta", tenantID),
		SourceId: "okta",
		TenantId: tenantID,
		Config:   map[string]string{"family": "admin_role"},
	}
	googleRuntime := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID("identity-admin-anchor-google", tenantID),
		SourceId: "google_workspace",
		TenantId: tenantID,
		Config:   map[string]string{"family": "role_assignment"},
	}
	rule := mustBuiltinRule(t, tenantScopedIdentityAdminRuleID)
	registry, err := findings.NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q): %v", tenantScopedIdentityAdminRuleID, err)
	}
	replayer := &stubReplayer{}
	service := findings.NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			oktaRuntime.GetId():   oktaRuntime,
			googleRuntime.GetId(): googleRuntime,
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)

	oktaAttrs := map[string]string{
		"domain":        "writer.okta.com",
		"role_id":       "super-admin",
		"role_name":     "Super Admin",
		"status":        "ACTIVE",
		"subject_email": "admin@example.com",
		"subject_id":    "00u-okta-admin",
		"subject_type":  "user",
	}
	googleAttrs := map[string]string{
		"domain":        "writer.com",
		"role_id":       "super-admin",
		"role_name":     "Super Admin",
		"status":        "ACTIVE",
		"subject_email": "admin@example.com",
		"subject_id":    "google-admin-1001",
		"subject_type":  "user",
	}
	oktaOpen := withRuntimeID(tenantScopedEvent("provider-okta-admin-open", tenantID, "okta", "okta.admin_role", oktaAttrs, tenantScopedBaseTime), oktaRuntime.GetId())
	oktaFinding := evaluateTenantScopedRule(t, ctx, service, replayer, oktaRuntime.GetId(), oktaOpen, tenantScopedIdentityAdminRuleID)
	googleOpen := withRuntimeID(tenantScopedEvent("provider-google-admin-open", tenantID, "google_workspace", "google_workspace.role_assignment", googleAttrs, tenantScopedBaseTime.Add(time.Minute)), googleRuntime.GetId())
	googleFinding := evaluateTenantScopedRule(t, ctx, service, replayer, googleRuntime.GetId(), googleOpen, tenantScopedIdentityAdminRuleID)
	if got := strings.TrimSpace(oktaFinding.Status); got != tenantScopedFindingStatusOpen {
		t.Fatalf("okta finding status = %q, want open", got)
	}
	if got := strings.TrimSpace(googleFinding.Status); got != tenantScopedFindingStatusOpen {
		t.Fatalf("google finding status = %q, want open", got)
	}
	if oktaFinding.Fingerprint == googleFinding.Fingerprint {
		t.Fatalf("admin privilege fingerprints are equal across providers: %q", oktaFinding.Fingerprint)
	}
	if got := strings.TrimSpace(oktaFinding.Attributes["user"]); got != "admin@example.com" {
		t.Fatalf("okta finding user = %q, want shared admin@example.com", got)
	}
	if got := strings.TrimSpace(googleFinding.Attributes["user"]); got != "admin@example.com" {
		t.Fatalf("google finding user = %q, want shared admin@example.com", got)
	}

	oktaRevokedAttrs := cloneTenantScopedAttrs(oktaAttrs)
	oktaRevokedAttrs["action"] = "admin.role.revoked"
	oktaRevokedAttrs["assignment_status"] = "removed"
	oktaRevoked := withRuntimeID(tenantScopedEvent("provider-okta-admin-revoked", tenantID, "okta", "okta.admin_role", oktaRevokedAttrs, tenantScopedBaseTime.Add(2*time.Minute)), oktaRuntime.GetId())
	replayer.events = []*cerebrov1.EventEnvelope{oktaRevoked}
	revokeResult, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: oktaRuntime.GetId(),
		RuleIDs:   []string{tenantScopedIdentityAdminRuleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(okta revoke): %v", err)
	}
	if revokeResult == nil || len(revokeResult.Evaluations) != 1 {
		t.Fatalf("okta revoke result = %#v, want one evaluation", revokeResult)
	}
	if got := len(revokeResult.Evaluations[0].Findings); got != 0 {
		t.Fatalf("okta revoke emitted %d findings, want remediation-only pass", got)
	}

	oktaAfter, err := store.GetFinding(ctx, oktaFinding.ID)
	if err != nil {
		t.Fatalf("reload okta finding %q: %v", oktaFinding.ID, err)
	}
	googleAfter, err := store.GetFinding(ctx, googleFinding.ID)
	if err != nil {
		t.Fatalf("reload google finding %q: %v", googleFinding.ID, err)
	}
	if got := strings.TrimSpace(oktaAfter.Status); got != tenantScopedFindingStatusResolved {
		t.Fatalf("Okta finding status after Okta revoke = %q, want resolved", got)
	}
	if got := strings.TrimSpace(googleAfter.Status); got != tenantScopedFindingStatusOpen {
		t.Fatalf("Google Workspace finding status after Okta revoke = %q, want open", got)
	}
}

func TestCrossTenantFingerprintCollisionRegression(t *testing.T) {
	store := tenantScopedPostgresStore(t)
	cases := []tenantScopedFingerprintCase{
		githubDependabotTenantScopedCase(),
		sentinelOneTenantScopedCase(),
	}
	if !tenantScopedRuleRetired(t, tenantScopedGitHubAuditRuleID) {
		cases = append([]tenantScopedFingerprintCase{githubAuditTenantScopedCase()}, cases...)
	}
	cases = append(cases, identityTenantScopedCases()...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, second := runTenantScopedFingerprintPair(t, store, tc)
			if first.Fingerprint == second.Fingerprint {
				t.Fatalf("%s fingerprints are equal across tenants: %q", tc.name, first.Fingerprint)
			}
			for _, finding := range []*ports.FindingRecord{first, second} {
				rows, err := store.ListFindings(context.Background(), ports.ListFindingsRequest{
					TenantID: strings.TrimSpace(finding.TenantID),
					RuleID:   tc.ruleID,
					Status:   tenantScopedFindingStatusOpen,
				})
				if err != nil {
					t.Fatalf("ListFindings(%s, %s): %v", finding.TenantID, tc.ruleID, err)
				}
				if len(rows) != 1 {
					t.Fatalf("active rows for tenant %q rule %q = %d, want 1 (rows=%#v)", finding.TenantID, tc.ruleID, len(rows), rows)
				}
				if got := strings.TrimSpace(rows[0].TenantID); got != strings.TrimSpace(finding.TenantID) {
					t.Fatalf("persisted row tenant_id = %q, want originating tenant %q", got, finding.TenantID)
				}
			}
		})
	}
}

func runTenantScopedFingerprintPair(t *testing.T, store *postgres.Store, tc tenantScopedFingerprintCase) (*ports.FindingRecord, *ports.FindingRecord) {
	t.Helper()
	ctx := context.Background()
	tenantA := tenantScopedTestTenant(tc.name + "-a")
	tenantB := tenantScopedTestTenant(tc.name + "-b")
	runtimeA := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID(tc.name, tenantA),
		SourceId: tc.sourceID,
		TenantId: tenantA,
		Config:   map[string]string{"family": tc.family},
	}
	runtimeB := &cerebrov1.SourceRuntime{
		Id:       tenantScopedRuntimeID(tc.name, tenantB),
		SourceId: tc.sourceID,
		TenantId: tenantB,
		Config:   map[string]string{"family": tc.family},
	}
	registry, err := findings.NewRegistry(mustBuiltinRule(t, tc.ruleID))
	if err != nil {
		t.Fatalf("NewRegistry(%q): %v", tc.ruleID, err)
	}
	replayer := &stubReplayer{}
	service := findings.NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeA.GetId(): runtimeA,
			runtimeB.GetId(): runtimeB,
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	)
	first := evaluateTenantScopedRule(t, ctx, service, replayer, runtimeA.GetId(), tenantScopedCloneEvent(tc.event, tenantA, tc.name+"-tenant-a", runtimeA.GetId()), tc.ruleID)
	second := evaluateTenantScopedRule(t, ctx, service, replayer, runtimeB.GetId(), tenantScopedCloneEvent(tc.event, tenantB, tc.name+"-tenant-b", runtimeB.GetId()), tc.ruleID)
	if first.TenantID != tenantA {
		t.Fatalf("first finding TenantID = %q, want %q", first.TenantID, tenantA)
	}
	if second.TenantID != tenantB {
		t.Fatalf("second finding TenantID = %q, want %q", second.TenantID, tenantB)
	}
	if first.ID == second.ID {
		t.Fatalf("finding IDs are equal across tenants: %q", first.ID)
	}
	return first, second
}

func evaluateTenantScopedRule(t *testing.T, ctx context.Context, service *findings.Service, replayer *stubReplayer, runtimeID string, event *cerebrov1.EventEnvelope, ruleID string) *ports.FindingRecord {
	t.Helper()
	replayer.events = []*cerebrov1.EventEnvelope{event}
	result, err := service.EvaluateSourceRuntimeRules(ctx, findings.EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%s): %v", ruleID, err)
	}
	if result == nil || len(result.Evaluations) != 1 {
		t.Fatalf("EvaluateSourceRuntimeRules(%s) result = %#v, want one evaluation", ruleID, result)
	}
	evaluation := result.Evaluations[0]
	if evaluation == nil || len(evaluation.Findings) != 1 {
		t.Fatalf("EvaluateSourceRuntimeRules(%s) findings = %#v, want one finding for event %#v", ruleID, evaluation, event)
	}
	return evaluation.Findings[0]
}

func tenantScopedPostgresStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run tenant-scoped fingerprint integration tests")
	}
	store, err := postgres.Open(config.StateStoreConfig{
		Driver:      config.StateStoreDriverPostgres,
		PostgresDSN: dsn,
	})
	if err != nil {
		t.Fatalf("open postgres store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustBuiltinRule(t *testing.T, ruleID string) findings.Rule {
	t.Helper()
	rule, ok := findings.Builtin().Get(ruleID)
	if !ok {
		t.Fatalf("builtin rule %q not found", ruleID)
	}
	return rule
}

func tenantScopedRuleRetired(t *testing.T, ruleID string) bool {
	t.Helper()
	metadataRule, ok := mustBuiltinRule(t, ruleID).(findings.MetadataRule)
	if !ok {
		return false
	}
	return metadataRule.RuleMetadata().Lifecycle.Kind == findings.LifecycleRetired
}

func tenantScopedTestTenant(name string) string {
	return "example-" + tenantScopedSlug(name) + fmt.Sprintf("-%d", time.Now().UnixNano())
}

func tenantScopedRuntimeID(name string, tenantID string) string {
	return "runtime-" + tenantScopedSlug(name) + "-" + tenantScopedSlug(tenantID)
}

func tenantScopedSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-", "|", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "tenant-scope"
	}
	return value
}

func tenantScopedCloneEvent(event *cerebrov1.EventEnvelope, tenantID string, idSuffix string, runtimeID string) *cerebrov1.EventEnvelope {
	cloned := proto.Clone(event).(*cerebrov1.EventEnvelope)
	cloned.Id = strings.TrimSpace(event.GetId()) + "-" + tenantScopedSlug(idSuffix)
	cloned.TenantId = tenantID
	return withRuntimeID(cloned, runtimeID)
}

func withRuntimeID(event *cerebrov1.EventEnvelope, runtimeID string) *cerebrov1.EventEnvelope {
	cloned := proto.Clone(event).(*cerebrov1.EventEnvelope)
	if cloned.Attributes == nil {
		cloned.Attributes = map[string]string{}
	}
	cloned.Attributes = cloneTenantScopedAttrs(cloned.Attributes)
	cloned.Attributes[ports.EventAttributeSourceRuntimeID] = runtimeID
	return cloned
}

func githubAuditTenantScopedCase() tenantScopedFingerprintCase {
	return tenantScopedFingerprintCase{
		name:     "github-audit",
		ruleID:   tenantScopedGitHubAuditRuleID,
		sourceID: "github",
		family:   "audit",
		event: tenantScopedEvent("tenant-scope-github-audit", "writer", "github", "github.audit", map[string]string{
			"action": "repo.add_member",
			"actor":  "admin",
			"repo":   "writer/cerebro",
			"user":   "octocat",
		}, tenantScopedBaseTime),
	}
}

func githubDependabotTenantScopedCase() tenantScopedFingerprintCase {
	return tenantScopedFingerprintCase{
		name:     "github-dependabot",
		ruleID:   tenantScopedDependabotRuleID,
		sourceID: "github",
		family:   "dependabot_alert",
		event: tenantScopedEvent("tenant-scope-dependabot", "writer", "github", "github.dependabot_alert", map[string]string{
			"alert_number":             "7",
			"advisory_ghsa_id":         "GHSA-example",
			"package":                  "example-module",
			"repository":               "writer/cerebro",
			"severity":                 "high",
			"state":                    "open",
			"vulnerable_version_range": "< 1.2.3",
		}, tenantScopedBaseTime),
	}
}

func sentinelOneTenantScopedCase() tenantScopedFingerprintCase {
	return tenantScopedFingerprintCase{
		name:     "sentinelone-protection-control",
		ruleID:   tenantScopedSentinelOneRuleID,
		sourceID: "sentinelone",
		family:   "agent",
		event: tenantScopedEvent("tenant-scope-s1-control", "writer", "sentinelone", "sentinelone.agent", map[string]string{
			"agent_id":         "agent-99",
			"computer_name":    "mac-99",
			"firewall_enabled": "false",
			"activity_id":      "tenant-scope-activity",
			"site_id":          "site-1",
			"site_name":        "Production",
			"group_id":         "group-1",
			"group_name":       "Default",
		}, tenantScopedBaseTime),
	}
}

func identityTenantScopedCases() []tenantScopedFingerprintCase {
	return []tenantScopedFingerprintCase{
		{
			name:     "identity-user",
			ruleID:   tenantScopedIdentityUserRuleID,
			sourceID: "google_workspace",
			family:   "user",
			event:    tenantScopedEvent("tenant-scope-identity-user", "writer", "google_workspace", "google_workspace.user", identityUserTenantScopedAttrs(), tenantScopedBaseTime),
		},
		{
			name:     "identity-admin-privilege",
			ruleID:   tenantScopedIdentityAdminRuleID,
			sourceID: "google_workspace",
			family:   "role_assignment",
			event:    tenantScopedEvent("tenant-scope-identity-admin", "writer", "google_workspace", "google_workspace.role_assignment", identityAdminTenantScopedAttrs(), tenantScopedBaseTime),
		},
		{
			name:     "identity-auth-control",
			ruleID:   tenantScopedIdentityAuthRuleID,
			sourceID: "okta",
			family:   "audit",
			event:    tenantScopedEvent("tenant-scope-identity-auth", "writer", "okta", "okta.audit", identityAuthControlTenantScopedAttrs(), tenantScopedBaseTime),
		},
		{
			name:     "identity-api-token",
			ruleID:   tenantScopedIdentityTokenRuleID,
			sourceID: "aws",
			family:   "access_key",
			event:    tenantScopedEvent("tenant-scope-identity-token", "writer", "aws", "aws.access_key", identityTokenTenantScopedAttrs(), tenantScopedBaseTime),
		},
		{
			name:     "identity-external-group-member",
			ruleID:   tenantScopedIdentityGroupRuleID,
			sourceID: "okta",
			family:   "group_membership",
			event:    tenantScopedEvent("tenant-scope-identity-group", "writer", "okta", "okta.group_membership", identityExternalGroupTenantScopedAttrs(), tenantScopedBaseTime),
		},
	}
}

func tenantScopedEvent(id string, tenantID string, sourceID string, kind string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		OccurredAt: timestamppb.New(occurredAt),
		Attributes: cloneTenantScopedAttrs(attrs),
	}
}

func identityUserTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":        "writer.com",
		"email":         "admin@writer.com",
		"is_admin":      "true",
		"mfa_enrolled":  "false",
		"primary_email": "admin@writer.com",
		"user_id":       "1001",
	}
}

func identityAdminTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":        "writer.com",
		"role_id":       "super-admin",
		"role_name":     "Super Admin",
		"status":        "ACTIVE",
		"subject_email": "admin@writer.com",
		"subject_id":    "1001",
		"subject_type":  "user",
	}
}

func identityAuthControlTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":                "writer.okta.com",
		"event_type":            "policy.lifecycle.update",
		"actor_email":           "admin@writer.com",
		"policy_id":             "pol-sign-on",
		"resource_id":           "pol-sign-on",
		"resource_type":         "policy",
		"auth_control_weakened": "true",
		"outcome_result":        "SUCCESS",
	}
}

func identityTokenTenantScopedAttrs() map[string]string {
	return map[string]string{
		"credential_id":   "AKIAEXAMPLE",
		"credential_type": "aws_access_key",
		"domain":          "123456789012",
		"status":          "ACTIVE",
		"user":            "arn:aws:iam::123456789012:user/admin",
		"subject_id":      "AIDADEV",
		"subject_type":    "user",
	}
}

func identityExternalGroupTenantScopedAttrs() map[string]string {
	return map[string]string{
		"domain":         "writer.okta.com",
		"group_id":       "grp-security",
		"group_name":     "Security",
		"member_email":   "external@gmail.com",
		"member_status":  "ACTIVE",
		"member_type":    "user",
		"member_user_id": "00u-external",
	}
}

func cloneTenantScopedAttrs(attrs map[string]string) map[string]string {
	cloned := make(map[string]string, len(attrs))
	for key, value := range attrs {
		cloned[key] = value
	}
	return cloned
}

func tenantScopedHash(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubRule struct {
	spec               *cerebrov1.RuleSpec
	supportedSourceIDs map[string]struct{}
}

func (r *stubRule) Spec() *cerebrov1.RuleSpec {
	if r == nil {
		return nil
	}
	return r.spec
}

func (r *stubRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	if r == nil || runtime == nil {
		return false
	}
	_, ok := r.supportedSourceIDs[runtime.GetSourceId()]
	return ok
}

func (r *stubRule) Evaluate(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	return nil, nil
}

func TestNewRegistryRejectsDuplicateRuleIDs(t *testing.T) {
	_, err := NewRegistry(
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-1"}},
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-1"}},
	)
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want non-nil")
	}
}

func TestRegistryGetAndListSortByRuleID(t *testing.T) {
	registry, err := NewRegistry(
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-b"}},
		&stubRule{spec: &cerebrov1.RuleSpec{Id: "rule-a"}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	rule, ok := registry.Get("rule-a")
	if !ok || rule == nil {
		t.Fatal("Get(rule-a) = nil, want rule")
	}
	specs := registry.List()
	if got := len(specs); got != 2 {
		t.Fatalf("len(List()) = %d, want 2", got)
	}
	if specs[0].GetId() != "rule-a" || specs[1].GetId() != "rule-b" {
		t.Fatalf("List() ids = [%q %q], want [rule-a rule-b]", specs[0].GetId(), specs[1].GetId())
	}
}

func TestRegistryForRuntimeFiltersSupportedRules(t *testing.T) {
	registry, err := NewRegistry(
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-a"},
			supportedSourceIDs: map[string]struct{}{"okta": {}},
		},
		&stubRule{
			spec:               &cerebrov1.RuleSpec{Id: "rule-b"},
			supportedSourceIDs: map[string]struct{}{"github": {}},
		},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	rules := registry.ForRuntime(&cerebrov1.SourceRuntime{SourceId: "okta"})
	if got := len(rules); got != 1 {
		t.Fatalf("len(ForRuntime()) = %d, want 1", got)
	}
	if got := rules[0].Spec().GetId(); got != "rule-a" {
		t.Fatalf("ForRuntime()[0].Spec().Id = %q, want rule-a", got)
	}
}

func TestBuiltinRulePacksFlattenIntoCatalog(t *testing.T) {
	packs := builtinRulePacks()
	if got := len(packs); got != 24 {
		t.Fatalf("len(builtinRulePacks()) = %d, want 24", got)
	}
	rules := flattenRulePacks(packs)
	if got := len(rules); got < 10 {
		t.Fatalf("len(flattenRulePacks()) = %d, want at least 10", got)
	}
	registry, err := NewRegistry(rules...)
	if err != nil {
		t.Fatalf("NewRegistry(flattenRulePacks()) error = %v", err)
	}
	if _, ok := registry.Get(githubDependabotOpenAlertRuleID); !ok {
		t.Fatalf("registry missing %q", githubDependabotOpenAlertRuleID)
	}
	if _, ok := registry.Get(githubSecretScanningAlertCreatedRuleID); !ok {
		t.Fatalf("registry missing %q", githubSecretScanningAlertCreatedRuleID)
	}
	if _, ok := registry.Get(oktaPolicyRuleLifecycleTamperingRuleID); !ok {
		t.Fatalf("registry missing %q", oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if _, ok := registry.Get(identityAdminPrivilegeGrantedRuleID); !ok {
		t.Fatalf("registry missing %q", identityAdminPrivilegeGrantedRuleID)
	}
	if _, ok := registry.Get(cloudPublicResourceExposureRuleID); !ok {
		t.Fatalf("registry missing %q", cloudPublicResourceExposureRuleID)
	}
	if _, ok := registry.Get(runtimeActiveThreatEvidenceRuleID); !ok {
		t.Fatalf("registry missing %q", runtimeActiveThreatEvidenceRuleID)
	}
	if _, ok := registry.Get(panopticonCuratedCaseRuleID); !ok {
		t.Fatalf("registry missing %q", panopticonCuratedCaseRuleID)
	}
	if _, ok := registry.Get(grcControlTestNeedsAttentionRuleID); !ok {
		t.Fatalf("registry missing %q", grcControlTestNeedsAttentionRuleID)
	}
	if _, ok := registry.Get(grcVulnerabilitySLAOverdueRuleID); !ok {
		t.Fatalf("registry missing %q", grcVulnerabilitySLAOverdueRuleID)
	}
	if _, ok := registry.Get(grcVendorReviewOverdueRuleID); !ok {
		t.Fatalf("registry missing %q", grcVendorReviewOverdueRuleID)
	}
	if _, ok := registry.Get(grcInactiveIdentityActiveAccessRuleID); !ok {
		t.Fatalf("registry missing %q", grcInactiveIdentityActiveAccessRuleID)
	}
	if _, ok := registry.Get(grcPrivilegedAccountMissingPersonRuleID); !ok {
		t.Fatalf("registry missing %q", grcPrivilegedAccountMissingPersonRuleID)
	}
	if _, ok := registry.Get(grcOverdueVulnerabilityLiveOnAssetsRuleID); !ok {
		t.Fatalf("registry missing %q", grcOverdueVulnerabilityLiveOnAssetsRuleID)
	}
	if _, ok := registry.Get(grcFailingControlOpenOperationalFindingsID); !ok {
		t.Fatalf("registry missing %q", grcFailingControlOpenOperationalFindingsID)
	}
	if _, ok := registry.Get(sentinelOneEndpointActiveInfectionRuleID); !ok {
		t.Fatalf("registry missing %q", sentinelOneEndpointActiveInfectionRuleID)
	}
	if _, ok := registry.Get(vulnViewActionableExternalFindingRuleID); !ok {
		t.Fatalf("registry missing %q", vulnViewActionableExternalFindingRuleID)
	}
	if _, ok := registry.Get(trivyImageVulnerabilityActiveRuleID); !ok {
		t.Fatalf("registry missing %q", trivyImageVulnerabilityActiveRuleID)
	}
	if _, ok := registry.Get(vulnViewExternalAssetConcentratedSignalRuleID); !ok {
		t.Fatalf("registry missing %q", vulnViewExternalAssetConcentratedSignalRuleID)
	}
	if _, ok := registry.Get(dataSensitiveAssetRiskRuleID); !ok {
		t.Fatalf("registry missing %q", dataSensitiveAssetRiskRuleID)
	}
	if _, ok := registry.Get("aws-s3-bucket-no-public-access"); !ok {
		t.Fatal("registry missing generated policy rule aws-s3-bucket-no-public-access")
	}
	// Graph rules must be in the catalog so the orchestrator's
	// graph-rule evaluator picks them up when okta-user / github-audit
	// runtimes complete a sync. A rule that ships in code but never
	// registers is a silent regression: the cypher never runs and no
	// finding is emitted, with no observable error.
	if _, ok := registry.Get(identityDeprovisionedOktaActiveGitHubRuleID); !ok {
		t.Fatalf("registry missing %q", identityDeprovisionedOktaActiveGitHubRuleID)
	}
	if _, ok := registry.Get(identityGitHubActiveWithoutOktaLinkRuleID); !ok {
		t.Fatalf("registry missing %q", identityGitHubActiveWithoutOktaLinkRuleID)
	}
}

package nlq

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func TestSchemaPromptIncludesGraphVocabulary(t *testing.T) {
	prompt := DefaultSchemaContext().Prompt()
	if !containsAny(prompt, "instance", "database") {
		t.Fatalf("expected prompt to include node kinds, got %q", prompt)
	}
	if !containsAny(prompt, "can_admin", "exposed_to") {
		t.Fatalf("expected prompt to include edge kinds, got %q", prompt)
	}
}

func TestTranslatorInternetFacingCriticalCVEs(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)
	translator.Now = func() time.Time { return time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC) }

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which internet-facing instances have critical unpatched CVEs?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.Kind != PlanKindEntityFindingsQuery {
		t.Fatalf("plan.Kind = %s, want %s", plan.Kind, PlanKindEntityFindingsQuery)
	}
	if plan.CompositeQuery == nil {
		t.Fatal("expected composite query")
	}
	if len(plan.CompositeQuery.Entities.Kinds) != 1 || plan.CompositeQuery.Entities.Kinds[0] != graph.NodeKindInstance {
		t.Fatalf("entity kinds = %#v, want [instance]", plan.CompositeQuery.Entities.Kinds)
	}
	if len(plan.CompositeQuery.Entities.Capabilities) != 1 || plan.CompositeQuery.Entities.Capabilities[0] != graph.NodeCapabilityInternetExposable {
		t.Fatalf("capabilities = %#v, want [internet_exposable]", plan.CompositeQuery.Entities.Capabilities)
	}
	if plan.CompositeQuery.Findings.Severity != "critical" {
		t.Fatalf("severity = %q, want critical", plan.CompositeQuery.Findings.Severity)
	}
}

func TestTranslatorAdminAccessToProductionDatabases(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Show me all admin access paths to production databases",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.Kind != PlanKindReverseAccessQuery {
		t.Fatalf("plan.Kind = %s, want %s", plan.Kind, PlanKindReverseAccessQuery)
	}
	if plan.ReverseAccess == nil {
		t.Fatal("expected reverse access payload")
	}
	if !plan.ReverseAccess.AdminOnly {
		t.Fatal("expected admin_only=true")
	}
	if len(plan.ReverseAccess.Targets.Kinds) != 1 || plan.ReverseAccess.Targets.Kinds[0] != graph.NodeKindDatabase {
		t.Fatalf("target kinds = %#v, want [database]", plan.ReverseAccess.Targets.Kinds)
	}
	if !containsAny(plan.ReverseAccess.Targets.Search, "prod", "production") {
		t.Fatalf("target search = %q, want prod/production", plan.ReverseAccess.Targets.Search)
	}
}

func TestTranslatorDoesNotTreatUnchangedAsGraphChange(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Show me unchanged resources this week",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.Kind != PlanKindEntityQuery {
		t.Fatalf("plan.Kind = %s, want %s", plan.Kind, PlanKindEntityQuery)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
}

func TestTranslatorAppliesFollowUpProviderFilter(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)
	previous := &Plan{
		Question:   "Which internet-facing instances have critical unpatched CVEs?",
		Intent:     "internet_exposure_findings",
		Kind:       PlanKindEntityFindingsQuery,
		ReadOnly:   true,
		Confidence: 0.9,
		CompositeQuery: &EntityFindingsQuery{
			Entities: EntityQuery{
				Kinds:        []graph.NodeKind{graph.NodeKindInstance},
				Capabilities: []graph.NodeKindCapability{graph.NodeCapabilityInternetExposable},
				Limit:        50,
			},
			Findings: FindingsQuery{
				Severity: "critical",
				Query:    "cve",
				Limit:    100,
			},
			JoinOn: "entity_or_resource_id",
		},
	}

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Now filter those by AWS only",
		Context:  &Context{PreviousPlan: previous},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.CompositeQuery == nil {
		t.Fatal("expected composite query")
	}
	if plan.CompositeQuery.Entities.Provider != "aws" {
		t.Fatalf("provider = %q, want aws", plan.CompositeQuery.Entities.Provider)
	}
}

func TestTranslatorAppliesFollowUpSeverityFilter(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)
	previous := &Plan{
		Question:   "Show critical findings",
		Intent:     "critical_findings",
		Kind:       PlanKindFindingsQuery,
		ReadOnly:   true,
		Confidence: 0.9,
		FindingsQuery: &FindingsQuery{
			Severity: "critical",
			Query:    "vulnerability",
			Limit:    100,
		},
	}

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Now make those high",
		Context:  &Context{PreviousPlan: previous},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.FindingsQuery == nil {
		t.Fatal("expected findings query")
	}
	if plan.FindingsQuery.Severity != "high" {
		t.Fatalf("severity = %q, want high", plan.FindingsQuery.Severity)
	}
}

func TestTranslatorRejectsMutationRequests(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)
	if _, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Delete all public buckets",
	}); !errors.Is(err, ErrMutationNotAllowed) {
		t.Fatalf("Translate() error = %v, want %v", err, ErrMutationNotAllowed)
	}
	if _, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Can you please delete all public buckets?",
	}); !errors.Is(err, ErrMutationNotAllowed) {
		t.Fatalf("Translate() embedded mutation error = %v, want %v", err, ErrMutationNotAllowed)
	}
}

func TestTranslatorRejectsEmbeddedMutationRequestsBeforeModelFallback(t *testing.T) {
	model := &trackingCompletionProvider{
		response: `{"question":"Show public buckets","intent":"model_fallback","kind":"entity_query","read_only":true,"confidence":0.7,"entity_query":{"kinds":["bucket"],"limit":10}}`,
	}
	translator := NewTranslator(DefaultSchemaContext(), model)
	if _, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Can you please delete all public buckets?",
	}); !errors.Is(err, ErrMutationNotAllowed) {
		t.Fatalf("Translate() error = %v, want %v", err, ErrMutationNotAllowed)
	}
	if model.called {
		t.Fatal("expected mutation request to be rejected before model fallback")
	}
}

func TestTranslatorAllowsReadOnlyPermissionQuestionsWithMutationVerbs(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)

	adminPlan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which roles grant admin access to production databases?",
	})
	if err != nil {
		t.Fatalf("Translate() admin access error = %v", err)
	}
	if adminPlan.Kind != PlanKindReverseAccessQuery {
		t.Fatalf("admin plan.Kind = %s, want %s", adminPlan.Kind, PlanKindReverseAccessQuery)
	}

	writePlan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Show me all principals with write access to S3 buckets",
	})
	if err != nil {
		t.Fatalf("Translate() write access error = %v", err)
	}
	if !writePlan.ReadOnly {
		t.Fatal("expected write-access investigation plan to remain read-only")
	}
}

func TestTranslatorUsesModelFallback(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		response: `{"question":"Which AWS secrets are critical?","intent":"model_fallback","kind":"entity_query","read_only":true,"confidence":0.7,"entity_query":{"kinds":["secret"],"provider":"aws","risk":"critical","limit":10}}`,
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.Kind != PlanKindEntityQuery {
		t.Fatalf("plan.Kind = %s, want %s", plan.Kind, PlanKindEntityQuery)
	}
	if plan.EntityQuery == nil {
		t.Fatal("expected entity query")
	}
	if plan.EntityQuery.Provider != "aws" {
		t.Fatalf("provider = %q, want aws", plan.EntityQuery.Provider)
	}
	if len(plan.EntityQuery.Kinds) != 1 || plan.EntityQuery.Kinds[0] != graph.NodeKindSecret {
		t.Fatalf("kinds = %#v, want [secret]", plan.EntityQuery.Kinds)
	}
}

func TestTranslatorCapsModelConfidenceAndForcesReadOnly(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		response: `{"question":"Which AWS secrets are critical?","intent":"model_fallback","kind":"entity_query","read_only":false,"confidence":1.0,"entity_query":{"kinds":["secret"],"provider":"aws","risk":"critical","limit":10}}`,
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if !plan.ReadOnly {
		t.Fatal("expected model fallback plan to be forced read-only")
	}
	if plan.Confidence != maxLLMPlanConfidence {
		t.Fatalf("Confidence = %v, want %v", plan.Confidence, maxLLMPlanConfidence)
	}
}

func TestTranslatorFallsBackWhenModelPlanMissingPayload(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		response: `{"question":"Which AWS secrets are critical?","intent":"model_fallback","kind":"entity_query","read_only":true,"confidence":0.7}`,
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.Kind != PlanKindEntityQuery {
		t.Fatalf("plan.Kind = %s, want %s", plan.Kind, PlanKindEntityQuery)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("plan.TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
	if plan.EntityQuery == nil {
		t.Fatal("expected fallback entity query")
	}
	if plan.EntityQuery.Provider != "aws" {
		t.Fatalf("provider = %q, want aws", plan.EntityQuery.Provider)
	}
	if len(plan.EntityQuery.Kinds) != 1 || plan.EntityQuery.Kinds[0] != graph.NodeKindSecret {
		t.Fatalf("kinds = %#v, want [secret]", plan.EntityQuery.Kinds)
	}
}

func TestTranslatorFallsBackWhenModelReturnsMismatchedPayload(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		response: `{"question":"Show critical findings","intent":"model_fallback","kind":"findings_query","read_only":true,"confidence":0.7,"entity_query":{"kinds":["secret"],"limit":10}}`,
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
}

func TestInferSeverityIgnoresSubstringMatches(t *testing.T) {
	normalized := normalizeQuestion("Which instances allow public access?")
	if got := inferSeverity(normalized); got != "" {
		t.Fatalf("inferSeverity() = %q, want empty", got)
	}
}

func TestInferSeverityUsesWordBoundaries(t *testing.T) {
	for _, question := range []string{
		"Which instances allow public access?",
		"Which network flows follow the app path?",
		"Which findings are below the threshold?",
		"Which of those have a high number of connections?",
		"Show me low latency services",
		"Which systems have medium term maintenance windows?",
	} {
		if got := inferSeverity(normalizeQuestion(question)); got != "" {
			t.Fatalf("inferSeverity(%q) = %q, want empty", question, got)
		}
	}
	if got := inferSeverity(normalizeQuestion("Show low severity findings")); got != "low" {
		t.Fatalf("inferSeverity(low severity) = %q, want low", got)
	}
}

func TestInferRiskRequiresExplicitRiskPhrase(t *testing.T) {
	if got := inferRisk(normalizeQuestion("Which AWS secrets have critical findings?")); got != "" {
		t.Fatalf("inferRisk() = %q, want empty", got)
	}
	if got := inferRisk(normalizeQuestion("Which AWS secrets are high risk?")); got != graph.RiskHigh {
		t.Fatalf("inferRisk() = %q, want %q", got, graph.RiskHigh)
	}
}

func TestInferKindsUsesWholePhraseMatches(t *testing.T) {
	kinds := inferKinds(normalizeQuestion("Which service accounts have admin access?"))
	if len(kinds) != 1 || kinds[0] != graph.NodeKindServiceAccount {
		t.Fatalf("inferKinds(service accounts) = %#v, want [service_account]", kinds)
	}

	kinds = inferKinds(normalizeQuestion("Show unapproved network changes"))
	for _, kind := range kinds {
		if kind == graph.NodeKindApplication {
			t.Fatalf("inferKinds(unapproved...) unexpectedly included application: %#v", kinds)
		}
	}
}

func TestTranslatorFallsBackWhenModelReturnsInvalidPlan(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		response: `{"question":"Which AWS secrets are critical?","kind":"entity_query","read_only":true,"confidence":0.7}`,
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
	if plan.EntityQuery == nil {
		t.Fatal("expected fallback entity query")
	}
	if plan.EntityQuery.Provider != "aws" {
		t.Fatalf("provider = %q, want aws", plan.EntityQuery.Provider)
	}
}

func TestTranslatorFallsBackWhenFollowUpPlanIsStructurallyInvalid(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), nil)
	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Now make those critical",
		Context: &Context{PreviousPlan: &Plan{
			Kind:          PlanKindEntityQuery,
			FindingsQuery: &FindingsQuery{Limit: 10},
		}},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
}

func TestInferKindsDoesNotConfuseServiceAccountsWithServices(t *testing.T) {
	kinds := inferKinds("Which service accounts can access production data?")
	if len(kinds) != 1 || kinds[0] != graph.NodeKindServiceAccount {
		t.Fatalf("kinds = %#v, want [service_account]", kinds)
	}

	kinds = inferKinds("Which service account can access production data?")
	if len(kinds) != 1 || kinds[0] != graph.NodeKindServiceAccount {
		t.Fatalf("kinds = %#v, want [service_account]", kinds)
	}
}

func TestInferSeverityAvoidsSubstringFalsePositives(t *testing.T) {
	if severity := inferSeverity("Which instances allow public access?"); severity != "" {
		t.Fatalf("severity = %q, want empty", severity)
	}
}

func TestNormalizePlanClampsCallerControlledBounds(t *testing.T) {
	plan := Plan{
		Kind: PlanKindReverseAccessQuery,
		ReverseAccess: &ReverseAccessQuery{
			Targets:  EntityQuery{Limit: 99999},
			MaxDepth: 99999,
		},
		FindingsQuery: &FindingsQuery{Limit: 99999},
	}

	normalizePlan(&plan)

	if plan.ReverseAccess.MaxDepth != maxNLQReverseAccessDepth {
		t.Fatalf("MaxDepth = %d, want %d", plan.ReverseAccess.MaxDepth, maxNLQReverseAccessDepth)
	}
	if plan.ReverseAccess.Targets.Limit != maxNLQResultLimit {
		t.Fatalf("Targets.Limit = %d, want %d", plan.ReverseAccess.Targets.Limit, maxNLQResultLimit)
	}
	if plan.FindingsQuery.Limit != maxNLQResultLimit {
		t.Fatalf("FindingsQuery.Limit = %d, want %d", plan.FindingsQuery.Limit, maxNLQResultLimit)
	}
}

type staticCompletionProvider struct {
	response string
	err      error
}

func (s staticCompletionProvider) Complete(context.Context, string, string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.response, nil
}

type trackingCompletionProvider struct {
	response string
	called   bool
}

func (t *trackingCompletionProvider) Complete(context.Context, string, string) (string, error) {
	t.called = true
	return t.response, nil
}

func TestTranslatorStillFallsBackWhenModelErrors(t *testing.T) {
	translator := NewTranslator(DefaultSchemaContext(), staticCompletionProvider{
		err: errors.New("model unavailable"),
	})

	plan, err := translator.Translate(context.Background(), TranslateRequest{
		Question: "Which AWS secrets are critical?",
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	if plan.TemplateID != "entity-search-fallback" {
		t.Fatalf("TemplateID = %q, want entity-search-fallback", plan.TemplateID)
	}
}

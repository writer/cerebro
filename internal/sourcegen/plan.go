package sourcegen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

const (
	PlanStatusReady   = "ready"
	PlanStatusWarning = "warning"
	PlanStatusBlocked = "blocked"
)

// PromotionPlan describes the Source CDK work needed to move a definition from dynamic runtime to code.
type PromotionPlan struct {
	GeneratedAt string                             `json:"generated_at"`
	Definition  connectordefinitions.Definition    `json:"definition"`
	Support     connectordefinitions.SupportReport `json:"support"`
	Status      string                             `json:"status"`
	Summary     string                             `json:"summary"`
	NextStage   string                             `json:"next_stage,omitempty"`
	Checklist   []PromotionPlanStep                `json:"checklist"`
	Blockers    []string                           `json:"blockers,omitempty"`
	Warnings    []string                           `json:"warnings,omitempty"`
	Metrics     PromotionPlanMetrics               `json:"metrics"`
	Scaffold    *Result                            `json:"scaffold,omitempty"`
	Commands    []string                           `json:"commands,omitempty"`
}

// PromotionPlanStep is one checklist item in a Source CDK promotion plan.
type PromotionPlanStep struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Action   string `json:"action,omitempty"`
	Blocking bool   `json:"blocking,omitempty"`
}

// PromotionPlanMetrics summarizes onboarding surface area for prioritization.
type PromotionPlanMetrics struct {
	ResourceFamilies int `json:"resource_families"`
	ConfigFields     int `json:"config_fields"`
	CredentialFields int `json:"credential_fields"`
	ScopeOptions     int `json:"scope_options"`
	GeneratedFiles   int `json:"generated_files"`
	ReadyChecks      int `json:"ready_checks"`
	WarningChecks    int `json:"warning_checks"`
	BlockedChecks    int `json:"blocked_checks"`
}

// PlanDefinition returns a dry-run Source CDK promotion checklist for a connector definition.
func PlanDefinition(request DefinitionRequest) (*PromotionPlan, error) {
	definition, err := connectordefinitions.Normalize(request.Definition)
	if err != nil {
		return nil, err
	}
	support, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
	if err != nil {
		return nil, err
	}
	plan := &PromotionPlan{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Definition:  definition,
		Support:     support,
		Status:      PlanStatusReady,
		NextStage:   firstString(definition.Promotion.EligibleStages),
		Metrics: PromotionPlanMetrics{
			ResourceFamilies: len(definition.ResourceFamilies),
			ConfigFields:     len(definition.ConfigFields),
			CredentialFields: len(definition.Auth.CredentialFields),
			ScopeOptions:     len(definition.ScopeOptions),
		},
	}

	addStep := func(step PromotionPlanStep) {
		step.Status = normalizePlanStatus(step.Status)
		plan.Checklist = append(plan.Checklist, step)
		switch step.Status {
		case PlanStatusBlocked:
			plan.Metrics.BlockedChecks++
			plan.Blockers = append(plan.Blockers, step.ID)
		case PlanStatusWarning:
			plan.Metrics.WarningChecks++
			plan.Warnings = append(plan.Warnings, step.ID)
		default:
			plan.Metrics.ReadyChecks++
		}
	}

	for _, check := range definition.Validation.Checks {
		addStep(PromotionPlanStep{
			ID:       "definition." + check.ID,
			Title:    check.Label,
			Category: "definition",
			Status:   validationStatusToPlan(check.Status),
			Detail:   check.Detail,
			Action:   check.NextAction,
			Blocking: check.Blocking,
		})
	}
	for _, check := range support.Checks {
		status := PlanStatusReady
		blocking := false
		action := ""
		if check.Status == connectordefinitions.SupportStatusMissing {
			status = PlanStatusBlocked
			blocking = true
			action = "Add this capability to the definition or extend the generic Source CDK grammar."
		}
		addStep(PromotionPlanStep{
			ID:       "grammar." + check.ID,
			Title:    titleFromPlanID(check.ID),
			Category: "grammar",
			Status:   status,
			Detail:   check.Detail,
			Action:   action,
			Blocking: blocking,
		})
	}

	scaffold, scaffoldErr := GenerateDefinition(DefinitionRequest{
		Definition:           definition,
		FreshnessExpectation: request.FreshnessExpectation,
		HealthPath:           request.HealthPath,
		OutputDir:            request.OutputDir,
		DryRun:               true,
	})
	if scaffoldErr != nil {
		addStep(PromotionPlanStep{
			ID:       "source_cdk.scaffold",
			Title:    "Source CDK scaffold",
			Category: "source_cdk",
			Status:   PlanStatusBlocked,
			Action:   scaffoldErr.Error(),
			Blocking: true,
		})
	} else {
		plan.Scaffold = scaffold
		plan.Metrics.GeneratedFiles = len(scaffold.Files)
		addStep(PromotionPlanStep{
			ID:       "source_cdk.scaffold",
			Title:    "Source CDK scaffold",
			Category: "source_cdk",
			Status:   PlanStatusReady,
			Detail:   fmt.Sprintf("%d files can be generated in dry-run mode.", len(scaffold.Files)),
		})
	}

	if step := providerAPIProofStep(definition); step != nil {
		addStep(*step)
	}
	addStep(PromotionPlanStep{
		ID:       "source_cdk.fixture_suite",
		Title:    "Fixture suite",
		Category: "source_cdk",
		Status:   PlanStatusReady,
		Detail:   fixtureSuiteDetail(definition),
	})
	addStep(PromotionPlanStep{
		ID:       "source_cdk.projector_tests",
		Title:    "Projector tests",
		Category: "source_cdk",
		Status:   PlanStatusReady,
		Detail:   projectorTestsDetail(definition),
	})
	addStep(PromotionPlanStep{
		ID:       "source_cdk.health_receipt",
		Title:    "Health receipt",
		Category: "source_cdk",
		Status:   PlanStatusReady,
		Detail:   "Generated health receipt records freshness SLOs and runtime health endpoint.",
	})
	addStep(PromotionPlanStep{
		ID:       "promotion." + firstNonEmptyString(plan.NextStage, "certified"),
		Title:    "Lifecycle promotion",
		Category: "promotion",
		Status:   lifecycleStatus(definition),
		Detail:   definition.Promotion.NextAction,
		Blocking: definition.Validation.Status == connectordefinitions.ValidationBlocked,
	})

	if plan.Scaffold != nil {
		plan.Commands = append(plan.Commands, plan.Scaffold.NextSteps...)
	} else {
		plan.Commands = []string{"Resolve blocked checklist items, then rerun source-runtime sdk plan."}
	}
	if len(plan.Blockers) > 0 {
		plan.Status = PlanStatusBlocked
		plan.Summary = fmt.Sprintf("Source CDK promotion is blocked by %d checklist items.", len(plan.Blockers))
	} else if len(plan.Warnings) > 0 || definition.Validation.Status == connectordefinitions.ValidationWarning {
		plan.Status = PlanStatusWarning
		plan.Summary = "Source CDK promotion is ready with warnings that need review."
	} else {
		plan.Summary = "Source CDK promotion is ready for scaffold generation and wiring."
	}
	return plan, nil
}

func validationStatusToPlan(status string) string {
	switch status {
	case connectordefinitions.ValidationBlocked:
		return PlanStatusBlocked
	case connectordefinitions.ValidationWarning:
		return PlanStatusWarning
	default:
		return PlanStatusReady
	}
}

func normalizePlanStatus(status string) string {
	switch status {
	case PlanStatusBlocked, PlanStatusWarning:
		return status
	default:
		return PlanStatusReady
	}
}

func lifecycleStatus(definition connectordefinitions.Definition) string {
	if definition.Validation.Status == connectordefinitions.ValidationBlocked {
		return PlanStatusBlocked
	}
	if definition.Stage == connectordefinitions.StageCertified {
		return PlanStatusWarning
	}
	return PlanStatusReady
}

func titleFromPlanID(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func firstString(values []string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func providerAPIProofStep(definition connectordefinitions.Definition) *PromotionPlanStep {
	if definition.ProviderAPI == nil {
		return nil
	}
	missing := providerAPIProofGaps(definition)
	step := PromotionPlanStep{
		ID:       "runtime_depth.provider_api_proof",
		Title:    "Provider API proof",
		Category: "runtime_depth",
		Status:   PlanStatusReady,
		Detail:   fmt.Sprintf("Provider API proof maps %d of %d resource families.", len(providerAPIMappedFamilies(definition.ProviderAPI)), len(resourceFamilyIDs(definition.ResourceFamilies))),
	}
	if len(missing) == 0 {
		return &step
	}
	step.Status = PlanStatusWarning
	step.Detail = "Provider API proof is incomplete: " + strings.Join(missing, ", ") + "."
	step.Action = "Add missing provider API proof fields before reference runtime promotion."
	return &step
}

func providerAPIProofGaps(definition connectordefinitions.Definition) []string {
	api := definition.ProviderAPI
	if api == nil {
		return nil
	}
	missing := []string{}
	if strings.TrimSpace(api.Status) != "verified" {
		missing = append(missing, "status")
	}
	if strings.TrimSpace(api.Basis) == "" {
		missing = append(missing, "basis")
	}
	if strings.TrimSpace(api.VerifiedAt) == "" {
		missing = append(missing, "verified_at")
	}
	if strings.TrimSpace(api.Transport) == "" {
		missing = append(missing, "transport")
	}
	if strings.TrimSpace(api.Auth) == "" {
		missing = append(missing, "auth")
	}
	if strings.TrimSpace(api.AuthMechanics) == "" {
		missing = append(missing, "auth_mechanics")
	}
	if strings.TrimSpace(api.BaseURL) == "" && strings.TrimSpace(api.Endpoint) == "" {
		missing = append(missing, "locator")
	}
	if len(normalizedPlanStrings(api.References)) == 0 {
		missing = append(missing, "references")
	}
	if strings.TrimSpace(api.SpecURL) == "" && strings.TrimSpace(api.Transport) != "graphql" {
		missing = append(missing, "machine_readable_spec")
	}
	missing = append(missing, providerAPIFamilyProofGaps(resourceFamilyIDs(definition.ResourceFamilies), api)...)
	return normalizedPlanStrings(missing)
}

func providerAPIMappedFamilies(api *connectordefinitions.ProviderAPISpec) []string {
	if api == nil {
		return nil
	}
	transport := strings.TrimSpace(api.Transport)
	seen := map[string]struct{}{}
	for _, family := range api.Families {
		id := strings.TrimSpace(family.ID)
		if id == "" {
			continue
		}
		switch transport {
		case "graphql":
			if strings.TrimSpace(family.Operation) == "" {
				continue
			}
		default:
			if strings.TrimSpace(family.Path) == "" {
				continue
			}
		}
		seen[id] = struct{}{}
	}
	return sortedPlanKeys(seen)
}

func providerAPIFamilyProofGaps(resourceIDs []string, api *connectordefinitions.ProviderAPISpec) []string {
	if api == nil {
		return nil
	}
	transport := strings.TrimSpace(api.Transport)
	gaps := []string{}
	for _, resourceID := range resourceIDs {
		hasFamily := false
		hasPath := false
		hasOperation := false
		for _, family := range api.Families {
			if strings.TrimSpace(family.ID) != resourceID {
				continue
			}
			hasFamily = true
			if strings.TrimSpace(family.Path) != "" {
				hasPath = true
			}
			if strings.TrimSpace(family.Operation) != "" {
				hasOperation = true
			}
		}
		if !hasFamily {
			gaps = append(gaps, "family:"+resourceID)
			continue
		}
		if transport == "graphql" {
			if !hasOperation {
				gaps = append(gaps, "family:"+resourceID+".operation")
			}
			continue
		}
		if !hasPath {
			gaps = append(gaps, "family:"+resourceID+".path")
		}
	}
	return gaps
}

func resourceFamilyIDs(families []connectordefinitions.ResourceFamily) []string {
	seen := map[string]struct{}{}
	for _, family := range families {
		if id := strings.TrimSpace(family.ID); id != "" {
			seen[id] = struct{}{}
		}
	}
	return sortedPlanKeys(seen)
}

func fixtureSuiteDetail(definition connectordefinitions.Definition) string {
	families := resourceFamilyIDs(definition.ResourceFamilies)
	if len(families) == 0 {
		return "Generated fixture suite has no resource families."
	}
	return fmt.Sprintf("Generated fixture suite includes read and discover fixture pairs for %d resource families: %s.", len(families), strings.Join(families, ", "))
}

func projectorTestsDetail(definition connectordefinitions.Definition) string {
	kinds := eventKinds(definition.ResourceFamilies, definition.SourceID)
	if len(kinds) == 0 {
		return "Generated projector tests have no event kinds."
	}
	return fmt.Sprintf("Generated projector tests cover %d event kinds: %s.", len(kinds), strings.Join(kinds, ", "))
}

func eventKinds(families []connectordefinitions.ResourceFamily, sourceID string) []string {
	seen := map[string]struct{}{}
	for _, family := range families {
		kind := strings.TrimSpace(family.Event.Kind)
		if kind == "" && strings.TrimSpace(sourceID) != "" && strings.TrimSpace(family.ID) != "" {
			kind = strings.TrimSpace(sourceID) + "." + strings.TrimSpace(family.ID)
		}
		if kind != "" {
			seen[kind] = struct{}{}
		}
	}
	return sortedPlanKeys(seen)
}

func normalizedPlanStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	return sortedPlanKeys(seen)
}

func sortedPlanKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

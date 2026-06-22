package sourcegen

import (
	"fmt"
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

	addStep(PromotionPlanStep{
		ID:       "source_cdk.fixture_suite",
		Title:    "Fixture suite",
		Category: "source_cdk",
		Status:   PlanStatusReady,
		Detail:   "Generated source tests exercise auth headers, health checks, provider reads, and projection registration.",
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

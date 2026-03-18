package policy

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

const (
	ConditionFormatLegacy = "legacy"
	ConditionFormatCEL    = "cel"
)

func newPolicyConditionEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("resource", cel.DynType),
		ext.Strings(),
		policyConditionCELLibrary(),
	)
}

func normalizeConditionFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", ConditionFormatLegacy:
		return ConditionFormatLegacy
	case ConditionFormatCEL:
		return ConditionFormatCEL
	default:
		return strings.ToLower(strings.TrimSpace(format))
	}
}

func validConditionFormat(format string) bool {
	switch normalizeConditionFormat(format) {
	case ConditionFormatLegacy, ConditionFormatCEL:
		return true
	default:
		return false
	}
}

func canonicalizePolicyConditionFormat(p *Policy) error {
	if p == nil {
		return nil
	}
	rawFormat := strings.TrimSpace(p.ConditionFormat)
	p.ConditionFormat = normalizeConditionFormat(rawFormat)
	if rawFormat != "" || len(p.Conditions) == 0 {
		return nil
	}
	if !policyConditionsLikelyCEL(p.Conditions) {
		env, err := newPolicyConditionEnv()
		if err != nil {
			return fmt.Errorf("initialize CEL environment: %w", err)
		}
		if !policyConditionsCompileAsCEL(env, p.Conditions) {
			return nil
		}
		p.ConditionFormat = ConditionFormatCEL
		return nil
	}
	env, err := newPolicyConditionEnv()
	if err != nil {
		return fmt.Errorf("initialize CEL environment: %w", err)
	}
	copy := clonePolicy(p)
	copy.ConditionFormat = ConditionFormatCEL
	if err := validatePolicyConditionProgramsWithEnv(env, copy); err != nil {
		return err
	}
	p.ConditionFormat = ConditionFormatCEL
	return nil
}

func policyConditionsLikelyCEL(conditions []string) bool {
	for _, condition := range conditions {
		trimmed := strings.TrimSpace(condition)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "resource.") ||
			strings.Contains(trimmed, "resource[") ||
			strings.Contains(trimmed, "exists_path(") ||
			strings.Contains(trimmed, "contains_value(") ||
			strings.Contains(trimmed, "path(") ||
			strings.Contains(trimmed, ".contains(") ||
			strings.Contains(trimmed, ".startsWith(") ||
			strings.Contains(trimmed, ".endsWith(") ||
			strings.Contains(trimmed, ".matches(") {
			return true
		}
	}
	return false
}

func policyConditionsCompileAsCEL(env *cel.Env, conditions []string) bool {
	if env == nil || len(conditions) == 0 {
		return false
	}
	for _, condition := range conditions {
		trimmed := strings.TrimSpace(condition)
		if trimmed == "" {
			return false
		}
		ast, issues := env.Compile(trimmed)
		if issues != nil && issues.Err() != nil {
			return false
		}
		if ast == nil {
			return false
		}
		if _, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize)); err != nil {
			return false
		}
		if ast.OutputType() != cel.BoolType {
			return false
		}
	}
	return true
}

func (e *Engine) ensureConditionEnvLocked() error {
	if e.celEnv != nil {
		return nil
	}
	env, err := newPolicyConditionEnv()
	if err != nil {
		return fmt.Errorf("initialize CEL environment: %w", err)
	}
	e.celEnv = env
	return nil
}

func (e *Engine) validatePolicyConditionPrograms(p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy is required")
	}
	if normalizeConditionFormat(p.ConditionFormat) != ConditionFormatCEL || len(p.Conditions) == 0 {
		return nil
	}
	env, err := e.conditionEnvForValidation()
	if err != nil {
		return err
	}
	return validatePolicyConditionProgramsWithEnv(env, p)
}

func (e *Engine) conditionEnvForValidation() (*cel.Env, error) {
	e.mu.RLock()
	env := e.celEnv
	e.mu.RUnlock()
	if env != nil {
		return env, nil
	}
	var err error
	env, err = newPolicyConditionEnv()
	if err != nil {
		return nil, fmt.Errorf("initialize CEL environment: %w", err)
	}
	return env, nil
}

func validatePolicyConditionProgramsWithEnv(env *cel.Env, p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy is required")
	}
	if normalizeConditionFormat(p.ConditionFormat) != ConditionFormatCEL || len(p.Conditions) == 0 {
		return nil
	}

	for i, condition := range p.Conditions {
		trimmed := strings.TrimSpace(condition)
		if trimmed == "" {
			return fmt.Errorf("policy %s: condition %d must not be empty", strings.TrimSpace(p.ID), i+1)
		}
		ast, issues := env.Compile(trimmed)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("policy %s: invalid CEL condition %d: %w", strings.TrimSpace(p.ID), i+1, issues.Err())
		}
		if _, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize)); err != nil {
			return fmt.Errorf("policy %s: build CEL program %d: %w", strings.TrimSpace(p.ID), i+1, err)
		}
		if ast.OutputType() != cel.BoolType {
			return fmt.Errorf("policy %s: CEL condition %d must evaluate to a boolean", strings.TrimSpace(p.ID), i+1)
		}
	}

	return nil
}

func (e *Engine) syncConditionProgramsLocked(p *Policy) error {
	if p == nil {
		return nil
	}
	if e.celPrograms == nil {
		e.celPrograms = make(map[string][]cel.Program)
	}

	policyID := strings.TrimSpace(p.ID)
	delete(e.celPrograms, policyID)
	if normalizeConditionFormat(p.ConditionFormat) != ConditionFormatCEL || len(p.Conditions) == 0 || policyID == "" {
		return nil
	}
	if err := e.ensureConditionEnvLocked(); err != nil {
		return err
	}

	programs := make([]cel.Program, 0, len(p.Conditions))
	for i, condition := range p.Conditions {
		trimmed := strings.TrimSpace(condition)
		if trimmed == "" {
			return fmt.Errorf("policy %s: condition %d must not be empty", policyID, i+1)
		}
		ast, issues := e.celEnv.Compile(trimmed)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("policy %s: invalid CEL condition %d: %w", policyID, i+1, issues.Err())
		}
		program, err := e.celEnv.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return fmt.Errorf("policy %s: build CEL program %d: %w", policyID, i+1, err)
		}
		programs = append(programs, program)
	}
	e.celPrograms[policyID] = programs
	return nil
}

func (e *Engine) evaluateCELConditions(p *Policy, asset map[string]interface{}) bool {
	if e == nil || p == nil {
		return false
	}
	programs := e.celPrograms[strings.TrimSpace(p.ID)]
	if len(programs) == 0 {
		return false
	}
	activation := map[string]any{"resource": asset}
	for _, program := range programs {
		out, _, err := program.Eval(activation)
		if err != nil {
			return false
		}
		matched, ok := out.Value().(bool)
		if !ok || !matched {
			return false
		}
	}
	return true
}

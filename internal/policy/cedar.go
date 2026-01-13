// Package policy implements a policy engine for evaluating cloud security policies
// against cloud resources. Policies define security requirements using a declarative
// format inspired by AWS Cedar policy language.
//
// The engine supports:
//   - Loading policies from JSON files organized by category (aws, gcp, azure, etc.)
//   - Real-time evaluation of policies against cloud asset data
//   - Generation of security findings with severity ratings
//   - Condition-based matching for flexible policy definitions
//
// Policies use permit/forbid effects to define what configurations are allowed
// or prohibited. When a resource violates a "forbid" policy, a finding is generated.
//
// Example policy structure:
//
//	{
//	  "id": "s3-public-access",
//	  "name": "S3 Bucket Public Access",
//	  "description": "S3 buckets should not allow public access",
//	  "effect": "forbid",
//	  "resource": "aws::s3::bucket",
//	  "conditions": ["public_access_block_enabled == false"],
//	  "severity": "critical"
//	}
//
// Example usage:
//
//	engine := policy.NewEngine()
//	engine.LoadPolicies("policies/")
//	findings, _ := engine.EvaluateAsset(ctx, s3BucketData)
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Engine is the core policy evaluation engine. It maintains an in-memory cache
// of policies and provides methods for evaluating cloud resources against
// those policies to identify security violations.
//
// The engine is thread-safe and supports concurrent policy evaluation.
type Engine struct {
	policies map[string]*Policy // Policies indexed by ID
	mu       sync.RWMutex       // Protects policies map
}

// Policy defines a security policy rule. Policies specify what configurations
// are permitted or forbidden for cloud resources.
//
// The Effect field determines whether matching resources are allowed ("permit")
// or generate violations ("forbid"). Conditions are evaluated against resource
// attributes to determine if the policy matches.
type Policy struct {
	ID          string   `json:"id"`          // Unique policy identifier
	Name        string   `json:"name"`        // Human-readable policy name
	Description string   `json:"description"` // Detailed description of policy intent
	Effect      string   `json:"effect"`      // "permit" or "forbid"
	Principal   string   `json:"principal"`   // Who the policy applies to (optional)
	Action      string   `json:"action"`      // What action is being evaluated
	Resource    string   `json:"resource"`    // Resource type pattern (e.g., "aws::s3::bucket")
	Conditions  []string `json:"conditions"`  // Conditions that must be true for policy to match
	Severity    string   `json:"severity"`    // critical, high, medium, low
	Tags        []string `json:"tags"`        // Tags for categorization
	Raw         string   `json:"raw,omitempty"` // Raw Cedar policy text (optional)
}

type EvalRequest struct {
	Principal map[string]interface{} `json:"principal"`
	Action    string                 `json:"action"`
	Resource  map[string]interface{} `json:"resource"`
	Context   map[string]interface{} `json:"context"`
}

type EvalResponse struct {
	Decision string   `json:"decision"` // "allow", "deny"
	Matched  []string `json:"matched"`  // policy IDs that matched
	Reasons  []string `json:"reasons"`
}

type Finding struct {
	ID          string                 `json:"id"`
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	Severity    string                 `json:"severity"`
	Resource    map[string]interface{} `json:"resource"`
	Description string                 `json:"description"`
	Remediation string                 `json:"remediation"`
}

func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
	}
}

func (e *Engine) LoadPolicies(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		var policy Policy
		if err := json.Unmarshal(data, &policy); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		e.policies[policy.ID] = &policy
		return nil
	})
}

func (e *Engine) AddPolicy(p *Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[p.ID] = p
}

func (e *Engine) GetPolicy(id string) (*Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.policies[id]
	return p, ok
}

func (e *Engine) ListPolicies() []*Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		result = append(result, p)
	}
	return result
}

func (e *Engine) Evaluate(ctx context.Context, req *EvalRequest) (*EvalResponse, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	resp := &EvalResponse{
		Decision: "allow",
		Matched:  make([]string, 0),
		Reasons:  make([]string, 0),
	}

	for _, p := range e.policies {
		if matches := e.matchPolicy(p, req); matches {
			resp.Matched = append(resp.Matched, p.ID)
			if p.Effect == "forbid" {
				resp.Decision = "deny"
				resp.Reasons = append(resp.Reasons, fmt.Sprintf("policy %s: %s", p.ID, p.Description))
			}
		}
	}

	return resp, nil
}

func (e *Engine) EvaluateAsset(ctx context.Context, asset map[string]interface{}) ([]Finding, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var findings []Finding

	for _, p := range e.policies {
		if violation := e.checkAssetViolation(p, asset); violation != "" {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("%s-%v", p.ID, asset["_cq_id"]),
				PolicyID:    p.ID,
				PolicyName:  p.Name,
				Severity:    p.Severity,
				Resource:    asset,
				Description: violation,
			})
		}
	}

	return findings, nil
}

func (e *Engine) matchPolicy(p *Policy, req *EvalRequest) bool {
	if p.Action != "*" && p.Action != req.Action {
		return false
	}
	return true
}

func (e *Engine) checkAssetViolation(p *Policy, asset map[string]interface{}) string {
	// All conditions must match for a violation (AND logic)
	if len(p.Conditions) == 0 {
		return ""
	}
	for _, cond := range p.Conditions {
		if !evaluateCondition(cond, asset) {
			return "" // If any condition doesn't match, no violation
		}
	}
	return p.Description // All conditions matched - violation
}

func evaluateCondition(condition string, asset map[string]interface{}) bool {
	parts := strings.SplitN(condition, "==", 2)
	if len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		if val, ok := asset[field]; ok {
			return fmt.Sprintf("%v", val) == expected
		}
	}

	parts = strings.SplitN(condition, "!=", 2)
	if len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		expected := strings.TrimSpace(parts[1])
		if val, ok := asset[field]; ok {
			return fmt.Sprintf("%v", val) != expected
		}
	}

	return false
}

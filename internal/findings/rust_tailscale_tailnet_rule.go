package findings

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/wasmjson"
)

const (
	tailscaleTailnetDeviceApprovalDisabledRuleID = "tailscale-tailnet-device-approval-disabled"
	tailscaleRustAuthoritySchema                 = "cerebro.finding-rule-authority.v1"
	tailscaleRustDefinitionDigest                = "af1b1d2e11b9cc726ffe44a2d4c46e5e898e45c01da9e1b414fc2b6b56a09f8b"
)

var tailscaleTailnetDeviceApprovalDisabledDefinition = RuleDefinition{
	ID: tailscaleTailnetDeviceApprovalDisabledRuleID, Name: "Tailscale Tailnet Device Approval Disabled",
	Description: "Detect Tailscale tailnets whose device approval is currently disabled, allowing new devices to join the tailnet without administrator review.",
	SourceID:    "tailscale", EventKinds: []string{"tailscale.tailnet"}, OutputKind: "finding.tailscale_tailnet_device_approval_disabled",
	Severity: "MEDIUM", Status: "open", Maturity: "test", Tags: []string{"tailscale", "tailnet", "device-approval", "access-control"},
	References: []string{"https://tailscale.com/kb/1099/device-approval"}, FalsePositives: []string{"Tailnets that intentionally rely on tag/ACL-based authorization instead of manual device approval."},
	Runbook:            "Confirm whether device approval should be enforced for this tailnet; if so, enable device approval so new devices require administrator review before joining.",
	RequiredAttributes: []string{"tailnet"}, FingerprintFields: []string{"tailscale_tailnet_urn"},
	ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}, {FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"}},
	Lifecycle:   Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

//go:embed findingrule.wasm
var findingRuleWasm []byte

type findingRuleEvaluator interface {
	Evaluate(context.Context, []byte) ([]byte, error)
}

var rustFindingRuleEvaluator = wasmjson.New(wasmjson.Config{
	Name: "embedded Rust finding-rule evaluator", Module: findingRuleWasm, ABIVersion: 1,
	ABIVersionExport: "cerebro_finding_rule_abi_version", AllocateExport: "cerebro_finding_rule_alloc", EvaluateExport: "cerebro_finding_rule_evaluate",
	MemoryLimitPages: 128, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, InitializeTimeout: 30 * time.Second, CallTimeout: 2 * time.Second,
})

type rustTailscaleRule struct{ evaluator findingRuleEvaluator }
type rustFindingRequest struct {
	Operation          string            `json:"operation"`
	RuleID             string            `json:"rule_id"`
	RuntimeID          string            `json:"runtime_id"`
	RuntimeSourceID    string            `json:"runtime_source_id"`
	RuntimeTenantID    string            `json:"runtime_tenant_id"`
	RuntimeWorkspaceID string            `json:"runtime_workspace_id"`
	EventID            string            `json:"event_id"`
	EventTenantID      string            `json:"event_tenant_id"`
	EventSourceID      string            `json:"event_source_id"`
	EventKind          string            `json:"event_kind"`
	EventSchemaRef     string            `json:"event_schema_ref"`
	OccurredAt         string            `json:"occurred_at"`
	ReplaySequence     uint64            `json:"replay_sequence"`
	Attributes         map[string]string `json:"attributes"`
	Payload            []int             `json:"payload"`
}
type rustFindingResponse struct {
	SchemaVersion    string               `json:"schema_version"`
	RuleID           string               `json:"rule_id"`
	DefinitionDigest string               `json:"definition_digest"`
	InputDigest      string               `json:"input_digest"`
	DecisionDigest   string               `json:"decision_digest"`
	Action           string               `json:"action"`
	Anchor           string               `json:"anchor"`
	Finding          *ports.FindingRecord `json:"finding"`
}

func newTailscaleTailnetDeviceApprovalDisabledRule() Rule {
	return &rustTailscaleRule{evaluator: rustFindingRuleEvaluator}
}
func (r *rustTailscaleRule) Spec() *cerebrov1.RuleSpec {
	return tailscaleTailnetDeviceApprovalDisabledDefinition.RuleSpec()
}
func (r *rustTailscaleRule) RuleMetadata() RuleDefinition {
	return cloneRuleDefinition(tailscaleTailnetDeviceApprovalDisabledDefinition)
}
func (r *rustTailscaleRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return runtime != nil && strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), "tailscale") && runtimeMayEmitEventKind(runtime, []string{"tailscale.tailnet"})
}
func (r *rustTailscaleRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	response, err := r.run(ctx, rustTailscaleRequest("evaluate", runtime, event, nil))
	if err != nil {
		return nil, err
	}
	switch response.Action {
	case "none":
		return nil, nil
	case "open":
		if response.Finding == nil {
			return nil, fmt.Errorf("rust finding-rule authority returned an empty open decision")
		}
		return []*ports.FindingRecord{response.Finding}, nil
	default:
		return nil, fmt.Errorf("rust finding-rule authority returned unexpected action %q", response.Action)
	}
}
func (r *rustTailscaleRule) OpenAnchorContext(ctx context.Context, attributes map[string]string) (string, error) {
	response, err := r.run(ctx, rustTailscaleRequest("open_anchor", nil, nil, attributes))
	if err != nil {
		return "", err
	}
	if response.Action != "open_anchor" {
		return "", fmt.Errorf("rust finding-rule authority returned unexpected action %q", response.Action)
	}
	return strings.TrimSpace(response.Anchor), nil
}
func (r *rustTailscaleRule) CloseOnEventContext(ctx context.Context, event Event) (string, bool, error) {
	response, err := r.run(ctx, rustTailscaleRequest("close", nil, event, nil))
	if err != nil {
		return "", false, err
	}
	if response.Action == "none" {
		return "", false, nil
	}
	if response.Action != "close" || strings.TrimSpace(response.Anchor) == "" {
		return "", false, fmt.Errorf("rust finding-rule authority returned invalid close decision")
	}
	return strings.TrimSpace(response.Anchor), true, nil
}
func (r *rustTailscaleRule) run(ctx context.Context, request rustFindingRequest) (rustFindingResponse, error) {
	return runRustFinding(ctx, r.evaluator, request, tailscaleRustDefinitionDigest)
}

func runRustFinding(ctx context.Context, evaluator findingRuleEvaluator, request rustFindingRequest, definitionDigest string) (rustFindingResponse, error) {
	requestBody, err := json.Marshal(request)
	if err != nil {
		return rustFindingResponse{}, err
	}
	inputDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(requestBody))
	payload, err := json.Marshal(struct {
		SchemaVersion string             `json:"schema_version"`
		InputDigest   string             `json:"input_digest"`
		Request       rustFindingRequest `json:"request"`
	}{tailscaleRustAuthoritySchema, inputDigest, request})
	if err != nil {
		return rustFindingResponse{}, err
	}
	output, err := evaluator.Evaluate(ctx, payload)
	if err != nil {
		return rustFindingResponse{}, fmt.Errorf("rust finding-rule authority unavailable: %w", err)
	}
	var response rustFindingResponse
	if err := decodeStrictRustFindingResponse(output, &response); err != nil {
		return rustFindingResponse{}, fmt.Errorf("decode Rust finding-rule authority: %w", err)
	}
	decisionDigest, err := rustFindingDecisionDigest(response.Action, response.Anchor, response.Finding)
	if err != nil {
		return rustFindingResponse{}, fmt.Errorf("digest Rust finding-rule decision: %w", err)
	}
	if response.SchemaVersion != tailscaleRustAuthoritySchema || response.RuleID != request.RuleID || response.DefinitionDigest != definitionDigest || response.InputDigest != inputDigest || response.DecisionDigest != decisionDigest {
		return rustFindingResponse{}, fmt.Errorf("rust finding-rule authority receipt mismatch")
	}
	if err := validateRustFindingResponse(request, response); err != nil {
		return rustFindingResponse{}, err
	}
	return response, nil
}

func rustTailscaleRequest(operation string, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, attributes map[string]string) rustFindingRequest {
	request := rustFindingRequest{Operation: operation, RuleID: tailscaleTailnetDeviceApprovalDisabledRuleID, Attributes: attributes, Payload: []int{}}
	if runtime != nil {
		request.RuntimeID, request.RuntimeSourceID, request.RuntimeTenantID = runtime.GetId(), runtime.GetSourceId(), runtime.GetTenantId()
		request.RuntimeWorkspaceID = runtime.GetConfig()[ports.SourceRuntimeApplicationWorkspaceIDConfigKey]
	}
	if event != nil {
		request.EventID, request.EventTenantID, request.EventSourceID, request.EventKind, request.EventSchemaRef, request.Attributes = event.GetId(), event.GetTenantId(), event.GetSourceId(), event.GetKind(), event.GetSchemaRef(), event.GetAttributes()
		if event.GetOccurredAt() != nil {
			request.OccurredAt = event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339Nano)
		}
	}
	if request.Attributes == nil {
		request.Attributes = map[string]string{}
	}
	return request
}

func rustFindingDecisionDigest(action string, anchor string, finding *ports.FindingRecord) (string, error) {
	var findingBody []byte
	if finding != nil {
		var err error
		findingBody, err = json.Marshal(struct {
			ID                string                    `json:"ID"`
			Fingerprint       string                    `json:"Fingerprint"`
			TenantID          string                    `json:"TenantID"`
			RuntimeID         string                    `json:"RuntimeID"`
			RuleID            string                    `json:"RuleID"`
			Title             string                    `json:"Title"`
			Severity          string                    `json:"Severity"`
			Status            string                    `json:"Status"`
			Summary           string                    `json:"Summary"`
			ResourceURNs      []string                  `json:"ResourceURNs"`
			EventIDs          []string                  `json:"EventIDs"`
			ObservedPolicyIDs []string                  `json:"ObservedPolicyIDs"`
			PolicyID          string                    `json:"PolicyID"`
			PolicyName        string                    `json:"PolicyName"`
			CheckID           string                    `json:"CheckID"`
			CheckName         string                    `json:"CheckName"`
			ControlRefs       []ports.FindingControlRef `json:"ControlRefs"`
			Attributes        map[string]string         `json:"Attributes"`
			FirstObservedAt   time.Time                 `json:"FirstObservedAt"`
			LastObservedAt    time.Time                 `json:"LastObservedAt"`
		}{finding.ID, finding.Fingerprint, finding.TenantID, finding.RuntimeID, finding.RuleID, finding.Title, finding.Severity, finding.Status, finding.Summary, finding.ResourceURNs, finding.EventIDs, finding.ObservedPolicyIDs, finding.PolicyID, finding.PolicyName, finding.CheckID, finding.CheckName, finding.ControlRefs, finding.Attributes, finding.FirstObservedAt, finding.LastObservedAt})
		if err != nil {
			return "", err
		}
	}
	hash := sha256.New()
	for _, value := range [][]byte{[]byte(strings.TrimSpace(action)), []byte(strings.TrimSpace(anchor)), findingBody} {
		_, _ = hash.Write(value)
		_, _ = hash.Write([]byte{0})
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)), nil
}

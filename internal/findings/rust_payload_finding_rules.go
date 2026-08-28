package findings

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	aureliusPromotedVulnerabilityActiveRuleID = "aurelius-promoted-vulnerability-active"
	aureliusRustDefinitionDigest              = "5ec15d147ab34294d8214a19f519a7f52fce6bb2a59dfed9b408c3028695aab9"
	cosmoCoordinationActiveRiskRuleID         = "cosmo-coordination-active-risk"
	cosmoRustDefinitionDigest                 = "1367f20b5cfe85e3f901760f27d8540d15227712b86e5ca3da41122e296225a4"
	trustedTenantWorkspacePrefix              = "tenant-only:"
)

var aureliusPromotedVulnerabilityActiveDefinition = RuleDefinition{
	ID: aureliusPromotedVulnerabilityActiveRuleID, Name: "Aurelius Promoted Image Unresolved High Vulnerability",
	Description: "Detect catalog-promoted container images carrying an active, unresolved high or critical Aurelius vulnerability that is not covered by an active policy exception, so promoted production risk does not silently persist.",
	SourceID:    "aurelius", EventKinds: []string{"aurelius.finding"}, OutputKind: "finding.aurelius_promoted_vulnerability_active",
	Severity: "dynamic", Status: findingStatusOpen, Maturity: "test",
	Tags:               []string{"aurelius", "container", "vulnerability", "image", "promotion", "attack.initial-access"},
	References:         []string{"https://kubernetes.io/docs/concepts/security/supply-chain-security/"},
	FalsePositives:     []string{"Vulnerability covered by an active, approved Aurelius policy exception, already downgraded below high severity, or remediated by a newer promoted image build."},
	Runbook:            "Confirm the promoted image still carries the unresolved vulnerability; rebuild and re-promote a fixed image or grant an approved policy exception, then re-scan to clear the finding.",
	RequiredAttributes: []string{"image_digest", "cve_id", "package", "severity"}, FingerprintFields: []string{"aurelius_vulnerability_urn"},
	ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}, {FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"}},
	Lifecycle:   Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
}

var cosmoCoordinationActiveRiskDefinition = RuleDefinition{
	ID: cosmoCoordinationActiveRiskRuleID, Name: "Cosmo Agent Memory Coordination Risk Active",
	Description: "Detect Cosmo agent-memory facts that record an active coordination-risk pattern in a session, so a durable finding tracks the risky condition until an operator reviews and resolves it.",
	SourceID:    "cosmo", EventKinds: []string{"cosmo.fact"}, OutputKind: "finding.cosmo_coordination_active_risk",
	Severity: "HIGH", Status: findingStatusOpen, Maturity: "test", Tags: []string{"cosmo", "agent-memory", "coordination", "posture"},
	References: []string{"https://github.com/writer/cerebro/blob/main/docs/domains/source-runtime-guide.md"},
	FalsePositives: []string{
		"Memory facts that record a historical coordination-risk pattern that has already been remediated but still require operator review before the finding is resolved.",
		"Resolved Cosmo memory facts do not close a matching finding by themselves; prompt-injected or otherwise agent-written resolution state must be operator-verified against session and runtime evidence.",
		"risk_reason and risk_severity are evidence hints from Cosmo memory when their source attributes are agent_memory_payload; validate them before treating the text as authoritative.",
	},
	Runbook:            "Review the coordination-risk pattern recorded for the affected session and remediate the underlying risky coordination. Treat risk_reason and risk_severity as agent-written evidence hints when their source is agent_memory_payload, verify resolved memory facts against session and runtime evidence, and resolve the finding through the reviewed finding workflow rather than Cosmo memory alone.",
	RequiredAttributes: []string{"key"}, FingerprintFields: []string{"cosmo_risk_urn"},
	ControlRefs: []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}, {FrameworkName: "ISO 27001:2022", ControlID: "A.5.7"}},
	Lifecycle:   Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

type rustPayloadFindingRule struct {
	definition       RuleDefinition
	definitionDigest string
	schemaRef        string
	evaluator        findingRuleEvaluator
}

func newAureliusPromotedVulnerabilityActiveRule() Rule {
	return newRustPayloadFindingRule(aureliusPromotedVulnerabilityActiveDefinition, aureliusRustDefinitionDigest, "aurelius/finding/v1")
}

func newCosmoCoordinationActiveRiskRule() Rule {
	return newRustPayloadFindingRule(cosmoCoordinationActiveRiskDefinition, cosmoRustDefinitionDigest, "cosmo/fact/v1")
}

func newRustPayloadFindingRule(definition RuleDefinition, digest, schemaRef string) *rustPayloadFindingRule {
	return &rustPayloadFindingRule{definition: definition, definitionDigest: digest, schemaRef: schemaRef, evaluator: rustFindingRuleEvaluator}
}

func (r *rustPayloadFindingRule) Spec() *cerebrov1.RuleSpec { return r.definition.RuleSpec() }
func (r *rustPayloadFindingRule) RuleMetadata() RuleDefinition {
	return cloneRuleDefinition(r.definition)
}
func (r *rustPayloadFindingRule) SupportsRuntime(runtime *cerebrov1.SourceRuntime) bool {
	return runtime != nil && strings.EqualFold(strings.TrimSpace(runtime.GetSourceId()), r.definition.SourceID) && runtimeMayEmitEventKind(runtime, r.definition.EventKinds)
}

func (r *rustPayloadFindingRule) Evaluate(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	response, err := r.run(ctx, r.request("evaluate", runtime, event, nil))
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
		response.Finding.ApplicationWorkspaceID = trustedFindingWorkspace(runtime)
		return []*ports.FindingRecord{response.Finding}, nil
	default:
		return nil, fmt.Errorf("rust finding-rule authority returned unexpected action %q", response.Action)
	}
}

func (r *rustPayloadFindingRule) OpenAnchor(attributes map[string]string) string {
	anchor, _ := r.OpenAnchorContext(context.Background(), attributes)
	return anchor
}
func (r *rustPayloadFindingRule) CloseOnEvent(event Event) (string, bool) {
	anchor, closes, _ := r.CloseOnEventContext(context.Background(), event)
	return anchor, closes
}
func (r *rustPayloadFindingRule) OpenAnchorContext(ctx context.Context, attributes map[string]string) (string, error) {
	tenantID := "host-anchor"
	runtime := &cerebrov1.SourceRuntime{Id: "host-anchor", SourceId: r.definition.SourceID, TenantId: tenantID, Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: trustedTenantWorkspacePrefix + tenantID}}
	event := &cerebrov1.EventEnvelope{Id: "host-anchor", TenantId: tenantID, SourceId: r.definition.SourceID, Kind: r.definition.EventKinds[0], SchemaRef: r.schemaRef, OccurredAt: timestamppb.New(time.Unix(0, 0).UTC()), Attributes: cloneStringMap(attributes)}
	response, err := r.run(ctx, r.request("open_anchor", runtime, event, attributes))
	if err != nil {
		return "", err
	}
	if response.Action == "none" {
		return "", nil
	}
	if response.Action != "open_anchor" || strings.TrimSpace(response.Anchor) == "" {
		return "", fmt.Errorf("rust finding-rule authority returned invalid open-anchor decision")
	}
	return strings.TrimSpace(response.Anchor), nil
}
func (r *rustPayloadFindingRule) OpenAnchorForFindingContext(ctx context.Context, finding *ports.FindingRecord) (string, error) {
	if finding == nil {
		return "", nil
	}
	runtime := &cerebrov1.SourceRuntime{Id: strings.TrimSpace(finding.RuntimeID), SourceId: r.definition.SourceID, TenantId: strings.TrimSpace(finding.TenantID), Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: strings.TrimSpace(finding.ApplicationWorkspaceID)}}
	eventID := "host-open-anchor"
	if len(finding.EventIDs) > 0 && strings.TrimSpace(finding.EventIDs[0]) != "" {
		eventID = strings.TrimSpace(finding.EventIDs[0])
	}
	observedAt := finding.LastObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = finding.FirstObservedAt.UTC()
	}
	if observedAt.IsZero() {
		observedAt = time.Unix(0, 0).UTC()
	}
	event := &cerebrov1.EventEnvelope{Id: eventID, TenantId: runtime.GetTenantId(), SourceId: r.definition.SourceID, Kind: r.definition.EventKinds[0], SchemaRef: r.schemaRef, OccurredAt: timestamppb.New(observedAt), Attributes: cloneStringMap(finding.Attributes)}
	response, err := r.run(ctx, r.request("open_anchor", runtime, event, finding.Attributes))
	if err != nil {
		return "", err
	}
	if response.Action == "none" {
		return "", nil
	}
	if response.Action != "open_anchor" || strings.TrimSpace(response.Anchor) == "" {
		return "", fmt.Errorf("rust finding-rule authority returned invalid open-anchor decision")
	}
	return strings.TrimSpace(response.Anchor), nil
}
func (r *rustPayloadFindingRule) CloseOnEventContext(ctx context.Context, event Event) (string, bool, error) {
	runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID])
	if runtimeID == "" {
		runtimeID = "host-close"
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	runtime := &cerebrov1.SourceRuntime{Id: runtimeID, SourceId: r.definition.SourceID, TenantId: tenantID, Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: trustedTenantWorkspacePrefix + tenantID}}
	return r.closeWithRuntime(ctx, runtime, event)
}
func (r *rustPayloadFindingRule) CloseOnEventForRuntimeContext(ctx context.Context, runtime *cerebrov1.SourceRuntime, event Event) (string, bool, error) {
	return r.closeWithRuntime(ctx, runtime, event)
}

func (r *rustPayloadFindingRule) closeWithRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime, event Event) (string, bool, error) {
	if r.definition.ID == cosmoCoordinationActiveRiskRuleID {
		return "", false, nil
	}
	request := r.request("close", runtime, event, nil)
	projected, err := projectAureliusCloseAttributes(event)
	if err != nil {
		return "", false, err
	}
	request.Attributes = projected
	request.Payload = []int{}
	response, err := r.run(ctx, request)
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

func (r *rustPayloadFindingRule) run(ctx context.Context, request rustFindingRequest) (rustFindingResponse, error) {
	return runRustFinding(ctx, r.evaluator, request, r.definitionDigest)
}

func (r *rustPayloadFindingRule) request(operation string, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, attributes map[string]string) rustFindingRequest {
	request := rustFindingRequest{Operation: operation, RuleID: r.definition.ID, EventSchemaRef: r.schemaRef, Attributes: cloneStringMap(attributes), Payload: []int{}}
	if runtime != nil {
		request.RuntimeID, request.RuntimeSourceID, request.RuntimeTenantID = runtime.GetId(), runtime.GetSourceId(), runtime.GetTenantId()
		request.RuntimeWorkspaceID = trustedFindingWorkspace(runtime)
	}
	if event != nil {
		request.EventID, request.EventTenantID, request.EventSourceID, request.EventKind = event.GetId(), event.GetTenantId(), event.GetSourceId(), event.GetKind()
		request.EventSchemaRef, request.Attributes = event.GetSchemaRef(), cloneStringMap(event.GetAttributes())
		if event.GetOccurredAt() != nil {
			request.OccurredAt = event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339Nano)
		}
		if operation == "evaluate" {
			request.Payload = payloadBytes(event.GetPayload())
		}
	}
	if request.Attributes == nil {
		request.Attributes = map[string]string{}
	}
	return request
}

func trustedFindingWorkspace(runtime *cerebrov1.SourceRuntime) string {
	if runtime == nil {
		return ""
	}
	if workspaceID := strings.TrimSpace(runtime.GetConfig()[ports.SourceRuntimeApplicationWorkspaceIDConfigKey]); workspaceID != "" {
		return workspaceID
	}
	return trustedTenantWorkspacePrefix + strings.TrimSpace(runtime.GetTenantId())
}

func payloadBytes(raw []byte) []int {
	result := make([]int, len(raw))
	for index, value := range raw {
		result[index] = int(value)
	}
	return result
}

func projectAureliusCloseAttributes(event Event) (map[string]string, error) {
	attributes := cloneStringMap(event.GetAttributes())
	if len(event.GetPayload()) == 0 {
		return attributes, nil
	}
	preflight := json.NewDecoder(bytes.NewReader(event.GetPayload()))
	preflight.UseNumber()
	if err := validateUniqueBoundedJSON(preflight, 1); err != nil {
		// Go parity permits a malformed payload when the complete remediation
		// decision is already present in trusted promoted attributes.
		if aureliusCloseAttributesComplete(attributes) {
			return attributes, nil
		}
		return nil, fmt.Errorf("project Aurelius close payload: %w", err)
	}
	if err := requireJSONEOF(preflight); err != nil {
		return nil, fmt.Errorf("project Aurelius close payload: %w", err)
	}
	var payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(event.GetPayload()))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("project Aurelius close payload: %w", err)
	}
	allowed := map[string]struct{}{"image_digest": {}, "image_uri": {}, "cve_id": {}, "package": {}, "severity": {}, "installed_version": {}, "fixed_version": {}, "state": {}, "promoted": {}, "exception_status": {}, "track": {}}
	for key, value := range payload {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("project Aurelius close payload: unknown field %q", key)
		}
		if canonicalGoScalar(value) == "" && value != "" {
			return nil, fmt.Errorf("project Aurelius close payload: field %q is not a scalar", key)
		}
	}
	for _, key := range []string{"state", "promoted", "exception_status", "track", "image_uri"} {
		value := payload[key]
		if strings.TrimSpace(attributes[key]) == "" {
			attributes[key] = canonicalGoScalar(value)
		}
	}
	return attributes, nil
}

func aureliusCloseAttributesComplete(attributes map[string]string) bool {
	state := strings.ToLower(strings.TrimSpace(attributes["state"]))
	promoted := strings.ToLower(strings.TrimSpace(attributes["promoted"]))
	exceptionStatus := strings.ToLower(strings.TrimSpace(attributes["exception_status"]))
	severity := strings.ToLower(strings.TrimSpace(attributes["severity"]))
	return state == "fixed" || state == "resolved" || state == "remediated" || state == "downgraded" || state == "not_affected" || state == "notaffected" || state == "closed" || promoted == "false" || promoted == "no" || promoted == "0" || promoted == "unpromoted" || promoted == "not_promoted" || exceptionStatus == "active" || exceptionStatus == "approved" || exceptionStatus == "granted" || severity == "medium" || severity == "moderate" || severity == "low" || severity == "info" || severity == "informational" || severity == "negligible"
}

func canonicalGoScalar(value any) string {
	switch value := value.(type) {
	case string:
		return strings.TrimSpace(value)
	case bool:
		if value {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case json.Number:
		parsed, err := strconv.ParseFloat(value.String(), 64)
		if err != nil {
			return ""
		}
		return strconv.FormatFloat(parsed, 'f', -1, 64)
	default:
		return ""
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func decodeStrictRustFindingResponse(raw []byte, response *rustFindingResponse) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return fmt.Errorf("response size is outside the closed limit")
	}
	preflight := json.NewDecoder(bytes.NewReader(raw))
	preflight.UseNumber()
	if err := validateUniqueBoundedJSON(preflight, 1); err != nil {
		return err
	}
	if err := requireJSONEOF(preflight); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateRustFindingResponse(request rustFindingRequest, response rustFindingResponse) error {
	validShape := false
	switch response.Action {
	case "none":
		validShape = response.Finding == nil && strings.TrimSpace(response.Anchor) == ""
	case "open":
		validShape = response.Finding != nil && strings.TrimSpace(response.Anchor) == ""
	case "close", "open_anchor":
		validShape = response.Finding == nil && strings.TrimSpace(response.Anchor) != ""
	}
	if !validShape {
		return fmt.Errorf("rust finding-rule authority returned malformed decision shape")
	}
	if response.Finding == nil {
		return nil
	}
	finding := response.Finding
	if strings.TrimSpace(finding.ID) == "" || finding.ID != finding.Fingerprint || finding.TenantID != strings.TrimSpace(request.RuntimeTenantID) || finding.RuntimeID != strings.TrimSpace(request.RuntimeID) || finding.RuleID != strings.TrimSpace(request.RuleID) {
		return fmt.Errorf("rust finding-rule authority returned mismatched finding scope")
	}
	if finding.FirstObservedAt.IsZero() || finding.LastObservedAt.IsZero() || finding.LastObservedAt.Before(finding.FirstObservedAt) {
		return fmt.Errorf("rust finding-rule authority returned invalid chronology")
	}
	return nil
}

func validateUniqueBoundedJSON(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("response nesting exceeds the closed limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		fields := 0
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("response object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("response contains duplicate field %q", key)
			}
			seen[key] = struct{}{}
			fields++
			if fields > 128 {
				return fmt.Errorf("response object exceeds the closed field limit")
			}
			if err := validateUniqueBoundedJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("malformed response object")
		}
	case '[':
		items := 0
		for decoder.More() {
			items++
			if items > 256 {
				return fmt.Errorf("response array exceeds the closed item limit")
			}
			if err := validateUniqueBoundedJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("malformed response array")
		}
	default:
		return fmt.Errorf("unexpected response delimiter %q", delimiter)
	}
	return nil
}

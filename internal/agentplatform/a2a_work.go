package agentplatform

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	A2AWorkJobKind                  = "a2a_task"
	A2AWorkSkillAgentEvidencePacket = "agent-evidence-packet"

	A2ATaskStateSubmitted    = "TASK_STATE_SUBMITTED"
	A2ATaskStateWorking      = "TASK_STATE_WORKING"
	A2ATaskStateCompleted    = "TASK_STATE_COMPLETED"
	A2ATaskStateFailed       = "TASK_STATE_FAILED"
	A2ATaskStateCanceled     = "TASK_STATE_CANCELED"
	A2ATaskStateInputNeeded  = "TASK_STATE_INPUT_REQUIRED"
	A2ATaskStateRejected     = "TASK_STATE_REJECTED"
	A2ATaskStateAuthRequired = "TASK_STATE_AUTH_REQUIRED"
)

type A2ASendMessageParams struct {
	Tenant        string                      `json:"tenant,omitempty"`
	Message       A2AMessage                  `json:"message"`
	Configuration A2ASendMessageConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any              `json:"metadata,omitempty"`
}

type A2ASendMessageConfiguration struct {
	AcceptedOutputModes        []string `json:"acceptedOutputModes,omitempty"`
	HistoryLength              *int     `json:"historyLength,omitempty"`
	ReturnImmediately          bool     `json:"returnImmediately,omitempty"`
	TaskPushNotificationConfig any      `json:"taskPushNotificationConfig,omitempty"`
}

type A2AGetTaskParams struct {
	Tenant        string `json:"tenant,omitempty"`
	ID            string `json:"id"`
	HistoryLength *int   `json:"historyLength,omitempty"`
}

type A2AListTasksParams struct {
	Tenant string `json:"tenant,omitempty"`
	Limit  uint32 `json:"limit,omitempty"`
}

type A2AMessage struct {
	Role             string         `json:"role"`
	MessageID        string         `json:"messageId"`
	ContextID        string         `json:"contextId,omitempty"`
	TaskID           string         `json:"taskId,omitempty"`
	Parts            []A2APart      `json:"parts"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	Extensions       []string       `json:"extensions,omitempty"`
	ReferenceTaskIDs []string       `json:"referenceTaskIds,omitempty"`
}

type A2APart struct {
	Text      string         `json:"text,omitempty"`
	Raw       string         `json:"raw,omitempty"`
	URL       string         `json:"url,omitempty"`
	Data      any            `json:"data,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Filename  string         `json:"filename,omitempty"`
	MediaType string         `json:"mediaType,omitempty"`
}

type A2ATask struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitempty"`
	Status    A2ATaskStatus  `json:"status"`
	Artifacts []A2AArtifact  `json:"artifacts,omitempty"`
	History   []A2AMessage   `json:"history,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type A2ATaskStatus struct {
	State     string      `json:"state"`
	Message   *A2AMessage `json:"message,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

type A2AArtifact struct {
	ArtifactID  string         `json:"artifactId"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Parts       []A2APart      `json:"parts"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Extensions  []string       `json:"extensions,omitempty"`
}

func DecodeA2ASendMessageParams(raw json.RawMessage) (A2ASendMessageParams, error) {
	var params A2ASendMessageParams
	if len(bytes.TrimSpace(raw)) == 0 {
		return params, nil
	}
	if err := decodeA2AParams(raw, &params); err != nil {
		return A2ASendMessageParams{}, err
	}
	return params, nil
}

func DecodeA2AGetTaskParams(raw json.RawMessage) (A2AGetTaskParams, error) {
	var params A2AGetTaskParams
	if err := decodeA2AParams(raw, &params); err != nil {
		return A2AGetTaskParams{}, err
	}
	params.Tenant = strings.TrimSpace(params.Tenant)
	params.ID = strings.TrimSpace(params.ID)
	return params, nil
}

func DecodeA2AListTasksParams(raw json.RawMessage) (A2AListTasksParams, error) {
	var params A2AListTasksParams
	if len(bytes.TrimSpace(raw)) == 0 {
		return params, nil
	}
	if err := decodeA2AParams(raw, &params); err != nil {
		return A2AListTasksParams{}, err
	}
	params.Tenant = strings.TrimSpace(params.Tenant)
	return params, nil
}

func decodeA2AParams(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func A2ARequestedSkillID(params A2ASendMessageParams) string {
	for _, metadata := range []map[string]any{params.Metadata, params.Message.Metadata} {
		if skillID := a2AMetadataString(metadata, "skillId", "skill_id", "cerebroSkillId", "cerebro_skill_id"); skillID != "" {
			return strings.ToLower(skillID)
		}
	}
	for _, part := range params.Message.Parts {
		data, ok := part.Data.(map[string]any)
		if !ok {
			continue
		}
		if skillID := a2AMetadataString(data, "skillId", "skill_id", "cerebroSkillId", "cerebro_skill_id"); skillID != "" {
			return strings.ToLower(skillID)
		}
	}
	return ""
}

func EvidencePacketRequestFromA2ASendMessage(params A2ASendMessageParams) (EvidencePacketRequest, bool, error) {
	request := EvidencePacketRequest{}
	found := false
	for _, metadata := range []map[string]any{params.Metadata, params.Message.Metadata} {
		candidate, ok := a2AMetadataValue(metadata, "evidencePacket", "evidence_packet", "evidencePacketRequest", "evidence_packet_request")
		if !ok {
			continue
		}
		if err := decodeEvidencePacketCandidate(candidate, &request); err != nil {
			return EvidencePacketRequest{}, false, err
		}
		found = true
	}
	for _, part := range params.Message.Parts {
		data, ok := part.Data.(map[string]any)
		if ok {
			if candidate, exists := a2AMetadataValue(data, "evidencePacket", "evidence_packet", "evidencePacketRequest", "evidence_packet_request"); exists {
				if err := decodeEvidencePacketCandidate(candidate, &request); err != nil {
					return EvidencePacketRequest{}, false, err
				}
				found = true
			} else if a2ALooksLikeEvidencePacketRequest(data) {
				if err := decodeEvidencePacketCandidate(data, &request); err == nil {
					found = true
				}
			}
		}
		if request.Question == "" {
			request.Question = strings.TrimSpace(part.Text)
			if request.Question != "" {
				found = true
			}
		}
	}
	return request, found, nil
}

func BuildA2AEvidencePacketTask(taskID string, contextID string, input A2AMessage, packet AgentEvidencePacket, generatedAt time.Time) A2ATask {
	taskID = strings.TrimSpace(taskID)
	contextID = strings.TrimSpace(contextID)
	if contextID == "" {
		contextID = taskID
	}
	timestamp := generatedAt.UTC().Format(time.RFC3339Nano)
	statusMessage := A2AMessage{
		Role:      "ROLE_AGENT",
		MessageID: taskID + "-completed",
		ContextID: contextID,
		TaskID:    taskID,
		Parts: []A2APart{{
			Text:      "Cerebro produced a tenant-scoped agent evidence packet artifact.",
			MediaType: "text/plain",
		}},
	}
	history := []A2AMessage{}
	if strings.TrimSpace(input.MessageID) != "" || len(input.Parts) > 0 {
		input.ContextID = contextID
		input.TaskID = taskID
		history = append(history, input)
	}
	return A2ATask{
		ID:        taskID,
		ContextID: contextID,
		Status: A2ATaskStatus{
			State:     A2ATaskStateCompleted,
			Message:   &statusMessage,
			Timestamp: timestamp,
		},
		Artifacts: []A2AArtifact{{
			ArtifactID:  "evidence-packet",
			Name:        "Agent evidence packet",
			Description: "Preflight, verifier, connector-gate, eval, memory, simulation, confidence, and write-back guidance for a governed Cerebro agent run.",
			Parts: []A2APart{{
				Data:      packet,
				MediaType: "application/json",
			}},
			Metadata: map[string]any{
				"skillId":       A2AWorkSkillAgentEvidencePacket,
				"capabilityIds": append([]string(nil), packet.Preflight.SelectedCapabilities...),
			},
		}},
		History: history,
		Metadata: map[string]any{
			"skillId":         A2AWorkSkillAgentEvidencePacket,
			"contractVersion": ContractVersion,
			"tenantForced":    packet.Preflight.Policy.TenantForced,
			"writeBack":       packet.RequiredWriteBack,
		},
	}
}

func A2ATaskWithHistoryLimit(task A2ATask, historyLength *int) A2ATask {
	if historyLength == nil {
		return task
	}
	limit := *historyLength
	if limit <= 0 {
		task.History = nil
		return task
	}
	if len(task.History) > limit {
		task.History = append([]A2AMessage(nil), task.History[len(task.History)-limit:]...)
	}
	return task
}

func a2AMetadataString(metadata map[string]any, keys ...string) string {
	value, ok := a2AMetadataValue(metadata, keys...)
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func a2AMetadataValue(metadata map[string]any, keys ...string) (any, bool) {
	if len(metadata) == 0 {
		return nil, false
	}
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func a2ALooksLikeEvidencePacketRequest(values map[string]any) bool {
	for _, key := range []string{"question", "scope_urn", "scopeURN", "capability_ids", "capabilityIds", "action", "evidence_urns", "memory_hints"} {
		if _, ok := values[key]; ok {
			return true
		}
	}
	return false
}

func decodeEvidencePacketCandidate(candidate any, request *EvidencePacketRequest) error {
	payload, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	var decoded EvidencePacketRequest
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return err
	}
	mergeEvidencePacketRequest(request, decoded)
	return nil
}

func mergeEvidencePacketRequest(target *EvidencePacketRequest, source EvidencePacketRequest) {
	if source.TenantID != "" {
		target.TenantID = source.TenantID
	}
	if source.ActorID != "" {
		target.ActorID = source.ActorID
	}
	if source.Question != "" {
		target.Question = source.Question
	}
	if source.ScopeURN != "" {
		target.ScopeURN = source.ScopeURN
	}
	if source.Model != "" {
		target.Model = source.Model
	}
	if len(source.CapabilityIDs) > 0 {
		target.CapabilityIDs = append([]string(nil), source.CapabilityIDs...)
	}
	if len(source.AgentProfileIDs) > 0 {
		target.AgentProfileIDs = append([]string(nil), source.AgentProfileIDs...)
	}
	if len(source.RequestedScopes) > 0 {
		target.RequestedScopes = append([]string(nil), source.RequestedScopes...)
	}
	if source.ScopeUnrestricted {
		target.ScopeUnrestricted = true
	}
	if len(source.ConnectorReadiness) > 0 {
		target.ConnectorReadiness = cloneStringMapAny(source.ConnectorReadiness)
	}
	if len(source.EvalStatusOverrides) > 0 {
		target.EvalStatusOverrides = cloneStringMapAny(source.EvalStatusOverrides)
	}
	if source.AllowPreview {
		target.AllowPreview = true
	}
	if source.Action.Stage != "" || len(source.Action.TargetURNs) > 0 || source.Action.HumanApproved {
		target.Action = source.Action
	}
	if source.CoverageContext != nil {
		target.CoverageContext = cloneCoverageContext(source.CoverageContext)
	}
	if len(source.EvidenceURNs) > 0 {
		target.EvidenceURNs = append([]string(nil), source.EvidenceURNs...)
	}
	if len(source.MemoryHints) > 0 {
		target.MemoryHints = append([]SecurityMemoryHint(nil), source.MemoryHints...)
	}
	if source.GeneratedAt != "" {
		target.GeneratedAt = source.GeneratedAt
	}
}

func cloneStringMapAny(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

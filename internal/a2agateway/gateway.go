package a2agateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/ports"
)

type ResolvedContext struct {
	TenantID          string
	ActorID           string
	RequestedScopes   []string
	ScopeUnrestricted bool
}

type Resolver func(context.Context, string, string, []string) (ResolvedContext, error)
type CoverageContextFunc func(context.Context, string) *agentplatform.AgentCoverageContext
type EvidenceAuthorizer func(context.Context, agentplatform.EvidencePacketRequest) error
type RequestedTenantRecorder func(context.Context, string)

type Handler struct {
	Store                 ports.JobStore
	Card                  agentplatform.A2AAgentCard
	Resolve               Resolver
	CoverageContext       CoverageContextFunc
	AuthorizeEvidence     EvidenceAuthorizer
	RecordRequestedTenant RequestedTenantRecorder
	IdempotencyKey        string
}

func (h Handler) Respond(ctx context.Context, request agentplatform.A2AJSONRPCRequest) agentplatform.A2AJSONRPCResponse {
	response := agentplatform.A2AJSONRPCResponse{JSONRPC: "2.0", ID: request.ID}
	if strings.TrimSpace(request.JSONRPC) != "2.0" {
		response.Error = &agentplatform.A2AJSONError{Code: -32600, Message: "Invalid Request"}
		return response
	}
	switch strings.TrimSpace(request.Method) {
	case "SendMessage":
		return h.sendMessage(ctx, request)
	case "GetTask":
		return h.getTask(ctx, request)
	case "ListTasks":
		return h.listTasks(ctx, request)
	default:
		return agentplatform.A2AJSONRPCResponseFor(request, h.Card)
	}
}

func (h Handler) sendMessage(ctx context.Context, request agentplatform.A2AJSONRPCRequest) agentplatform.A2AJSONRPCResponse {
	response := agentplatform.A2AJSONRPCResponse{JSONRPC: "2.0", ID: request.ID}
	params, err := agentplatform.DecodeA2ASendMessageParams(request.Params)
	if err != nil {
		response.Error = invalidParams("SendMessage params are invalid")
		return response
	}
	skillID := agentplatform.A2ARequestedSkillID(params)
	if skillID == "" || skillID == "agent-platform-contract" || skillID == "event-subscription-contract" || skillID == "idempotency-contract" {
		if _, err := h.resolve(ctx, params.Tenant, "", nil); err != nil {
			response.Error = forbidden()
			return response
		}
		return agentplatform.A2AJSONRPCResponseFor(request, h.Card)
	}
	if skillID != agentplatform.A2AWorkSkillAgentEvidencePacket {
		response.Error = &agentplatform.A2AJSONError{
			Code:    -32004,
			Message: "UnsupportedOperationError",
			Data: map[string]any{
				"supportedSkills": []string{"agent-platform-contract", agentplatform.A2AWorkSkillAgentEvidencePacket, "event-subscription-contract", "idempotency-contract"},
				"reason":          "The requested A2A skill is not supported by this Cerebro endpoint.",
			},
		}
		return response
	}
	task, err := h.createEvidencePacketTask(ctx, params)
	if err != nil {
		response.Error = jsonRPCErrorFromError(err)
		return response
	}
	response.Result = map[string]any{"task": task}
	return response
}

func (h Handler) createEvidencePacketTask(ctx context.Context, params agentplatform.A2ASendMessageParams) (agentplatform.A2ATask, error) {
	evidenceRequest, found, err := agentplatform.EvidencePacketRequestFromA2ASendMessage(params)
	if err != nil {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "evidence packet request is invalid"}
	}
	if !found {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "agent-evidence-packet requires a text question or structured evidence packet request"}
	}
	requestedTenantID, ok := matchingTenant(params.Tenant, evidenceRequest.TenantID)
	if !ok {
		if h.RecordRequestedTenant != nil {
			h.RecordRequestedTenant(ctx, evidenceRequest.TenantID)
		}
		return agentplatform.A2ATask{}, requestError{code: -32003, message: "ForbiddenError", reason: "A2A tenant values do not match"}
	}
	resolved, err := h.resolve(ctx, requestedTenantID, evidenceRequest.ActorID, evidenceRequest.RequestedScopes)
	if err != nil {
		return agentplatform.A2ATask{}, requestError{code: -32003, message: "ForbiddenError", reason: "A2A tenant is not authorized"}
	}
	if strings.TrimSpace(resolved.TenantID) == "" {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "A2A agent-evidence-packet tasks require a tenant"}
	}
	evidenceRequest.TenantID = resolved.TenantID
	evidenceRequest.ActorID = resolved.ActorID
	evidenceRequest.RequestedScopes = resolved.RequestedScopes
	evidenceRequest.ScopeUnrestricted = resolved.ScopeUnrestricted
	if h.CoverageContext != nil {
		evidenceRequest.CoverageContext = h.CoverageContext(ctx, evidenceRequest.TenantID)
	}
	if h.AuthorizeEvidence != nil {
		if err := h.AuthorizeEvidence(ctx, evidenceRequest); err != nil {
			return agentplatform.A2ATask{}, requestError{code: -32003, message: "ForbiddenError", reason: "A2A evidence packet references are not authorized"}
		}
	}
	if h.Store == nil {
		return agentplatform.A2ATask{}, requestError{code: -32603, message: "InternalError", reason: "A2A task store is unavailable"}
	}
	idempotencyKey, err := h.idempotencyKey(params)
	if err != nil {
		return agentplatform.A2ATask{}, err
	}
	now := time.Now().UTC()
	if strings.TrimSpace(evidenceRequest.GeneratedAt) == "" {
		evidenceRequest.GeneratedAt = now.Format(time.RFC3339Nano)
	}
	contextID := strings.TrimSpace(params.Message.ContextID)
	job, created, err := h.Store.CreateJob(ctx, ports.CreateJobRequest{
		Kind:           agentplatform.A2AWorkJobKind,
		TenantID:       evidenceRequest.TenantID,
		SubjectType:    agentplatform.A2AWorkSkillAgentEvidencePacket,
		SubjectID:      contextID,
		IdempotencyKey: idempotencyKey,
		Payload: map[string]any{
			"skill_id":                agentplatform.A2AWorkSkillAgentEvidencePacket,
			"context_id":              contextID,
			"message_id":              strings.TrimSpace(params.Message.MessageID),
			"evidence_packet_request": evidenceRequest,
			"accepted_output_modes":   append([]string(nil), params.Configuration.AcceptedOutputModes...),
			"return_immediately":      params.Configuration.ReturnImmediately,
			"task_push_notifications": params.Configuration.TaskPushNotificationConfig != nil,
			"source_protocol":         "a2a-jsonrpc",
			"contract_version":        agentplatform.ContractVersion,
		},
	})
	if err != nil {
		return agentplatform.A2ATask{}, err
	}
	if !created {
		if !jobVisible(job, resolved) || job.Kind != agentplatform.A2AWorkJobKind {
			return agentplatform.A2ATask{}, requestError{code: -32001, message: "TaskNotFoundError", reason: "A2A idempotent task is not visible"}
		}
		task, err := taskFromJob(job)
		if err != nil {
			return agentplatform.A2ATask{}, err
		}
		return agentplatform.A2ATaskWithHistoryLimit(task, params.Configuration.HistoryLength), nil
	}
	if _, err := h.Store.AppendJobEvent(ctx, ports.JobEvent{
		JobID:   job.ID,
		Type:    "a2a.task.submitted",
		Status:  ports.JobStatusQueued,
		Message: "A2A agent-evidence-packet task submitted.",
		Payload: map[string]any{"skill_id": agentplatform.A2AWorkSkillAgentEvidencePacket},
	}); err != nil {
		h.failEvidencePacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	startedAt := now
	updatedJob, err := h.Store.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status:          ports.JobStatusRunning,
		Progress:        uint32Pointer(25),
		Message:         "Building A2A agent evidence packet.",
		StartedAt:       &startedAt,
		AllowedStatuses: []string{ports.JobStatusQueued},
	})
	if err != nil {
		h.failEvidencePacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	job = updatedJob
	if _, err := h.Store.AppendJobEvent(ctx, ports.JobEvent{
		JobID:   job.ID,
		Type:    "a2a.task.working",
		Status:  ports.JobStatusRunning,
		Message: "A2A agent-evidence-packet task is building the evidence artifact.",
	}); err != nil {
		h.failEvidencePacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	packet := agentplatform.BuildEvidencePacket(evidenceRequest)
	task := agentplatform.BuildA2AEvidencePacketTask(job.ID, contextID, params.Message, packet, now)
	finishedAt := now
	updatedJob, err = h.Store.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status:          ports.JobStatusCompleted,
		Progress:        uint32Pointer(100),
		Message:         "A2A agent evidence packet completed.",
		Result:          map[string]any{"task": task},
		FinishedAt:      &finishedAt,
		AllowedStatuses: []string{ports.JobStatusRunning},
	})
	if err != nil {
		h.failEvidencePacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	job = updatedJob
	if _, err := h.Store.AppendJobEvent(ctx, ports.JobEvent{
		JobID:   job.ID,
		Type:    "a2a.task.completed",
		Status:  ports.JobStatusCompleted,
		Message: "A2A agent-evidence-packet task completed.",
		Payload: map[string]any{
			"artifact_id": "evidence-packet",
			"state":       agentplatform.A2ATaskStateCompleted,
		},
	}); err != nil {
		return agentplatform.A2ATask{}, err
	}
	return agentplatform.A2ATaskWithHistoryLimit(task, params.Configuration.HistoryLength), nil
}

func (h Handler) failEvidencePacketTask(ctx context.Context, job *ports.Job, cause error) {
	if h.Store == nil || job == nil || cause == nil {
		return
	}
	finishedAt := time.Now().UTC()
	_, _ = h.Store.UpdateJob(context.WithoutCancel(ctx), job.ID, ports.JobUpdate{
		Status:          ports.JobStatusFailed,
		Message:         "A2A agent evidence packet failed.",
		Error:           cause.Error(),
		FinishedAt:      &finishedAt,
		AllowedStatuses: []string{ports.JobStatusQueued, ports.JobStatusRunning},
	})
	_, _ = h.Store.AppendJobEvent(context.WithoutCancel(ctx), ports.JobEvent{
		JobID:   job.ID,
		Type:    "a2a.task.failed",
		Status:  ports.JobStatusFailed,
		Message: "A2A agent-evidence-packet task failed.",
		Payload: map[string]any{"state": agentplatform.A2ATaskStateFailed},
	})
}

func (h Handler) getTask(ctx context.Context, request agentplatform.A2AJSONRPCRequest) agentplatform.A2AJSONRPCResponse {
	response := agentplatform.A2AJSONRPCResponse{JSONRPC: "2.0", ID: request.ID}
	params, err := agentplatform.DecodeA2AGetTaskParams(request.Params)
	if err != nil || params.ID == "" {
		response.Error = invalidParams("GetTask params are invalid")
		return response
	}
	resolved, err := h.resolve(ctx, params.Tenant, "", nil)
	if err != nil {
		response.Error = forbidden()
		return response
	}
	if h.Store == nil {
		response.Error = &agentplatform.A2AJSONError{Code: -32603, Message: "InternalError", Data: map[string]any{"reason": "A2A task store is unavailable"}}
		return response
	}
	job, err := h.Store.GetJob(ctx, params.ID)
	if err != nil || !jobVisible(job, resolved) || job.Kind != agentplatform.A2AWorkJobKind {
		response.Error = &agentplatform.A2AJSONError{Code: -32001, Message: "TaskNotFoundError"}
		return response
	}
	task, err := taskFromJob(job)
	if err != nil {
		response.Error = jsonRPCErrorFromError(err)
		return response
	}
	response.Result = agentplatform.A2ATaskWithHistoryLimit(task, params.HistoryLength)
	return response
}

func (h Handler) listTasks(ctx context.Context, request agentplatform.A2AJSONRPCRequest) agentplatform.A2AJSONRPCResponse {
	response := agentplatform.A2AJSONRPCResponse{JSONRPC: "2.0", ID: request.ID}
	params, err := agentplatform.DecodeA2AListTasksParams(request.Params)
	if err != nil {
		response.Error = invalidParams("ListTasks params are invalid")
		return response
	}
	resolved, err := h.resolve(ctx, params.Tenant, "", nil)
	if err != nil {
		response.Error = forbidden()
		return response
	}
	if strings.TrimSpace(resolved.TenantID) == "" {
		response.Error = invalidParams("ListTasks requires a tenant")
		return response
	}
	if h.Store == nil {
		response.Error = &agentplatform.A2AJSONError{Code: -32603, Message: "InternalError", Data: map[string]any{"reason": "A2A task store is unavailable"}}
		return response
	}
	filter := ports.JobFilter{TenantID: resolved.TenantID, Kind: agentplatform.A2AWorkJobKind, Limit: params.Limit}
	jobs, err := h.Store.ListJobs(ctx, filter)
	if err != nil {
		response.Error = jsonRPCErrorFromError(err)
		return response
	}
	totalSize, err := h.Store.CountJobs(ctx, filter)
	if err != nil {
		response.Error = jsonRPCErrorFromError(err)
		return response
	}
	tasks := make([]agentplatform.A2ATask, 0, len(jobs))
	for _, job := range jobs {
		if !jobVisible(job, resolved) || job.Kind != agentplatform.A2AWorkJobKind {
			continue
		}
		task, err := taskFromJob(job)
		if err != nil {
			response.Error = jsonRPCErrorFromError(err)
			return response
		}
		task.History = nil
		tasks = append(tasks, task)
	}
	response.Result = map[string]any{"tasks": tasks, "totalSize": totalSize, "returnedSize": len(tasks), "hasMore": totalSize > uint64(len(tasks))}
	return response
}

func (h Handler) resolve(ctx context.Context, requestedTenantID string, requestedActorID string, requestedScopes []string) (ResolvedContext, error) {
	if h.Resolve != nil {
		return h.Resolve(ctx, requestedTenantID, requestedActorID, requestedScopes)
	}
	return ResolvedContext{
		TenantID:        strings.TrimSpace(requestedTenantID),
		ActorID:         strings.TrimSpace(requestedActorID),
		RequestedScopes: append([]string(nil), requestedScopes...),
	}, nil
}

type requestError struct {
	code    int
	message string
	reason  string
}

func (e requestError) Error() string {
	if e.reason != "" {
		return e.reason
	}
	return e.message
}

func matchingTenant(paramTenantID string, bodyTenantID string) (string, bool) {
	paramTenantID = strings.TrimSpace(paramTenantID)
	bodyTenantID = strings.TrimSpace(bodyTenantID)
	if paramTenantID != "" && bodyTenantID != "" && paramTenantID != bodyTenantID {
		return "", false
	}
	if paramTenantID != "" {
		return paramTenantID, true
	}
	return bodyTenantID, true
}

func (h Handler) idempotencyKey(params agentplatform.A2ASendMessageParams) (string, error) {
	key := strings.TrimSpace(h.IdempotencyKey)
	if key == "" {
		key = strings.TrimSpace(params.Message.MessageID)
	}
	if key == "" {
		return "", nil
	}
	if len(key) > agentplatform.Idempotency().MaxLengthBytes {
		return "", requestError{code: -32602, message: "InvalidParams", reason: "A2A idempotency key exceeds the public contract length limit"}
	}
	return "a2a:" + key, nil
}

func jobVisible(job *ports.Job, resolved ResolvedContext) bool {
	if job == nil {
		return false
	}
	tenantID := strings.TrimSpace(resolved.TenantID)
	jobTenantID := strings.TrimSpace(job.TenantID)
	if tenantID == "" {
		return jobTenantID == ""
	}
	return jobTenantID == tenantID
}

func taskFromJob(job *ports.Job) (agentplatform.A2ATask, error) {
	if job == nil {
		return agentplatform.A2ATask{}, errors.New("A2A task job is nil")
	}
	if value, ok := job.Result["task"]; ok && value != nil {
		task, err := decodeTaskValue(value)
		if err != nil {
			return agentplatform.A2ATask{}, err
		}
		if strings.TrimSpace(task.ID) != "" {
			return task, nil
		}
	}
	contextID := stringFromMap(job.Payload, "context_id")
	if contextID == "" {
		contextID = job.ID
	}
	state := agentplatform.A2ATaskStateSubmitted
	switch job.Status {
	case ports.JobStatusRunning:
		state = agentplatform.A2ATaskStateWorking
	case ports.JobStatusCompleted:
		state = agentplatform.A2ATaskStateCompleted
	case ports.JobStatusFailed:
		state = agentplatform.A2ATaskStateFailed
	case ports.JobStatusCancelled:
		state = agentplatform.A2ATaskStateCanceled
	}
	timestamp := job.UpdatedAt
	if timestamp.IsZero() {
		timestamp = job.CreatedAt
	}
	statusText := strings.TrimSpace(job.Message)
	if statusText == "" {
		statusText = strings.TrimSpace(job.Error)
	}
	var message *agentplatform.A2AMessage
	if statusText != "" {
		message = &agentplatform.A2AMessage{
			Role:      "ROLE_AGENT",
			MessageID: job.ID + "-status",
			ContextID: contextID,
			TaskID:    job.ID,
			Parts: []agentplatform.A2APart{{
				Text:      statusText,
				MediaType: "text/plain",
			}},
		}
	}
	task := agentplatform.A2ATask{
		ID:        job.ID,
		ContextID: contextID,
		Status: agentplatform.A2ATaskStatus{
			State:   state,
			Message: message,
		},
		Metadata: map[string]any{
			"skillId":         stringFromMap(job.Payload, "skill_id"),
			"contractVersion": stringFromMap(job.Payload, "contract_version"),
		},
	}
	if !timestamp.IsZero() {
		task.Status.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
	}
	return task, nil
}

func decodeTaskValue(value any) (agentplatform.A2ATask, error) {
	if task, ok := value.(agentplatform.A2ATask); ok {
		return task, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return agentplatform.A2ATask{}, err
	}
	var task agentplatform.A2ATask
	if err := json.Unmarshal(payload, &task); err != nil {
		return agentplatform.A2ATask{}, err
	}
	return task, nil
}

func stringFromMap(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	text, _ := values[key].(string)
	return strings.TrimSpace(text)
}

func invalidParams(reason string) *agentplatform.A2AJSONError {
	return &agentplatform.A2AJSONError{Code: -32602, Message: "InvalidParams", Data: map[string]any{"reason": reason}}
}

func forbidden() *agentplatform.A2AJSONError {
	return &agentplatform.A2AJSONError{Code: -32003, Message: "ForbiddenError"}
}

func jsonRPCErrorFromError(err error) *agentplatform.A2AJSONError {
	var requestErr requestError
	if errors.As(err, &requestErr) {
		return &agentplatform.A2AJSONError{
			Code:    requestErr.code,
			Message: requestErr.message,
			Data:    map[string]any{"reason": requestErr.reason},
		}
	}
	if errors.Is(err, ports.ErrJobNotFound) {
		return &agentplatform.A2AJSONError{Code: -32001, Message: "TaskNotFoundError"}
	}
	return &agentplatform.A2AJSONError{Code: -32603, Message: "InternalError", Data: map[string]any{"reason": "A2A task processing failed"}}
}

func uint32Pointer(value uint32) *uint32 {
	return &value
}

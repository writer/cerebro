package a2agateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/decisionpacket"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

type DecisionPacketBuilder interface {
	Build(context.Context, decisionpacket.AuthorizedTenant, decisionpacket.AuthorizedActor, decisionpacket.Request) (*decisionpacket.Packet, error)
}

func (h Handler) createDecisionPacketTask(ctx context.Context, params agentplatform.A2ASendMessageParams) (agentplatform.A2ATask, error) {
	request, found, err := decisionPacketRequestFromA2A(params)
	if err != nil {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "decision packet request is invalid"}
	}
	if !found || strings.TrimSpace(request.Workflow) == "" || strings.TrimSpace(request.Question) == "" {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "decision-packet requires workflow and question"}
	}
	resolved, err := h.resolve(ctx, params.Tenant, "", nil)
	if err != nil {
		return agentplatform.A2ATask{}, requestError{code: -32003, message: "ForbiddenError", reason: "A2A tenant is not authorized"}
	}
	if strings.TrimSpace(resolved.TenantID) == "" {
		return agentplatform.A2ATask{}, requestError{code: -32602, message: "InvalidParams", reason: "A2A decision-packet tasks require a tenant"}
	}
	if h.Store == nil {
		return agentplatform.A2ATask{}, requestError{code: -32603, message: "InternalError", reason: "A2A task store is unavailable"}
	}
	if h.DecisionPackets == nil {
		return agentplatform.A2ATask{}, requestError{code: -32603, message: "InternalError", reason: "DecisionPacket service is unavailable"}
	}
	idempotencyKey, err := h.idempotencyKey(params)
	if err != nil {
		return agentplatform.A2ATask{}, err
	}
	if idempotencyKey != "" {
		idempotencyKey += ":" + agentplatform.A2AWorkSkillDecisionPacket
	}
	now := time.Now().UTC()
	contextID := strings.TrimSpace(params.Message.ContextID)
	job, created, err := h.Store.CreateJob(ctx, ports.CreateJobRequest{
		Kind:           agentplatform.A2AWorkJobKind,
		TenantID:       resolved.TenantID,
		SubjectType:    agentplatform.A2AWorkSkillDecisionPacket,
		SubjectID:      contextID,
		IdempotencyKey: idempotencyKey,
		Payload: map[string]any{
			"skill_id":                agentplatform.A2AWorkSkillDecisionPacket,
			"context_id":              contextID,
			"message_id":              strings.TrimSpace(params.Message.MessageID),
			"decision_packet_request": request,
			"accepted_output_modes":   append([]string(nil), params.Configuration.AcceptedOutputModes...),
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
		JobID: job.ID, Type: "a2a.task.submitted", Status: ports.JobStatusQueued,
		Message: "A2A DecisionPacket task submitted.", Payload: map[string]any{"skill_id": agentplatform.A2AWorkSkillDecisionPacket},
	}); err != nil {
		h.failDecisionPacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	startedAt := now
	updatedJob, err := h.Store.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status: ports.JobStatusRunning, Progress: uint32Pointer(25), Message: "Resolving authoritative DecisionPacket context.",
		StartedAt: &startedAt, AllowedStatuses: []string{ports.JobStatusQueued},
	})
	if err != nil {
		h.failDecisionPacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	job = updatedJob
	if _, err := h.Store.AppendJobEvent(ctx, ports.JobEvent{
		JobID: job.ID, Type: "a2a.task.working", Status: ports.JobStatusRunning,
		Message: "A2A DecisionPacket task is resolving authoritative server records.",
	}); err != nil {
		h.failDecisionPacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	packet, err := h.DecisionPackets.Build(ctx,
		decisionpacket.AuthorizedTenant{ID: resolved.TenantID},
		decisionpacket.AuthorizedActor{ID: resolved.ActorID, Scopes: append([]string(nil), resolved.RequestedScopes...)},
		request,
	)
	if err != nil {
		h.failDecisionPacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	task := agentplatform.BuildA2ADecisionPacketTask(job.ID, contextID, params.Message, packet, packet.ID, packet.SchemaVersion, packet.GeneratedAt)
	finishedAt := time.Now().UTC()
	updatedJob, err = h.Store.UpdateJob(ctx, job.ID, ports.JobUpdate{
		Status: ports.JobStatusCompleted, Progress: uint32Pointer(100), Message: "A2A DecisionPacket completed.",
		Result: map[string]any{"task": task}, FinishedAt: &finishedAt, AllowedStatuses: []string{ports.JobStatusRunning},
	})
	if err != nil {
		h.failDecisionPacketTask(ctx, job, err)
		return agentplatform.A2ATask{}, err
	}
	job = updatedJob
	if _, err := h.Store.AppendJobEvent(ctx, ports.JobEvent{
		JobID: job.ID, Type: "a2a.task.completed", Status: ports.JobStatusCompleted,
		Message: "A2A DecisionPacket task completed.",
		Payload: map[string]any{"artifact_id": "decision-packet", "packet_id": packet.ID, "state": agentplatform.A2ATaskStateCompleted},
	}); err != nil {
		return agentplatform.A2ATask{}, err
	}
	return agentplatform.A2ATaskWithHistoryLimit(task, params.Configuration.HistoryLength), nil
}

func decisionPacketRequestFromA2A(params agentplatform.A2ASendMessageParams) (decisionpacket.Request, bool, error) {
	request := decisionpacket.Request{}
	found := false
	for _, metadata := range []map[string]any{params.Metadata, params.Message.Metadata} {
		if candidate, ok := metadataValue(metadata, "decisionPacket", "decision_packet", "decisionPacketRequest", "decision_packet_request"); ok {
			if err := decodeDecisionPacketCandidate(candidate, &request); err != nil {
				return decisionpacket.Request{}, false, err
			}
			found = true
		}
	}
	for _, part := range params.Message.Parts {
		if data, ok := part.Data.(map[string]any); ok {
			if candidate, exists := metadataValue(data, "decisionPacket", "decision_packet", "decisionPacketRequest", "decision_packet_request"); exists {
				if err := decodeDecisionPacketCandidate(candidate, &request); err != nil {
					return decisionpacket.Request{}, false, err
				}
				found = true
			} else if looksLikeDecisionPacketRequest(data) {
				if err := decodeDecisionPacketCandidate(data, &request); err != nil {
					return decisionpacket.Request{}, false, err
				}
				found = true
			}
		}
		if request.Question == "" && strings.TrimSpace(part.Text) != "" {
			request.Question = strings.TrimSpace(part.Text)
			found = true
		}
	}
	return request, found, nil
}

func decodeDecisionPacketCandidate(candidate any, target *decisionpacket.Request) error {
	payload, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("multiple JSON values")
	}
	return nil
}

func metadataValue(values map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func looksLikeDecisionPacketRequest(values map[string]any) bool {
	for _, key := range []string{"workflow", "question", "finding_ids", "claim_ids", "evidence_urns", "audit_packet_ids", "required_sources"} {
		if _, ok := values[key]; ok {
			return true
		}
	}
	return false
}

func (h Handler) failDecisionPacketTask(ctx context.Context, job *ports.Job, cause error) {
	if h.Store == nil || job == nil || cause == nil {
		return
	}
	finishedAt := time.Now().UTC()
	bgCtx := context.WithoutCancel(ctx)
	if _, err := h.Store.UpdateJob(bgCtx, job.ID, ports.JobUpdate{
		Status: ports.JobStatusFailed, Message: "A2A DecisionPacket failed.", Error: cause.Error(), FinishedAt: &finishedAt,
		AllowedStatuses: []string{ports.JobStatusQueued, ports.JobStatusRunning},
	}); err != nil {
		telemetry.CaptureError(bgCtx, "a2a.decision_packet.update_job_failed", err, telemetry.Attrs(telemetry.Field{Key: "job_id", Value: job.ID}))
	}
	if _, err := h.Store.AppendJobEvent(bgCtx, ports.JobEvent{
		JobID: job.ID, Type: "a2a.task.failed", Status: ports.JobStatusFailed, Message: "A2A DecisionPacket task failed.",
		Payload: map[string]any{"state": agentplatform.A2ATaskStateFailed},
	}); err != nil {
		telemetry.CaptureError(bgCtx, "a2a.decision_packet.event_append_failed", err, telemetry.Attrs(telemetry.Field{Key: "job_id", Value: job.ID}))
	}
}

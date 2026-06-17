package a2agateway

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/ports"
)

func TestCreateEvidencePacketTaskFailsJobWhenCompletionUpdateFails(t *testing.T) {
	store := newGatewayTestJobStore()
	store.failCompleteUpdate = true
	handler := Handler{Store: store, Resolve: gatewayTestResolver, IdempotencyKey: "task-key"}

	response := handler.Respond(context.Background(), gatewayTestSendMessageRequest("message-1"))
	if response.Error == nil {
		t.Fatalf("Respond() error = nil, want transient store error")
	}
	job := store.mustJob(t, "job-test")
	if job.Status != ports.JobStatusFailed {
		t.Fatalf("job status = %q, want failed after compensation", job.Status)
	}
	if job.Error == "" {
		t.Fatal("job error is empty after compensation")
	}

	replay := handler.Respond(context.Background(), gatewayTestSendMessageRequest("message-1"))
	if replay.Error != nil {
		t.Fatalf("replay error = %+v, want failed task result", replay.Error)
	}
	task := gatewayTestTaskResult(t, replay.Result)
	if task.Status.State != agentplatform.A2ATaskStateFailed {
		t.Fatalf("replay task state = %q, want failed", task.Status.State)
	}
}

func TestCreateEvidencePacketTaskChecksVisibilityOnIdempotentReplay(t *testing.T) {
	store := newGatewayTestJobStore()
	store.jobs["job-other"] = &ports.Job{
		ID:             "job-other",
		Kind:           agentplatform.A2AWorkJobKind,
		Status:         ports.JobStatusCompleted,
		TenantID:       "other",
		IdempotencyKey: "a2a:message-1",
		Payload: map[string]any{
			"context_id":       "ctx-other",
			"skill_id":         agentplatform.A2AWorkSkillAgentEvidencePacket,
			"contract_version": agentplatform.ContractVersion,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	store.idempotent["writer\x00a2a:message-1"] = "job-other"
	handler := Handler{Store: store, Resolve: gatewayTestResolver}

	response := handler.Respond(context.Background(), gatewayTestSendMessageRequest("message-1"))
	if response.Error == nil || response.Error.Code != -32001 {
		t.Fatalf("cross-tenant replay response = %+v, want TaskNotFoundError", response)
	}
}

func TestCreateEvidencePacketTaskRejectsLongMessageIDFallbackKey(t *testing.T) {
	store := newGatewayTestJobStore()
	handler := Handler{Store: store, Resolve: gatewayTestResolver}
	longMessageID := strings.Repeat("m", agentplatform.Idempotency().MaxLengthBytes+1)

	response := handler.Respond(context.Background(), gatewayTestSendMessageRequest(longMessageID))
	if response.Error == nil || response.Error.Code != -32602 {
		t.Fatalf("long messageId fallback response = %+v, want InvalidParams", response)
	}
	if len(store.jobs) != 0 {
		t.Fatalf("jobs created = %d, want none", len(store.jobs))
	}
}

func gatewayTestSendMessageRequest(messageID string) agentplatform.A2AJSONRPCRequest {
	const tenantID = "writer"
	params := agentplatform.A2ASendMessageParams{
		Tenant: tenantID,
		Message: agentplatform.A2AMessage{
			Role:      "ROLE_USER",
			MessageID: messageID,
			ContextID: "ctx-1",
			Parts: []agentplatform.A2APart{{
				Text:      "Build an evidence packet",
				MediaType: "text/plain",
			}},
		},
		Metadata: map[string]any{
			"skillId": agentplatform.A2AWorkSkillAgentEvidencePacket,
			"evidencePacket": map[string]any{
				"tenant_id":      tenantID,
				"question":       "Build an evidence packet",
				"scope_urn":      "urn:cerebro:" + tenantID + ":finding:alert-1",
				"capability_ids": []string{"graph-reasoning"},
			},
		},
	}
	raw, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	return agentplatform.A2AJSONRPCRequest{JSONRPC: "2.0", ID: "request-1", Method: "SendMessage", Params: raw}
}

func gatewayTestResolver(_ context.Context, requestedTenantID string, requestedActorID string, requestedScopes []string) (ResolvedContext, error) {
	if requestedTenantID == "" {
		return ResolvedContext{}, errors.New("tenant required")
	}
	if requestedActorID == "" {
		requestedActorID = "tester"
	}
	return ResolvedContext{
		TenantID:        requestedTenantID,
		ActorID:         requestedActorID,
		RequestedScopes: append([]string(nil), requestedScopes...),
	}, nil
}

func gatewayTestTaskResult(t *testing.T, result any) agentplatform.A2ATask {
	t.Helper()
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var wrapped map[string]agentplatform.A2ATask
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		t.Fatalf("decode task result: %v", err)
	}
	task, ok := wrapped["task"]
	if !ok {
		t.Fatalf("result = %+v, missing task", wrapped)
	}
	return task
}

type gatewayTestJobStore struct {
	mu                 sync.Mutex
	nextID             int
	jobs               map[string]*ports.Job
	idempotent         map[string]string
	events             []*ports.JobEvent
	failCompleteUpdate bool
}

func newGatewayTestJobStore() *gatewayTestJobStore {
	return &gatewayTestJobStore{
		nextID:     1,
		jobs:       map[string]*ports.Job{},
		idempotent: map[string]string{},
	}
}

func (s *gatewayTestJobStore) Ping(context.Context) error {
	return nil
}

func (s *gatewayTestJobStore) CreateJob(_ context.Context, request ports.CreateJobRequest) (*ports.Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if request.IdempotencyKey != "" {
		if id := s.idempotent[request.TenantID+"\x00"+request.IdempotencyKey]; id != "" {
			return cloneGatewayTestJob(s.jobs[id]), false, nil
		}
	}
	id := "job-test"
	if s.nextID > 1 {
		id = "job-test-" + strconv.Itoa(s.nextID)
	}
	s.nextID++
	now := time.Now().UTC()
	job := &ports.Job{
		ID:             id,
		Kind:           request.Kind,
		Status:         ports.JobStatusQueued,
		TenantID:       request.TenantID,
		SubjectType:    request.SubjectType,
		SubjectID:      request.SubjectID,
		IdempotencyKey: request.IdempotencyKey,
		Payload:        cloneGatewayTestMap(request.Payload),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.jobs[id] = cloneGatewayTestJob(job)
	if request.IdempotencyKey != "" {
		s.idempotent[request.TenantID+"\x00"+request.IdempotencyKey] = id
	}
	return cloneGatewayTestJob(job), true, nil
}

func (s *gatewayTestJobStore) GetJob(_ context.Context, id string) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	return cloneGatewayTestJob(job), nil
}

func (s *gatewayTestJobStore) ListJobs(_ context.Context, filter ports.JobFilter) ([]*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := []*ports.Job{}
	for _, job := range s.jobs {
		if filter.TenantID != "" && job.TenantID != filter.TenantID {
			continue
		}
		if filter.Kind != "" && job.Kind != filter.Kind {
			continue
		}
		jobs = append(jobs, cloneGatewayTestJob(job))
	}
	return jobs, nil
}

func (s *gatewayTestJobStore) UpdateJob(_ context.Context, id string, update ports.JobUpdate) (*ports.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failCompleteUpdate && update.Status == ports.JobStatusCompleted {
		return nil, errors.New("transient completion write failed")
	}
	job := s.jobs[id]
	if job == nil {
		return nil, ports.ErrJobNotFound
	}
	if len(update.AllowedStatuses) > 0 && !gatewayTestContainsStatus(update.AllowedStatuses, job.Status) {
		return nil, ports.ErrJobUpdateConflict
	}
	if update.Status != "" {
		job.Status = update.Status
	}
	if update.Progress != nil {
		job.Progress = *update.Progress
	}
	if update.Message != "" {
		job.Message = update.Message
	}
	if update.Error != "" {
		job.Error = update.Error
	}
	if update.Result != nil {
		job.Result = cloneGatewayTestMap(update.Result)
	}
	if update.StartedAt != nil {
		job.StartedAt = *update.StartedAt
	}
	if update.FinishedAt != nil {
		job.FinishedAt = *update.FinishedAt
	}
	job.UpdatedAt = time.Now().UTC()
	return cloneGatewayTestJob(job), nil
}

func (s *gatewayTestJobStore) AppendJobEvent(_ context.Context, event ports.JobEvent) (*ports.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	event.Sequence = uint64(len(s.events) + 1)
	event.CreatedAt = time.Now().UTC()
	event.Payload = cloneGatewayTestMap(event.Payload)
	s.events = append(s.events, &event)
	return &event, nil
}

func (s *gatewayTestJobStore) ListJobEvents(_ context.Context, jobID string, limit uint32) ([]*ports.JobEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	events := []*ports.JobEvent{}
	for _, event := range s.events {
		if event.JobID != jobID {
			continue
		}
		cloned := *event
		cloned.Payload = cloneGatewayTestMap(event.Payload)
		events = append(events, &cloned)
		if limit > 0 && len(events) >= int(limit) {
			break
		}
	}
	return events, nil
}

func (s *gatewayTestJobStore) mustJob(t *testing.T, id string) *ports.Job {
	t.Helper()
	job, err := s.GetJob(context.Background(), id)
	if err != nil {
		t.Fatalf("GetJob(%q) error = %v", id, err)
	}
	return job
}

func gatewayTestContainsStatus(values []string, status string) bool {
	for _, value := range values {
		if value == status {
			return true
		}
	}
	return false
}

func cloneGatewayTestJob(job *ports.Job) *ports.Job {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.Payload = cloneGatewayTestMap(job.Payload)
	cloned.Result = cloneGatewayTestMap(job.Result)
	return &cloned
}

func cloneGatewayTestMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

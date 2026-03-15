package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/evalops/cerebro/internal/runtime"
)

type runtimeIngestSession struct {
	store runtime.IngestStore
	run   *runtime.IngestRunRecord
}

func (r *runtimeIngestSession) runID() string {
	if r == nil || r.run == nil {
		return ""
	}
	return r.run.ID
}

func (s *Server) runtimeIngestStore() runtime.IngestStore {
	if s == nil || s.app == nil {
		return nil
	}
	return s.app.RuntimeIngest
}

func (s *Server) startRuntimeIngestSession(ctx context.Context, source string, metadata map[string]string) (*runtimeIngestSession, error) {
	store := s.runtimeIngestStore()
	if store == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	run := &runtime.IngestRunRecord{
		ID:          "runtime_ingest:" + uuid.NewString(),
		Source:      strings.TrimSpace(source),
		Status:      runtime.IngestRunStatusRunning,
		Stage:       "detect",
		SubmittedAt: now,
		StartedAt:   &now,
		UpdatedAt:   now,
		Metadata:    cloneRuntimeIngestMetadata(metadata),
	}
	if err := store.SaveRun(ctx, run); err != nil {
		return nil, fmt.Errorf("save runtime ingest run: %w", err)
	}
	if _, err := store.AppendEvent(ctx, run.ID, runtime.IngestEvent{
		Type:       "ingest_started",
		RecordedAt: now,
		Data: map[string]any{
			"source":   run.Source,
			"metadata": cloneRuntimeIngestMetadata(metadata),
		},
	}); err != nil {
		return nil, fmt.Errorf("append runtime ingest start event: %w", err)
	}
	return &runtimeIngestSession{store: store, run: run}, nil
}

func (r *runtimeIngestSession) recordObservation(ctx context.Context, observation *runtime.RuntimeObservation, findings int, index int) error {
	if r == nil || r.store == nil || r.run == nil {
		return nil
	}

	processedAt := time.Now().UTC()

	r.run.ObservationCount++
	r.run.FindingCount += findings
	r.run.UpdatedAt = processedAt

	data := map[string]any{
		"index":         index,
		"finding_count": findings,
	}
	if observation != nil {
		if !observation.ObservedAt.IsZero() {
			data["observed_at"] = observation.ObservedAt.UTC().Format(time.RFC3339Nano)
		}
		if observation.ID != "" {
			data["observation_id"] = observation.ID
		}
		if observation.Kind != "" {
			data["kind"] = observation.Kind
		}
		if observation.ResourceID != "" {
			data["resource_id"] = observation.ResourceID
		}
		if observation.ResourceType != "" {
			data["resource_type"] = observation.ResourceType
		}
		if observation.Cluster != "" {
			data["cluster"] = observation.Cluster
		}
		if observation.NodeName != "" {
			data["node_name"] = observation.NodeName
		}
		if observation.WorkloadRef != "" {
			data["workload_ref"] = observation.WorkloadRef
		}
	}

	if err := r.store.SaveRun(ctx, r.run); err != nil {
		return fmt.Errorf("save runtime ingest progress: %w", err)
	}
	if _, err := r.store.AppendEvent(ctx, r.run.ID, runtime.IngestEvent{
		Type:       "observation_processed",
		RecordedAt: processedAt,
		Data:       data,
	}); err != nil {
		return fmt.Errorf("append runtime ingest observation event: %w", err)
	}
	return nil
}

func (r *runtimeIngestSession) complete(ctx context.Context, checkpoint runtime.IngestCheckpoint) error {
	if r == nil || r.store == nil || r.run == nil {
		return nil
	}

	completedAt := time.Now().UTC()
	if checkpoint.RecordedAt.IsZero() {
		checkpoint.RecordedAt = completedAt
	}
	if checkpoint.Cursor == "" {
		checkpoint.Cursor = "observations:" + strconv.Itoa(r.run.ObservationCount)
	}
	if _, err := r.store.SaveCheckpoint(ctx, r.run.ID, checkpoint); err != nil {
		return fmt.Errorf("save runtime ingest checkpoint: %w", err)
	}

	updated, err := r.store.LoadRun(ctx, r.run.ID)
	if err != nil {
		return fmt.Errorf("reload runtime ingest run: %w", err)
	}
	if updated == nil {
		return fmt.Errorf("reload runtime ingest run: missing run after checkpoint save")
	}
	r.run = updated
	r.run.Status = runtime.IngestRunStatusCompleted
	r.run.Stage = "completed"
	r.run.CompletedAt = &completedAt
	r.run.UpdatedAt = completedAt
	if err := r.store.SaveRun(ctx, r.run); err != nil {
		return fmt.Errorf("save completed runtime ingest run: %w", err)
	}
	if _, err := r.store.AppendEvent(ctx, r.run.ID, runtime.IngestEvent{
		Type:       "ingest_completed",
		RecordedAt: completedAt,
		Data: map[string]any{
			"observations": r.run.ObservationCount,
			"findings":     r.run.FindingCount,
		},
	}); err != nil {
		return fmt.Errorf("append runtime ingest completed event: %w", err)
	}
	return nil
}

func (r *runtimeIngestSession) fail(ctx context.Context, stage string, runErr error) {
	if r == nil || r.store == nil || r.run == nil {
		return
	}
	failedAt := time.Now().UTC()
	r.run.Status = runtime.IngestRunStatusFailed
	r.run.Stage = strings.TrimSpace(stage)
	r.run.Error = strings.TrimSpace(errorString(runErr))
	r.run.CompletedAt = &failedAt
	r.run.UpdatedAt = failedAt
	_ = r.store.SaveRun(ctx, r.run)
	_, _ = r.store.AppendEvent(ctx, r.run.ID, runtime.IngestEvent{
		Type:       "ingest_failed",
		RecordedAt: failedAt,
		Data: map[string]any{
			"stage": r.run.Stage,
			"error": r.run.Error,
		},
	})
}

func cloneRuntimeIngestMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if trimmedKey := strings.TrimSpace(key); trimmedKey != "" {
			cloned[trimmedKey] = strings.TrimSpace(value)
		}
	}
	if len(cloned) == 0 {
		return nil
	}
	return cloned
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func enrichRuntimeObservation(observation *runtime.RuntimeObservation, cluster, node, agentVersion string) *runtime.RuntimeObservation {
	if observation == nil {
		return nil
	}
	if observation.Metadata == nil {
		observation.Metadata = make(map[string]any)
	}
	cluster = strings.TrimSpace(cluster)
	node = strings.TrimSpace(node)
	agentVersion = strings.TrimSpace(agentVersion)
	if observation.Cluster == "" && cluster != "" {
		observation.Cluster = cluster
	}
	if observation.NodeName == "" && node != "" {
		observation.NodeName = node
	}
	if observation.Cluster != "" {
		observation.Metadata["cluster"] = observation.Cluster
	}
	if observation.NodeName != "" {
		observation.Metadata["node_name"] = observation.NodeName
	}
	if agentVersion != "" {
		observation.Metadata["agent_version"] = agentVersion
	}
	if observation.Namespace == "" && observation.Container != nil {
		observation.Namespace = strings.TrimSpace(observation.Container.Namespace)
	}
	return observation
}

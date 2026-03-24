package forensics

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/workloadscan"
)

const graphMaterializationSourceSystem = "cerebro_forensics"

type GraphMaterializationResult struct {
	CapturesMaterialized  int `json:"captures_materialized"`
	EvidenceMaterialized  int `json:"evidence_materialized"`
	WorkloadNodesUpserted int `json:"workload_nodes_upserted"`
	IncidentNodesUpserted int `json:"incident_nodes_upserted"`
	EvidenceNodesUpserted int `json:"evidence_nodes_upserted"`
	ActionNodesUpserted   int `json:"action_nodes_upserted"`
	EdgesCreated          int `json:"edges_created"`
}

func MaterializeIntoGraph(g *graph.Graph, captures []CaptureRecord, evidence []RemediationEvidenceRecord, now time.Time) GraphMaterializationResult {
	var result GraphMaterializationResult
	if g == nil {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for i := range captures {
		result.merge(materializeCapture(g, captures[i], now))
	}
	for i := range evidence {
		result.merge(materializeEvidence(g, evidence[i], now))
	}
	g.BuildIndex()
	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		meta.BuiltAt = now.UTC()
	}
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
	return result
}

func materializeCapture(g *graph.Graph, record CaptureRecord, now time.Time) GraphMaterializationResult {
	var result GraphMaterializationResult
	if g == nil || strings.TrimSpace(record.ID) == "" {
		return result
	}
	observedAt := record.SubmittedAt.UTC()
	if observedAt.IsZero() {
		observedAt = now.UTC()
	}
	workloadID := ensureWorkloadNode(g, record, observedAt, &result)
	incidentID := ensureIncidentNode(g, record.IncidentID, observedAt, &result)
	evidenceID := captureEvidenceNodeID(record.ID)

	properties := cloneMap(record.Metadata)
	properties["evidence_type"] = "forensic_snapshot"
	properties["detail"] = firstNonEmpty(strings.TrimSpace(record.Reason), "Forensic snapshot capture")
	properties["capture_id"] = record.ID
	properties["capture_status"] = string(record.Status)
	properties["requested_by"] = strings.TrimSpace(record.RequestedBy)
	properties["target_identity"] = record.Target.Identity()
	properties["snapshot_count"] = len(record.Snapshots)
	properties["snapshot_ids"] = snapshotIDs(record.Snapshots)
	properties["retention_days"] = record.RetentionDays
	properties["chain_of_custody"] = custodySteps(record.ChainOfCustody)
	if record.RetainUntil != nil && !record.RetainUntil.IsZero() {
		properties["retention_until"] = record.RetainUntil.UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(record.IncidentID) != "" {
		properties["incident_id"] = strings.TrimSpace(record.IncidentID)
	}
	if strings.TrimSpace(record.Error) != "" {
		properties["capture_error"] = strings.TrimSpace(record.Error)
	}
	applyWriteMetadata(properties, observedAt, fmt.Sprintf("forensic_capture:%s", record.ID))

	g.AddNode(&graph.Node{
		ID:         evidenceID,
		Kind:       graph.NodeKindEvidence,
		Name:       "Forensic Snapshot " + record.ID,
		Provider:   graphMaterializationSourceSystem,
		Properties: properties,
		Risk:       captureRisk(record.Status),
	})
	result.CapturesMaterialized++
	result.EvidenceNodesUpserted++

	if workloadID != "" {
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", evidenceID, workloadID, graph.EdgeKindTargets),
			Source:     evidenceID,
			Target:     workloadID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeWriteProperties(observedAt, fmt.Sprintf("forensic_capture:%s", record.ID)),
		})
		result.EdgesCreated++
	}
	if incidentID != "" {
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", incidentID, evidenceID, graph.EdgeKindBasedOn),
			Source:     incidentID,
			Target:     evidenceID,
			Kind:       graph.EdgeKindBasedOn,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeWriteProperties(observedAt, fmt.Sprintf("forensic_capture:%s", record.ID)),
		})
		result.EdgesCreated++
	}
	return result
}

func materializeEvidence(g *graph.Graph, record RemediationEvidenceRecord, now time.Time) GraphMaterializationResult {
	var result GraphMaterializationResult
	if g == nil || strings.TrimSpace(record.ID) == "" {
		return result
	}
	observedAt := record.CreatedAt.UTC()
	if observedAt.IsZero() {
		observedAt = now.UTC()
	}
	workloadID := strings.TrimSpace(record.WorkloadID)
	incidentID := ensureIncidentNode(g, record.IncidentID, observedAt, &result)
	actionID := remediationActionNodeID(record.ID)
	properties := cloneMap(record.Metadata)
	properties["action_type"] = "remediation_evidence"
	properties["status"] = string(record.Status)
	properties["performed_at"] = observedAt.Format(time.RFC3339)
	properties["actor_id"] = strings.TrimSpace(record.Actor)
	properties["remediation_execution_id"] = strings.TrimSpace(record.RemediationExecutionID)
	properties["action_summary"] = strings.TrimSpace(record.ActionSummary)
	properties["before_capture_id"] = strings.TrimSpace(record.BeforeCaptureID)
	properties["after_capture_id"] = strings.TrimSpace(record.AfterCaptureID)
	properties["notes"] = strings.TrimSpace(record.Notes)
	properties["chain_of_custody"] = custodySteps(record.ChainOfCustody)
	applyWriteMetadata(properties, observedAt, fmt.Sprintf("remediation_evidence:%s", record.ID))

	g.AddNode(&graph.Node{
		ID:         actionID,
		Kind:       graph.NodeKindAction,
		Name:       firstNonEmpty(strings.TrimSpace(record.ActionSummary), "Remediation Evidence"),
		Provider:   graphMaterializationSourceSystem,
		Properties: properties,
	})
	result.EvidenceMaterialized++
	result.ActionNodesUpserted++

	if workloadID != "" {
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", actionID, workloadID, graph.EdgeKindTargets),
			Source:     actionID,
			Target:     workloadID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeWriteProperties(observedAt, fmt.Sprintf("remediation_evidence:%s", record.ID)),
		})
		result.EdgesCreated++
	}
	if incidentID != "" {
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", actionID, incidentID, graph.EdgeKindTargets),
			Source:     actionID,
			Target:     incidentID,
			Kind:       graph.EdgeKindTargets,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeWriteProperties(observedAt, fmt.Sprintf("remediation_evidence:%s", record.ID)),
		})
		result.EdgesCreated++
	}
	for _, captureID := range []string{strings.TrimSpace(record.BeforeCaptureID), strings.TrimSpace(record.AfterCaptureID)} {
		if captureID == "" {
			continue
		}
		evidenceID := captureEvidenceNodeID(captureID)
		g.AddEdge(&graph.Edge{
			ID:         fmt.Sprintf("%s->%s:%s", actionID, evidenceID, graph.EdgeKindBasedOn),
			Source:     actionID,
			Target:     evidenceID,
			Kind:       graph.EdgeKindBasedOn,
			Effect:     graph.EdgeEffectAllow,
			Properties: edgeWriteProperties(observedAt, fmt.Sprintf("remediation_evidence:%s", record.ID)),
		})
		result.EdgesCreated++
	}
	return result
}

func ensureWorkloadNode(g *graph.Graph, record CaptureRecord, observedAt time.Time, result *GraphMaterializationResult) string {
	workloadID := strings.TrimSpace(record.WorkloadID)
	if workloadID == "" {
		workloadID = inferredWorkloadNodeID(record.Target)
	}
	if workloadID == "" {
		return ""
	}
	if node, ok := g.GetNode(workloadID); ok && node != nil {
		return workloadID
	}
	properties := map[string]any{
		"workload_identity": record.Target.Identity(),
		"provider":          string(record.Target.Provider),
		"instance_id":       strings.TrimSpace(record.Target.InstanceID),
		"instance_name":     strings.TrimSpace(record.Target.InstanceName),
		"account_id":        strings.TrimSpace(record.Target.AccountID),
		"project_id":        strings.TrimSpace(record.Target.ProjectID),
		"subscription_id":   strings.TrimSpace(record.Target.SubscriptionID),
	}
	applyWriteMetadata(properties, observedAt, fmt.Sprintf("forensic_workload:%s", workloadID))
	g.AddNode(&graph.Node{
		ID:         workloadID,
		Kind:       graph.NodeKindWorkload,
		Name:       firstNonEmpty(strings.TrimSpace(record.Target.InstanceName), strings.TrimSpace(record.Target.InstanceID), record.Target.Identity(), workloadID),
		Provider:   string(record.Target.Provider),
		Account:    firstNonEmpty(strings.TrimSpace(record.Target.AccountID), strings.TrimSpace(record.Target.ProjectID), strings.TrimSpace(record.Target.SubscriptionID)),
		Region:     strings.TrimSpace(record.Target.Region),
		Properties: properties,
	})
	if result != nil {
		result.WorkloadNodesUpserted++
	}
	return workloadID
}

func ensureIncidentNode(g *graph.Graph, incidentID string, observedAt time.Time, result *GraphMaterializationResult) string {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return ""
	}
	if node, ok := g.GetNode(incidentID); ok && node != nil {
		return incidentID
	}
	properties := map[string]any{
		"incident_id": incidentID,
		"status":      "investigating",
		"severity":    "high",
	}
	applyWriteMetadata(properties, observedAt, fmt.Sprintf("forensic_incident:%s", incidentID))
	g.AddNode(&graph.Node{
		ID:         incidentID,
		Kind:       graph.NodeKindIncident,
		Name:       incidentID,
		Provider:   graphMaterializationSourceSystem,
		Properties: properties,
		Risk:       graph.RiskHigh,
	})
	if result != nil {
		result.IncidentNodesUpserted++
	}
	return incidentID
}

func applyWriteMetadata(properties map[string]any, observedAt time.Time, sourceEventID string) {
	if properties == nil {
		return
	}
	properties["source_system"] = graphMaterializationSourceSystem
	properties["source_event_id"] = strings.TrimSpace(sourceEventID)
	properties["observed_at"] = observedAt.UTC().Format(time.RFC3339)
	properties["valid_from"] = observedAt.UTC().Format(time.RFC3339)
	properties["confidence"] = 1.0
}

func edgeWriteProperties(observedAt time.Time, sourceEventID string) map[string]any {
	properties := map[string]any{}
	applyWriteMetadata(properties, observedAt, sourceEventID)
	return properties
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func captureEvidenceNodeID(captureID string) string {
	return "evidence:forensic_capture:" + strings.TrimSpace(captureID)
}

func remediationActionNodeID(evidenceID string) string {
	return "action:forensics:" + strings.TrimSpace(evidenceID)
}

func snapshotIDs(snapshots []workloadscan.SnapshotArtifact) []string {
	out := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if id := strings.TrimSpace(snapshot.ID); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func custodySteps(events []CustodyEvent) []map[string]any {
	out := make([]map[string]any, 0, len(events))
	for _, event := range events {
		entry := map[string]any{
			"step":        event.Step,
			"actor":       event.Actor,
			"location":    event.Location,
			"detail":      event.Detail,
			"recorded_at": event.RecordedAt.UTC().Format(time.RFC3339),
		}
		if len(event.Metadata) > 0 {
			entry["metadata"] = cloneMap(event.Metadata)
		}
		out = append(out, entry)
	}
	return out
}

func inferredWorkloadNodeID(target workloadscan.VMTarget) string {
	identity := strings.TrimSpace(target.Identity())
	if identity == "" {
		return ""
	}
	provider := strings.TrimSpace(string(target.Provider))
	if provider == "" {
		return "workload:" + identity
	}
	return fmt.Sprintf("workload:%s:%s", provider, identity)
}

func captureRisk(status CaptureStatus) graph.RiskLevel {
	switch status {
	case CaptureStatusFailed:
		return graph.RiskHigh
	case CaptureStatusPartial:
		return graph.RiskMedium
	default:
		return graph.RiskLow
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (r *GraphMaterializationResult) merge(other GraphMaterializationResult) {
	if r == nil {
		return
	}
	r.CapturesMaterialized += other.CapturesMaterialized
	r.EvidenceMaterialized += other.EvidenceMaterialized
	r.WorkloadNodesUpserted += other.WorkloadNodesUpserted
	r.IncidentNodesUpserted += other.IncidentNodesUpserted
	r.EvidenceNodesUpserted += other.EvidenceNodesUpserted
	r.ActionNodesUpserted += other.ActionNodesUpserted
	r.EdgesCreated += other.EdgesCreated
}

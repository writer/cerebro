// Package grcauditpacket owns immutable audit packet identity, references,
// canonical digesting, and state-store persistence.
package grcauditpacket

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grcaudit"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/grcfindings"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const SchemaVersion = "grc.audit-packet.v1"

type Packet struct {
	ID                 string                       `json:"id"`
	SchemaVersion      string                       `json:"schema_version,omitempty"`
	ResourceState      string                       `json:"resource_state"`
	Digest             string                       `json:"digest,omitempty"`
	TenantID           string                       `json:"tenant_id,omitempty"`
	FindingReference   FindingReference             `json:"finding_reference,omitempty"`
	EvidenceReferences []EvidenceReference          `json:"evidence_references,omitempty"`
	ControlReferences  []ControlReference           `json:"control_references,omitempty"`
	GraphReferences    GraphReferences              `json:"graph_references,omitempty"`
	SourceRuntimes     []SourceRuntimeReference     `json:"source_runtimes,omitempty"`
	Gaps               []Gap                        `json:"gaps"`
	ReviewState        string                       `json:"review_state,omitempty"`
	ExportState        string                       `json:"export_state,omitempty"`
	Supersedes         []string                     `json:"supersedes"`
	Finding            grcfindings.FindingItem      `json:"finding"`
	Evidence           []grcfindings.EvidenceItem   `json:"evidence"`
	Graph              *ports.EntityNeighborhood    `json:"graph,omitempty"`
	Controls           []grcfindings.ControlRef     `json:"controls,omitempty"`
	RecommendedAction  string                       `json:"recommended_action"`
	Metadata           grccontrol.ReportMetadata    `json:"metadata"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	FindingRecord      *ports.FindingRecord         `json:"-"`
	EvidenceRecords    []*cerebrov1.FindingEvidence `json:"-"`
	RuntimeRecords     []*cerebrov1.SourceRuntime   `json:"-"`
}

type FindingReference struct {
	ID             string    `json:"id"`
	Fingerprint    string    `json:"fingerprint,omitempty"`
	Status         string    `json:"status"`
	StatusRevision time.Time `json:"status_revision"`
}

type EvidenceReference struct {
	ID                string   `json:"id"`
	EvaluationRunIDs  []string `json:"evaluation_run_ids"`
	ObservationRunIDs []string `json:"observation_run_ids"`
	ClaimIDs          []string `json:"claim_ids,omitempty"`
	EventIDs          []string `json:"event_ids,omitempty"`
	GraphRootURNs     []string `json:"graph_root_urns,omitempty"`
	GraphPathURNs     []string `json:"graph_path_urns,omitempty"`
}

type ControlReference struct {
	FrameworkID      string `json:"framework_id"`
	ControlID        string `json:"control_id"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	ProfileID        string `json:"profile_id,omitempty"`
	ProfileVersion   string `json:"profile_version,omitempty"`
}

type GraphReferences struct {
	RootURNs             []string  `json:"root_urns"`
	PathURNs             []string  `json:"path_urns"`
	FactRefs             []string  `json:"fact_refs"`
	ObservationWatermark time.Time `json:"observation_watermark,omitempty"`
}

type SourceRuntimeReference struct {
	ID                  string    `json:"id"`
	SourceID            string    `json:"source_id"`
	FreshnessState      string    `json:"freshness_state"`
	CompletenessState   string    `json:"completeness_state"`
	LastSyncedAt        time.Time `json:"last_synced_at,omitempty"`
	CheckpointWatermark time.Time `json:"checkpoint_watermark,omitempty"`
}

type Gap struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Freeze(ctx context.Context, store ports.GRCAuditPacketStore, preview Packet, supersedes []string, tenantAllowed func(string) bool) (Packet, error) {
	if store == nil || preview.FindingRecord == nil {
		return Packet{}, fmt.Errorf("GRC audit packet store and finding snapshot are required")
	}
	supersedes = NormalizeStrings(supersedes)
	for _, packetID := range supersedes {
		receipt, err := store.GetGRCAuditPacket(ctx, packetID)
		if err != nil || receipt.TenantID != preview.FindingRecord.TenantID || (tenantAllowed != nil && !tenantAllowed(receipt.TenantID)) {
			return Packet{}, ports.ErrGRCAuditPacketNotFound
		}
	}
	packetID, err := newID()
	if err != nil {
		return Packet{}, err
	}
	packet := preview
	packet.ID, packet.SchemaVersion, packet.ResourceState = packetID, SchemaVersion, "immutable"
	packet.TenantID = preview.FindingRecord.TenantID
	packet.FindingReference = findingReference(preview.FindingRecord)
	packet.EvidenceReferences, packet.GraphReferences = evidenceReferences(preview.EvidenceRecords, preview.FindingRecord.LastObservedAt)
	packet.ControlReferences = controlReferences(packet.Controls, packet.Metadata)
	packet.SourceRuntimes = sourceRuntimeReferences(preview.RuntimeRecords)
	packet.Graph = nil
	packet.Gaps = gaps(preview, packet)
	packet.ReviewState, packet.ExportState, packet.Supersedes = "unreviewed", "ready", supersedes
	packet.FindingRecord, packet.EvidenceRecords, packet.RuntimeRecords = nil, nil, nil
	packet.Digest, err = Digest(packet)
	if err != nil {
		return Packet{}, err
	}
	return packet, nil
}

// RecordedEvent returns the append-first compliance event used to rebuild the
// immutable receipt projection in Postgres.
func RecordedEvent(packet Packet) (*cerebrov1.EventEnvelope, error) {
	if err := Verify(packet); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		return nil, fmt.Errorf("marshal GRC audit packet event: %w", err)
	}
	return workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceAuditPackageRecorded, TenantID: packet.TenantID,
		AggregateType: grcaudit.AuditAggregatePacketReceipt, AggregateID: packet.ID,
		AggregateVersion: 1, Operation: "recorded", ContentDigest: packet.Digest,
		PayloadJSON: string(payload), RecordedAt: packet.GeneratedAt.UTC().Format(time.RFC3339Nano),
	})
}

func Verify(packet Packet) error {
	if packet.ID == "" || packet.TenantID == "" || packet.FindingReference.ID == "" || packet.SchemaVersion != SchemaVersion || packet.ResourceState != "immutable" || packet.GeneratedAt.IsZero() {
		return fmt.Errorf("invalid GRC audit packet receipt")
	}
	digest, err := Digest(packet)
	if err != nil {
		return err
	}
	if packet.Digest == "" || packet.Digest != digest {
		return fmt.Errorf("GRC audit packet digest verification failed")
	}
	return nil
}

func Load(ctx context.Context, store ports.GRCAuditPacketStore, packetID string, tenantAllowed func(string) bool) (Packet, error) {
	receipt, err := store.GetGRCAuditPacket(ctx, strings.TrimSpace(packetID))
	if err != nil {
		return Packet{}, err
	}
	if tenantAllowed != nil && !tenantAllowed(receipt.TenantID) {
		return Packet{}, ports.ErrGRCAuditPacketNotFound
	}
	packet := Packet{}
	if err := json.Unmarshal(receipt.Payload, &packet); err != nil {
		return Packet{}, fmt.Errorf("decode GRC audit packet %q: %w", packetID, err)
	}
	if packet.ID != receipt.ID || packet.TenantID != receipt.TenantID || packet.Digest != receipt.Digest {
		return Packet{}, fmt.Errorf("GRC audit packet %q envelope does not match stored payload", packetID)
	}
	if err := Verify(packet); err != nil {
		return Packet{}, fmt.Errorf("GRC audit packet %q: %w", packetID, err)
	}
	return packet, nil
}

func Digest(packet Packet) (string, error) {
	packet.Digest = ""
	payload, err := json.Marshal(packet)
	if err != nil {
		return "", fmt.Errorf("marshal GRC audit packet digest payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate GRC audit packet id: %w", err)
	}
	return "audit-packet-" + hex.EncodeToString(value[:]), nil
}

func findingReference(finding *ports.FindingRecord) FindingReference {
	return FindingReference{ID: finding.ID, Fingerprint: finding.Fingerprint, Status: finding.Status, StatusRevision: finding.StatusUpdatedAt.UTC()}
}

func evidenceReferences(evidence []*cerebrov1.FindingEvidence, findingWatermark time.Time) ([]EvidenceReference, GraphReferences) {
	refs := make([]EvidenceReference, 0, len(evidence))
	graph := GraphReferences{RootURNs: []string{}, PathURNs: []string{}, FactRefs: []string{}, ObservationWatermark: findingWatermark.UTC()}
	for _, item := range evidence {
		if item == nil {
			continue
		}
		observationRuns := []string{}
		for _, observation := range item.GetObservations() {
			observationRuns = append(observationRuns, observation.GetRunId())
			if at := observation.GetObservedAt(); at != nil && at.AsTime().After(graph.ObservationWatermark) {
				graph.ObservationWatermark = at.AsTime().UTC()
			}
		}
		if at := item.GetLastObservedAt(); at != nil && at.AsTime().After(graph.ObservationWatermark) {
			graph.ObservationWatermark = at.AsTime().UTC()
		}
		roots, paths := NormalizeStrings(item.GetGraphRootUrns()), NormalizeStrings(item.GetGraphPathUrns())
		for _, row := range item.GetGraphRows() {
			if ref := graphFactRef(row); ref != "" {
				graph.FactRefs = append(graph.FactRefs, ref)
			}
		}
		for _, observation := range item.GetObservations() {
			for _, row := range observation.GetGraphRows() {
				if ref := graphFactRef(row); ref != "" {
					graph.FactRefs = append(graph.FactRefs, ref)
				}
			}
		}
		refs = append(refs, EvidenceReference{
			ID: item.GetId(), EvaluationRunIDs: NormalizeStrings(append([]string{item.GetRunId()}, item.GetRunIds()...)), ObservationRunIDs: NormalizeStrings(observationRuns),
			ClaimIDs: NormalizeStrings(item.GetClaimIds()), EventIDs: NormalizeStrings(item.GetEventIds()), GraphRootURNs: roots, GraphPathURNs: paths,
		})
		graph.RootURNs, graph.PathURNs = append(graph.RootURNs, roots...), append(graph.PathURNs, paths...)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	graph.RootURNs, graph.PathURNs, graph.FactRefs = NormalizeStrings(graph.RootURNs), NormalizeStrings(graph.PathURNs), NormalizeStrings(graph.FactRefs)
	return refs, graph
}

func graphFactRef(row *cerebrov1.GraphEvidenceRow) string {
	if row == nil {
		return ""
	}
	if factID := strings.TrimSpace(row.GetAttributes()["fact_id"]); factID != "" {
		return factID
	}
	payload, err := json.Marshal(row)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "graph-row:sha256:" + hex.EncodeToString(sum[:])
}

func controlReferences(controls []grcfindings.ControlRef, metadata grccontrol.ReportMetadata) []ControlReference {
	refs := make([]ControlReference, 0, len(controls))
	for _, control := range controls {
		refs = append(refs, ControlReference{
			FrameworkID: control.FrameworkName, ControlID: control.ControlID,
			ProfileID: metadata.Provenance.ProfileID, ProfileVersion: metadata.Provenance.PacketVersion,
		})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].FrameworkID == refs[j].FrameworkID {
			return refs[i].ControlID < refs[j].ControlID
		}
		return refs[i].FrameworkID < refs[j].FrameworkID
	})
	return refs
}

func sourceRuntimeReferences(runtimes []*cerebrov1.SourceRuntime) []SourceRuntimeReference {
	refs := make([]SourceRuntimeReference, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		ref := SourceRuntimeReference{ID: runtime.GetId(), SourceID: runtime.GetSourceId(), FreshnessState: "never_synced", CompletenessState: "unknown"}
		if at := runtime.GetLastSyncedAt(); at != nil {
			ref.LastSyncedAt, ref.FreshnessState = at.AsTime().UTC(), "observed"
		}
		if checkpoint := runtime.GetCheckpoint(); checkpoint != nil && checkpoint.GetWatermark() != nil {
			ref.CheckpointWatermark = checkpoint.GetWatermark().AsTime().UTC()
			ref.CompletenessState = "complete"
		}
		if cursor := runtime.GetNextCursor(); cursor != nil && strings.TrimSpace(cursor.GetOpaque()) != "" {
			ref.CompletenessState = "partial"
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	return refs
}

func gaps(preview Packet, packet Packet) []Gap {
	result := append([]Gap(nil), preview.Gaps...)
	if strings.TrimSpace(packet.FindingReference.Fingerprint) == "" {
		result = append(result, Gap{Code: "finding_fingerprint_unavailable", Message: "The finding had no durable fingerprint when this packet was created."})
	}
	if packet.FindingReference.StatusRevision.IsZero() {
		result = append(result, Gap{Code: "finding_status_revision_unavailable", Message: "The finding had no status revision timestamp when this packet was created."})
	}
	if preview.Graph == nil {
		result = append(result, Gap{Code: "graph_context_unavailable", Message: "No graph neighborhood was available when this packet was created; the receipt contains only cited graph roots and paths."})
	}
	for _, control := range packet.ControlReferences {
		if control.FrameworkVersion == "" {
			result = append(result, Gap{Code: "framework_version_unavailable", Message: "Framework " + control.FrameworkID + " had no version reference when this packet was created."})
		}
		if control.ProfileVersion == "" {
			result = append(result, Gap{Code: "profile_version_unavailable", Message: "Control " + control.ControlID + " had no profile version when this packet was created."})
		}
	}
	if len(packet.EvidenceReferences) == 0 {
		result = append(result, Gap{Code: "evidence_unavailable", Message: "No evidence records were available when this packet was created."})
	}
	for _, evidence := range packet.EvidenceReferences {
		if len(evidence.EvaluationRunIDs) == 0 {
			result = append(result, Gap{Code: "evaluation_run_unavailable", Message: "Evidence " + evidence.ID + " had no evaluation run reference."})
		}
		if len(evidence.ObservationRunIDs) == 0 {
			result = append(result, Gap{Code: "observation_run_unavailable", Message: "Evidence " + evidence.ID + " had no observation run reference."})
		}
	}
	if packet.GraphReferences.ObservationWatermark.IsZero() {
		result = append(result, Gap{Code: "graph_observation_watermark_unavailable", Message: "No graph observation watermark was available when this packet was created."})
	}
	if len(packet.GraphReferences.FactRefs) == 0 && (len(packet.GraphReferences.RootURNs) != 0 || len(packet.GraphReferences.PathURNs) != 0) {
		result = append(result, Gap{Code: "graph_fact_refs_unavailable", Message: "Graph roots or paths were captured without graph fact references."})
	}
	for _, runtime := range packet.SourceRuntimes {
		if runtime.CheckpointWatermark.IsZero() {
			result = append(result, Gap{Code: "source_checkpoint_unavailable", Message: "Source runtime " + runtime.ID + " had no checkpoint watermark when this packet was created."})
		}
	}
	return result
}

func NormalizeStrings(values []string) []string {
	seen, result := map[string]struct{}{}, []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, ok := seen[value]; value == "" || ok {
			continue
		}
		seen[value], result = struct{}{}, append(result, value)
	}
	sort.Strings(result)
	return result
}

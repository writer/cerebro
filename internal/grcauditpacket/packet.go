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
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/grcfindings"
	"github.com/writer/cerebro/internal/ports"
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

type GraphReferences struct {
	RootURNs             []string  `json:"root_urns"`
	PathURNs             []string  `json:"path_urns"`
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
	packet.SourceRuntimes = sourceRuntimeReferences(preview.RuntimeRecords)
	packet.Graph = nil
	packet.Gaps = gaps(preview, packet)
	packet.ReviewState, packet.ExportState, packet.Supersedes = "unreviewed", "ready", supersedes
	packet.FindingRecord, packet.EvidenceRecords, packet.RuntimeRecords = nil, nil, nil
	packet.Digest, err = Digest(packet)
	if err != nil {
		return Packet{}, err
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		return Packet{}, fmt.Errorf("marshal GRC audit packet: %w", err)
	}
	err = store.PutGRCAuditPacket(ctx, &ports.GRCAuditPacketReceipt{
		ID: packet.ID, TenantID: packet.TenantID, FindingID: packet.FindingReference.ID,
		Digest: packet.Digest, Payload: payload, CreatedAt: packet.GeneratedAt,
	})
	return packet, err
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
	digest, err := Digest(packet)
	if err != nil || digest != packet.Digest {
		return Packet{}, fmt.Errorf("GRC audit packet %q digest verification failed", packetID)
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
	revision := finding.StatusUpdatedAt
	if revision.IsZero() {
		revision = finding.LastObservedAt
	}
	return FindingReference{ID: finding.ID, Fingerprint: finding.Fingerprint, Status: finding.Status, StatusRevision: revision.UTC()}
}

func evidenceReferences(evidence []*cerebrov1.FindingEvidence, findingWatermark time.Time) ([]EvidenceReference, GraphReferences) {
	refs := make([]EvidenceReference, 0, len(evidence))
	graph := GraphReferences{RootURNs: []string{}, PathURNs: []string{}, ObservationWatermark: findingWatermark.UTC()}
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
		refs = append(refs, EvidenceReference{
			ID: item.GetId(), EvaluationRunIDs: NormalizeStrings(append([]string{item.GetRunId()}, item.GetRunIds()...)), ObservationRunIDs: NormalizeStrings(observationRuns),
			ClaimIDs: NormalizeStrings(item.GetClaimIds()), EventIDs: NormalizeStrings(item.GetEventIds()), GraphRootURNs: roots, GraphPathURNs: paths,
		})
		graph.RootURNs, graph.PathURNs = append(graph.RootURNs, roots...), append(graph.PathURNs, paths...)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	graph.RootURNs, graph.PathURNs = NormalizeStrings(graph.RootURNs), NormalizeStrings(graph.PathURNs)
	return refs, graph
}

func sourceRuntimeReferences(runtimes []*cerebrov1.SourceRuntime) []SourceRuntimeReference {
	refs := make([]SourceRuntimeReference, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		ref := SourceRuntimeReference{ID: runtime.GetId(), SourceID: runtime.GetSourceId(), FreshnessState: "never_synced", CompletenessState: "complete"}
		if at := runtime.GetLastSyncedAt(); at != nil {
			ref.LastSyncedAt, ref.FreshnessState = at.AsTime().UTC(), "observed"
		}
		if checkpoint := runtime.GetCheckpoint(); checkpoint != nil && checkpoint.GetWatermark() != nil {
			ref.CheckpointWatermark = checkpoint.GetWatermark().AsTime().UTC()
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
	result := []Gap{}
	if preview.Graph == nil {
		result = append(result, Gap{Code: "graph_context_unavailable", Message: "No graph neighborhood was available when this packet was created; the receipt contains only cited graph roots and paths."})
	}
	if len(packet.Controls) != 0 && packet.Metadata.Provenance.PacketVersion == "" {
		result = append(result, Gap{Code: "control_version_unavailable", Message: "The finding carried control identifiers without a versioned control profile."})
	}
	if len(packet.EvidenceReferences) == 0 {
		result = append(result, Gap{Code: "evidence_unavailable", Message: "No evidence records were available when this packet was created."})
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

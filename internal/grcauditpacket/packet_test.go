package grcauditpacket

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/grcfindings"
	"github.com/writer/cerebro/internal/ports"
)

func TestPacketReferencesAndGapsPreserveUnavailableHistory(t *testing.T) {
	t.Parallel()
	evidence := []*cerebrov1.FindingEvidence{{
		Id: "evidence-one", GraphRootUrns: []string{"root-one"}, GraphPathUrns: []string{"path-one"},
		GraphRows: []*cerebrov1.GraphEvidenceRow{{Attributes: map[string]string{"fact_id": "fact-one"}}},
	}}
	evidenceRefs, graphRefs := evidenceReferences(evidence, time.Time{})
	if len(evidenceRefs) != 1 || len(graphRefs.FactRefs) != 1 || graphRefs.FactRefs[0] != "fact-one" {
		t.Fatalf("evidence refs = %#v graph refs = %#v", evidenceRefs, graphRefs)
	}
	packet := Packet{
		FindingReference:   FindingReference{ID: "finding-one", Status: "open"},
		EvidenceReferences: evidenceRefs, GraphReferences: graphRefs,
		ControlReferences: controlReferences([]grcfindings.ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}}, grccontrol.ReportMetadata{}),
		SourceRuntimes:    sourceRuntimeReferences([]*cerebrov1.SourceRuntime{{Id: "runtime-one", SourceId: "okta"}}),
	}
	packet.Gaps = gaps(Packet{}, packet)
	for _, code := range []string{
		"finding_fingerprint_unavailable", "finding_status_revision_unavailable",
		"framework_version_unavailable", "profile_version_unavailable",
		"evaluation_run_unavailable", "observation_run_unavailable",
		"graph_observation_watermark_unavailable", "source_checkpoint_unavailable",
	} {
		if !hasGap(packet.Gaps, code) {
			t.Fatalf("gaps = %#v, want %q", packet.Gaps, code)
		}
	}
	if got := packet.SourceRuntimes[0].CompletenessState; got != "unknown" {
		t.Fatalf("completeness = %q, want unknown without checkpoint", got)
	}
}

func TestFindingReferenceDoesNotSubstituteObservationTimeForStatusRevision(t *testing.T) {
	t.Parallel()
	reference := findingReference(&ports.FindingRecord{
		ID: "finding-one", Status: "open", LastObservedAt: time.Date(2026, time.July, 14, 8, 0, 0, 0, time.UTC),
	})
	if !reference.StatusRevision.IsZero() {
		t.Fatalf("status revision = %v, want unavailable when status_updated_at is absent", reference.StatusRevision)
	}
	packet := Packet{FindingReference: reference}
	if got := gaps(Packet{}, packet); !hasGap(got, "finding_status_revision_unavailable") {
		t.Fatalf("gaps = %#v, want finding_status_revision_unavailable", got)
	}
}

func hasGap(gaps []Gap, code string) bool {
	for _, gap := range gaps {
		if gap.Code == code {
			return true
		}
	}
	return false
}

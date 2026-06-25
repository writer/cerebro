package evidencepackets

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBuildUsesStableFrameworkIDAndRuleScopedTestResults(t *testing.T) {
	observedAt := time.Unix(90, 0).UTC()
	response := Build(grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "security-core", Name: "Security Core"},
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: time.Unix(100, 0).UTC(),
			Controls: []compliance.ControlEvidencePacketControl{{
				Control: compliance.ControlPostureControl{FrameworkName: "SOC 2", ControlID: "CC6.1"},
				Evidence: compliance.ControlEvidencePacketEvidence{
					Expectations: []compliance.ControlEvidenceExpectationPosture{{
						ID:          "automated-proof",
						Status:      compliance.ControlEvidenceExpectationSatisfied,
						Quality:     compliance.ControlEvidenceQualityStrong,
						Reason:      "request evidence is current",
						EvidenceIDs: []string{"ev-1"},
					}},
					Items: []compliance.ControlEvidencePacketEvidenceItem{{
						ID:           "ev-1",
						RuleID:       "rule.fail",
						EvidenceType: "finding_evidence",
						Quality:      compliance.ControlEvidenceQualityStrong,
						Reason:       "packet evidence is current",
						ObservedAt:   observedAt,
					}},
				},
				Overrides: compliance.ControlPostureOverrides{ExceptionIDs: []string{"risk accepted"}},
			}},
		},
		Controls: []grccontrol.ControlItem{{
			FrameworkName: "SOC 2",
			FrameworkID:   "soc2",
			ControlID:     "CC6.1",
			Status:        "needs_attention",
			MappedRules:   []string{"rule.pass", "rule.fail"},
			Findings:      []grccontrol.FindingItem{{RuleID: "rule.fail", Status: "open"}},
		}},
		Evidence: []*cerebrov1.FindingEvidence{{
			Id:             "ev-1",
			RuntimeId:      "runtime-1",
			FindingId:      "finding-1",
			RuleId:         "rule.fail",
			RunId:          "run-1",
			ClaimIds:       []string{"claim-1"},
			EventIds:       []string{"event-1"},
			GraphRootUrns:  []string{"urn:cerebro:test:identity:admin"},
			LastObservedAt: timestamppb.New(observedAt),
		}},
		Runtimes: []*cerebrov1.SourceRuntime{{
			Id:           "runtime-1",
			SourceId:     "source-1",
			TenantId:     "tenant-1",
			LastSyncedAt: timestamppb.New(observedAt),
		}},
		SourceIDs: map[string]string{"runtime-1": "source-1"},
		Metadata: grccontrol.ReportMetadata{
			Readiness: grccontrol.ReportReadiness{Status: "needs_attention"},
			Scope: grccontrol.ReportScope{
				SourceIDs:  []string{"source-1"},
				RuntimeIDs: []string{"runtime-1"},
				IncrementalFetch: grccontrol.ReportIncrementalFetch{
					Status:                  "all_collected",
					PolicyAppliedBeforeRead: true,
				},
			},
			Provenance: grccontrol.ReportProvenance{ProfileID: "security-core"},
			Redaction:  grccontrol.ReportRedaction{DefaultMode: "share_safe"},
		},
	})

	if len(response.Controls) != 1 {
		t.Fatalf("controls = %d, want 1", len(response.Controls))
	}
	control := response.Controls[0]
	if control.FrameworkID != "soc2" {
		t.Fatalf("framework_id = %q, want stable framework id", control.FrameworkID)
	}
	results := map[string]string{}
	for _, result := range control.TestResults {
		results[result.RuleID] = result.Result
	}
	if results["rule.pass"] != "pass" || results["rule.fail"] != "fail" {
		t.Fatalf("test results = %#v, want per-rule pass/fail results", results)
	}
	if len(response.Sources) != 1 || response.Sources[0].Status != "collected" {
		t.Fatalf("sources = %#v, want collected source runtime", response.Sources)
	}
	if len(response.Items) != 1 || len(response.Lineage) != 1 || len(response.Resources) != 1 {
		t.Fatalf("expanded records items=%d lineage=%d resources=%d, want raw evidence records", len(response.Items), len(response.Lineage), len(response.Resources))
	}
	if response.Items[0].PacketIDs[0] == "" || response.Lineage[0].PacketIDs[0] == "" {
		t.Fatalf("lineage links item=%#v lineage=%#v, want packet links", response.Items[0], response.Lineage[0])
	}
	if len(control.ExceptionIDs) != 1 || len(response.Exceptions) != 1 || control.ExceptionIDs[0] != response.Exceptions[0].ID {
		t.Fatalf("exception links control=%#v exceptions=%#v, want stable exception cross-reference", control.ExceptionIDs, response.Exceptions)
	}
	reviewReasons := map[string]string{}
	for _, review := range response.Reviews {
		reviewReasons[review.SubjectID] = review.Reason
	}
	if reviewReasons[response.Requests[0].ID] != "request evidence is current" {
		t.Fatalf("request review reason = %q, want expectation reason", reviewReasons[response.Requests[0].ID])
	}
	if reviewReasons[response.Packets[0].ID] != "packet evidence is current" {
		t.Fatalf("packet review reason = %q, want evidence item reason", reviewReasons[response.Packets[0].ID])
	}
}

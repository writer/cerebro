package evidencepackets

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
)

func TestBuildUsesStableFrameworkIDAndRuleScopedTestResults(t *testing.T) {
	response := Build(grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "security-core", Name: "Security Core"},
		Packet: compliance.ControlEvidencePacket{
			GeneratedAt: time.Unix(100, 0).UTC(),
			Controls: []compliance.ControlEvidencePacketControl{{
				Control: compliance.ControlPostureControl{FrameworkName: "SOC 2", ControlID: "CC6.1"},
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
		Metadata: grccontrol.ReportMetadata{
			Readiness: grccontrol.ReportReadiness{Status: "needs_attention"},
			Redaction: grccontrol.ReportRedaction{DefaultMode: "share_safe"},
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
}

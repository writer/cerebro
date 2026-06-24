package grcprogram

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
)

func TestBuildTreatsStaleEvidenceAsNeedsReview(t *testing.T) {
	result := grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "soc2-security-core", Name: "SOC 2 Security"},
		Controls: []grccontrol.ControlItem{{
			FrameworkName: "SOC 2",
			ControlID:     "CC6.1",
			Title:         "Logical access",
			Status:        "passing",
			EvidenceScore: 95,
			StaleEvidence: 1,
		}},
		Metadata: grccontrol.ReportMetadata{
			Readiness:  grccontrol.ReportReadiness{},
			Provenance: grccontrol.ReportProvenance{EvidenceCount: 1},
		},
	}
	readiness := Build(BuildInput{
		Result:      result,
		Query:       url.Values{"profile": []string{"soc2-security-core"}},
		GeneratedAt: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC),
	})

	if readiness.Summary.Status != "needs_review" {
		t.Fatalf("summary status = %q, want needs_review", readiness.Summary.Status)
	}
	if readiness.Summary.Score != 95 || readiness.ProofBundle.Score != readiness.Summary.Score {
		t.Fatalf("scores = summary %d proof %d, want matching fallback score 95", readiness.Summary.Score, readiness.ProofBundle.Score)
	}
	if readiness.ProofBundle.Status != readiness.Summary.Status {
		t.Fatalf("proof status = %q, want summary status %q", readiness.ProofBundle.Status, readiness.Summary.Status)
	}
	if len(readiness.Frameworks) != 1 || readiness.Frameworks[0].Status != "needs_review" {
		t.Fatalf("frameworks = %+v, want needs_review rollup", readiness.Frameworks)
	}
	if len(readiness.Controls) != 1 || !strings.HasPrefix(readiness.Controls[0].Href, "/grc/controls?") {
		t.Fatalf("control href = %+v, want /grc/controls API path", readiness.Controls)
	}
	if len(readiness.WorkItems) != 1 || readiness.WorkItems[0].Action != "Refresh stale evidence" {
		t.Fatalf("work items = %+v, want stale evidence work item", readiness.WorkItems)
	}
}

func TestBuildDistinguishesExceptionsAndNotApplicableControls(t *testing.T) {
	result := grccontrol.PacketResult{
		Profile: grccontrol.Profile{ID: "soc2-security-core", Name: "SOC 2 Security"},
		Controls: []grccontrol.ControlItem{
			{
				FrameworkName: "SOC 2",
				ControlID:     "CC6.1",
				Title:         "Logical access",
				Status:        string(compliance.ControlPostureNotApplicable),
			},
			{
				FrameworkName: "ISO 27001",
				ControlID:     "A.5.1",
				Title:         "Exception-managed control",
				Status:        string(compliance.ControlPostureException),
			},
		},
	}
	readiness := Build(BuildInput{Result: result, GeneratedAt: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)})

	if readiness.Summary.ManualReviewControls != 0 {
		t.Fatalf("manual review controls = %d, want 0", readiness.Summary.ManualReviewControls)
	}
	if readiness.Summary.PassingControls != 1 {
		t.Fatalf("passing controls = %d, want not-applicable control counted as passing", readiness.Summary.PassingControls)
	}
	if len(readiness.WorkItems) != 1 || readiness.WorkItems[0].ControlID != "A.5.1" || readiness.WorkItems[0].Action == "Complete manual assessment" {
		t.Fatalf("work items = %+v, want only exception follow-up and no manual assessment", readiness.WorkItems)
	}
	frameworkStatus := map[string]string{}
	for _, framework := range readiness.Frameworks {
		frameworkStatus[framework.FrameworkName] = framework.Status
	}
	if frameworkStatus["SOC 2"] != "ready" || frameworkStatus["ISO 27001"] != "needs_review" {
		t.Fatalf("framework statuses = %+v, want not-applicable ready and exception needs_review", frameworkStatus)
	}
}

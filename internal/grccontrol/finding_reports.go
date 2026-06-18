package grccontrol

import (
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/resourcescope"
)

type FindingAuditReadinessInput struct {
	Owner          string
	ControlCount   int
	EvidenceCount  int
	HasImpactProof bool
}

type FindingAuditMarkdownInput struct {
	Finding           FindingAuditMarkdownFinding
	Controls          []ControlRef
	Evidence          []FindingAuditMarkdownEvidence
	RecommendedAction string
	Metadata          ReportMetadata
	GeneratedAt       time.Time
}

type FindingAuditMarkdownFinding struct {
	ID        string
	Title     string
	Severity  string
	Status    string
	Summary   string
	RiskScore int
	Owner     string
	SLAStatus string
}

type FindingAuditMarkdownEvidence struct {
	ID        string
	RuleID    string
	CreatedAt time.Time
}

func BuildFindingAuditReadiness(input FindingAuditReadinessInput) ReportReadiness {
	readiness := ReportReadiness{
		Status:  "ready",
		Score:   100,
		Summary: "Finding packet has owner, controls, evidence, and impact proof.",
	}
	addBlocker := func(code string, label string, count int, penalty int) {
		if count <= 0 {
			return
		}
		readiness.Blockers = append(readiness.Blockers, ReportReadinessBlocker{Code: code, Label: label, Count: count})
		readiness.Score -= penalty
	}
	if strings.TrimSpace(input.Owner) == "" || strings.EqualFold(input.Owner, "Unassigned") {
		addBlocker("missing_owner", "No accountable owner", 1, 20)
	}
	if input.ControlCount == 0 {
		addBlocker("missing_controls", "No mapped controls", 1, 25)
	}
	if input.EvidenceCount == 0 {
		addBlocker("missing_evidence", "No evidence attached", 1, 30)
	}
	if !input.HasImpactProof {
		addBlocker("missing_impact_proof", "No impact graph proof", 1, 20)
	}
	if readiness.Score < 0 {
		readiness.Score = 0
	}
	if len(readiness.Blockers) != 0 {
		readiness.Status = "needs_attention"
		readiness.Summary = "Packet can be reviewed, but the listed gaps should be resolved or accepted before auditor reliance."
	}
	if input.EvidenceCount == 0 || input.ControlCount == 0 {
		readiness.Status = "blocked"
		readiness.Summary = "Packet is not audit-ready until evidence and control mappings are present."
	}
	return readiness
}

func RenderFindingAuditPacketMarkdown(input FindingAuditMarkdownInput) string {
	var builder strings.Builder
	writeMarkdownLine(&builder, "# Finding Audit Packet")
	writeMarkdownLine(&builder, "")
	writeMarkdownLine(&builder, "- Finding: "+markdownValue(input.Finding.Title))
	writeMarkdownLine(&builder, "- Finding ID: "+markdownValue(input.Finding.ID))
	writeMarkdownLine(&builder, "- Severity: "+markdownValue(input.Finding.Severity))
	writeMarkdownLine(&builder, "- Status: "+markdownValue(input.Finding.Status))
	writeMarkdownLine(&builder, "- Risk score: "+fmt.Sprintf("%d", input.Finding.RiskScore))
	writeMarkdownLine(&builder, "- Owner: "+markdownValue(input.Finding.Owner))
	writeMarkdownLine(&builder, "- SLA: "+markdownValue(input.Finding.SLAStatus))
	writeMarkdownLine(&builder, "- Generated: "+markdownTime(input.GeneratedAt))
	writeMarkdownLine(&builder, "- Readiness: "+markdownValue(input.Metadata.Readiness.Status)+" ("+fmt.Sprintf("%d", input.Metadata.Readiness.Score)+"/100)")
	writeMarkdownLine(&builder, "- Collection exclusions: "+fmt.Sprintf("%d", input.Metadata.Scope.Exclusions.Total))
	if input.RecommendedAction != "" {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## Recommended Action")
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, markdownValue(input.RecommendedAction))
	}
	if input.Finding.Summary != "" {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## Summary")
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, markdownValue(input.Finding.Summary))
	}
	if len(input.Controls) != 0 {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## Controls")
		writeMarkdownLine(&builder, "")
		for _, control := range input.Controls {
			writeMarkdownLine(&builder, "- "+markdownValue(control.FrameworkName+" "+control.ControlID))
		}
	}
	if len(input.Evidence) != 0 {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## Evidence")
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "| ID | Rule | Created |")
		writeMarkdownLine(&builder, "| --- | --- | --- |")
		for _, evidence := range input.Evidence {
			writeMarkdownLine(&builder, "| "+markdownCell(evidence.ID)+" | "+markdownCell(evidence.RuleID)+" | "+markdownCell(markdownTime(evidence.CreatedAt))+" |")
		}
	}
	if len(input.Metadata.Readiness.Blockers) != 0 {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## Readiness Blockers")
		writeMarkdownLine(&builder, "")
		for _, blocker := range input.Metadata.Readiness.Blockers {
			writeMarkdownLine(&builder, "- "+markdownValue(blocker.Label)+" ("+fmt.Sprintf("%d", blocker.Count)+")")
		}
	}
	return strings.TrimRight(builder.String(), "\n") + "\n"
}

func ReportScopeRuntimeSnapshots(runtimes []*cerebrov1.SourceRuntime) []*cerebrov1.SourceRuntime {
	snapshots := make([]*cerebrov1.SourceRuntime, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		snapshot := &cerebrov1.SourceRuntime{
			Id:       runtime.GetId(),
			SourceId: runtime.GetSourceId(),
			TenantId: runtime.GetTenantId(),
		}
		if value := strings.TrimSpace(runtime.GetConfig()[resourcescope.ConfigKey]); value != "" {
			snapshot.Config = map[string]string{resourcescope.ConfigKey: value}
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

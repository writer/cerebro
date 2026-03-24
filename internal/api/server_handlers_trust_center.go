package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/graph"
)

type trustCenterSnapshotResponse struct {
	GeneratedAt       string                        `json:"generated_at"`
	Summary           trustCenterSummary            `json:"summary"`
	Frameworks        []trustCenterFrameworkSummary `json:"frameworks"`
	SecurityPractices []trustCenterSecurityPractice `json:"security_practices"`
	Subprocessors     []trustCenterSubprocessor     `json:"subprocessors"`
	EvidenceCatalog   []trustCenterEvidenceDocument `json:"evidence_catalog"`
}

type trustCenterSummary struct {
	FrameworkCount          int     `json:"framework_count"`
	AverageComplianceScore  float64 `json:"average_compliance_score"`
	PassingFrameworkCount   int     `json:"passing_framework_count"`
	AttentionFrameworkCount int     `json:"attention_framework_count"`
	SubprocessorCount       int     `json:"subprocessor_count"`
	HighRiskVendorCount     int     `json:"high_risk_vendor_count"`
	EvidenceDocumentCount   int     `json:"evidence_document_count"`
}

type trustCenterFrameworkSummary struct {
	FrameworkID     string  `json:"framework_id"`
	FrameworkName   string  `json:"framework_name"`
	Version         string  `json:"version,omitempty"`
	ComplianceScore float64 `json:"compliance_score"`
	PassingControls int     `json:"passing_controls"`
	TotalControls   int     `json:"total_controls"`
	Status          string  `json:"status"`
	LastAssessedAt  string  `json:"last_assessed_at,omitempty"`
}

type trustCenterSecurityPractice struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Status          string   `json:"status"`
	Summary         string   `json:"summary"`
	EvidenceControl []string `json:"evidence_controls,omitempty"`
}

type trustCenterSubprocessor struct {
	VendorID                string          `json:"vendor_id"`
	Name                    string          `json:"name"`
	Category                string          `json:"category,omitempty"`
	VerificationStatus      string          `json:"verification_status,omitempty"`
	PermissionLevel         string          `json:"permission_level,omitempty"`
	RiskLevel               graph.RiskLevel `json:"risk_level"`
	RiskScore               int             `json:"risk_score"`
	AccessibleResourceKinds []string        `json:"accessible_resource_kinds,omitempty"`
	SourceProviders         []string        `json:"source_providers,omitempty"`
}

type trustCenterEvidenceCatalogResponse struct {
	GeneratedAt string                        `json:"generated_at"`
	Count       int                           `json:"count"`
	Documents   []trustCenterEvidenceDocument `json:"documents"`
}

type trustCenterEvidenceDocument struct {
	ID                      string `json:"id"`
	Title                   string `json:"title"`
	Description             string `json:"description"`
	FrameworkID             string `json:"framework_id,omitempty"`
	FrameworkName           string `json:"framework_name,omitempty"`
	Delivery                string `json:"delivery"`
	RequiresNDA             bool   `json:"requires_nda"`
	PublicPath              string `json:"public_path,omitempty"`
	AuthenticatedExportPath string `json:"authenticated_export_path,omitempty"`
}

type trustCenterFrameworkAssessment struct {
	Framework compliance.Framework
	Report    compliance.ComplianceReport
}

func (s *Server) trustCenterSnapshot(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, s.buildTrustCenterSnapshot(r.Context()))
}

func (s *Server) trustCenterEvidenceCatalog(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	frameworks := s.buildTrustCenterFrameworks(r.Context(), now)
	documents := buildTrustCenterEvidenceCatalog(frameworks)
	s.json(w, http.StatusOK, trustCenterEvidenceCatalogResponse{
		GeneratedAt: now.Format(time.RFC3339),
		Count:       len(documents),
		Documents:   documents,
	})
}

func (s *Server) buildTrustCenterSnapshot(ctx context.Context) trustCenterSnapshotResponse {
	now := time.Now().UTC()
	frameworks := s.buildTrustCenterFrameworks(ctx, now)
	subprocessors := s.buildTrustCenterSubprocessors(ctx)
	evidenceCatalog := buildTrustCenterEvidenceCatalog(frameworks)
	practices := buildTrustCenterSecurityPractices(frameworks)

	summary := trustCenterSummary{
		FrameworkCount:        len(frameworks),
		SubprocessorCount:     len(subprocessors),
		EvidenceDocumentCount: len(evidenceCatalog),
	}
	for _, framework := range frameworks {
		summary.AverageComplianceScore += framework.Report.Summary.ComplianceScore
		switch trustCenterFrameworkStatus(framework.Report) {
		case "passing":
			summary.PassingFrameworkCount++
		case "attention":
			summary.AttentionFrameworkCount++
		}
	}
	for _, vendor := range subprocessors {
		if vendor.RiskLevel == graph.RiskHigh || vendor.RiskLevel == graph.RiskCritical {
			summary.HighRiskVendorCount++
		}
	}
	if len(frameworks) > 0 {
		summary.AverageComplianceScore = roundTrustCenterPercent(summary.AverageComplianceScore / float64(len(frameworks)))
	}

	return trustCenterSnapshotResponse{
		GeneratedAt:       now.Format(time.RFC3339),
		Summary:           summary,
		Frameworks:        buildTrustCenterFrameworkSummaries(frameworks),
		SecurityPractices: practices,
		Subprocessors:     subprocessors,
		EvidenceCatalog:   evidenceCatalog,
	}
}

func (s *Server) buildTrustCenterFrameworks(ctx context.Context, now time.Time) []trustCenterFrameworkAssessment {
	openByPolicy := map[string]int{}
	if s != nil && s.findingsCompliance != nil {
		openByPolicy = openFindingsByPolicy(s.findingsCompliance.FindingsStore(ctx))
	}

	var g *graph.Graph
	if s != nil && s.app != nil {
		g, _ = currentOrStoredTenantGraphView(ctx, s.app)
	}

	frameworks := compliance.GetFrameworks()
	assessments := make([]trustCenterFrameworkAssessment, 0, len(frameworks))
	for _, framework := range frameworks {
		report := compliance.EvaluateFramework(g, &framework, compliance.EvaluationOptions{
			GeneratedAt:          now,
			OpenFindingsByPolicy: openByPolicy,
		})
		assessments = append(assessments, trustCenterFrameworkAssessment{
			Framework: framework,
			Report:    report,
		})
	}
	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].Framework.Name < assessments[j].Framework.Name
	})
	return assessments
}

func buildTrustCenterFrameworkSummaries(assessments []trustCenterFrameworkAssessment) []trustCenterFrameworkSummary {
	out := make([]trustCenterFrameworkSummary, 0, len(assessments))
	for _, assessment := range assessments {
		out = append(out, trustCenterFrameworkSummary{
			FrameworkID:     assessment.Framework.ID,
			FrameworkName:   assessment.Framework.Name,
			Version:         assessment.Framework.Version,
			ComplianceScore: roundTrustCenterPercent(assessment.Report.Summary.ComplianceScore),
			PassingControls: assessment.Report.Summary.PassingControls,
			TotalControls:   assessment.Report.Summary.TotalControls,
			Status:          trustCenterFrameworkStatus(assessment.Report),
			LastAssessedAt:  assessment.Report.GeneratedAt,
		})
	}
	return out
}

func (s *Server) buildTrustCenterSubprocessors(ctx context.Context) []trustCenterSubprocessor {
	if s == nil || s.app == nil {
		return nil
	}
	g, _ := currentOrStoredTenantGraphView(ctx, s.app)
	if g == nil {
		return nil
	}
	nodes := g.GetNodesByKind(graph.NodeKindVendor)
	out := make([]trustCenterSubprocessor, 0, len(nodes))
	for _, node := range nodes {
		if node == nil {
			continue
		}
		riskScore := trustCenterNodeInt(node, "vendor_risk_score")
		riskLevel := node.Risk
		if riskLevel == "" {
			riskLevel = trustCenterRiskLevelFromScore(riskScore)
		}
		out = append(out, trustCenterSubprocessor{
			VendorID:                node.ID,
			Name:                    strings.TrimSpace(node.Name),
			Category:                trustCenterNodeString(node, "vendor_category"),
			VerificationStatus:      trustCenterNodeString(node, "verification_status"),
			PermissionLevel:         trustCenterNodeString(node, "permission_level"),
			RiskLevel:               riskLevel,
			RiskScore:               riskScore,
			AccessibleResourceKinds: trustCenterNodeStrings(node, "accessible_resource_kinds"),
			SourceProviders:         trustCenterNodeStrings(node, "source_providers"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RiskScore != out[j].RiskScore {
			return out[i].RiskScore > out[j].RiskScore
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func buildTrustCenterEvidenceCatalog(frameworks []trustCenterFrameworkAssessment) []trustCenterEvidenceDocument {
	documents := []trustCenterEvidenceDocument{{
		ID:          "live-compliance-summary",
		Title:       "Live compliance summary",
		Description: "Public trust center snapshot with real-time framework status, subprocessors, and security practices derived from the current graph state.",
		Delivery:    "public",
		RequiresNDA: false,
		PublicPath:  "/api/v1/trust-center",
	}}
	for _, assessment := range frameworks {
		documents = append(documents, trustCenterEvidenceDocument{
			ID:                      "audit-package:" + assessment.Framework.ID,
			Title:                   assessment.Framework.Name + " audit package",
			Description:             "Redacted control evidence export derived from the current graph-backed compliance evaluation.",
			FrameworkID:             assessment.Framework.ID,
			FrameworkName:           assessment.Framework.Name,
			Delivery:                "nda_required",
			RequiresNDA:             true,
			AuthenticatedExportPath: "/api/v1/compliance/frameworks/" + assessment.Framework.ID + "/export",
		})
	}
	return documents
}

func buildTrustCenterSecurityPractices(frameworks []trustCenterFrameworkAssessment) []trustCenterSecurityPractice {
	definitions := []struct {
		ID       string
		Title    string
		Keywords []string
	}{
		{ID: "data_encryption", Title: "Data encryption", Keywords: []string{"encrypt", "tls", "ssl", "kms"}},
		{ID: "access_control", Title: "Access control", Keywords: []string{"mfa", "iam", "access", "permission", "password", "privilege"}},
		{ID: "network_protection", Title: "Network protection", Keywords: []string{"public", "network", "security group", "firewall", "ingress", "egress"}},
		{ID: "monitoring_response", Title: "Monitoring and incident response", Keywords: []string{"logging", "log", "cloudtrail", "monitor", "alert", "incident", "response"}},
	}

	practices := make([]trustCenterSecurityPractice, 0, len(definitions))
	for _, definition := range definitions {
		matched := 0
		passing := 0
		evidence := make([]string, 0, 3)
		for _, assessment := range frameworks {
			statusByID := make(map[string]compliance.ControlStatus, len(assessment.Report.Controls))
			for _, status := range assessment.Report.Controls {
				statusByID[status.ControlID] = status
			}
			for _, control := range assessment.Framework.Controls {
				if !trustCenterControlMatches(control, definition.Keywords) {
					continue
				}
				status, ok := statusByID[control.ID]
				if !ok || status.Status == "not_applicable" {
					continue
				}
				matched++
				if status.Status == "passing" {
					passing++
				}
				if len(evidence) < 3 {
					evidence = append(evidence, fmt.Sprintf("%s %s", assessment.Framework.Name, control.ID))
				}
			}
		}
		status := "unavailable"
		summary := "No mapped controls are currently available for this practice."
		if matched > 0 {
			status = "attention"
			if passing == matched {
				status = "passing"
			}
			summary = fmt.Sprintf("%d/%d mapped controls are currently passing.", passing, matched)
		}
		practices = append(practices, trustCenterSecurityPractice{
			ID:              definition.ID,
			Title:           definition.Title,
			Status:          status,
			Summary:         summary,
			EvidenceControl: evidence,
		})
	}
	return practices
}

func trustCenterControlMatches(control compliance.Control, keywords []string) bool {
	content := strings.ToLower(strings.TrimSpace(control.Title + " " + control.Description + " " + strings.Join(control.PolicyIDs, " ")))
	if content == "" {
		return false
	}
	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func trustCenterFrameworkStatus(report compliance.ComplianceReport) string {
	score := report.Summary.ComplianceScore
	switch {
	case score >= 95 && report.Summary.FailingControls == 0 && report.Summary.PartialControls == 0:
		return "passing"
	case score > 0:
		return "attention"
	default:
		return "unavailable"
	}
}

func trustCenterRiskLevelFromScore(score int) graph.RiskLevel {
	switch {
	case score >= 70:
		return graph.RiskHigh
	case score >= 40:
		return graph.RiskMedium
	case score > 0:
		return graph.RiskLow
	default:
		return graph.RiskNone
	}
}

func trustCenterNodeString(node *graph.Node, key string) string {
	if node == nil {
		return ""
	}
	value, ok := node.PropertyValue(key)
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func trustCenterNodeStrings(node *graph.Node, key string) []string {
	if node == nil {
		return nil
	}
	value, ok := node.PropertyValue(key)
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" {
			return nil
		}
		return []string{text}
	}
}

func trustCenterNodeInt(node *graph.Node, key string) int {
	if node == nil {
		return 0
	}
	value, ok := node.PropertyValue(key)
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func roundTrustCenterPercent(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

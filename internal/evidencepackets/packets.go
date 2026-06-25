package evidencepackets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
)

const ContractVersion = "2026-06-24"

type Response struct {
	Version     string                    `json:"version"`
	GeneratedAt time.Time                 `json:"generated_at"`
	Program     AuditProgram              `json:"program"`
	Frameworks  []FrameworkPosture        `json:"frameworks"`
	Controls    []ControlPosture          `json:"controls"`
	Requests    []EvidenceRequest         `json:"evidence_requests"`
	Packets     []EvidencePacket          `json:"evidence_packets"`
	Reviews     []EvidenceReview          `json:"evidence_reviews"`
	Activity    []EvidenceActivity        `json:"activity"`
	Export      EvidenceExport            `json:"export"`
	Snapshot    AuditSnapshot             `json:"snapshot"`
	Metadata    grccontrol.ReportMetadata `json:"metadata"`
}

type AuditProgram struct {
	ID              string `json:"id"`
	Name            string `json:"name,omitempty"`
	ProfileID       string `json:"profile_id,omitempty"`
	Status          string `json:"status"`
	ReadinessScore  int    `json:"readiness_score"`
	FrameworkCount  int    `json:"framework_count"`
	ControlCount    int    `json:"control_count"`
	RequestCount    int    `json:"evidence_request_count"`
	PacketCount     int    `json:"evidence_packet_count"`
	OpenReviewCount int    `json:"open_review_count"`
}

type FrameworkPosture struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Version                string `json:"version,omitempty"`
	Lifecycle              string `json:"lifecycle,omitempty"`
	Status                 string `json:"status"`
	ControlCount           int    `json:"control_count"`
	PassingControls        int    `json:"passing_controls"`
	NeedsAttentionControls int    `json:"needs_attention_controls"`
	MissingEvidence        int    `json:"missing_evidence_count"`
	StaleEvidence          int    `json:"stale_evidence_count"`
	EvidenceScore          int    `json:"evidence_score"`
}

type ControlPosture struct {
	ID                 string              `json:"id"`
	FrameworkID        string              `json:"framework_id,omitempty"`
	FrameworkName      string              `json:"framework_name,omitempty"`
	Title              string              `json:"title,omitempty"`
	OwnerDomain        string              `json:"owner_domain,omitempty"`
	Status             string              `json:"status"`
	EvidenceQuality    string              `json:"evidence_quality,omitempty"`
	EvidenceScore      int                 `json:"evidence_score"`
	OpenFindings       int                 `json:"open_findings"`
	CriticalFindings   int                 `json:"critical_findings"`
	HighFindings       int                 `json:"high_findings"`
	EvidenceItems      int                 `json:"evidence_items"`
	MissingEvidence    int                 `json:"missing_evidence_items"`
	StaleEvidence      int                 `json:"stale_evidence_items"`
	MappedRules        []string            `json:"mapped_rules,omitempty"`
	TestResults        []ControlTestResult `json:"test_results,omitempty"`
	EvidenceRequestIDs []string            `json:"evidence_request_ids,omitempty"`
	EvidencePacketIDs  []string            `json:"evidence_packet_ids,omitempty"`
}

type ControlTestResult struct {
	ID              string `json:"id"`
	RuleID          string `json:"rule_id"`
	ControlID       string `json:"control_id"`
	Status          string `json:"status"`
	Result          string `json:"result"`
	EvidenceQuality string `json:"evidence_quality,omitempty"`
}

type EvidenceRequest struct {
	ID                string   `json:"id"`
	ControlID         string   `json:"control_id"`
	FrameworkID       string   `json:"framework_id,omitempty"`
	Title             string   `json:"title,omitempty"`
	Description       string   `json:"description,omitempty"`
	Type              string   `json:"type,omitempty"`
	Required          bool     `json:"required"`
	Status            string   `json:"status"`
	Quality           string   `json:"quality"`
	FreshnessSLA      string   `json:"freshness_sla,omitempty"`
	AssessmentMethods []string `json:"assessment_methods,omitempty"`
	AcceptedFrom      []string `json:"accepted_from,omitempty"`
	EvidencePacketIDs []string `json:"evidence_packet_ids,omitempty"`
	ReviewStatus      string   `json:"review_status"`
}

type EvidencePacket struct {
	ID             string            `json:"id"`
	RequestID      string            `json:"request_id,omitempty"`
	ControlID      string            `json:"control_id,omitempty"`
	FrameworkID    string            `json:"framework_id,omitempty"`
	EvidenceType   string            `json:"evidence_type,omitempty"`
	Status         string            `json:"status"`
	Quality        string            `json:"quality,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Source         string            `json:"source,omitempty"`
	ObservedAt     *time.Time        `json:"observed_at,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	Manual         bool              `json:"manual,omitempty"`
	Citations      EvidenceCitations `json:"citations"`
	Freshness      EvidenceFreshness `json:"freshness"`
	Review         EvidenceReview    `json:"review"`
	ExportArtifact EvidenceExportRef `json:"export_artifact"`
}

type EvidenceCitations struct {
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	RuleIDs     []string `json:"rule_ids,omitempty"`
	EventIDs    []string `json:"event_ids,omitempty"`
	ClaimIDs    []string `json:"claim_ids,omitempty"`
	GraphRoots  []string `json:"graph_root_urns,omitempty"`
	RunIDs      []string `json:"run_ids,omitempty"`
}

type EvidenceFreshness struct {
	Status     string `json:"status"`
	SLA        string `json:"sla,omitempty"`
	Reason     string `json:"reason,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type EvidenceReview struct {
	ID        string `json:"id"`
	SubjectID string `json:"subject_id"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	Actor     string `json:"actor,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type EvidenceActivity struct {
	ID        string    `json:"id"`
	SubjectID string    `json:"subject_id"`
	Type      string    `json:"type"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type EvidenceExport struct {
	ID        string   `json:"id"`
	Formats   []string `json:"formats"`
	Redaction string   `json:"redaction"`
	Path      string   `json:"path,omitempty"`
}

type EvidenceExportRef struct {
	Format string `json:"format"`
	Path   string `json:"path,omitempty"`
}

type AuditSnapshot struct {
	ID              string    `json:"id"`
	Hash            string    `json:"hash"`
	GeneratedAt     time.Time `json:"generated_at"`
	ControlCount    int       `json:"control_count"`
	RequestCount    int       `json:"evidence_request_count"`
	PacketCount     int       `json:"evidence_packet_count"`
	ReviewOpenCount int       `json:"open_review_count"`
}

func Build(result grccontrol.PacketResult) Response {
	generatedAt := result.Packet.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	controls := make([]ControlPosture, 0, len(result.Controls))
	requests := []EvidenceRequest{}
	packets := []EvidencePacket{}
	reviews := []EvidenceReview{}
	activity := []EvidenceActivity{}

	packetControlsByKey := map[string]compliance.ControlEvidencePacketControl{}
	for _, control := range result.Packet.Controls {
		packetControlsByKey[controlKey(control.Control.FrameworkName, control.Control.ControlID)] = control
	}
	for _, item := range result.Controls {
		packetControl := packetControlsByKey[controlKey(item.FrameworkName, item.ControlID)]
		controlID := stableControlID(item.FrameworkName, item.ControlID)
		control := ControlPosture{
			ID:                 controlID,
			FrameworkID:        strings.TrimSpace(item.FrameworkName),
			FrameworkName:      strings.TrimSpace(item.FrameworkName),
			Title:              strings.TrimSpace(item.Title),
			OwnerDomain:        strings.TrimSpace(item.OwnerDomain),
			Status:             strings.TrimSpace(item.Status),
			EvidenceQuality:    strings.TrimSpace(item.EvidenceQuality),
			EvidenceScore:      item.EvidenceScore,
			OpenFindings:       item.OpenFindings,
			CriticalFindings:   item.CriticalFindings,
			HighFindings:       item.HighFindings,
			EvidenceItems:      item.EvidenceItems,
			MissingEvidence:    item.MissingEvidence,
			StaleEvidence:      item.StaleEvidence,
			MappedRules:        append([]string(nil), item.MappedRules...),
			TestResults:        testResults(controlID, item),
			EvidenceRequestIDs: []string{},
			EvidencePacketIDs:  []string{},
		}
		for _, expectation := range packetControl.Evidence.Expectations {
			requestID := stableID("evidence-request", controlID, expectation.ID)
			requestPacketIDs := []string{}
			for _, evidenceID := range expectation.EvidenceIDs {
				packetID := stableID("evidence-packet", controlID, requestID, evidenceID)
				requestPacketIDs = append(requestPacketIDs, packetID)
				control.EvidencePacketIDs = append(control.EvidencePacketIDs, packetID)
			}
			request := EvidenceRequest{
				ID:                requestID,
				ControlID:         controlID,
				FrameworkID:       control.FrameworkID,
				Title:             strings.TrimSpace(expectation.Title),
				Description:       strings.TrimSpace(expectation.Description),
				Type:              strings.TrimSpace(expectation.Type),
				Required:          expectation.Required,
				Status:            string(expectation.Status),
				Quality:           string(expectation.Quality),
				FreshnessSLA:      strings.TrimSpace(expectation.FreshnessSLA),
				AssessmentMethods: append([]string(nil), expectation.AssessmentMethods...),
				AcceptedFrom:      append([]string(nil), expectation.AcceptedFrom...),
				EvidencePacketIDs: requestPacketIDs,
				ReviewStatus:      reviewStatusForExpectation(expectation),
			}
			control.EvidenceRequestIDs = append(control.EvidenceRequestIDs, requestID)
			requests = append(requests, request)
			reviews = append(reviews, reviewFor(request.ID, request.ReviewStatus, request.Quality, generatedAt))
			activity = append(activity, activityFor(request.ID, "evidence_request.generated", generatedAt))
			for _, packet := range packetsForExpectation(control, request, packetControl.Evidence.Items, expectation, generatedAt) {
				packets = append(packets, packet)
				reviews = append(reviews, packet.Review)
				activity = append(activity, activityFor(packet.ID, "evidence_packet.generated", generatedAt))
			}
		}
		controls = append(controls, control)
	}
	frameworks := frameworksFromControls(controls)
	sort.Slice(controls, func(i, j int) bool { return controls[i].ID < controls[j].ID })
	sort.Slice(requests, func(i, j int) bool { return requests[i].ID < requests[j].ID })
	sort.Slice(packets, func(i, j int) bool { return packets[i].ID < packets[j].ID })
	sort.Slice(reviews, func(i, j int) bool { return reviews[i].ID < reviews[j].ID })
	sort.Slice(activity, func(i, j int) bool { return activity[i].ID < activity[j].ID })
	openReviews := countOpenReviews(reviews)
	program := AuditProgram{
		ID:              stableID("audit-program", result.Profile.ID),
		Name:            result.Profile.Name,
		ProfileID:       result.Profile.ID,
		Status:          result.Metadata.Readiness.Status,
		ReadinessScore:  result.Metadata.Readiness.Score,
		FrameworkCount:  len(frameworks),
		ControlCount:    len(controls),
		RequestCount:    len(requests),
		PacketCount:     len(packets),
		OpenReviewCount: openReviews,
	}
	snapshot := AuditSnapshot{
		ID:              stableID("audit-snapshot", result.Profile.ID, fmt.Sprint(generatedAt.Unix())),
		GeneratedAt:     generatedAt,
		ControlCount:    len(controls),
		RequestCount:    len(requests),
		PacketCount:     len(packets),
		ReviewOpenCount: openReviews,
	}
	snapshot.Hash = snapshotHash(program, frameworks, controls, requests, packets)
	return Response{
		Version:     ContractVersion,
		GeneratedAt: generatedAt,
		Program:     program,
		Frameworks:  frameworks,
		Controls:    controls,
		Requests:    requests,
		Packets:     packets,
		Reviews:     reviews,
		Activity:    activity,
		Export: EvidenceExport{
			ID:        stableID("evidence-export", result.Profile.ID),
			Formats:   []string{"json"},
			Redaction: result.Metadata.Redaction.DefaultMode,
			Path:      exportPath(result.Profile.ID),
		},
		Snapshot: snapshot,
		Metadata: result.Metadata,
	}
}

func packetsForExpectation(control ControlPosture, request EvidenceRequest, items []compliance.ControlEvidencePacketEvidenceItem, expectation compliance.ControlEvidenceExpectationPosture, generatedAt time.Time) []EvidencePacket {
	itemByID := map[string]compliance.ControlEvidencePacketEvidenceItem{}
	for _, item := range items {
		itemByID[strings.TrimSpace(item.ID)] = item
	}
	packets := make([]EvidencePacket, 0, len(expectation.EvidenceIDs))
	for _, evidenceID := range expectation.EvidenceIDs {
		item := itemByID[strings.TrimSpace(evidenceID)]
		packetID := stableID("evidence-packet", control.ID, request.ID, evidenceID)
		observedAt := timePtr(item.ObservedAt)
		expiresAt := timePtr(item.ExpiresAt)
		freshness := freshnessFor(item, expectation)
		reviewStatus := reviewStatusForPacket(item, expectation)
		packets = append(packets, EvidencePacket{
			ID:           packetID,
			RequestID:    request.ID,
			ControlID:    control.ID,
			FrameworkID:  control.FrameworkID,
			EvidenceType: strings.TrimSpace(item.EvidenceType),
			Status:       firstNonEmpty(item.Status, string(expectation.Status)),
			Quality:      string(item.Quality),
			Reason:       strings.TrimSpace(item.Reason),
			Source:       strings.TrimSpace(item.Source),
			ObservedAt:   observedAt,
			ExpiresAt:    expiresAt,
			Manual:       item.Manual,
			Citations: EvidenceCitations{
				EvidenceIDs: nonEmptyStrings(evidenceID),
				RuleIDs:     nonEmptyStrings(item.RuleID),
			},
			Freshness: freshness,
			Review:    reviewFor(packetID, reviewStatus, string(item.Quality), generatedAt),
			ExportArtifact: EvidenceExportRef{
				Format: "json",
			},
		})
	}
	return packets
}

func testResults(controlID string, item grccontrol.ControlItem) []ControlTestResult {
	results := make([]ControlTestResult, 0, len(item.MappedRules))
	for _, ruleID := range item.MappedRules {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			continue
		}
		result := "pass"
		if item.OpenFindings > 0 {
			result = "fail"
		}
		results = append(results, ControlTestResult{
			ID:              stableID("control-test", controlID, ruleID),
			RuleID:          ruleID,
			ControlID:       controlID,
			Status:          strings.TrimSpace(item.Status),
			Result:          result,
			EvidenceQuality: strings.TrimSpace(item.EvidenceQuality),
		})
	}
	return results
}

func frameworksFromControls(controls []ControlPosture) []FrameworkPosture {
	byID := map[string]*FrameworkPosture{}
	for _, control := range controls {
		id := firstNonEmpty(control.FrameworkID, "default")
		framework := byID[id]
		if framework == nil {
			framework = &FrameworkPosture{ID: id, Name: id, Status: "ready"}
			byID[id] = framework
		}
		framework.ControlCount++
		framework.MissingEvidence += control.MissingEvidence
		framework.StaleEvidence += control.StaleEvidence
		framework.EvidenceScore += control.EvidenceScore
		if strings.EqualFold(control.Status, "passing") || strings.EqualFold(control.Status, "ready") {
			framework.PassingControls++
		} else {
			framework.NeedsAttentionControls++
			framework.Status = "needs_attention"
		}
	}
	frameworks := make([]FrameworkPosture, 0, len(byID))
	for _, framework := range byID {
		if framework.ControlCount > 0 {
			framework.EvidenceScore = framework.EvidenceScore / framework.ControlCount
		}
		if framework.MissingEvidence > 0 {
			framework.Status = "blocked"
		}
		frameworks = append(frameworks, *framework)
	}
	sort.Slice(frameworks, func(i, j int) bool { return frameworks[i].ID < frameworks[j].ID })
	return frameworks
}

func reviewStatusForExpectation(expectation compliance.ControlEvidenceExpectationPosture) string {
	switch expectation.Status {
	case compliance.ControlEvidenceExpectationSatisfied:
		if expectation.Quality == compliance.ControlEvidenceQualityStrong {
			return "ready"
		}
		return "needs_review"
	case compliance.ControlEvidenceExpectationOptional:
		return "not_required"
	default:
		return "needs_review"
	}
}

func reviewStatusForPacket(item compliance.ControlEvidencePacketEvidenceItem, expectation compliance.ControlEvidenceExpectationPosture) string {
	if item.Manual || item.Quality == compliance.ControlEvidenceQualityManual || expectation.Quality == compliance.ControlEvidenceQualityManual {
		return "needs_review"
	}
	if item.Quality == compliance.ControlEvidenceQualityStrong && expectation.Status == compliance.ControlEvidenceExpectationSatisfied {
		return "ready"
	}
	return "needs_review"
}

func reviewFor(subjectID string, status string, reason string, generatedAt time.Time) EvidenceReview {
	return EvidenceReview{
		ID:        stableID("evidence-review", subjectID),
		SubjectID: subjectID,
		Status:    firstNonEmpty(status, "needs_review"),
		Reason:    strings.TrimSpace(reason),
		UpdatedAt: generatedAt.Format(time.RFC3339),
	}
}

func activityFor(subjectID string, kind string, generatedAt time.Time) EvidenceActivity {
	return EvidenceActivity{
		ID:        stableID("evidence-activity", subjectID, kind),
		SubjectID: subjectID,
		Type:      kind,
		CreatedAt: generatedAt,
	}
}

func freshnessFor(item compliance.ControlEvidencePacketEvidenceItem, expectation compliance.ControlEvidenceExpectationPosture) EvidenceFreshness {
	status := "fresh"
	if expectation.Status == compliance.ControlEvidenceExpectationStale || item.Quality == compliance.ControlEvidenceQualityStale {
		status = "stale"
	}
	if expectation.Status == compliance.ControlEvidenceExpectationMissing {
		status = "missing"
	}
	return EvidenceFreshness{
		Status:     status,
		SLA:        strings.TrimSpace(expectation.FreshnessSLA),
		Reason:     strings.TrimSpace(item.Reason),
		ObservedAt: formatTime(item.ObservedAt),
		ExpiresAt:  formatTime(item.ExpiresAt),
	}
}

func snapshotHash(values ...any) string {
	payload, _ := json.Marshal(values)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func stableID(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.ToLower(strings.TrimSpace(part))
		normalized = strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				return r
			case r == '-', r == '_', r == ':', r == '.':
				return r
			default:
				return '-'
			}
		}, normalized)
		normalized = strings.Trim(normalized, "-")
		if normalized != "" {
			clean = append(clean, normalized)
		}
	}
	if len(clean) == 0 {
		return "evidence-record"
	}
	return strings.Join(clean, ":")
}

func stableControlID(framework string, control string) string {
	return stableID("control", framework, control)
}

func controlKey(framework string, control string) string {
	return strings.TrimSpace(framework) + "\x00" + strings.TrimSpace(control)
}

func countOpenReviews(reviews []EvidenceReview) int {
	count := 0
	for _, review := range reviews {
		switch review.Status {
		case "ready", "accepted", "not_required":
		default:
			count++
		}
	}
	return count
}

func exportPath(profileID string) string {
	path := "/grc/evidence-packets"
	if strings.TrimSpace(profileID) != "" {
		path += "?profile=" + strings.TrimSpace(profileID)
	}
	return path
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}

func nonEmptyStrings(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

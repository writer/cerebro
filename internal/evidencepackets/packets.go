package evidencepackets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const ContractVersion = "2026-06-24"

type Response struct {
	Version     string               `json:"version"`
	GeneratedAt time.Time            `json:"generated_at"`
	Program     AuditProgram         `json:"program"`
	Frameworks  []FrameworkPosture   `json:"frameworks"`
	Controls    []ControlPosture     `json:"controls"`
	Requests    []EvidenceRequest    `json:"evidence_requests"`
	Packets     []EvidencePacket     `json:"evidence_packets"`
	Reviews     []EvidenceReview     `json:"evidence_reviews"`
	Activity    []EvidenceActivity   `json:"activity"`
	Scope       AssessmentScope      `json:"assessment_scope"`
	Sources     []CollectionSource   `json:"collection_sources"`
	Items       []EvidenceItemRecord `json:"evidence_items"`
	Findings    []FindingWorkflow    `json:"finding_workflow"`
	Resources   []ResourceSubject    `json:"resource_subjects"`
	Lineage     []EvidenceLineage    `json:"evidence_lineage"`
	Claims      []ClaimRecord        `json:"claim_records"`
	Runs        []EvaluationRun      `json:"evaluation_runs"`
	ResponseGraphRecords
	ResponseReasoningRecords
	Exceptions []ExceptionAcceptance     `json:"exceptions_acceptances"`
	Artifacts  []EvidenceExportArtifact  `json:"export_artifacts"`
	Export     EvidenceExport            `json:"export"`
	Snapshot   AuditSnapshot             `json:"snapshot"`
	Metadata   grccontrol.ReportMetadata `json:"metadata"`
}

type ResponseGraphRecords struct {
	GraphRows  []GraphEvidenceRecord `json:"graph_evidence_rows"`
	GraphPaths []GraphPathRecord     `json:"graph_path_records"`
}

type ResponseReasoningRecords struct {
	Access    []AccessEvidenceSubject `json:"access_evidence_subjects,omitempty"`
	Reasoning []EvidenceReasoningTask `json:"reasoning_tasks,omitempty"`
}

type AuditProgram struct {
	ID                string `json:"id"`
	Name              string `json:"name,omitempty"`
	ProfileID         string `json:"profile_id,omitempty"`
	Status            string `json:"status"`
	ReadinessScore    int    `json:"readiness_score"`
	FrameworkCount    int    `json:"framework_count"`
	ControlCount      int    `json:"control_count"`
	RequestCount      int    `json:"evidence_request_count"`
	PacketCount       int    `json:"evidence_packet_count"`
	SourceCount       int    `json:"collection_source_count"`
	EvidenceItemCount int    `json:"evidence_item_count"`
	ResourceCount     int    `json:"resource_subject_count"`
	LineageCount      int    `json:"lineage_count"`
	ClaimCount        int    `json:"claim_record_count"`
	RunCount          int    `json:"evaluation_run_count"`
	GraphPathCount    int    `json:"graph_path_count"`
	OpenReviewCount   int    `json:"open_review_count"`
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
	ControlPostureIdentity
	ControlPostureMetadata
	ControlPostureStatus
	ControlPostureLinks
}

type ControlPostureIdentity struct {
	ID                 string `json:"id"`
	FrameworkID        string `json:"framework_id,omitempty"`
	FrameworkName      string `json:"framework_name,omitempty"`
	Title              string `json:"title,omitempty"`
	OwnerDomain        string `json:"owner_domain,omitempty"`
	FrameworkVersion   string `json:"framework_version,omitempty"`
	FrameworkLifecycle string `json:"framework_lifecycle,omitempty"`
	FamilyID           string `json:"family_id,omitempty"`
	FamilyName         string `json:"family_name,omitempty"`
}

type ControlPostureMetadata struct {
	MappedRules []string `json:"mapped_rules,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type ControlPostureStatus struct {
	Status           string `json:"status"`
	EvidenceQuality  string `json:"evidence_quality,omitempty"`
	EvidenceScore    int    `json:"evidence_score"`
	AuditSummary     string `json:"audit_summary,omitempty"`
	OpenFindings     int    `json:"open_findings"`
	CriticalFindings int    `json:"critical_findings"`
	HighFindings     int    `json:"high_findings"`
	EvidenceItems    int    `json:"evidence_items"`
	MissingEvidence  int    `json:"missing_evidence_items"`
	StaleEvidence    int    `json:"stale_evidence_items"`
}

type ControlPostureLinks struct {
	TestResults        []ControlTestResult `json:"test_results,omitempty"`
	EvidenceRequestIDs []string            `json:"evidence_request_ids,omitempty"`
	EvidencePacketIDs  []string            `json:"evidence_packet_ids,omitempty"`
	FindingIDs         []string            `json:"finding_ids,omitempty"`
	ExceptionIDs       []string            `json:"exception_ids,omitempty"`
}

type ControlTestResult struct {
	ID              string   `json:"id"`
	RuleID          string   `json:"rule_id"`
	ControlID       string   `json:"control_id"`
	Status          string   `json:"status"`
	Result          string   `json:"result"`
	EvidenceQuality string   `json:"evidence_quality,omitempty"`
	FindingIDs      []string `json:"finding_ids,omitempty"`
	EvidenceIDs     []string `json:"evidence_ids,omitempty"`
	LastObservedAt  string   `json:"last_observed_at,omitempty"`
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
	OwnerDomain       string   `json:"owner_domain,omitempty"`
	DueAt             string   `json:"due_at,omitempty"`
	ControlTestIDs    []string `json:"control_test_ids,omitempty"`
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

type AssessmentScope struct {
	ID                       string    `json:"id"`
	ReportType               string    `json:"report_type,omitempty"`
	ProfileID                string    `json:"profile_id,omitempty"`
	ProfileName              string    `json:"profile_name,omitempty"`
	GeneratedAt              time.Time `json:"generated_at"`
	SourceIDs                []string  `json:"source_ids,omitempty"`
	RuntimeIDs               []string  `json:"runtime_ids,omitempty"`
	ControlCount             int       `json:"control_count"`
	FindingCount             int       `json:"finding_count"`
	EvidenceCount            int       `json:"evidence_count"`
	RuntimeCount             int       `json:"runtime_count"`
	ExclusionCount           int       `json:"exclusion_count"`
	CollectionPolicy         string    `json:"collection_policy"`
	PolicyAppliedBeforeRead  bool      `json:"policy_applied_before_read"`
	FilteredBeforeProjection bool      `json:"filtered_before_graph_projection"`
	RedactionMode            string    `json:"redaction_mode,omitempty"`
}

type CollectionSource struct {
	ID                string `json:"id"`
	RuntimeID         string `json:"runtime_id"`
	SourceID          string `json:"source_id,omitempty"`
	TenantID          string `json:"tenant_id,omitempty"`
	Status            string `json:"status"`
	LastSyncedAt      string `json:"last_synced_at,omitempty"`
	FindingCount      int    `json:"finding_count"`
	EvidenceItemCount int    `json:"evidence_item_count"`
	ControlCount      int    `json:"control_count"`
}

type EvidenceItemRecord struct {
	ID               string   `json:"id"`
	RuntimeID        string   `json:"runtime_id,omitempty"`
	SourceID         string   `json:"source_id,omitempty"`
	FindingID        string   `json:"finding_id,omitempty"`
	RuleID           string   `json:"rule_id,omitempty"`
	RunID            string   `json:"run_id,omitempty"`
	RunIDs           []string `json:"run_ids,omitempty"`
	ClaimIDs         []string `json:"claim_ids,omitempty"`
	EventIDs         []string `json:"event_ids,omitempty"`
	GraphRoots       []string `json:"graph_root_urns,omitempty"`
	GraphPaths       []string `json:"graph_path_urns,omitempty"`
	CreatedAt        string   `json:"created_at,omitempty"`
	LastObservedAt   string   `json:"last_observed_at,omitempty"`
	ObservationCount uint32   `json:"observation_count,omitempty"`
	ControlIDs       []string `json:"control_ids,omitempty"`
	RequestIDs       []string `json:"evidence_request_ids,omitempty"`
	PacketIDs        []string `json:"evidence_packet_ids,omitempty"`
}

type FindingWorkflow struct {
	ID             string   `json:"id"`
	Title          string   `json:"title,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Status         string   `json:"status,omitempty"`
	Owner          string   `json:"owner,omitempty"`
	SLAStatus      string   `json:"sla_status,omitempty"`
	RuntimeID      string   `json:"runtime_id,omitempty"`
	SourceID       string   `json:"source_id,omitempty"`
	RuleID         string   `json:"rule_id,omitempty"`
	PolicyID       string   `json:"policy_id,omitempty"`
	PolicyName     string   `json:"policy_name,omitempty"`
	CheckID        string   `json:"check_id,omitempty"`
	CheckName      string   `json:"check_name,omitempty"`
	RiskScore      int      `json:"risk_score,omitempty"`
	RiskReasons    []string `json:"risk_reasons,omitempty"`
	DueAt          string   `json:"due_at,omitempty"`
	StatusReason   string   `json:"status_reason,omitempty"`
	ControlIDs     []string `json:"control_ids,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	PacketIDs      []string `json:"evidence_packet_ids,omitempty"`
	LastObservedAt string   `json:"last_observed_at,omitempty"`
	ReviewStatus   string   `json:"review_status"`
}

type ResourceSubject struct {
	ID             string   `json:"id"`
	URN            string   `json:"urn"`
	Kind           string   `json:"kind,omitempty"`
	ControlIDs     []string `json:"control_ids,omitempty"`
	FindingIDs     []string `json:"finding_ids,omitempty"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	PacketIDs      []string `json:"evidence_packet_ids,omitempty"`
	LastObservedAt string   `json:"last_observed_at,omitempty"`
}

type EvidenceLineage struct {
	ID         string   `json:"id"`
	EvidenceID string   `json:"evidence_id"`
	FindingID  string   `json:"finding_id,omitempty"`
	RuntimeID  string   `json:"runtime_id,omitempty"`
	SourceID   string   `json:"source_id,omitempty"`
	RuleID     string   `json:"rule_id,omitempty"`
	RunIDs     []string `json:"run_ids,omitempty"`
	ClaimIDs   []string `json:"claim_ids,omitempty"`
	EventIDs   []string `json:"event_ids,omitempty"`
	GraphRoots []string `json:"graph_root_urns,omitempty"`
	RequestIDs []string `json:"evidence_request_ids,omitempty"`
	PacketIDs  []string `json:"evidence_packet_ids,omitempty"`
	ControlIDs []string `json:"control_ids,omitempty"`
}

type ClaimRecord struct {
	ID          string   `json:"id"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	ControlIDs  []string `json:"control_ids,omitempty"`
	PacketIDs   []string `json:"evidence_packet_ids,omitempty"`
}

type EvaluationRun struct {
	ID          string   `json:"id"`
	RuntimeID   string   `json:"runtime_id,omitempty"`
	SourceID    string   `json:"source_id,omitempty"`
	RuleIDs     []string `json:"rule_ids,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	FindingIDs  []string `json:"finding_ids,omitempty"`
	ControlIDs  []string `json:"control_ids,omitempty"`
	PacketIDs   []string `json:"evidence_packet_ids,omitempty"`
}

type GraphEvidenceRecord struct {
	ID         string            `json:"id"`
	EvidenceID string            `json:"evidence_id,omitempty"`
	FindingID  string            `json:"finding_id,omitempty"`
	Label      string            `json:"label,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	PathIDs    []string          `json:"graph_path_ids,omitempty"`
}

type GraphPathRecord struct {
	ID         string            `json:"id"`
	EvidenceID string            `json:"evidence_id,omitempty"`
	FindingID  string            `json:"finding_id,omitempty"`
	FromURN    string            `json:"from_urn,omitempty"`
	FromType   string            `json:"from_type,omitempty"`
	Relation   string            `json:"relation,omitempty"`
	ToURN      string            `json:"to_urn,omitempty"`
	ToType     string            `json:"to_type,omitempty"`
	ObservedAt string            `json:"observed_at,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type ExceptionAcceptance struct {
	ID          string `json:"id"`
	ControlID   string `json:"control_id"`
	FrameworkID string `json:"framework_id,omitempty"`
	Type        string `json:"type"`
	Status      string `json:"status"`
}

type EvidenceExportArtifact struct {
	ID          string `json:"id"`
	SnapshotID  string `json:"snapshot_id"`
	Format      string `json:"format"`
	Redaction   string `json:"redaction"`
	Path        string `json:"path,omitempty"`
	ContentHash string `json:"content_hash"`
	Included    bool   `json:"included"`
}

type recordLinks struct {
	ControlIDs []string
	RequestIDs []string
	PacketIDs  []string
}

type AuditSnapshot struct {
	ID                string    `json:"id"`
	Hash              string    `json:"hash"`
	GeneratedAt       time.Time `json:"generated_at"`
	ControlCount      int       `json:"control_count"`
	RequestCount      int       `json:"evidence_request_count"`
	PacketCount       int       `json:"evidence_packet_count"`
	SourceCount       int       `json:"collection_source_count"`
	EvidenceItemCount int       `json:"evidence_item_count"`
	ResourceCount     int       `json:"resource_subject_count"`
	LineageCount      int       `json:"lineage_count"`
	ClaimCount        int       `json:"claim_record_count"`
	RunCount          int       `json:"evaluation_run_count"`
	GraphPathCount    int       `json:"graph_path_count"`
	ReviewOpenCount   int       `json:"open_review_count"`
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
	exceptions := []ExceptionAcceptance{}
	evidenceLinks := map[string]*recordLinks{}
	evidenceByID := evidenceByID(result.Evidence)

	packetControlsByKey := map[string]compliance.ControlEvidencePacketControl{}
	for _, control := range result.Packet.Controls {
		packetControlsByKey[controlKey(control.Control.FrameworkName, control.Control.ControlID)] = control
	}
	for _, item := range result.Controls {
		packetControl := packetControlsByKey[controlKey(item.FrameworkName, item.ControlID)]
		frameworkID := stableFrameworkID(item)
		controlID := stableControlID(frameworkID, item.ControlID)
		ruleEvidenceIDs := evidenceIDsByRule(packetControl.Evidence.Items)
		control := ControlPosture{
			ControlPostureIdentity: ControlPostureIdentity{
				ID:                 controlID,
				FrameworkID:        frameworkID,
				FrameworkName:      strings.TrimSpace(item.FrameworkName),
				Title:              strings.TrimSpace(item.Title),
				OwnerDomain:        strings.TrimSpace(item.OwnerDomain),
				FrameworkVersion:   strings.TrimSpace(item.FrameworkVersion),
				FrameworkLifecycle: strings.TrimSpace(item.FrameworkLifecycle),
				FamilyID:           strings.TrimSpace(item.FamilyID),
				FamilyName:         strings.TrimSpace(item.FamilyName),
			},
			ControlPostureMetadata: ControlPostureMetadata{
				MappedRules: append([]string(nil), item.MappedRules...),
				Reasons:     append([]string(nil), item.Reasons...),
				Tags:        append([]string(nil), item.Tags...),
			},
			ControlPostureStatus: ControlPostureStatus{
				Status:           strings.TrimSpace(item.Status),
				EvidenceQuality:  strings.TrimSpace(item.EvidenceQuality),
				EvidenceScore:    item.EvidenceScore,
				AuditSummary:     strings.TrimSpace(item.AuditSummary),
				OpenFindings:     item.OpenFindings,
				CriticalFindings: item.CriticalFindings,
				HighFindings:     item.HighFindings,
				EvidenceItems:    item.EvidenceItems,
				MissingEvidence:  item.MissingEvidence,
				StaleEvidence:    item.StaleEvidence,
			},
			ControlPostureLinks: ControlPostureLinks{
				TestResults:        testResults(controlID, item, ruleEvidenceIDs),
				EvidenceRequestIDs: []string{},
				EvidencePacketIDs:  []string{},
				FindingIDs:         findingIDs(item.Findings),
				ExceptionIDs:       exceptionIDsForControl(controlID, packetControl),
			},
		}
		exceptions = append(exceptions, exceptionsForControl(control, packetControl)...)
		for _, expectation := range packetControl.Evidence.Expectations {
			requestID := stableID("evidence-request", controlID, expectation.ID)
			requestPacketIDs := []string{}
			for _, evidenceID := range expectation.EvidenceIDs {
				packetID := stableID("evidence-packet", controlID, requestID, evidenceID)
				requestPacketIDs = append(requestPacketIDs, packetID)
				control.EvidencePacketIDs = append(control.EvidencePacketIDs, packetID)
				linkEvidence(evidenceLinks, evidenceID, controlID, requestID, packetID)
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
				OwnerDomain:       control.OwnerDomain,
				DueAt:             formatTime(packetControl.Evidence.Summary.EvidenceDueAt),
				ControlTestIDs:    controlTestIDs(control.TestResults),
			}
			control.EvidenceRequestIDs = append(control.EvidenceRequestIDs, requestID)
			requests = append(requests, request)
			reviews = append(reviews, reviewFor(request.ID, request.ReviewStatus, expectation.Reason, generatedAt))
			activity = append(activity, activityFor(request.ID, "evidence_request.generated", generatedAt))
			for _, packet := range packetsForExpectation(control, request, packetControl.Evidence.Items, evidenceByID, expectation, generatedAt) {
				packets = append(packets, packet)
				reviews = append(reviews, packet.Review)
				activity = append(activity, activityFor(packet.ID, "evidence_packet.generated", generatedAt))
			}
		}
		controls = append(controls, control)
	}
	frameworks := frameworksFromControls(controls)
	items := evidenceItemsFromRaw(result.Evidence, result.SourceIDs, evidenceLinks)
	findings := findingWorkflowFromControls(result.Controls, result.Findings, items)
	resources := resourceSubjects(result.Findings, items)
	lineage := evidenceLineageFromItems(items)
	claims := claimRecordsFromItems(items)
	runs := evaluationRunsFromItems(items)
	graphRows, graphPaths := graphRecordsFromEvidence(result.Evidence)
	sources := collectionSources(result.Runtimes, result.SourceIDs, result.Controls, items)
	sort.Slice(controls, func(i, j int) bool { return controls[i].ID < controls[j].ID })
	sort.Slice(requests, func(i, j int) bool { return requests[i].ID < requests[j].ID })
	sort.Slice(packets, func(i, j int) bool { return packets[i].ID < packets[j].ID })
	sort.Slice(reviews, func(i, j int) bool { return reviews[i].ID < reviews[j].ID })
	sort.Slice(activity, func(i, j int) bool { return activity[i].ID < activity[j].ID })
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].ID < exceptions[j].ID })
	openReviews := countOpenReviews(reviews)
	program := AuditProgram{
		ID:                stableID("audit-program", result.Profile.ID),
		Name:              result.Profile.Name,
		ProfileID:         result.Profile.ID,
		Status:            result.Metadata.Readiness.Status,
		ReadinessScore:    result.Metadata.Readiness.Score,
		FrameworkCount:    len(frameworks),
		ControlCount:      len(controls),
		RequestCount:      len(requests),
		PacketCount:       len(packets),
		SourceCount:       len(sources),
		EvidenceItemCount: len(items),
		ResourceCount:     len(resources),
		LineageCount:      len(lineage),
		ClaimCount:        len(claims),
		RunCount:          len(runs),
		GraphPathCount:    len(graphPaths),
		OpenReviewCount:   openReviews,
	}
	snapshot := AuditSnapshot{
		ID:                stableID("audit-snapshot", result.Profile.ID, fmt.Sprint(generatedAt.Unix())),
		GeneratedAt:       generatedAt,
		ControlCount:      len(controls),
		RequestCount:      len(requests),
		PacketCount:       len(packets),
		SourceCount:       len(sources),
		EvidenceItemCount: len(items),
		ResourceCount:     len(resources),
		LineageCount:      len(lineage),
		ClaimCount:        len(claims),
		RunCount:          len(runs),
		GraphPathCount:    len(graphPaths),
		ReviewOpenCount:   openReviews,
	}
	snapshot.Hash = snapshotHash(program, frameworks, controls, requests, packets, items, findings, resources, lineage, claims, runs, graphRows, graphPaths, exceptions)
	export := EvidenceExport{
		ID:        stableID("evidence-export", result.Profile.ID),
		Formats:   []string{"json"},
		Redaction: result.Metadata.Redaction.DefaultMode,
		Path:      exportPath(result.Profile.ID),
	}
	artifacts := exportArtifacts(export, snapshot)
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
		Scope:       assessmentScope(result, generatedAt),
		Sources:     sources,
		Items:       items,
		Findings:    findings,
		Resources:   resources,
		Lineage:     lineage,
		Claims:      claims,
		Runs:        runs,
		ResponseGraphRecords: ResponseGraphRecords{
			GraphRows:  graphRows,
			GraphPaths: graphPaths,
		},
		Exceptions: exceptions,
		Artifacts:  artifacts,
		Export:     export,
		Snapshot:   snapshot,
		Metadata:   result.Metadata,
	}
}

func assessmentScope(result grccontrol.PacketResult, generatedAt time.Time) AssessmentScope {
	return AssessmentScope{
		ID:                       stableID("assessment-scope", result.Profile.ID),
		ReportType:               result.Metadata.Provenance.ReportType,
		ProfileID:                result.Metadata.Provenance.ProfileID,
		ProfileName:              result.Metadata.Provenance.ProfileName,
		GeneratedAt:              generatedAt,
		SourceIDs:                append([]string(nil), result.Metadata.Scope.SourceIDs...),
		RuntimeIDs:               append([]string(nil), result.Metadata.Scope.RuntimeIDs...),
		ControlCount:             result.Metadata.Provenance.ControlCount,
		FindingCount:             result.Metadata.Provenance.FindingCount,
		EvidenceCount:            result.Metadata.Provenance.EvidenceCount,
		RuntimeCount:             result.Metadata.Provenance.RuntimeCount,
		ExclusionCount:           result.Metadata.Scope.Exclusions.Total,
		CollectionPolicy:         result.Metadata.Scope.IncrementalFetch.Status,
		PolicyAppliedBeforeRead:  result.Metadata.Scope.IncrementalFetch.PolicyAppliedBeforeRead,
		FilteredBeforeProjection: result.Metadata.Scope.Exclusions.FilteredBeforeGraphProjection,
		RedactionMode:            result.Metadata.Redaction.DefaultMode,
	}
}

func collectionSources(runtimes []*cerebrov1.SourceRuntime, sourceIDs map[string]string, controls []grccontrol.ControlItem, items []EvidenceItemRecord) []CollectionSource {
	sourcesByRuntime := map[string]*CollectionSource{}
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		runtimeID := strings.TrimSpace(runtime.GetId())
		if runtimeID == "" {
			continue
		}
		source := &CollectionSource{
			ID:           stableID("collection-source", runtimeID),
			RuntimeID:    runtimeID,
			SourceID:     runtime.GetSourceId(),
			TenantID:     runtime.GetTenantId(),
			Status:       "configured",
			LastSyncedAt: protoTime(runtime.GetLastSyncedAt()),
		}
		if source.LastSyncedAt != "" {
			source.Status = "collected"
		}
		sourcesByRuntime[runtimeID] = source
	}
	for _, item := range items {
		ensureCollectionSource(sourcesByRuntime, sourceIDs, item.RuntimeID)
		if source := sourcesByRuntime[item.RuntimeID]; source != nil {
			source.EvidenceItemCount++
		}
	}
	findingsByRuntime := map[string]map[string]bool{}
	for _, control := range controls {
		seen := map[string]bool{}
		for _, finding := range control.Findings {
			runtimeID := strings.TrimSpace(finding.RuntimeID)
			ensureCollectionSource(sourcesByRuntime, sourceIDs, runtimeID)
			if source := sourcesByRuntime[runtimeID]; source != nil {
				if findingsByRuntime[runtimeID] == nil {
					findingsByRuntime[runtimeID] = map[string]bool{}
				}
				findingsByRuntime[runtimeID][strings.TrimSpace(finding.ID)] = true
				if !seen[runtimeID] {
					source.ControlCount++
					seen[runtimeID] = true
				}
			}
		}
	}
	for runtimeID, findingIDs := range findingsByRuntime {
		if source := sourcesByRuntime[runtimeID]; source != nil {
			source.FindingCount = len(findingIDs)
		}
	}
	sources := make([]CollectionSource, 0, len(sourcesByRuntime))
	for _, source := range sourcesByRuntime {
		sources = append(sources, *source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	return sources
}

func ensureCollectionSource(sources map[string]*CollectionSource, sourceIDs map[string]string, runtimeID string) {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" || sources[runtimeID] != nil {
		return
	}
	sources[runtimeID] = &CollectionSource{
		ID:        stableID("collection-source", runtimeID),
		RuntimeID: runtimeID,
		SourceID:  sourceIDForRuntime(sourceIDs, runtimeID),
		Status:    "observed",
	}
}

func sourceIDForRuntime(sourceIDs map[string]string, runtimeID string) string {
	runtimeID = strings.TrimSpace(runtimeID)
	if sourceID := strings.TrimSpace(sourceIDs[runtimeID]); sourceID != "" {
		return sourceID
	}
	for key, sourceID := range sourceIDs {
		if strings.TrimSpace(key) == runtimeID {
			return strings.TrimSpace(sourceID)
		}
	}
	return ""
}

func evidenceItemsFromRaw(evidence []*cerebrov1.FindingEvidence, sourceIDs map[string]string, links map[string]*recordLinks) []EvidenceItemRecord {
	items := make([]EvidenceItemRecord, 0, len(evidence))
	for _, item := range evidence {
		if item == nil {
			continue
		}
		evidenceID := strings.TrimSpace(item.GetId())
		if evidenceID == "" {
			continue
		}
		runtimeID := strings.TrimSpace(item.GetRuntimeId())
		link := links[evidenceID]
		items = append(items, EvidenceItemRecord{
			ID:               evidenceID,
			RuntimeID:        runtimeID,
			SourceID:         sourceIDForRuntime(sourceIDs, runtimeID),
			FindingID:        strings.TrimSpace(item.GetFindingId()),
			RuleID:           strings.TrimSpace(item.GetRuleId()),
			RunID:            strings.TrimSpace(item.GetRunId()),
			RunIDs:           uniqueSortedStrings(append(append([]string{}, item.GetRunIds()...), item.GetRunId())),
			ClaimIDs:         uniqueSortedStrings(item.GetClaimIds()),
			EventIDs:         uniqueSortedStrings(item.GetEventIds()),
			GraphRoots:       uniqueSortedStrings(item.GetGraphRootUrns()),
			GraphPaths:       uniqueSortedStrings(item.GetGraphPathUrns()),
			CreatedAt:        protoTime(item.GetCreatedAt()),
			LastObservedAt:   protoTime(item.GetLastObservedAt()),
			ObservationCount: item.GetObservationCount(),
			ControlIDs:       linkValues(link, "controls"),
			RequestIDs:       linkValues(link, "requests"),
			PacketIDs:        linkValues(link, "packets"),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func evidenceByID(evidence []*cerebrov1.FindingEvidence) map[string]*cerebrov1.FindingEvidence {
	byID := map[string]*cerebrov1.FindingEvidence{}
	for _, item := range evidence {
		if item != nil && strings.TrimSpace(item.GetId()) != "" {
			byID[strings.TrimSpace(item.GetId())] = item
		}
	}
	return byID
}

func evidenceClaimIDs(evidence *cerebrov1.FindingEvidence) []string {
	if evidence == nil {
		return nil
	}
	return uniqueSortedStrings(evidence.GetClaimIds())
}

func evidenceEventIDs(evidence *cerebrov1.FindingEvidence) []string {
	if evidence == nil {
		return nil
	}
	return uniqueSortedStrings(evidence.GetEventIds())
}

func evidenceGraphRoots(evidence *cerebrov1.FindingEvidence) []string {
	if evidence == nil {
		return nil
	}
	return uniqueSortedStrings(evidence.GetGraphRootUrns())
}

func evidenceRunIDs(evidence *cerebrov1.FindingEvidence) []string {
	if evidence == nil {
		return nil
	}
	return uniqueSortedStrings(append(append([]string{}, evidence.GetRunIds()...), evidence.GetRunId()))
}

func findingWorkflowFromControls(controls []grccontrol.ControlItem, rawFindings []*ports.FindingRecord, items []EvidenceItemRecord) []FindingWorkflow {
	byID := map[string]*FindingWorkflow{}
	rawByID := rawFindingsByID(rawFindings)
	for _, control := range controls {
		controlID := stableControlID(stableFrameworkID(control), control.ControlID)
		for _, finding := range control.Findings {
			id := strings.TrimSpace(finding.ID)
			if id == "" {
				continue
			}
			workflow := byID[id]
			if workflow == nil {
				workflow = &FindingWorkflow{
					ID:             id,
					Title:          finding.Title,
					Severity:       finding.Severity,
					Status:         finding.Status,
					Owner:          finding.Owner,
					SLAStatus:      finding.SLAStatus,
					RuntimeID:      finding.RuntimeID,
					SourceID:       finding.SourceID,
					RuleID:         finding.RuleID,
					LastObservedAt: formatTimePtr(finding.LastObservedAt),
					ReviewStatus:   reviewStatusForFinding(finding),
				}
				if raw := rawByID[id]; raw != nil {
					workflow.PolicyID = raw.PolicyID
					workflow.PolicyName = raw.PolicyName
					workflow.CheckID = raw.CheckID
					workflow.CheckName = raw.CheckName
					workflow.RiskScore = raw.RiskScore
					workflow.RiskReasons = append([]string(nil), raw.RiskReasons...)
					workflow.DueAt = formatTime(raw.DueAt)
					workflow.StatusReason = raw.StatusReason
				}
				byID[id] = workflow
			}
			workflow.ControlIDs = append(workflow.ControlIDs, controlID)
		}
	}
	for _, item := range items {
		if workflow := byID[item.FindingID]; workflow != nil {
			workflow.EvidenceIDs = append(workflow.EvidenceIDs, item.ID)
			workflow.PacketIDs = append(workflow.PacketIDs, item.PacketIDs...)
		}
	}
	workflows := make([]FindingWorkflow, 0, len(byID))
	for _, workflow := range byID {
		workflow.ControlIDs = uniqueSortedStrings(workflow.ControlIDs)
		workflow.EvidenceIDs = uniqueSortedStrings(workflow.EvidenceIDs)
		workflow.PacketIDs = uniqueSortedStrings(workflow.PacketIDs)
		workflows = append(workflows, *workflow)
	}
	sort.Slice(workflows, func(i, j int) bool { return workflows[i].ID < workflows[j].ID })
	return workflows
}

func resourceSubjects(rawFindings []*ports.FindingRecord, items []EvidenceItemRecord) []ResourceSubject {
	byURN := map[string]*ResourceSubject{}
	for _, item := range items {
		for _, urn := range append(append([]string{}, item.GraphRoots...), item.GraphPaths...) {
			urn = strings.TrimSpace(urn)
			if urn == "" {
				continue
			}
			subject := byURN[urn]
			if subject == nil {
				subject = &ResourceSubject{ID: stableID("resource-subject", urn), URN: urn, Kind: resourceKind(urn)}
				byURN[urn] = subject
			}
			subject.ControlIDs = append(subject.ControlIDs, item.ControlIDs...)
			subject.FindingIDs = append(subject.FindingIDs, item.FindingID)
			subject.EvidenceIDs = append(subject.EvidenceIDs, item.ID)
			subject.PacketIDs = append(subject.PacketIDs, item.PacketIDs...)
			subject.LastObservedAt = maxTimeString(subject.LastObservedAt, item.LastObservedAt)
		}
	}
	for _, finding := range rawFindings {
		if finding == nil {
			continue
		}
		for _, urn := range finding.ResourceURNs {
			urn = strings.TrimSpace(urn)
			if urn == "" {
				continue
			}
			subject := byURN[urn]
			if subject == nil {
				subject = &ResourceSubject{ID: stableID("resource-subject", urn), URN: urn, Kind: resourceKind(urn)}
				byURN[urn] = subject
			}
			subject.FindingIDs = append(subject.FindingIDs, finding.ID)
			subject.LastObservedAt = maxTimeString(subject.LastObservedAt, formatTime(finding.LastObservedAt))
		}
	}
	resources := make([]ResourceSubject, 0, len(byURN))
	for _, subject := range byURN {
		subject.ControlIDs = uniqueSortedStrings(subject.ControlIDs)
		subject.FindingIDs = uniqueSortedStrings(subject.FindingIDs)
		subject.EvidenceIDs = uniqueSortedStrings(subject.EvidenceIDs)
		subject.PacketIDs = uniqueSortedStrings(subject.PacketIDs)
		resources = append(resources, *subject)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	return resources
}

func evidenceLineageFromItems(items []EvidenceItemRecord) []EvidenceLineage {
	lineage := make([]EvidenceLineage, 0, len(items))
	for _, item := range items {
		lineage = append(lineage, EvidenceLineage{
			ID:         stableID("evidence-lineage", item.ID),
			EvidenceID: item.ID,
			FindingID:  item.FindingID,
			RuntimeID:  item.RuntimeID,
			SourceID:   item.SourceID,
			RuleID:     item.RuleID,
			RunIDs:     append([]string(nil), item.RunIDs...),
			ClaimIDs:   append([]string(nil), item.ClaimIDs...),
			EventIDs:   append([]string(nil), item.EventIDs...),
			GraphRoots: append([]string(nil), item.GraphRoots...),
			RequestIDs: append([]string(nil), item.RequestIDs...),
			PacketIDs:  append([]string(nil), item.PacketIDs...),
			ControlIDs: append([]string(nil), item.ControlIDs...),
		})
	}
	sort.Slice(lineage, func(i, j int) bool { return lineage[i].ID < lineage[j].ID })
	return lineage
}

func claimRecordsFromItems(items []EvidenceItemRecord) []ClaimRecord {
	byID := map[string]*ClaimRecord{}
	for _, item := range items {
		for _, claimID := range item.ClaimIDs {
			record := byID[claimID]
			if record == nil {
				record = &ClaimRecord{ID: claimID}
				byID[claimID] = record
			}
			record.EvidenceIDs = append(record.EvidenceIDs, item.ID)
			record.FindingIDs = append(record.FindingIDs, item.FindingID)
			record.ControlIDs = append(record.ControlIDs, item.ControlIDs...)
			record.PacketIDs = append(record.PacketIDs, item.PacketIDs...)
		}
	}
	claims := make([]ClaimRecord, 0, len(byID))
	for _, record := range byID {
		record.EvidenceIDs = uniqueSortedStrings(record.EvidenceIDs)
		record.FindingIDs = uniqueSortedStrings(record.FindingIDs)
		record.ControlIDs = uniqueSortedStrings(record.ControlIDs)
		record.PacketIDs = uniqueSortedStrings(record.PacketIDs)
		claims = append(claims, *record)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].ID < claims[j].ID })
	return claims
}

func evaluationRunsFromItems(items []EvidenceItemRecord) []EvaluationRun {
	byID := map[string]*EvaluationRun{}
	for _, item := range items {
		for _, runID := range item.RunIDs {
			record := byID[runID]
			if record == nil {
				record = &EvaluationRun{ID: runID, RuntimeID: item.RuntimeID, SourceID: item.SourceID}
				byID[runID] = record
			}
			record.RuleIDs = append(record.RuleIDs, item.RuleID)
			record.EvidenceIDs = append(record.EvidenceIDs, item.ID)
			record.FindingIDs = append(record.FindingIDs, item.FindingID)
			record.ControlIDs = append(record.ControlIDs, item.ControlIDs...)
			record.PacketIDs = append(record.PacketIDs, item.PacketIDs...)
		}
	}
	runs := make([]EvaluationRun, 0, len(byID))
	for _, record := range byID {
		record.RuleIDs = uniqueSortedStrings(record.RuleIDs)
		record.EvidenceIDs = uniqueSortedStrings(record.EvidenceIDs)
		record.FindingIDs = uniqueSortedStrings(record.FindingIDs)
		record.ControlIDs = uniqueSortedStrings(record.ControlIDs)
		record.PacketIDs = uniqueSortedStrings(record.PacketIDs)
		runs = append(runs, *record)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ID < runs[j].ID })
	return runs
}

func graphRecordsFromEvidence(evidence []*cerebrov1.FindingEvidence) ([]GraphEvidenceRecord, []GraphPathRecord) {
	rows := []GraphEvidenceRecord{}
	paths := []GraphPathRecord{}
	for _, item := range evidence {
		if item == nil {
			continue
		}
		evidenceID := strings.TrimSpace(item.GetId())
		findingID := strings.TrimSpace(item.GetFindingId())
		for rowIndex, row := range item.GetGraphRows() {
			if row == nil {
				continue
			}
			rowID := stableID("graph-row", evidenceID, fmt.Sprint(rowIndex), row.GetLabel())
			pathIDs := []string{}
			for pathIndex, path := range row.GetPaths() {
				if path == nil {
					continue
				}
				pathID := stableID("graph-path", evidenceID, fmt.Sprint(rowIndex), fmt.Sprint(pathIndex), path.GetFromUrn(), path.GetRelation(), path.GetToUrn())
				pathIDs = append(pathIDs, pathID)
				paths = append(paths, GraphPathRecord{
					ID:         pathID,
					EvidenceID: evidenceID,
					FindingID:  findingID,
					FromURN:    path.GetFromUrn(),
					FromType:   path.GetFromType(),
					Relation:   path.GetRelation(),
					ToURN:      path.GetToUrn(),
					ToType:     path.GetToType(),
					ObservedAt: path.GetObservedAt(),
					Attributes: path.GetAttributes(),
				})
			}
			rows = append(rows, GraphEvidenceRecord{
				ID:         rowID,
				EvidenceID: evidenceID,
				FindingID:  findingID,
				Label:      row.GetLabel(),
				Attributes: row.GetAttributes(),
				PathIDs:    uniqueSortedStrings(pathIDs),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	sort.Slice(paths, func(i, j int) bool { return paths[i].ID < paths[j].ID })
	return rows, paths
}

func exceptionsForControl(control ControlPosture, packetControl compliance.ControlEvidencePacketControl) []ExceptionAcceptance {
	exceptions := []ExceptionAcceptance{}
	for _, id := range packetControl.Overrides.ExceptionIDs {
		exceptions = append(exceptions, ExceptionAcceptance{ID: stableID("exception", control.ID, id), ControlID: control.ID, FrameworkID: control.FrameworkID, Type: "exception", Status: "active"})
	}
	for _, id := range packetControl.Overrides.NotApplicableIDs {
		exceptions = append(exceptions, ExceptionAcceptance{ID: stableID("not-applicable", control.ID, id), ControlID: control.ID, FrameworkID: control.FrameworkID, Type: "not_applicable", Status: "active"})
	}
	return exceptions
}

func exceptionIDsForControl(controlID string, packetControl compliance.ControlEvidencePacketControl) []string {
	ids := []string{}
	for _, id := range packetControl.Overrides.ExceptionIDs {
		ids = append(ids, stableID("exception", controlID, id))
	}
	for _, id := range packetControl.Overrides.NotApplicableIDs {
		ids = append(ids, stableID("not-applicable", controlID, id))
	}
	return uniqueSortedStrings(ids)
}

func exportArtifacts(export EvidenceExport, snapshot AuditSnapshot) []EvidenceExportArtifact {
	artifacts := make([]EvidenceExportArtifact, 0, len(export.Formats))
	for _, format := range export.Formats {
		artifacts = append(artifacts, EvidenceExportArtifact{
			ID:          stableID("evidence-export-artifact", snapshot.ID, format),
			SnapshotID:  snapshot.ID,
			Format:      format,
			Redaction:   export.Redaction,
			Path:        export.Path,
			ContentHash: snapshot.Hash,
			Included:    true,
		})
	}
	return artifacts
}

func packetsForExpectation(control ControlPosture, request EvidenceRequest, items []compliance.ControlEvidencePacketEvidenceItem, rawEvidence map[string]*cerebrov1.FindingEvidence, expectation compliance.ControlEvidenceExpectationPosture, generatedAt time.Time) []EvidencePacket {
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
		raw := rawEvidence[evidenceID]
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
				EventIDs:    evidenceEventIDs(raw),
				ClaimIDs:    evidenceClaimIDs(raw),
				GraphRoots:  evidenceGraphRoots(raw),
				RunIDs:      evidenceRunIDs(raw),
			},
			Freshness: freshness,
			Review:    reviewFor(packetID, reviewStatus, item.Reason, generatedAt),
			ExportArtifact: EvidenceExportRef{
				Format: "json",
			},
		})
	}
	return packets
}

func testResults(controlID string, item grccontrol.ControlItem, evidenceIDs map[string][]string) []ControlTestResult {
	results := make([]ControlTestResult, 0, len(item.MappedRules))
	failingRules := failingRulesByID(item.Findings)
	for _, ruleID := range item.MappedRules {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			continue
		}
		result := "pass"
		if failingRules[ruleID] {
			result = "fail"
		}
		results = append(results, ControlTestResult{
			ID:              stableID("control-test", controlID, ruleID),
			RuleID:          ruleID,
			ControlID:       controlID,
			Status:          strings.TrimSpace(item.Status),
			Result:          result,
			EvidenceQuality: strings.TrimSpace(item.EvidenceQuality),
			FindingIDs:      findingIDsForRule(item.Findings, ruleID),
			EvidenceIDs:     uniqueSortedStrings(evidenceIDs[ruleID]),
			LastObservedAt:  lastObservedForRule(item.Findings, ruleID),
		})
	}
	return results
}

func evidenceIDsByRule(items []compliance.ControlEvidencePacketEvidenceItem) map[string][]string {
	byRule := map[string][]string{}
	for _, item := range items {
		ruleID := strings.TrimSpace(item.RuleID)
		if ruleID != "" {
			byRule[ruleID] = append(byRule[ruleID], strings.TrimSpace(item.ID))
		}
	}
	return byRule
}

func findingIDsForRule(findings []grccontrol.FindingItem, ruleID string) []string {
	ids := []string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.RuleID) == ruleID {
			ids = append(ids, finding.ID)
		}
	}
	return uniqueSortedStrings(ids)
}

func lastObservedForRule(findings []grccontrol.FindingItem, ruleID string) string {
	latest := ""
	for _, finding := range findings {
		if strings.TrimSpace(finding.RuleID) == ruleID {
			latest = maxTimeString(latest, formatTimePtr(finding.LastObservedAt))
		}
	}
	return latest
}

func failingRulesByID(findings []grccontrol.FindingItem) map[string]bool {
	failing := map[string]bool{}
	for _, finding := range findings {
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID != "" && !findingClosed(finding.Status) {
			failing[ruleID] = true
		}
	}
	return failing
}

func findingClosed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "closed", "fixed", "resolved", "accepted", "risk_accepted", "suppressed", "false_positive":
		return true
	default:
		return false
	}
}

func frameworksFromControls(controls []ControlPosture) []FrameworkPosture {
	byID := map[string]*FrameworkPosture{}
	for _, control := range controls {
		id := firstNonEmpty(control.FrameworkID, "default")
		framework := byID[id]
		if framework == nil {
			framework = &FrameworkPosture{
				ID:        id,
				Name:      firstNonEmpty(control.FrameworkName, id),
				Version:   control.FrameworkVersion,
				Lifecycle: control.FrameworkLifecycle,
				Status:    "ready",
			}
			byID[id] = framework
		}
		framework.ControlCount++
		notApplicable := frameworkControlNotApplicable(control.Status)
		hasEvidenceBlockers := !notApplicable && (control.MissingEvidence > 0 || control.StaleEvidence > 0)
		if !notApplicable {
			framework.MissingEvidence += control.MissingEvidence
			framework.StaleEvidence += control.StaleEvidence
		}
		framework.EvidenceScore += control.EvidenceScore
		if !hasEvidenceBlockers && (frameworkControlPassing(control.Status) || notApplicable) {
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

func frameworkControlPassing(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "passing", "ready", "satisfied", "ok":
		return true
	default:
		return false
	}
}

func frameworkControlNotApplicable(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "not_applicable")
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

func linkEvidence(links map[string]*recordLinks, evidenceID string, controlID string, requestID string, packetID string) {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return
	}
	link := links[evidenceID]
	if link == nil {
		link = &recordLinks{}
		links[evidenceID] = link
	}
	link.ControlIDs = append(link.ControlIDs, controlID)
	link.RequestIDs = append(link.RequestIDs, requestID)
	link.PacketIDs = append(link.PacketIDs, packetID)
}

func linkValues(link *recordLinks, kind string) []string {
	if link == nil {
		return nil
	}
	switch kind {
	case "controls":
		return uniqueSortedStrings(link.ControlIDs)
	case "requests":
		return uniqueSortedStrings(link.RequestIDs)
	case "packets":
		return uniqueSortedStrings(link.PacketIDs)
	default:
		return nil
	}
}

func controlTestIDs(results []ControlTestResult) []string {
	ids := make([]string, 0, len(results))
	for _, result := range results {
		ids = append(ids, result.ID)
	}
	return uniqueSortedStrings(ids)
}

func findingIDs(findings []grccontrol.FindingItem) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	return uniqueSortedStrings(ids)
}

func rawFindingsByID(findings []*ports.FindingRecord) map[string]*ports.FindingRecord {
	byID := map[string]*ports.FindingRecord{}
	for _, finding := range findings {
		if finding != nil && strings.TrimSpace(finding.ID) != "" {
			byID[strings.TrimSpace(finding.ID)] = finding
		}
	}
	return byID
}

func reviewStatusForFinding(finding grccontrol.FindingItem) string {
	if findingClosed(finding.Status) {
		return "ready"
	}
	if strings.EqualFold(finding.Severity, "critical") || strings.EqualFold(finding.Severity, "high") {
		return "blocked"
	}
	return "needs_review"
}

func resourceKind(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) >= 4 {
		return parts[len(parts)-2]
	}
	return ""
}

func maxTimeString(a string, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if b > a {
		return b
	}
	return a
}

func protoTime(value *timestamppb.Timestamp) string {
	if value == nil {
		return ""
	}
	return formatTime(value.AsTime())
}

func formatTimePtr(value *time.Time) string {
	if value == nil {
		return ""
	}
	return formatTime(*value)
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func snapshotHash(values ...any) string {
	payload, _ := json.Marshal(values)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func stableID(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		if encoded := stableIDPart(part); encoded != "" {
			clean = append(clean, encoded)
		}
	}
	if len(clean) == 0 {
		return "evidence-record"
	}
	return strings.Join(clean, ":")
}

func stableIDPart(part string) string {
	part = strings.TrimSpace(part)
	if part == "" {
		return ""
	}
	for _, r := range part {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':' || r == '.' {
			continue
		}
		return "h_" + hex.EncodeToString([]byte(part))
	}
	return part
}

func stableControlID(framework string, control string) string {
	return stableID("control", framework, control)
}

func stableFrameworkID(item grccontrol.ControlItem) string {
	if frameworkID := strings.TrimSpace(item.FrameworkID); frameworkID != "" {
		return frameworkID
	}
	return stableID("framework", item.FrameworkName)
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
		path += "?profile=" + url.QueryEscape(strings.TrimSpace(profileID))
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

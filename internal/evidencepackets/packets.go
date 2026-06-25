package evidencepackets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grccontrol"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	Scope       AssessmentScope           `json:"assessment_scope"`
	Sources     []CollectionSource        `json:"collection_sources"`
	Items       []EvidenceItemRecord      `json:"evidence_items"`
	Findings    []FindingWorkflow         `json:"finding_workflow"`
	Resources   []ResourceSubject         `json:"resource_subjects"`
	Lineage     []EvidenceLineage         `json:"evidence_lineage"`
	Exceptions  []ExceptionAcceptance     `json:"exceptions_acceptances"`
	Artifacts   []EvidenceExportArtifact  `json:"export_artifacts"`
	Export      EvidenceExport            `json:"export"`
	Snapshot    AuditSnapshot             `json:"snapshot"`
	Metadata    grccontrol.ReportMetadata `json:"metadata"`
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
	ID                 string              `json:"id"`
	FrameworkID        string              `json:"framework_id,omitempty"`
	FrameworkName      string              `json:"framework_name,omitempty"`
	Title              string              `json:"title,omitempty"`
	OwnerDomain        string              `json:"owner_domain,omitempty"`
	FrameworkVersion   string              `json:"framework_version,omitempty"`
	FrameworkLifecycle string              `json:"framework_lifecycle,omitempty"`
	FamilyID           string              `json:"family_id,omitempty"`
	FamilyName         string              `json:"family_name,omitempty"`
	Status             string              `json:"status"`
	EvidenceQuality    string              `json:"evidence_quality,omitempty"`
	EvidenceScore      int                 `json:"evidence_score"`
	AuditSummary       string              `json:"audit_summary,omitempty"`
	OpenFindings       int                 `json:"open_findings"`
	CriticalFindings   int                 `json:"critical_findings"`
	HighFindings       int                 `json:"high_findings"`
	EvidenceItems      int                 `json:"evidence_items"`
	MissingEvidence    int                 `json:"missing_evidence_items"`
	StaleEvidence      int                 `json:"stale_evidence_items"`
	MappedRules        []string            `json:"mapped_rules,omitempty"`
	Reasons            []string            `json:"reasons,omitempty"`
	Tags               []string            `json:"tags,omitempty"`
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

	packetControlsByKey := map[string]compliance.ControlEvidencePacketControl{}
	for _, control := range result.Packet.Controls {
		packetControlsByKey[controlKey(control.Control.FrameworkName, control.Control.ControlID)] = control
	}
	for _, item := range result.Controls {
		packetControl := packetControlsByKey[controlKey(item.FrameworkName, item.ControlID)]
		frameworkID := stableFrameworkID(item)
		controlID := stableControlID(frameworkID, item.ControlID)
		control := ControlPosture{
			ID:                 controlID,
			FrameworkID:        frameworkID,
			FrameworkName:      strings.TrimSpace(item.FrameworkName),
			Title:              strings.TrimSpace(item.Title),
			OwnerDomain:        strings.TrimSpace(item.OwnerDomain),
			FrameworkVersion:   strings.TrimSpace(item.FrameworkVersion),
			FrameworkLifecycle: strings.TrimSpace(item.FrameworkLifecycle),
			FamilyID:           strings.TrimSpace(item.FamilyID),
			FamilyName:         strings.TrimSpace(item.FamilyName),
			Status:             strings.TrimSpace(item.Status),
			EvidenceQuality:    strings.TrimSpace(item.EvidenceQuality),
			EvidenceScore:      item.EvidenceScore,
			AuditSummary:       strings.TrimSpace(item.AuditSummary),
			OpenFindings:       item.OpenFindings,
			CriticalFindings:   item.CriticalFindings,
			HighFindings:       item.HighFindings,
			EvidenceItems:      item.EvidenceItems,
			MissingEvidence:    item.MissingEvidence,
			StaleEvidence:      item.StaleEvidence,
			MappedRules:        append([]string(nil), item.MappedRules...),
			Reasons:            append([]string(nil), item.Reasons...),
			Tags:               append([]string(nil), item.Tags...),
			TestResults:        testResults(controlID, item),
			EvidenceRequestIDs: []string{},
			EvidencePacketIDs:  []string{},
			FindingIDs:         findingIDs(item.Findings),
			ExceptionIDs:       append([]string(nil), packetControl.Overrides.ExceptionIDs...),
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
	items := evidenceItemsFromRaw(result.Evidence, result.SourceIDs, evidenceLinks)
	findings := findingWorkflowFromControls(result.Controls, items)
	resources := resourceSubjectsFromEvidence(items)
	lineage := evidenceLineageFromItems(items)
	sources := collectionSources(result.Runtimes, result.Controls, items)
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
		ReviewOpenCount:   openReviews,
	}
	snapshot.Hash = snapshotHash(program, frameworks, controls, requests, packets, items, findings, resources, lineage, exceptions)
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
		Exceptions:  exceptions,
		Artifacts:   artifacts,
		Export:      export,
		Snapshot:    snapshot,
		Metadata:    result.Metadata,
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

func collectionSources(runtimes []*cerebrov1.SourceRuntime, controls []grccontrol.ControlItem, items []EvidenceItemRecord) []CollectionSource {
	sourcesByRuntime := map[string]*CollectionSource{}
	for _, runtime := range runtimes {
		if runtime == nil || strings.TrimSpace(runtime.GetId()) == "" {
			continue
		}
		source := &CollectionSource{
			ID:           stableID("collection-source", runtime.GetId()),
			RuntimeID:    runtime.GetId(),
			SourceID:     runtime.GetSourceId(),
			TenantID:     runtime.GetTenantId(),
			Status:       "configured",
			LastSyncedAt: protoTime(runtime.GetLastSyncedAt()),
		}
		if source.LastSyncedAt != "" {
			source.Status = "collected"
		}
		sourcesByRuntime[source.RuntimeID] = source
	}
	for _, item := range items {
		if source := sourcesByRuntime[item.RuntimeID]; source != nil {
			source.EvidenceItemCount++
		}
	}
	for _, control := range controls {
		seen := map[string]bool{}
		for _, finding := range control.Findings {
			if source := sourcesByRuntime[finding.RuntimeID]; source != nil {
				source.FindingCount++
				if !seen[source.RuntimeID] {
					source.ControlCount++
					seen[source.RuntimeID] = true
				}
			}
		}
	}
	sources := make([]CollectionSource, 0, len(sourcesByRuntime))
	for _, source := range sourcesByRuntime {
		sources = append(sources, *source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	return sources
}

func evidenceItemsFromRaw(evidence []*cerebrov1.FindingEvidence, sourceIDs map[string]string, links map[string]*recordLinks) []EvidenceItemRecord {
	items := make([]EvidenceItemRecord, 0, len(evidence))
	for _, item := range evidence {
		if item == nil || strings.TrimSpace(item.GetId()) == "" {
			continue
		}
		link := links[item.GetId()]
		items = append(items, EvidenceItemRecord{
			ID:               item.GetId(),
			RuntimeID:        item.GetRuntimeId(),
			SourceID:         sourceIDs[item.GetRuntimeId()],
			FindingID:        item.GetFindingId(),
			RuleID:           item.GetRuleId(),
			RunID:            item.GetRunId(),
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

func findingWorkflowFromControls(controls []grccontrol.ControlItem, items []EvidenceItemRecord) []FindingWorkflow {
	byID := map[string]*FindingWorkflow{}
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

func resourceSubjectsFromEvidence(items []EvidenceItemRecord) []ResourceSubject {
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
			LastObservedAt:  lastObservedForRule(item.Findings, ruleID),
		})
	}
	return results
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
			framework = &FrameworkPosture{ID: id, Name: firstNonEmpty(control.FrameworkName, id), Status: "ready"}
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

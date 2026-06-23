package grccontrol

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/resourcescope"
)

const DefaultEvidenceProfileID = "soc2-security-core"

var ErrInvalidRequest = errors.New("invalid grc control request")

type BuildInput struct {
	ProfileID string
	Framework string
	ControlID string
	Findings  []*ports.FindingRecord
	Evidence  []*cerebrov1.FindingEvidence
	SourceIDs map[string]string
	Runtimes  []*cerebrov1.SourceRuntime
	Now       time.Time
}

type CustomBuildInput struct {
	Request   compliance.ControlPackBuildRequest
	Framework string
	ControlID string
	Findings  []*ports.FindingRecord
	Evidence  []*cerebrov1.FindingEvidence
	SourceIDs map[string]string
	Runtimes  []*cerebrov1.SourceRuntime
	Now       time.Time
}

type PacketResult struct {
	Profile  Profile
	Packet   compliance.ControlEvidencePacket
	Controls []ControlItem
	Metadata ReportMetadata
}

type CustomPacketResult struct {
	Profile  Profile                          `json:"profile"`
	Packet   compliance.ControlEvidencePacket `json:"packet"`
	Controls []ControlItem                    `json:"controls"`
	Preview  compliance.ControlPackPreview    `json:"preview"`
	Metadata ReportMetadata                   `json:"metadata,omitempty"`
}

type Profile struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type ControlRef struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type FindingItem struct {
	ID             string       `json:"id"`
	Title          string       `json:"title"`
	Severity       string       `json:"severity"`
	Status         string       `json:"status"`
	TenantID       string       `json:"tenant_id,omitempty"`
	RuntimeID      string       `json:"runtime_id,omitempty"`
	SourceID       string       `json:"source_id,omitempty"`
	RuleID         string       `json:"rule_id,omitempty"`
	Controls       []ControlRef `json:"controls,omitempty"`
	EvidenceCount  int          `json:"evidence_count"`
	Owner          string       `json:"owner"`
	SLAStatus      string       `json:"sla_status"`
	LastObservedAt *time.Time   `json:"last_observed_at,omitempty"`
}

type ControlItem struct {
	FrameworkName      string        `json:"framework_name"`
	FrameworkID        string        `json:"framework_id,omitempty"`
	FrameworkVersion   string        `json:"framework_version,omitempty"`
	FrameworkLifecycle string        `json:"framework_lifecycle,omitempty"`
	FamilyID           string        `json:"family_id,omitempty"`
	FamilyName         string        `json:"family_name,omitempty"`
	ControlID          string        `json:"control_id"`
	Title              string        `json:"title,omitempty"`
	OwnerDomain        string        `json:"owner_domain,omitempty"`
	Status             string        `json:"status"`
	OpenFindings       int           `json:"open_findings"`
	CriticalFindings   int           `json:"critical_findings"`
	HighFindings       int           `json:"high_findings"`
	EvidenceItems      int           `json:"evidence_items"`
	MissingEvidence    int           `json:"missing_evidence_items,omitempty"`
	StaleEvidence      int           `json:"stale_evidence_items,omitempty"`
	Expectations       int           `json:"evidence_expectations,omitempty"`
	EvidenceScore      int           `json:"evidence_score"`
	EvidenceQuality    string        `json:"evidence_quality,omitempty"`
	AuditSummary       string        `json:"audit_summary,omitempty"`
	MappedRules        []string      `json:"mapped_rules,omitempty"`
	Reasons            []string      `json:"reasons,omitempty"`
	Tags               []string      `json:"tags,omitempty"`
	Findings           []FindingItem `json:"findings,omitempty"`
}

type ReportMetadata struct {
	Readiness  ReportReadiness  `json:"readiness"`
	Provenance ReportProvenance `json:"provenance"`
	Scope      ReportScope      `json:"scope"`
	Redaction  ReportRedaction  `json:"redaction"`
}

type ReportReadiness struct {
	Status   string                   `json:"status"`
	Score    int                      `json:"score"`
	Summary  string                   `json:"summary,omitempty"`
	Blockers []ReportReadinessBlocker `json:"blockers,omitempty"`
}

type ReportReadinessBlocker struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count,omitempty"`
}

type ReportProvenance struct {
	ReportType    string    `json:"report_type"`
	ProfileID     string    `json:"profile_id,omitempty"`
	ProfileName   string    `json:"profile_name,omitempty"`
	PacketVersion string    `json:"packet_version,omitempty"`
	GeneratedAt   time.Time `json:"generated_at"`
	ControlCount  int       `json:"control_count,omitempty"`
	FindingCount  int       `json:"finding_count,omitempty"`
	EvidenceCount int       `json:"evidence_count,omitempty"`
	RuntimeCount  int       `json:"runtime_count,omitempty"`
	SourceIDs     []string  `json:"source_ids,omitempty"`
}

type ReportScope struct {
	SourceIDs        []string               `json:"source_ids,omitempty"`
	RuntimeIDs       []string               `json:"runtime_ids,omitempty"`
	Exclusions       ReportScopeExclusions  `json:"exclusions"`
	IncrementalFetch ReportIncrementalFetch `json:"incremental_fetch"`
}

type ReportScopeExclusions struct {
	Total                         int                              `json:"total"`
	RuntimeIDs                    []string                         `json:"runtime_ids,omitempty"`
	ExcludedFamilies              []string                         `json:"excluded_families,omitempty"`
	ExcludedAssetClasses          []string                         `json:"excluded_asset_classes,omitempty"`
	ExcludedKinds                 []string                         `json:"excluded_kinds,omitempty"`
	ExcludedResourceURNs          []string                         `json:"excluded_resource_urns,omitempty"`
	ExcludedResources             []resourcescope.ResourceSelector `json:"excluded_resources,omitempty"`
	AppliedToIncrementalFetch     bool                             `json:"applied_to_incremental_fetch"`
	FilteredBeforeGraphProjection bool                             `json:"filtered_before_graph_projection"`
}

type ReportIncrementalFetch struct {
	Status                         string `json:"status"`
	PolicyAppliedBeforeRead        bool   `json:"policy_applied_before_read"`
	EventFilteringBeforeProjection bool   `json:"event_filtering_before_projection"`
	Summary                        string `json:"summary,omitempty"`
}

type ReportRedaction struct {
	DefaultMode     string   `json:"default_mode"`
	AvailableModes  []string `json:"available_modes,omitempty"`
	SensitiveFields []string `json:"sensitive_fields,omitempty"`
	Summary         string   `json:"summary,omitempty"`
}

type ReportMetadataInput struct {
	ReportType    string
	Profile       Profile
	PacketVersion string
	GeneratedAt   time.Time
	ControlCount  int
	FindingCount  int
	EvidenceCount int
	Readiness     ReportReadiness
	Runtimes      []*cerebrov1.SourceRuntime
}

func BuildBuiltinEvidencePacket(input BuildInput) (PacketResult, error) {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	profileID := strings.TrimSpace(input.ProfileID)
	if profileID == "" {
		profileID = DefaultEvidenceProfileID
	}
	profile, resolution, err := ResolveBuiltinProfile(profileID)
	if err != nil {
		return PacketResult{}, err
	}
	postureInput := compliance.ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: compliance.ResolveRuleCoverage(resolution, compliance.BuiltinRuleControlMappings()),
		Findings:     findingSignals(input.Findings),
		Evidence:     evidenceSignals(input.Evidence, input.Findings, input.SourceIDs),
		Now:          now,
	}
	packet := compliance.BuildControlEvidencePacket(postureInput)
	packet.Controls = FilterPacketControls(packet.Controls, input.Framework, input.ControlID)
	packet.Summary = SummarizePacket(packet.SelectionID, packet.Controls)
	controls := ControlItemsFromPacket(packet.Controls, input.Findings, input.SourceIDs)
	return PacketResult{
		Profile:  profile,
		Packet:   packet,
		Controls: controls,
		Metadata: BuildReportMetadata(ReportMetadataInput{
			ReportType:    "control",
			Profile:       profile,
			PacketVersion: packet.Version,
			GeneratedAt:   packet.GeneratedAt,
			ControlCount:  packet.Summary.Total,
			FindingCount:  len(input.Findings),
			EvidenceCount: len(input.Evidence),
			Readiness:     PacketReadiness(packet.Controls),
			Runtimes:      input.Runtimes,
		}),
	}, nil
}

func BuildCustomEvidencePacket(input CustomBuildInput) (CustomPacketResult, []compliance.ValidationIssue, error) {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	archetypes, err := compliance.LoadBuiltinControlArchetypeSet()
	if err != nil {
		return CustomPacketResult{}, nil, fmt.Errorf("load control archetypes: %w", err)
	}
	baseCatalog, err := compliance.LoadBuiltinControlCatalog()
	if err != nil {
		return CustomPacketResult{}, nil, fmt.Errorf("load control catalog: %w", err)
	}
	baseProfiles, err := compliance.LoadBuiltinControlProfileSet()
	if err != nil {
		return CustomPacketResult{}, nil, fmt.Errorf("load control profiles: %w", err)
	}
	preview, issues, err := compliance.BuildControlPackPreview(input.Request, archetypes, baseCatalog, baseProfiles, compliance.BuiltinRuleControlMappings())
	if err != nil || len(issues) != 0 {
		return CustomPacketResult{}, issues, err
	}
	catalogIndex, catalogIssues := compliance.BuildCatalogIndex(compliance.MergeControlCatalogs(baseCatalog, preview.Catalog))
	if len(catalogIssues) != 0 {
		return CustomPacketResult{}, catalogIssues, fmt.Errorf("%w: generated control catalog has validation issues", ErrInvalidRequest)
	}
	profiles := compliance.MergeControlProfileSets(baseProfiles, preview.Profiles)
	resolved, profileIssues := compliance.ResolveControlProfiles(catalogIndex, profiles)
	if len(profileIssues) != 0 {
		return CustomPacketResult{}, profileIssues, fmt.Errorf("%w: generated control profiles have validation issues", ErrInvalidRequest)
	}
	profileID := strings.TrimSpace(preview.Coverage.ID)
	for _, item := range resolved.Profiles {
		if strings.TrimSpace(item.Profile.ID) != profileID {
			continue
		}
		postureInput := compliance.ControlPostureInput{
			Selection:    item.Resolution,
			RuleCoverage: compliance.ResolveRuleCoverage(item.Resolution, compliance.BuiltinRuleControlMappings()),
			Findings:     findingSignals(input.Findings),
			Evidence:     evidenceSignals(input.Evidence, input.Findings, input.SourceIDs),
			Now:          now,
		}
		packet := compliance.BuildControlEvidencePacket(postureInput)
		packet.Controls = FilterPacketControls(packet.Controls, input.Framework, input.ControlID)
		packet.Summary = SummarizePacket(packet.SelectionID, packet.Controls)
		controls := ControlItemsFromPacket(packet.Controls, input.Findings, input.SourceIDs)
		return CustomPacketResult{
			Profile: Profile{
				ID:          item.Profile.ID,
				Name:        item.Profile.Name,
				Description: item.Profile.Description,
			},
			Packet:   packet,
			Controls: controls,
			Preview:  preview,
			Metadata: BuildReportMetadata(ReportMetadataInput{
				ReportType:    "control",
				Profile:       Profile{ID: item.Profile.ID, Name: item.Profile.Name, Description: item.Profile.Description},
				PacketVersion: packet.Version,
				GeneratedAt:   packet.GeneratedAt,
				ControlCount:  packet.Summary.Total,
				FindingCount:  len(input.Findings),
				EvidenceCount: len(input.Evidence),
				Readiness:     PacketReadiness(packet.Controls),
				Runtimes:      input.Runtimes,
			}),
		}, nil, nil
	}
	return CustomPacketResult{}, []compliance.ValidationIssue{{Path: "profile_id", Message: fmt.Sprintf("generated profile %q was not resolved", profileID)}}, nil
}

func ResolveBuiltinProfile(profileID string) (Profile, compliance.SelectionResolution, error) {
	catalog, err := compliance.LoadBuiltinControlCatalog()
	if err != nil {
		return Profile{}, compliance.SelectionResolution{}, fmt.Errorf("load control catalog: %w", err)
	}
	index, issues := compliance.BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		return Profile{}, compliance.SelectionResolution{}, fmt.Errorf("%w: builtin control catalog has validation issues", ErrInvalidRequest)
	}
	profiles, err := compliance.LoadBuiltinControlProfileSet()
	if err != nil {
		return Profile{}, compliance.SelectionResolution{}, fmt.Errorf("load control profiles: %w", err)
	}
	resolved, issues := compliance.ResolveControlProfiles(index, profiles)
	if len(issues) != 0 {
		return Profile{}, compliance.SelectionResolution{}, fmt.Errorf("%w: builtin control profiles have validation issues", ErrInvalidRequest)
	}
	for _, item := range resolved.Profiles {
		if strings.TrimSpace(item.Profile.ID) == strings.TrimSpace(profileID) {
			return Profile{
				ID:          item.Profile.ID,
				Name:        item.Profile.Name,
				Description: item.Profile.Description,
			}, item.Resolution, nil
		}
	}
	return Profile{}, compliance.SelectionResolution{}, fmt.Errorf("%w: control profile %q is not declared", ErrInvalidRequest, profileID)
}

func FilterPacketControls(controls []compliance.ControlEvidencePacketControl, framework, controlID string) []compliance.ControlEvidencePacketControl {
	framework = strings.TrimSpace(framework)
	controlID = strings.TrimSpace(controlID)
	if framework == "" && controlID == "" {
		return controls
	}
	filtered := make([]compliance.ControlEvidencePacketControl, 0, len(controls))
	controlQuery := strings.ToLower(controlID)
	for _, control := range controls {
		if framework != "" && !strings.EqualFold(control.Control.FrameworkName, framework) && !strings.EqualFold(control.Control.FrameworkID, framework) {
			continue
		}
		if controlQuery != "" && !strings.Contains(strings.ToLower(control.Control.ControlID), controlQuery) {
			continue
		}
		filtered = append(filtered, control)
	}
	return filtered
}

func SummarizePacket(selectionID string, controls []compliance.ControlEvidencePacketControl) compliance.ControlPostureSummary {
	summary := compliance.ControlPostureSummary{
		SelectionID: strings.TrimSpace(selectionID),
		Total:       len(controls),
		ByStatus:    map[compliance.ControlPostureStatus]int{},
	}
	for _, control := range controls {
		summary.ByStatus[control.Status]++
	}
	return summary
}

func ControlItemsFromPacket(packetControls []compliance.ControlEvidencePacketControl, findings []*ports.FindingRecord, sourceIDs map[string]string) []ControlItem {
	findingsByID := map[string]*ports.FindingRecord{}
	for _, finding := range findings {
		if finding != nil {
			findingsByID[finding.ID] = finding
		}
	}
	controls := make([]ControlItem, 0, len(packetControls))
	for _, packetControl := range packetControls {
		item := ControlItem{
			FrameworkName:      packetControl.Control.FrameworkName,
			FrameworkID:        packetControl.Control.FrameworkID,
			FrameworkVersion:   packetControl.Control.FrameworkVersion,
			FrameworkLifecycle: packetControl.Control.FrameworkLifecycle,
			FamilyID:           packetControl.Control.FamilyID,
			FamilyName:         packetControl.Control.FamilyName,
			ControlID:          packetControl.Control.ControlID,
			Title:              packetControl.Control.Title,
			OwnerDomain:        packetControl.Control.OwnerDomain,
			Status:             string(packetControl.Status),
			EvidenceItems:      len(packetControl.Evidence.Summary.EvidenceIDs),
			MissingEvidence:    len(packetControl.Evidence.Summary.MissingEvidenceIDs),
			StaleEvidence:      len(packetControl.Evidence.Summary.StaleEvidenceIDs),
			Expectations:       len(packetControl.Evidence.Expectations),
			EvidenceScore:      packetControl.Readiness.Score,
			EvidenceQuality:    string(packetControl.Readiness.Rating),
			AuditSummary:       packetControl.Readiness.Summary,
			MappedRules:        append([]string(nil), packetControl.MappedRules...),
			Reasons:            append([]string(nil), packetControl.Reasons...),
			Tags:               append([]string(nil), packetControl.Tags...),
		}
		for _, packetFinding := range packetControl.Findings {
			finding := findingsByID[packetFinding.ID]
			item.Findings = append(item.Findings, findingItem(finding, packetFinding, sourceIDs))
			if findingStatusOpen(packetFinding.Status) {
				item.OpenFindings++
				if strings.EqualFold(packetFinding.Severity, "CRITICAL") {
					item.CriticalFindings++
				}
				if strings.EqualFold(packetFinding.Severity, "HIGH") {
					item.HighFindings++
				}
			}
		}
		controls = append(controls, item)
	}
	sort.Slice(controls, func(i, j int) bool {
		left := controls[i]
		right := controls[j]
		if controlStatusRank(left.Status) != controlStatusRank(right.Status) {
			return controlStatusRank(left.Status) < controlStatusRank(right.Status)
		}
		if left.OpenFindings != right.OpenFindings {
			return left.OpenFindings > right.OpenFindings
		}
		return left.FrameworkName+left.ControlID < right.FrameworkName+right.ControlID
	})
	return controls
}

func PacketReadiness(controls []compliance.ControlEvidencePacketControl) ReportReadiness {
	if len(controls) == 0 {
		return ReportReadiness{
			Status:  "blocked",
			Score:   0,
			Summary: "No controls matched the selected packet filters.",
			Blockers: []ReportReadinessBlocker{{
				Code:  "no_controls",
				Label: "No controls matched",
				Count: 1,
			}},
		}
	}
	readiness := ReportReadiness{
		Status:  "ready",
		Score:   100,
		Summary: "Packet is ready for auditor review.",
	}
	scoreTotal := 0
	counts := map[string]int{}
	for _, control := range controls {
		scoreTotal += control.Readiness.Score
		switch control.Status {
		case compliance.ControlPostureFailing:
			counts["open_findings"] += maxInt(1, len(control.Findings))
		case compliance.ControlPostureMissingEvidence:
			counts["missing_evidence"] += maxInt(1, control.Readiness.MissingEvidence)
		case compliance.ControlPostureStaleEvidence:
			counts["stale_evidence"] += maxInt(1, control.Readiness.StaleEvidence)
		case compliance.ControlPostureManualReview:
			counts["manual_review"] += 1
		case compliance.ControlPostureException:
			counts["exceptions"] += 1
		}
	}
	readiness.Score = scoreTotal / len(controls)
	addBlocker := func(code string, label string) {
		if count := counts[code]; count > 0 {
			readiness.Blockers = append(readiness.Blockers, ReportReadinessBlocker{Code: code, Label: label, Count: count})
		}
	}
	addBlocker("open_findings", "Open findings remain mapped")
	addBlocker("missing_evidence", "Required evidence is missing")
	addBlocker("stale_evidence", "Evidence is stale")
	addBlocker("manual_review", "Manual evidence needs review")
	addBlocker("exceptions", "Exceptions limit reliance")
	if len(readiness.Blockers) != 0 {
		readiness.Status = "needs_attention"
		readiness.Summary = "Packet is useful, but blockers must be resolved or accepted before auditor reliance."
	}
	if counts["open_findings"] > 0 || counts["missing_evidence"] > 0 {
		readiness.Status = "blocked"
		readiness.Summary = "Packet is not audit-ready until open findings or missing evidence are addressed."
	}
	return readiness
}

func BuildReportMetadata(input ReportMetadataInput) ReportMetadata {
	generatedAt := input.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	scope := ReportScopeFromRuntimes(input.Runtimes)
	sourceIDs := scope.SourceIDs
	if len(sourceIDs) == 0 {
		sourceIDs = uniqueSortedRuntimeSourceIDs(input.Runtimes)
	}
	return ReportMetadata{
		Readiness: input.Readiness,
		Provenance: ReportProvenance{
			ReportType:    fallbackString(input.ReportType, "packet"),
			ProfileID:     input.Profile.ID,
			ProfileName:   input.Profile.Name,
			PacketVersion: input.PacketVersion,
			GeneratedAt:   generatedAt,
			ControlCount:  input.ControlCount,
			FindingCount:  input.FindingCount,
			EvidenceCount: input.EvidenceCount,
			RuntimeCount:  len(input.Runtimes),
			SourceIDs:     sourceIDs,
		},
		Scope: scope,
		Redaction: ReportRedaction{
			DefaultMode:    "share_safe",
			AvailableModes: []string{"share_safe", "internal"},
			SensitiveFields: []string{
				"finding IDs",
				"resource URNs",
				"runtime IDs",
				"source-specific identifiers",
				"identity labels",
			},
			Summary: "Use share-safe mode before sending packets outside the operating team.",
		},
	}
}

func ReportScopeFromRuntimes(runtimes []*cerebrov1.SourceRuntime) ReportScope {
	scope := ReportScope{
		SourceIDs:  uniqueSortedRuntimeSourceIDs(runtimes),
		RuntimeIDs: uniqueSortedRuntimeIDs(runtimes),
		IncrementalFetch: ReportIncrementalFetch{
			Status:                         "all_collected",
			PolicyAppliedBeforeRead:        true,
			EventFilteringBeforeProjection: true,
			Summary:                        "No collection exclusions are configured for the selected source runtimes.",
		},
	}
	excludedRuntimeIDs := []string{}
	families := []string{}
	assetClasses := []string{}
	kinds := []string{}
	resourceURNs := []string{}
	resources := []resourcescope.ResourceSelector{}
	for _, runtime := range runtimes {
		if runtime == nil {
			continue
		}
		policy, err := resourcescope.FromConfig(runtime.GetConfig())
		if err != nil || policy.Empty() {
			continue
		}
		excludedRuntimeIDs = append(excludedRuntimeIDs, runtime.GetId())
		families = append(families, policy.ExcludedFamilies...)
		assetClasses = append(assetClasses, policy.ExcludedAssetClasses...)
		kinds = append(kinds, policy.ExcludedKinds...)
		resourceURNs = append(resourceURNs, policy.ExcludedResourceURNs...)
		resources = append(resources, policy.ExcludedResources...)
	}
	scope.Exclusions = ReportScopeExclusions{
		RuntimeIDs:           uniqueSortedStrings(excludedRuntimeIDs),
		ExcludedFamilies:     uniqueSortedStrings(families),
		ExcludedAssetClasses: uniqueSortedStrings(assetClasses),
		ExcludedKinds:        uniqueSortedStrings(kinds),
		ExcludedResourceURNs: uniqueSortedStrings(resourceURNs),
		ExcludedResources:    uniqueSortedResources(resources),
	}
	scope.Exclusions.Total =
		len(scope.Exclusions.ExcludedFamilies) +
			len(scope.Exclusions.ExcludedAssetClasses) +
			len(scope.Exclusions.ExcludedKinds) +
			len(scope.Exclusions.ExcludedResourceURNs) +
			len(scope.Exclusions.ExcludedResources)
	if scope.Exclusions.Total > 0 {
		scope.Exclusions.AppliedToIncrementalFetch = true
		scope.Exclusions.FilteredBeforeGraphProjection = true
		scope.IncrementalFetch.Status = "exclusions_applied"
		scope.IncrementalFetch.Summary = "Configured exclusions are evaluated before source reads where possible and again before graph projection."
	}
	return scope
}

func RenderMarkdown(result PacketResult) string {
	var builder strings.Builder
	writeMarkdownLine(&builder, "# Control Evidence Packet")
	writeMarkdownLine(&builder, "")
	writeMarkdownLine(&builder, "- Profile: "+markdownValue(fallbackString(result.Profile.Name, result.Profile.ID)))
	writeMarkdownLine(&builder, "- Profile ID: "+markdownValue(result.Profile.ID))
	writeMarkdownLine(&builder, "- Generated: "+markdownTime(result.Packet.GeneratedAt))
	writeMarkdownLine(&builder, "- Controls: "+fmt.Sprintf("%d", result.Packet.Summary.Total))
	writeMarkdownLine(&builder, "- Failing controls: "+fmt.Sprintf("%d", result.Packet.Summary.ByStatus[compliance.ControlPostureFailing]))
	writeMarkdownLine(&builder, "- Missing-evidence controls: "+fmt.Sprintf("%d", result.Packet.Summary.ByStatus[compliance.ControlPostureMissingEvidence]))
	writeMarkdownLine(&builder, "- Stale-evidence controls: "+fmt.Sprintf("%d", result.Packet.Summary.ByStatus[compliance.ControlPostureStaleEvidence]))
	writeMarkdownLine(&builder, "- Readiness: "+markdownValue(result.Metadata.Readiness.Status)+" ("+fmt.Sprintf("%d", result.Metadata.Readiness.Score)+"/100)")
	writeMarkdownLine(&builder, "- Collection exclusions: "+fmt.Sprintf("%d", result.Metadata.Scope.Exclusions.Total))
	for _, control := range result.Packet.Controls {
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "## "+markdownHeading(control.Control.FrameworkName+" "+control.Control.ControlID))
		if title := strings.TrimSpace(control.Control.Title); title != "" {
			writeMarkdownLine(&builder, "")
			writeMarkdownLine(&builder, markdownValue(title))
		}
		writeMarkdownLine(&builder, "")
		writeMarkdownLine(&builder, "- Status: "+markdownValue(string(control.Status)))
		writeMarkdownLine(&builder, "- Evidence quality: "+markdownValue(string(control.Readiness.Rating)))
		writeMarkdownLine(&builder, "- Evidence score: "+fmt.Sprintf("%d", control.Readiness.Score))
		writeMarkdownLine(&builder, "- Owner domain: "+markdownValue(control.Control.OwnerDomain))
		if control.Readiness.Summary != "" {
			writeMarkdownLine(&builder, "- Auditor summary: "+markdownValue(control.Readiness.Summary))
		}
		if len(control.Reasons) != 0 {
			writeMarkdownLine(&builder, "")
			writeMarkdownLine(&builder, "### Assessment Notes")
			for _, reason := range control.Reasons {
				writeMarkdownLine(&builder, "- "+markdownValue(reason))
			}
		}
		writeExpectationsMarkdown(&builder, control.Evidence.Expectations)
		writeEvidenceItemsMarkdown(&builder, control.Evidence.Items)
		writeFindingsMarkdown(&builder, control.Findings)
	}
	return strings.TrimRight(builder.String(), "\n") + "\n"
}

func RenderCustomMarkdown(result CustomPacketResult) string {
	return RenderMarkdown(PacketResult{
		Profile: result.Profile,
		Packet:  result.Packet,
	})
}

func writeExpectationsMarkdown(builder *strings.Builder, expectations []compliance.ControlEvidenceExpectationPosture) {
	if len(expectations) == 0 {
		return
	}
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "### Evidence Expectations")
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "| Expectation | Type | Required | Status | Quality | Freshness | Evidence |")
	writeMarkdownLine(builder, "| --- | --- | --- | --- | --- | --- | --- |")
	for _, expectation := range expectations {
		writeMarkdownRow(builder,
			markdownCell(fallbackString(expectation.Title, expectation.ID)),
			markdownCell(expectation.Type),
			markdownCell(fmt.Sprintf("%t", expectation.Required)),
			markdownCell(string(expectation.Status)),
			markdownCell(string(expectation.Quality)),
			markdownCell(expectation.FreshnessSLA),
			markdownCell(strings.Join(expectation.EvidenceIDs, ", ")),
		)
	}
}

func writeEvidenceItemsMarkdown(builder *strings.Builder, evidence []compliance.ControlEvidencePacketEvidenceItem) {
	if len(evidence) == 0 {
		return
	}
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "### Evidence Items")
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "| ID | Type | Status | Quality | Observed | Expires | Collection |")
	writeMarkdownLine(builder, "| --- | --- | --- | --- | --- | --- | --- |")
	for _, item := range evidence {
		writeMarkdownRow(builder,
			markdownCell(item.ID),
			markdownCell(item.EvidenceType),
			markdownCell(item.Status),
			markdownCell(string(item.Quality)),
			markdownCell(markdownTime(item.ObservedAt)),
			markdownCell(markdownTime(item.ExpiresAt)),
			markdownCell(item.Source),
		)
	}
}

func writeFindingsMarkdown(builder *strings.Builder, findings []compliance.ControlEvidencePacketFinding) {
	if len(findings) == 0 {
		return
	}
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "### Open Findings")
	writeMarkdownLine(builder, "")
	writeMarkdownLine(builder, "| ID | Severity | Status | Rule | Title | Last Observed |")
	writeMarkdownLine(builder, "| --- | --- | --- | --- | --- | --- |")
	for _, finding := range findings {
		writeMarkdownRow(builder,
			markdownCell(finding.ID),
			markdownCell(finding.Severity),
			markdownCell(finding.Status),
			markdownCell(finding.RuleID),
			markdownCell(finding.Title),
			markdownCell(markdownTime(finding.LastObservedAt)),
		)
	}
}

func writeMarkdownLine(builder *strings.Builder, line string) {
	builder.WriteString(line)
	builder.WriteByte('\n')
}

func writeMarkdownRow(builder *strings.Builder, cells ...string) {
	builder.WriteString("| ")
	builder.WriteString(strings.Join(cells, " | "))
	builder.WriteString(" |\n")
}

func markdownHeading(value string) string {
	value = markdownSingleLine(value)
	if value == "" {
		return "Control"
	}
	return escapeMarkdownText(value)
}

func markdownCell(value string) string {
	value = markdownSingleLine(value)
	if value == "" {
		return "-"
	}
	return escapeMarkdownText(value)
}

func markdownValue(value string) string {
	value = markdownSingleLine(value)
	if value == "" {
		return "Not specified"
	}
	return escapeMarkdownText(value)
}

func markdownSingleLine(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func escapeMarkdownText(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		switch char {
		case '\\', '`', '*', '_', '~', '[', ']', '(', ')', '#', '!', '<', '>', '|':
			builder.WriteByte('\\')
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

func markdownTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}

func findingSignals(findings []*ports.FindingRecord) []compliance.ControlFindingSignal {
	items := make([]compliance.ControlFindingSignal, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		items = append(items, compliance.ControlFindingSignal{
			ID:              finding.ID,
			RuleID:          finding.RuleID,
			Title:           fallbackString(finding.Title, finding.RuleID, finding.ID),
			Status:          finding.Status,
			Severity:        finding.Severity,
			ControlRefs:     complianceControlRefs(finding.ControlRefs),
			FirstObservedAt: finding.FirstObservedAt,
			LastObservedAt:  finding.LastObservedAt,
		})
	}
	return items
}

func evidenceSignals(evidence []*cerebrov1.FindingEvidence, findings []*ports.FindingRecord, sourceIDs map[string]string) []compliance.ControlEvidenceSignal {
	findingsByID := map[string]*ports.FindingRecord{}
	for _, finding := range findings {
		if finding != nil {
			findingsByID[finding.ID] = finding
		}
	}
	items := make([]compliance.ControlEvidenceSignal, 0, len(evidence))
	for _, record := range evidence {
		if record == nil {
			continue
		}
		attributes := record.GetAttributes()
		signal := compliance.ControlEvidenceSignal{
			ID:           record.GetId(),
			RuleID:       record.GetRuleId(),
			EvidenceType: fallbackString(attributes["evidence_type"], attributes["type"], "finding-evidence"),
			Status:       fallbackString(attributes["status"], "valid"),
			Source:       fallbackString(attributes["source"], attributes["source_id"], sourceIDs[record.GetRuntimeId()], record.GetRuntimeId()),
			ObservedAt:   evidenceObservedAt(record),
			ExpiresAt:    parseEvidenceTime(attributes["expires_at"]),
			Manual:       strings.EqualFold(attributes["manual"], "true"),
		}
		if finding := findingsByID[record.GetFindingId()]; finding != nil {
			signal.ControlRefs = complianceControlRefs(finding.ControlRefs)
		}
		items = append(items, signal)
	}
	return items
}

func findingItem(finding *ports.FindingRecord, packetFinding compliance.ControlEvidencePacketFinding, sourceIDs map[string]string) FindingItem {
	if finding == nil {
		return FindingItem{
			ID:        packetFinding.ID,
			Title:     fallbackString(packetFinding.Title, packetFinding.RuleID, packetFinding.ID),
			Severity:  strings.ToUpper(strings.TrimSpace(packetFinding.Severity)),
			Status:    normalizedFindingStatus(packetFinding.Status),
			RuleID:    packetFinding.RuleID,
			Owner:     "Unassigned",
			SLAStatus: "no_due_date",
		}
	}
	return FindingItem{
		ID:             finding.ID,
		Title:          fallbackString(finding.Title, finding.RuleID, finding.ID),
		Severity:       strings.ToUpper(strings.TrimSpace(finding.Severity)),
		Status:         normalizedFindingStatus(finding.Status),
		TenantID:       finding.TenantID,
		RuntimeID:      finding.RuntimeID,
		SourceID:       sourceIDs[finding.RuntimeID],
		RuleID:         finding.RuleID,
		Controls:       controlRefs(finding.ControlRefs),
		Owner:          fallbackString(finding.Assignee, "Unassigned"),
		SLAStatus:      "no_due_date",
		LastObservedAt: timePtr(finding.LastObservedAt),
	}
}

func complianceControlRefs(refs []ports.FindingControlRef) []compliance.ControlRef {
	items := make([]compliance.ControlRef, 0, len(refs))
	for _, ref := range refs {
		framework := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if framework == "" || controlID == "" {
			continue
		}
		items = append(items, compliance.ControlRef{FrameworkName: framework, ControlID: controlID})
	}
	return items
}

func controlRefs(refs []ports.FindingControlRef) []ControlRef {
	items := make([]ControlRef, 0, len(refs))
	for _, ref := range refs {
		framework := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if framework == "" || controlID == "" {
			continue
		}
		items = append(items, ControlRef{FrameworkName: framework, ControlID: controlID})
	}
	return items
}

func evidenceObservedAt(record *cerebrov1.FindingEvidence) time.Time {
	if record.GetLastObservedAt() != nil {
		return record.GetLastObservedAt().AsTime().UTC()
	}
	if record.GetCreatedAt() != nil {
		return record.GetCreatedAt().AsTime().UTC()
	}
	return time.Time{}
}

func parseEvidenceTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func normalizedFindingStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(status)
}

func findingStatusOpen(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "open")
}

func controlStatusRank(status string) int {
	switch compliance.ControlPostureStatus(strings.TrimSpace(status)) {
	case compliance.ControlPostureFailing:
		return 0
	case compliance.ControlPostureMissingEvidence:
		return 1
	case compliance.ControlPostureStaleEvidence:
		return 2
	case compliance.ControlPostureManualReview:
		return 3
	case compliance.ControlPostureException:
		return 4
	case compliance.ControlPosturePassing:
		return 5
	case compliance.ControlPostureNotApplicable:
		return 6
	default:
		return 7
	}
}

func fallbackString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func uniqueSortedRuntimeSourceIDs(runtimes []*cerebrov1.SourceRuntime) []string {
	values := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			values = append(values, runtime.GetSourceId())
		}
	}
	return uniqueSortedStrings(values)
}

func uniqueSortedRuntimeIDs(runtimes []*cerebrov1.SourceRuntime) []string {
	values := make([]string, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime != nil {
			values = append(values, runtime.GetId())
		}
	}
	return uniqueSortedStrings(values)
}

func uniqueSortedStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedResources(values []resourcescope.ResourceSelector) []resourcescope.ResourceSelector {
	out := make([]resourcescope.ResourceSelector, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		key := strings.TrimSpace(value.URN) + "\x00" + strings.ToLower(strings.TrimSpace(value.Type)) + "\x00" + strings.TrimSpace(value.ID)
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].URN + out[i].Type + out[i].ID
		right := out[j].URN + out[j].Type + out[j].ID
		return left < right
	})
	return out
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func timePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

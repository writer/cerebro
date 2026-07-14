package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type FrameworkSummary struct {
	ID           string               `json:"id,omitempty"`
	Name         string               `json:"name"`
	Version      string               `json:"framework_version,omitempty"`
	Lifecycle    string               `json:"lifecycle"`
	Description  string               `json:"description,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	FamilyCount  int                  `json:"family_count"`
	ControlCount int                  `json:"control_count"`
	Maturity     FrameworkMaturity    `json:"maturity"`
	Coverage     FrameworkCoverage    `json:"coverage"`
	Readiness    FrameworkReadiness   `json:"readiness"`
	GapActions   []FrameworkGapAction `json:"gap_actions,omitempty"`
}

type FrameworkMaturity struct {
	Status  string `json:"status"`
	Score   int    `json:"score"`
	Summary string `json:"summary,omitempty"`
}

type FrameworkCoverage struct {
	SelectedControls int `json:"selected_controls"`
	MappedControls   int `json:"mapped_controls"`
	UnmappedControls int `json:"unmapped_controls"`
	MappedRules      int `json:"mapped_rules"`
}

type FrameworkReadiness struct {
	AuditorReadyControls    int `json:"auditor_ready_controls"`
	NeedsEnrichmentControls int `json:"needs_enrichment_controls"`
	PlaceholderControls     int `json:"placeholder_controls"`
}

type FrameworkGapAction struct {
	Code     string `json:"code"`
	Label    string `json:"label"`
	Priority int    `json:"priority"`
	Count    int    `json:"count,omitempty"`
}

type FrameworksResponse struct {
	Version     string             `json:"version"`
	Frameworks  []FrameworkSummary `json:"frameworks"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlArchetypesResponse struct {
	Version     string             `json:"version"`
	Archetypes  []ControlArchetype `json:"archetypes"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlProfilesResponse struct {
	Version     string                   `json:"version"`
	Profiles    []ControlCoverageProfile `json:"profiles"`
	GeneratedAt time.Time                `json:"generated_at"`
}

type ControlCoverageResponse struct {
	Version     string                   `json:"version"`
	Profiles    []ControlCoverageProfile `json:"profiles"`
	GeneratedAt time.Time                `json:"generated_at"`
}

type ControlPackResponse struct {
	Preview     ControlPackPreview `json:"preview"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlPackIssueResponse struct {
	Issues      []ValidationIssue `json:"issues"`
	GeneratedAt time.Time         `json:"generated_at"`
}

func BuiltinFrameworks(generatedAt time.Time) (FrameworksResponse, error) {
	catalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		return FrameworksResponse{}, fmt.Errorf("load control catalog: %w", err)
	}
	coverageIndex, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return FrameworksResponse{}, fmt.Errorf("load control coverage index: %w", err)
	}
	coverageByFramework := aggregateFrameworkCoverage(coverageIndex.Profiles)
	frameworks := make([]FrameworkSummary, 0, len(catalog.Frameworks))
	for _, framework := range catalog.Frameworks {
		lifecycle := normalizeFrameworkLifecycle(framework.Lifecycle)
		summary := FrameworkSummary{
			ID:          strings.TrimSpace(framework.ID),
			Name:        strings.TrimSpace(framework.Name),
			Version:     strings.TrimSpace(framework.Version),
			Lifecycle:   lifecycle,
			Description: strings.TrimSpace(framework.Description),
			Tags:        sortedUniqueStrings(framework.Tags),
			FamilyCount: len(framework.Families),
		}
		for _, family := range framework.Families {
			summary.ControlCount += len(family.Controls)
		}
		aggregate := coverageByFramework[frameworkAggregationKey(summary.ID, summary.Name)]
		if aggregate != nil {
			summary.Coverage = FrameworkCoverage{
				SelectedControls: aggregate.selectedControls,
				MappedControls:   aggregate.mappedControls,
				UnmappedControls: aggregate.unmappedControls,
				MappedRules:      len(aggregate.mappedRules),
			}
			summary.Readiness = FrameworkReadiness{
				AuditorReadyControls:    aggregate.auditorReadyControls,
				NeedsEnrichmentControls: aggregate.needsEnrichmentControls,
				PlaceholderControls:     aggregate.placeholderControls,
			}
		}
		summary.Maturity = frameworkMaturity(lifecycle, summary.Coverage, summary.Readiness)
		summary.GapActions = frameworkGapActions(lifecycle, summary.Coverage, summary.Readiness)
		frameworks = append(frameworks, summary)
	}
	sort.Slice(frameworks, func(i, j int) bool {
		if frameworks[i].Lifecycle != frameworks[j].Lifecycle {
			return frameworks[i].Lifecycle < frameworks[j].Lifecycle
		}
		return frameworks[i].Name < frameworks[j].Name
	})
	return FrameworksResponse{
		Version:     strings.TrimSpace(catalog.Version),
		Frameworks:  frameworks,
		GeneratedAt: generatedAt,
	}, nil
}

type frameworkCoverageAggregate struct {
	selectedControls        int
	mappedControls          int
	unmappedControls        int
	auditorReadyControls    int
	needsEnrichmentControls int
	placeholderControls     int
	mappedRules             map[string]struct{}
	seenControls            map[string]struct{}
}

func aggregateFrameworkCoverage(profiles []ControlCoverageProfile) map[string]*frameworkCoverageAggregate {
	aggregates := map[string]*frameworkCoverageAggregate{}
	for _, profile := range profiles {
		for _, control := range profile.Controls {
			key := frameworkAggregationKey(control.FrameworkID, control.FrameworkName)
			if key == "" {
				continue
			}
			aggregate := aggregates[key]
			if aggregate == nil {
				aggregate = &frameworkCoverageAggregate{
					mappedRules:  map[string]struct{}{},
					seenControls: map[string]struct{}{},
				}
				aggregates[key] = aggregate
			}
			controlKey := strings.ToLower(strings.TrimSpace(control.FamilyID)) + "\x00" + strings.ToLower(strings.TrimSpace(control.ControlID))
			if _, seen := aggregate.seenControls[controlKey]; seen {
				for _, ruleID := range control.MappedRules {
					if ruleID = strings.TrimSpace(ruleID); ruleID != "" {
						aggregate.mappedRules[ruleID] = struct{}{}
					}
				}
				continue
			}
			aggregate.seenControls[controlKey] = struct{}{}
			aggregate.selectedControls++
			if len(control.MappedRules) != 0 || len(control.MappedControlRefs) != 0 || control.RuleCount > 0 || strings.EqualFold(control.CoverageStatus, "mapped") {
				aggregate.mappedControls++
			} else {
				aggregate.unmappedControls++
			}
			switch control.AuditReadiness.Status {
			case ControlReadinessAuditorReady:
				aggregate.auditorReadyControls++
			case ControlReadinessNeedsEnrichment:
				aggregate.needsEnrichmentControls++
			case ControlReadinessPlaceholder:
				aggregate.placeholderControls++
			}
			for _, ruleID := range control.MappedRules {
				if ruleID = strings.TrimSpace(ruleID); ruleID != "" {
					aggregate.mappedRules[ruleID] = struct{}{}
				}
			}
		}
	}
	return aggregates
}

func frameworkAggregationKey(id, name string) string {
	if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
		return "id:" + id
	}
	if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
		return "name:" + name
	}
	return ""
}

func frameworkMaturity(lifecycle string, coverage FrameworkCoverage, readiness FrameworkReadiness) FrameworkMaturity {
	if lifecycle == FrameworkLifecycleUpcoming {
		return FrameworkMaturity{
			Status:  "planning",
			Score:   0,
			Summary: "Framework is discoverable for scoping, but controls are not measured yet.",
		}
	}
	if coverage.SelectedControls == 0 {
		return FrameworkMaturity{
			Status:  "not_configured",
			Score:   0,
			Summary: "No measured controls are available yet.",
		}
	}
	if readiness.AuditorReadyControls == coverage.SelectedControls {
		return FrameworkMaturity{
			Status:  "audit_ready",
			Score:   100,
			Summary: "All selected controls are auditor-ready.",
		}
	}
	score := (readiness.AuditorReadyControls*100 + readiness.NeedsEnrichmentControls*60 + readiness.PlaceholderControls*20) / coverage.SelectedControls
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	status := "mapped"
	summary := "Controls are mapped and ready for evidence review."
	if readiness.PlaceholderControls > 0 {
		status = "needs_catalog_work"
		summary = "Some controls still need catalog metadata before audit use."
	} else if readiness.NeedsEnrichmentControls > 0 {
		status = "needs_evidence_plan"
		summary = "Some controls need richer evidence plans before audit use."
	} else if coverage.UnmappedControls > 0 {
		status = "needs_mapping"
		summary = "Some controls still need rule or evidence mapping."
	}
	return FrameworkMaturity{Status: status, Score: score, Summary: summary}
}

func frameworkGapActions(lifecycle string, coverage FrameworkCoverage, readiness FrameworkReadiness) []FrameworkGapAction {
	if lifecycle == FrameworkLifecycleUpcoming {
		return []FrameworkGapAction{{
			Code:     "plan_framework_scope",
			Label:    "Define applicability, owners, and initial control scope.",
			Priority: 1,
		}}
	}
	actions := []FrameworkGapAction{}
	if coverage.SelectedControls == 0 {
		return []FrameworkGapAction{{
			Code:     "select_controls",
			Label:    "Select controls for the framework tracking scope.",
			Priority: 1,
		}}
	}
	if coverage.UnmappedControls > 0 {
		actions = append(actions, FrameworkGapAction{
			Code:     "map_controls",
			Label:    "Map controls to rules or evidence sources.",
			Priority: 1,
			Count:    coverage.UnmappedControls,
		})
	}
	incompleteReadiness := readiness.NeedsEnrichmentControls + readiness.PlaceholderControls
	if incompleteReadiness > 0 {
		actions = append(actions, FrameworkGapAction{
			Code:     "enrich_evidence_plan",
			Label:    "Complete audit objectives, procedures, and evidence expectations.",
			Priority: 2,
			Count:    incompleteReadiness,
		})
	}
	notAuditorReady := coverage.SelectedControls - readiness.AuditorReadyControls
	if notAuditorReady > 0 {
		actions = append(actions, FrameworkGapAction{
			Code:     "close_readiness_gaps",
			Label:    "Review non-ready controls and close audit readiness gaps.",
			Priority: 3,
			Count:    notAuditorReady,
		})
	}
	if len(actions) == 0 {
		actions = append(actions, FrameworkGapAction{
			Code:     "export_audit_packet",
			Label:    "Export an audit packet for review.",
			Priority: 4,
		})
	}
	return actions
}

func BuiltinControlArchetypes(generatedAt time.Time) (ControlArchetypesResponse, error) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		return ControlArchetypesResponse{}, fmt.Errorf("load control archetypes: %w", err)
	}
	return ControlArchetypesResponse{
		Version:     strings.TrimSpace(archetypes.Version),
		Archetypes:  archetypes.Archetypes,
		GeneratedAt: generatedAt,
	}, nil
}

func BuiltinControlProfiles(profileIDs []string, generatedAt time.Time) (ControlProfilesResponse, error) {
	index, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return ControlProfilesResponse{}, fmt.Errorf("load control coverage index: %w", err)
	}
	return ControlProfilesResponse{
		Version:     strings.TrimSpace(index.Version),
		Profiles:    filterControlCoverageProfiles(index.Profiles, profileIDs),
		GeneratedAt: generatedAt,
	}, nil
}

func BuiltinControlCoverage(profileIDs []string, generatedAt time.Time) (ControlCoverageResponse, error) {
	index, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return ControlCoverageResponse{}, fmt.Errorf("load control coverage index: %w", err)
	}
	return ControlCoverageResponse{
		Version:     strings.TrimSpace(index.Version),
		Profiles:    filterControlCoverageProfiles(index.Profiles, profileIDs),
		GeneratedAt: generatedAt,
	}, nil
}

func BuildBuiltinControlPackResponse(request ControlPackBuildRequest, ruleMappings []RuleControlMapping, generatedAt time.Time) (ControlPackResponse, []ValidationIssue, error) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control archetypes: %w", err)
	}
	baseCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control catalog: %w", err)
	}
	baseProfiles, err := LoadBuiltinControlProfileSet()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control profiles: %w", err)
	}
	preview, issues, err := BuildControlPackPreview(request, archetypes, baseCatalog, baseProfiles, ruleMappings)
	if err != nil {
		return ControlPackResponse{}, nil, err
	}
	if len(issues) != 0 {
		return ControlPackResponse{}, issues, nil
	}
	return ControlPackResponse{Preview: preview, GeneratedAt: generatedAt}, nil, nil
}

func filterControlCoverageProfiles(profiles []ControlCoverageProfile, ids []string) []ControlCoverageProfile {
	wanted := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			wanted[id] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return profiles
	}
	filtered := []ControlCoverageProfile{}
	for _, profile := range profiles {
		if _, ok := wanted[strings.TrimSpace(profile.ID)]; ok {
			filtered = append(filtered, profile)
		}
	}
	return filtered
}

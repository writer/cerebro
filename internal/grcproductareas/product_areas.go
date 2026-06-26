package grcproductareas

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

type Status string

const (
	StatusAttention Status = "attention"
	StatusMapped    Status = "mapped"
	StatusQuiet     Status = "quiet"
)

type Workflow struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type Area struct {
	ID                 string     `json:"id"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	Href               string     `json:"href"`
	Workflows          []Workflow `json:"workflows"`
	SourceFamilies     []string   `json:"source_families"`
	CoverageDimensions []string   `json:"coverage_dimensions"`
	EvidenceTypes      []string   `json:"evidence_types"`
	ControlDomains     []string   `json:"control_domains"`
}

type View struct {
	Area
	BlindSpots []sourcecoverage.Record `json:"blind_spots,omitempty"`
	Detail     string                  `json:"detail"`
	Signal     string                  `json:"signal"`
	Status     Status                  `json:"status"`
}

type BuildInput struct {
	CoverageBlindSpots []sourcecoverage.Record
	HasCoverageContext bool
}

var registry = []Area{
	{
		ID:          "compliance",
		Title:       "Compliance",
		Description: "Frameworks, common controls, tests, policies, documents, audits, and issues.",
		Href:        "/frameworks",
		Workflows: []Workflow{
			{Label: "Frameworks", Href: "/frameworks"},
			{Label: "Controls", Href: "/controls"},
			{Label: "Documents", Href: "/evidence"},
			{Label: "Audits", Href: "/reports"},
			{Label: "Issues", Href: "/risk-inbox"},
		},
		SourceFamilies:     []string{"framework", "control", "control_test", "policy", "document", "authorization_package", "poam_item"},
		CoverageDimensions: []string{"frameworks", "controls", "control_tests", "policies", "authorization_packages", "poam_items"},
		EvidenceTypes:      []string{"control_catalog", "control_assessment", "policy_document", "configuration_state"},
		ControlDomains:     []string{"compliance_operations", "security_operations"},
	},
	{
		ID:          "customer_trust",
		Title:       "Customer Trust",
		Description: "Trust packets, customer accounts, questionnaires, commitments, knowledge base content, and activity.",
		Href:        "/reports",
		Workflows: []Workflow{
			{Label: "Reports", Href: "/reports"},
			{Label: "Evidence", Href: "/evidence"},
			{Label: "Schedules", Href: "/reports/schedules"},
			{Label: "Questionnaires", Href: "/risk-inbox?source_id=grc&q=questionnaire"},
			{Label: "Activity", Href: "/developer/audit-log"},
		},
		SourceFamilies:     []string{"document", "contract", "control_test", "policy", "authorization_package", "assurance_document", "security_questionnaire", "customer_commitment", "event_log"},
		CoverageDimensions: []string{"policies", "contracts", "control_tests", "authorization_packages", "assurance_documents", "security_questionnaires", "customer_commitments", "audit_event_logs"},
		EvidenceTypes:      []string{"control_assessment", "policy_document", "source_snapshot", "assurance_package", "questionnaire_response", "audit_event"},
		ControlDomains:     []string{"compliance_operations", "customer_assurance"},
	},
	{
		ID:          "risk",
		Title:       "Risk",
		Description: "Risk register, risk library, action tracker, resilience objectives, notifications, and POA&M plans.",
		Href:        "/risk-inbox",
		Workflows: []Workflow{
			{Label: "Risk Inbox", Href: "/risk-inbox"},
			{Label: "Impact Map", Href: "/impact"},
			{Label: "Risk Scoring", Href: "/developer/risk-scoring"},
			{Label: "Trends", Href: "/trends"},
		},
		SourceFamilies:     []string{"risk_scenario", "recovery_objective", "regulatory_notification", "poam_item"},
		CoverageDimensions: []string{"risk_scenarios", "recovery_objectives", "regulatory_notifications", "poam_items"},
		EvidenceTypes:      []string{"source_snapshot", "configuration_state", "risk_register", "risk_treatment"},
		ControlDomains:     []string{"security_operations", "asset_inventory", "risk_management"},
	},
	{
		ID:          "vendors",
		Title:       "Vendors",
		Description: "Vendor inventory, security reviews, discovered vendors, contracts, and vendor risk attributes.",
		Href:        "/risk-inbox?source_id=grc&q=vendor",
		Workflows: []Workflow{
			{Label: "Vendor Findings", Href: "/risk-inbox?source_id=grc&q=vendor"},
			{Label: "Contracts", Href: "/evidence?source_id=grc&q=contract"},
			{Label: "Assessments", Href: "/risk-inbox?source_id=grc&q=assessment"},
			{Label: "Connector Scope", Href: "/connectors/grc?tab=scope"},
		},
		SourceFamilies:     []string{"vendor", "discovered_vendor", "vendor_risk_attribute", "contract", "security_review"},
		CoverageDimensions: []string{"vendors", "discovered_vendors", "vendor_risk_attributes", "contracts", "security_reviews"},
		EvidenceTypes:      []string{"third_party_risk", "source_snapshot", "security_review"},
		ControlDomains:     []string{"vendor_risk"},
	},
	{
		ID:          "privacy",
		Title:       "Privacy",
		Description: "Data inventory, privacy assessments, processing evidence, contracts, and policy coverage.",
		Href:        "/evidence?source_id=grc&q=privacy",
		Workflows: []Workflow{
			{Label: "Data Inventory", Href: "/inventory?q=data"},
			{Label: "Assessments", Href: "/risk-inbox?source_id=grc&q=privacy"},
			{Label: "Policies", Href: "/evidence?source_id=grc&q=policy"},
			{Label: "Vendors", Href: "/risk-inbox?source_id=grc&q=vendor"},
		},
		SourceFamilies:     []string{"data_inventory", "privacy_assessment", "policy", "document", "contract", "vendor", "risk_scenario"},
		CoverageDimensions: []string{"data_inventory", "privacy_assessments", "policies", "contracts", "vendors", "risk_scenarios"},
		EvidenceTypes:      []string{"privacy_assessment", "policy_document", "source_snapshot", "third_party_risk"},
		ControlDomains:     []string{"privacy_operations", "compliance_operations", "vendor_risk"},
	},
	{
		ID:          "assets",
		Title:       "Assets",
		Description: "Asset inventory, code changes, vulnerabilities, affected assets, and security alerts.",
		Href:        "/inventory",
		Workflows: []Workflow{
			{Label: "Inventory", Href: "/inventory"},
			{Label: "Vulnerabilities", Href: "/risk-inbox?source_id=grc&q=vulnerability"},
			{Label: "Impact", Href: "/impact"},
			{Label: "Trends", Href: "/trends"},
		},
		SourceFamilies:     []string{"integration", "vulnerability", "vulnerable_asset", "vulnerability_remediation", "event_log"},
		CoverageDimensions: []string{"integrations", "vulnerabilities", "vulnerable_assets", "vulnerability_remediations", "audit_event_logs"},
		EvidenceTypes:      []string{"source_snapshot", "relationship_evidence", "vulnerability_management", "audit_event", "code_change"},
		ControlDomains:     []string{"asset_inventory", "vulnerability_management", "security_operations"},
	},
	{
		ID:          "personnel",
		Title:       "Personnel",
		Description: "People, users, groups, device ownership, access posture, and training attestations.",
		Href:        "/inventory?q=people",
		Workflows: []Workflow{
			{Label: "People", Href: "/inventory?q=people"},
			{Label: "Access", Href: "/risk-inbox?source_id=grc&q=access"},
			{Label: "Groups", Href: "/connectors/grc?tab=scope&q=group"},
			{Label: "Training", Href: "/evidence?source_id=grc&q=training"},
		},
		SourceFamilies:     []string{"person", "user", "group", "training_attestation"},
		CoverageDimensions: []string{"people", "users", "groups", "training_attestations"},
		EvidenceTypes:      []string{"source_snapshot", "configuration_state", "access_review", "training_attestation"},
		ControlDomains:     []string{"identity_access", "security_operations"},
	},
	{
		ID:          "integrations",
		Title:       "Integrations",
		Description: "Connector health, source scope, collection activity, event logs, and source-CDK onboarding.",
		Href:        "/connectors",
		Workflows: []Workflow{
			{Label: "Connectors", Href: "/connectors"},
			{Label: "Source CDK", Href: "/connectors/source-cdk"},
			{Label: "Mission Control", Href: "/mission-control"},
			{Label: "Audit Log", Href: "/developer/audit-log"},
		},
		SourceFamilies:     []string{"integration", "event_log"},
		CoverageDimensions: []string{"integrations", "audit_event_logs"},
		EvidenceTypes:      []string{"source_snapshot", "audit_event", "runtime_activity"},
		ControlDomains:     []string{"asset_inventory", "security_operations"},
	},
}

var (
	knownCoverageDimensions = stringSet(flatMapAreas(func(area Area) []string { return area.CoverageDimensions }))
	knownSourceFamilies     = stringSet(flatMapAreas(func(area Area) []string { return area.SourceFamilies }))
)

func Catalog() []Area {
	areas := make([]Area, 0, len(registry))
	for _, area := range registry {
		areas = append(areas, cloneArea(area))
	}
	return areas
}

func BuildCoverageViews(coverage []sourcecoverage.Record) []View {
	return BuildViews(BuildInput{
		CoverageBlindSpots: sourcecoverage.BlindSpots(coverage),
		HasCoverageContext: len(coverage) > 0,
	})
}

func BuildViews(input BuildInput) []View {
	views := make([]View, 0, len(registry))
	for _, area := range registry {
		blindSpots := matchingBlindSpots(area, input.CoverageBlindSpots)
		status := statusFor(len(blindSpots), input.HasCoverageContext)
		views = append(views, View{
			Area:       cloneArea(area),
			BlindSpots: cloneRecords(blindSpots),
			Detail:     detailFor(area, len(blindSpots)),
			Signal:     signalFor(status, len(blindSpots)),
			Status:     status,
		})
	}
	return views
}

func MatchesCoverage(area Area, record sourcecoverage.Record) bool {
	dimensionID := strings.TrimSpace(record.DimensionID)
	family := strings.TrimSpace(record.Family)
	if contains(area.CoverageDimensions, dimensionID) || contains(area.SourceFamilies, family) {
		return true
	}
	if knownCoverageDimensions[dimensionID] || (family != "" && knownSourceFamilies[family]) {
		return false
	}
	return fallbackOwner(record) == area.ID
}

func matchingBlindSpots(area Area, records []sourcecoverage.Record) []sourcecoverage.Record {
	matches := make([]sourcecoverage.Record, 0)
	for _, record := range records {
		if MatchesCoverage(area, record) {
			matches = append(matches, record)
		}
	}
	return matches
}

func statusFor(blindSpotCount int, hasCoverageContext bool) Status {
	if blindSpotCount > 0 {
		return StatusAttention
	}
	if hasCoverageContext {
		return StatusMapped
	}
	return StatusQuiet
}

func detailFor(area Area, blindSpotCount int) string {
	if blindSpotCount > 0 {
		return fmt.Sprintf("%d coverage gap%s", blindSpotCount, pluralSuffix(blindSpotCount))
	}
	return fmt.Sprintf("%d workflows | %d dimensions | %d families", len(area.Workflows), len(area.CoverageDimensions), len(area.SourceFamilies))
}

func signalFor(status Status, blindSpotCount int) string {
	switch status {
	case StatusAttention:
		return fmt.Sprintf("%d gap%s", blindSpotCount, pluralSuffix(blindSpotCount))
	case StatusMapped:
		return "mapped"
	default:
		return "awaiting coverage"
	}
}

func fallbackOwner(record sourcecoverage.Record) string {
	owner := ""
	for _, area := range registry {
		if !fallbackMatches(area, record) {
			continue
		}
		if owner != "" {
			return ""
		}
		owner = area.ID
	}
	return owner
}

func fallbackMatches(area Area, record sourcecoverage.Record) bool {
	return intersects(area.EvidenceTypes, record.EvidenceTypes) || intersects(area.ControlDomains, record.ControlDomains)
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func flatMapAreas(values func(Area) []string) []string {
	var out []string
	for _, area := range registry {
		out = append(out, values(area)...)
	}
	return out
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = true
		}
	}
	return set
}

func contains(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func intersects(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	lookup := stringSet(left)
	for _, value := range right {
		if lookup[strings.TrimSpace(value)] {
			return true
		}
	}
	return false
}

func cloneArea(area Area) Area {
	area.Workflows = cloneWorkflows(area.Workflows)
	area.SourceFamilies = cloneStrings(area.SourceFamilies)
	area.CoverageDimensions = cloneStrings(area.CoverageDimensions)
	area.EvidenceTypes = cloneStrings(area.EvidenceTypes)
	area.ControlDomains = cloneStrings(area.ControlDomains)
	return area
}

func cloneWorkflows(workflows []Workflow) []Workflow {
	return append([]Workflow(nil), workflows...)
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneRecords(records []sourcecoverage.Record) []sourcecoverage.Record {
	out := make([]sourcecoverage.Record, 0, len(records))
	for _, record := range records {
		record.KnownUnsupportedFields = cloneStrings(record.KnownUnsupportedFields)
		record.Notes = cloneStrings(record.Notes)
		record.EvidenceTypes = cloneStrings(record.EvidenceTypes)
		record.ControlDomains = cloneStrings(record.ControlDomains)
		record.ControlRefs = append(record.ControlRefs[:0:0], record.ControlRefs...)
		record.SupportedRuntimeFamilies = cloneStrings(record.SupportedRuntimeFamilies)
		out = append(out, record)
	}
	return out
}

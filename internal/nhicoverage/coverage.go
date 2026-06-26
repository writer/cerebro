package nhicoverage

import (
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

const Version = "nhi-coverage/v1"

const (
	LaneInventory   = "inventory"
	LaneCredential  = "credential"
	LaneEntitlement = "entitlement"
	LaneTrust       = "trust"
	LaneExposure    = "exposure"
	LaneActivity    = "activity"
)

type Report struct {
	Version            string              `json:"version"`
	GeneratedAt        string              `json:"generated_at,omitempty"`
	TenantID           string              `json:"tenant_id,omitempty"`
	SourceID           string              `json:"source_id,omitempty"`
	Totals             Totals              `json:"totals"`
	Gate               sourcecoverage.Gate `json:"gate"`
	Records            []Record            `json:"records"`
	BlindSpots         []Record            `json:"blind_spots"`
	Summaries          []Summary           `json:"summaries"`
	LaneSummaries      []LaneSummary       `json:"lane_summaries"`
	BlindSpotSummaries []Summary           `json:"blind_spot_summaries"`
}

type SourceCoverageResponse struct {
	sourcecoverage.Report
	NHICoverage Report `json:"nhi_coverage"`
}

type Record struct {
	sourcecoverage.Record
	Lane        string `json:"lane"`
	SubjectKind string `json:"subject_kind"`
}

type Totals struct {
	Dimensions          int `json:"dimensions"`
	HighValueDimensions int `json:"high_value_dimensions"`
	Healthy             int `json:"healthy"`
	Partial             int `json:"partial"`
	Unsupported         int `json:"unsupported"`
	Unconfigured        int `json:"unconfigured"`
	Stale               int `json:"stale"`
	Failed              int `json:"failed"`
	Unknown             int `json:"unknown"`
	BlindSpots          int `json:"blind_spots"`
}

type Summary struct {
	SourceID     string `json:"source_id"`
	Lane         string `json:"lane"`
	Total        int    `json:"total"`
	Healthy      int    `json:"healthy"`
	Partial      int    `json:"partial"`
	Unsupported  int    `json:"unsupported"`
	Unconfigured int    `json:"unconfigured"`
	Stale        int    `json:"stale"`
	Failed       int    `json:"failed"`
	Unknown      int    `json:"unknown"`
	BlindSpots   int    `json:"blind_spots"`
}

type LaneSummary struct {
	Lane         string `json:"lane"`
	Total        int    `json:"total"`
	Healthy      int    `json:"healthy"`
	Partial      int    `json:"partial"`
	Unsupported  int    `json:"unsupported"`
	Unconfigured int    `json:"unconfigured"`
	Stale        int    `json:"stale"`
	Failed       int    `json:"failed"`
	Unknown      int    `json:"unknown"`
	BlindSpots   int    `json:"blind_spots"`
}

type classification struct {
	lane        string
	subjectKind string
}

func WithSourceCoverage(report sourcecoverage.Report) SourceCoverageResponse {
	return SourceCoverageResponse{
		Report:      report,
		NHICoverage: FromSourceCoverage(report),
	}
}

func FromSourceCoverage(report sourcecoverage.Report) Report {
	records := RecordsFromCoverage(report.Records)
	blindSpots := BlindSpots(records)
	totals := TotalsFor(records)
	return Report{
		Version:            Version,
		GeneratedAt:        report.GeneratedAt,
		TenantID:           report.TenantID,
		SourceID:           report.SourceID,
		Totals:             totals,
		Gate:               GateForTotals(totals),
		Records:            records,
		BlindSpots:         blindSpots,
		Summaries:          Summaries(records),
		LaneSummaries:      LaneSummaries(records),
		BlindSpotSummaries: Summaries(blindSpots),
	}
}

func RecordsFromCoverage(records []sourcecoverage.Record) []Record {
	out := make([]Record, 0, len(records))
	for _, record := range records {
		class, ok := classify(record)
		if !ok {
			continue
		}
		out = append(out, Record{
			Record:      cloneCoverageRecord(record),
			Lane:        class.lane,
			SubjectKind: class.subjectKind,
		})
	}
	sortRecords(out)
	return out
}

func BlindSpots(records []Record) []Record {
	out := make([]Record, 0)
	for _, record := range records {
		if record.BlindSpot {
			out = append(out, cloneRecord(record))
		}
	}
	return out
}

func TotalsFor(records []Record) Totals {
	var totals Totals
	for _, record := range records {
		totals.Dimensions++
		if record.HighValue {
			totals.HighValueDimensions++
		}
		addStateToTotals(record.State, &totals)
		if record.BlindSpot {
			totals.BlindSpots++
		}
	}
	return totals
}

func GateForTotals(totals Totals) sourcecoverage.Gate {
	switch {
	case totals.Failed > 0:
		return sourcecoverage.Gate{Status: "fail", BlockingReason: "failed"}
	case totals.BlindSpots > 0:
		return sourcecoverage.Gate{Status: "fail", BlockingReason: "blind_spot"}
	case totals.Stale > 0:
		return sourcecoverage.Gate{Status: "warn", BlockingReason: "stale"}
	case totals.Unconfigured > 0:
		return sourcecoverage.Gate{Status: "warn", BlockingReason: "unconfigured"}
	case totals.Unsupported > 0:
		return sourcecoverage.Gate{Status: "warn", BlockingReason: "unsupported"}
	case totals.Partial > 0:
		return sourcecoverage.Gate{Status: "warn", BlockingReason: "partial"}
	case totals.Unknown > 0:
		return sourcecoverage.Gate{Status: "warn", BlockingReason: "unknown"}
	default:
		return sourcecoverage.Gate{Status: "pass", BlockingReason: "none"}
	}
}

func Summaries(records []Record) []Summary {
	bySourceLane := map[string]*Summary{}
	for _, record := range records {
		sourceID := strings.TrimSpace(record.SourceID)
		if sourceID == "" {
			sourceID = "unknown"
		}
		lane := strings.TrimSpace(record.Lane)
		if lane == "" {
			lane = "unknown"
		}
		key := sourceID + "\x00" + lane
		summary := bySourceLane[key]
		if summary == nil {
			summary = &Summary{SourceID: sourceID, Lane: lane}
			bySourceLane[key] = summary
		}
		addRecordToSummary(record, summary)
	}
	summaries := make([]Summary, 0, len(bySourceLane))
	for _, summary := range bySourceLane {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i int, j int) bool {
		if summaries[i].BlindSpots != summaries[j].BlindSpots {
			return summaries[i].BlindSpots > summaries[j].BlindSpots
		}
		if summaries[i].Total != summaries[j].Total {
			return summaries[i].Total > summaries[j].Total
		}
		if summaries[i].SourceID != summaries[j].SourceID {
			return summaries[i].SourceID < summaries[j].SourceID
		}
		return summaries[i].Lane < summaries[j].Lane
	})
	return summaries
}

func LaneSummaries(records []Record) []LaneSummary {
	byLane := map[string]*LaneSummary{}
	for _, record := range records {
		lane := strings.TrimSpace(record.Lane)
		if lane == "" {
			lane = "unknown"
		}
		summary := byLane[lane]
		if summary == nil {
			summary = &LaneSummary{Lane: lane}
			byLane[lane] = summary
		}
		addRecordToLaneSummary(record, summary)
	}
	summaries := make([]LaneSummary, 0, len(byLane))
	for _, summary := range byLane {
		summaries = append(summaries, *summary)
	}
	sort.Slice(summaries, func(i int, j int) bool {
		if summaries[i].BlindSpots != summaries[j].BlindSpots {
			return summaries[i].BlindSpots > summaries[j].BlindSpots
		}
		if summaries[i].Total != summaries[j].Total {
			return summaries[i].Total > summaries[j].Total
		}
		return summaries[i].Lane < summaries[j].Lane
	})
	return summaries
}

func classify(record sourcecoverage.Record) (classification, bool) {
	if strings.TrimSpace(record.DimensionType) == "remediation_state" {
		return classification{}, false
	}
	text := normalizedRecordText(record)
	if text == "" {
		return classification{}, false
	}
	if record.DimensionType == "audit_event" && hasAny(text, activityTerms) {
		return classification{lane: LaneActivity, subjectKind: subjectKindFor(text, LaneActivity)}, true
	}
	if hasAny(text, credentialTerms) {
		return classification{lane: LaneCredential, subjectKind: subjectKindFor(text, LaneCredential)}, true
	}
	if hasAny(text, trustTerms) {
		return classification{lane: LaneTrust, subjectKind: subjectKindFor(text, LaneTrust)}, true
	}
	if hasAny(text, entitlementTerms) || (record.DimensionType == "app_entitlement" && hasAny(text, identityTerms)) {
		return classification{lane: LaneEntitlement, subjectKind: subjectKindFor(text, LaneEntitlement)}, true
	}
	if hasAny(text, exposureTerms) {
		return classification{lane: LaneExposure, subjectKind: subjectKindFor(text, LaneExposure)}, true
	}
	if hasAny(text, identityTerms) {
		return classification{lane: LaneInventory, subjectKind: subjectKindFor(text, LaneInventory)}, true
	}
	return classification{}, false
}

var identityTerms = []string{
	"application",
	"applications",
	"app_registration",
	"app_registrations",
	"bot",
	"client_application",
	"managed_identity",
	"managed_identities",
	"machine_user",
	"oauth_app",
	"oauth_apps",
	"oauth_client",
	"oauth_clients",
	"service_account",
	"service_accounts",
	"service_principal",
	"service_principals",
}

var credentialTerms = []string{
	"access_key",
	"access_keys",
	"admin_api_key",
	"api_key",
	"api_keys",
	"api_token",
	"api_tokens",
	"application_credential",
	"application_credentials",
	"client_secret",
	"client_secrets",
	"codebuild_source_credential",
	"external_key",
	"external_keys",
	"key_vault_secret",
	"key_vault_secrets",
	"project_api_key",
	"secret_manager_secret",
	"secret_manager_secrets",
	"service_account_key",
	"service_account_keys",
	"service_principal_credential",
	"service_principal_credentials",
	"source_credential",
	"source_credentials",
	"tokens_and_keys",
}

var trustTerms = []string{
	"federated",
	"federation",
	"federations",
	"iam_role_trust",
	"identity_pool",
	"identity_pools",
	"identity_provider",
	"identity_providers",
	"impersonation",
	"impersonations",
	"oidc",
	"saml_provider",
	"trusted_origin",
	"workload_identity",
	"workload_identities",
}

var entitlementTerms = []string{
	"account_assignment",
	"account_assignments",
	"app_assignment",
	"app_assignments",
	"cluster_role",
	"cluster_roles",
	"permission",
	"permissions",
	"permission_set",
	"permission_sets",
	"policy_assignment",
	"policy_assignments",
	"rbac",
	"role_binding",
	"role_bindings",
	"service_account_role",
	"service_account_roles",
}

var exposureTerms = []string{
	"cross_account",
	"external_principal",
	"external_principals",
	"internet",
	"public",
	"shared_secret",
}

var activityTerms = []string{
	"access_key",
	"api_key",
	"api_token",
	"client_secret",
	"codebuild_source_credential",
	"external_key",
	"impersonation",
	"service_account",
	"service_principal",
	"service_principal_credential",
	"workload_identity",
}

func subjectKindFor(text string, lane string) string {
	switch {
	case hasAny(text, []string{"service_account_key", "service_account_keys"}):
		return "service_account_key"
	case hasAny(text, []string{"service_account", "service_accounts"}):
		return "service_account"
	case hasAny(text, []string{"service_principal", "service_principals"}):
		return "service_principal"
	case hasAny(text, []string{"managed_identity", "managed_identities"}):
		return "managed_identity"
	case hasAny(text, []string{"workload_identity", "workload_identities"}):
		return "workload_identity"
	case hasAny(text, []string{"api_token", "api_tokens"}):
		return "api_token"
	case hasAny(text, []string{"api_key", "api_keys", "project_api_key", "admin_api_key", "tokens_and_keys"}):
		return "api_key"
	case hasAny(text, []string{"access_key", "access_keys"}):
		return "access_key"
	case hasAny(text, []string{"oauth_client", "oauth_clients", "oauth_app", "oauth_apps"}):
		return "oauth_client"
	case hasAny(text, []string{"client_secret", "client_secrets"}):
		return "client_secret"
	case hasAny(text, []string{"external_key", "external_keys"}):
		return "external_key"
	case hasAny(text, []string{"credential", "credentials"}):
		return "credential"
	case hasAny(text, []string{"token", "tokens"}):
		return "token"
	case hasAny(text, []string{"secret", "secrets"}):
		return "secret"
	case hasAny(text, []string{"rbac", "role_binding", "role_bindings", "cluster_role", "cluster_roles"}):
		return "rbac"
	case hasAny(text, []string{"permission", "permissions", "permission_set", "permission_sets"}):
		return "permission"
	case hasAny(text, []string{"federation", "federations", "federated"}):
		return "federation"
	case hasAny(text, []string{"impersonation", "impersonations"}):
		return "impersonation"
	case hasAny(text, []string{"external_principal", "external_principals"}):
		return "external_principal"
	case hasAny(text, []string{"application", "applications", "app_registration", "app_registrations", "client_application"}):
		return "application"
	case lane == LaneCredential:
		return "credential"
	case lane == LaneEntitlement:
		return "entitlement"
	case lane == LaneTrust:
		return "trust"
	default:
		return "identity"
	}
}

func normalizedRecordText(record sourcecoverage.Record) string {
	parts := []string{
		record.SourceID,
		record.DimensionID,
		record.DimensionType,
		record.Title,
		record.Family,
	}
	parts = append(parts, record.EvidenceTypes...)
	parts = append(parts, record.ControlDomains...)
	parts = append(parts, record.SupportedRuntimeFamilies...)
	return normalize(strings.Join(parts, " "))
}

func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "_", ".", "_", "/", "_", " ", "_", ":", "_")
	value = replacer.Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func hasAny(value string, terms []string) bool {
	for _, term := range terms {
		if containsTerm(value, term) {
			return true
		}
	}
	return false
}

func containsTerm(value string, term string) bool {
	value = "_" + normalize(value) + "_"
	term = "_" + normalize(term) + "_"
	return strings.Contains(value, term)
}

func sortRecords(records []Record) {
	sort.Slice(records, func(i int, j int) bool {
		if records[i].SourceID != records[j].SourceID {
			return records[i].SourceID < records[j].SourceID
		}
		if records[i].Lane != records[j].Lane {
			return records[i].Lane < records[j].Lane
		}
		if records[i].BlindSpot != records[j].BlindSpot {
			return records[i].BlindSpot
		}
		if stateRank(records[i].State) != stateRank(records[j].State) {
			return stateRank(records[i].State) < stateRank(records[j].State)
		}
		return records[i].DimensionID < records[j].DimensionID
	})
}

func addRecordToSummary(record Record, summary *Summary) {
	summary.Total++
	addStateToSummary(record.State, summary)
	if record.BlindSpot {
		summary.BlindSpots++
	}
}

func addRecordToLaneSummary(record Record, summary *LaneSummary) {
	summary.Total++
	addStateToLaneSummary(record.State, summary)
	if record.BlindSpot {
		summary.BlindSpots++
	}
}

func addStateToTotals(state string, totals *Totals) {
	switch state {
	case sourcecoverage.StateHealthy:
		totals.Healthy++
	case sourcecoverage.StatePartial:
		totals.Partial++
	case sourcecoverage.StateUnsupported:
		totals.Unsupported++
	case sourcecoverage.StateUnconfigured:
		totals.Unconfigured++
	case sourcecoverage.StateStale:
		totals.Stale++
	case sourcecoverage.StateFailed:
		totals.Failed++
	default:
		totals.Unknown++
	}
}

func addStateToSummary(state string, summary *Summary) {
	switch state {
	case sourcecoverage.StateHealthy:
		summary.Healthy++
	case sourcecoverage.StatePartial:
		summary.Partial++
	case sourcecoverage.StateUnsupported:
		summary.Unsupported++
	case sourcecoverage.StateUnconfigured:
		summary.Unconfigured++
	case sourcecoverage.StateStale:
		summary.Stale++
	case sourcecoverage.StateFailed:
		summary.Failed++
	default:
		summary.Unknown++
	}
}

func addStateToLaneSummary(state string, summary *LaneSummary) {
	switch state {
	case sourcecoverage.StateHealthy:
		summary.Healthy++
	case sourcecoverage.StatePartial:
		summary.Partial++
	case sourcecoverage.StateUnsupported:
		summary.Unsupported++
	case sourcecoverage.StateUnconfigured:
		summary.Unconfigured++
	case sourcecoverage.StateStale:
		summary.Stale++
	case sourcecoverage.StateFailed:
		summary.Failed++
	default:
		summary.Unknown++
	}
}

func stateRank(state string) int {
	switch state {
	case sourcecoverage.StateFailed:
		return 0
	case sourcecoverage.StateStale:
		return 1
	case sourcecoverage.StateUnconfigured:
		return 2
	case sourcecoverage.StateUnsupported:
		return 3
	case sourcecoverage.StatePartial:
		return 4
	case sourcecoverage.StateUnknown:
		return 5
	case sourcecoverage.StateHealthy:
		return 6
	default:
		return 7
	}
}

func cloneRecord(record Record) Record {
	return Record{
		Record:      cloneCoverageRecord(record.Record),
		Lane:        record.Lane,
		SubjectKind: record.SubjectKind,
	}
}

func cloneCoverageRecord(record sourcecoverage.Record) sourcecoverage.Record {
	record.KnownUnsupportedFields = append([]string(nil), record.KnownUnsupportedFields...)
	record.Notes = append([]string(nil), record.Notes...)
	record.EvidenceTypes = append([]string(nil), record.EvidenceTypes...)
	record.ControlDomains = append([]string(nil), record.ControlDomains...)
	if len(record.ControlRefs) > 0 {
		record.ControlRefs = append(record.ControlRefs[:0:0], record.ControlRefs...)
	}
	record.SupportedRuntimeFamilies = append([]string(nil), record.SupportedRuntimeFamilies...)
	return record
}

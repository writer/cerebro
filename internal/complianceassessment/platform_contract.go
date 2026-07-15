package complianceassessment

const (
	AssuranceSemanticModelVersion = "assurance-semantic-model/v1"
	LegacyCompatibilityVersion    = "compliance-legacy-compatibility/v1"
)

// AssuranceSemanticModel describes the stable entities and relationships that
// analytics, agents, and integrations can rely on without reading projections
// as if they were independent sources of truth.
type AssuranceSemanticModel struct {
	Version       string                      `json:"version"`
	Entities      []AssuranceSemanticEntity   `json:"entities"`
	Relationships []AssuranceSemanticRelation `json:"relationships"`
	Rules         []string                    `json:"rules"`
}

type AssuranceSemanticEntity struct {
	Name          string   `json:"name"`
	Key           string   `json:"key"`
	Authority     string   `json:"authority"`
	TimeField     string   `json:"time_field"`
	Dimensions    []string `json:"dimensions"`
	Measures      []string `json:"measures,omitempty"`
	Immutable     bool     `json:"immutable"`
	FreshnessRule string   `json:"freshness_rule"`
}

type AssuranceSemanticRelation struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Cardinality string `json:"cardinality"`
	Join        string `json:"join"`
}

// SemanticModel returns a deterministic contract. It names the append-log and
// immutable records as authorities and current-state queues as projections.
func SemanticModel() AssuranceSemanticModel {
	return AssuranceSemanticModel{
		Version: AssuranceSemanticModelVersion,
		Entities: []AssuranceSemanticEntity{
			{Name: "assessment_run", Key: "tenant_id + run_id", Authority: "compliance assessment event log", TimeField: "completed_at", Dimensions: []string{"program_id", "scope_revision_id", "plan_revision_id", "state"}, Measures: []string{"result_count"}, Immutable: false, FreshnessRule: "state and result-set digest must come from the same replayed run projection"},
			{Name: "objective_result", Key: "tenant_id + run_id + result_id", Authority: "content-addressed assessment result chunks", TimeField: "evaluated_at", Dimensions: []string{"objective_id", "control_ref", "scope_state", "automated_outcome", "evidence_state", "assurance", "auditor_state"}, Measures: []string{"evidence_count", "finding_count"}, Immutable: true, FreshnessRule: "read only through a verified result-set hash"},
			{Name: "assurance_decision", Key: "tenant_id + decision_id", Authority: "immutable assurance decision record", TimeField: "recorded_at", Dimensions: []string{"program_id", "objective_id", "qualified", "decision_digest"}, Immutable: true, FreshnessRule: "decision as_of and proof digests are evaluated at record time"},
			{Name: "assessment_snapshot", Key: "tenant_id + snapshot_id", Authority: "immutable assessment snapshot record", TimeField: "created_at", Dimensions: []string{"program_id", "scope_revision_id", "plan_revision_id", "decision_set_digest", "evidence_set_digest"}, Measures: []string{"result_count", "decision_count", "qualified_decision_count", "missing_decision_count", "evidence_count"}, Immutable: true, FreshnessRule: "all lens reads retain the snapshot cutoff and record digest"},
			{Name: "compliance_work_item", Key: "tenant_id + work_item_id", Authority: "replayable compliance work projection", TimeField: "updated_at", Dimensions: []string{"state", "owner_id", "priority", "objective_id", "control_ref", "verification_required"}, Measures: []string{"occurrence_count"}, Immutable: false, FreshnessRule: "current state is derived from ordered work events; verification links to an immutable assurance decision"},
		},
		Relationships: []AssuranceSemanticRelation{
			{From: "assessment_run", To: "objective_result", Cardinality: "one_to_many", Join: "tenant_id + run_id"},
			{From: "objective_result", To: "assurance_decision", Cardinality: "one_to_many", Join: "tenant_id + run_id + result_id"},
			{From: "assessment_run", To: "assessment_snapshot", Cardinality: "one_to_many", Join: "tenant_id + run_id"},
			{From: "objective_result", To: "compliance_work_item", Cardinality: "many_to_one", Join: "tenant_id + objective_id + control_ref + asset_scope + environment"},
		},
		Rules: []string{
			"tenant_id is required on every join",
			"missing evidence, stale evidence, conflicting evidence, and missing decisions remain distinct states",
			"legacy status is derived by the versioned compatibility adapter and never becomes an authority",
			"raw evidence remains in its source record; contracts carry stable IDs and digests",
		},
	}
}

// LegacyCompatibilityView preserves the existing one-dimensional status while
// attaching exact canonical identities for callers that can adopt them.
type LegacyCompatibilityView struct {
	Version              string       `json:"version"`
	Status               string       `json:"status"`
	ResultID             string       `json:"result_id"`
	ObjectiveID          string       `json:"objective_id"`
	ReasonCodes          []ReasonCode `json:"reason_codes,omitempty"`
	EvidenceIDs          []string     `json:"evidence_ids,omitempty"`
	AssuranceDecisionID  string       `json:"assurance_decision_id,omitempty"`
	AssessmentSnapshotID string       `json:"assessment_snapshot_id,omitempty"`
}

func NewLegacyCompatibilityView(result ObjectiveResult, decisionID, snapshotID string) LegacyCompatibilityView {
	return LegacyCompatibilityView{
		Version: LegacyCompatibilityVersion, Status: LegacyStatus(result), ResultID: result.ID,
		ObjectiveID: result.ObjectiveID, ReasonCodes: append([]ReasonCode(nil), result.ReasonCodes...),
		EvidenceIDs: append([]string(nil), result.EvidenceIDs...), AssuranceDecisionID: decisionID,
		AssessmentSnapshotID: snapshotID,
	}
}

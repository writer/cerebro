package decisionpacket

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentplatform"
)

func TestDecisionRuleGoldenFixtures(t *testing.T) {
	type fixture struct {
		Name               string `json:"name"`
		ClaimVerdict       string `json:"claim_verdict"`
		SupportingEvidence int    `json:"supporting_evidence"`
		GuardrailsPassed   bool   `json:"guardrails_passed"`
		RequiredGap        bool   `json:"required_gap"`
		RequiredStale      bool   `json:"required_stale"`
		UnresolvedConflict bool   `json:"unresolved_conflict"`
		PrimaryConflict    bool   `json:"primary_conflict"`
		DecisionState      string `json:"decision_state"`
		ConfidenceLevel    string `json:"confidence_level"`
	}
	raw, err := os.ReadFile("testdata/decision_rules.golden.json")
	if err != nil {
		t.Fatalf("read golden fixtures: %v", err)
	}
	var fixtures []fixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("decode golden fixtures: %v", err)
	}
	for _, item := range fixtures {
		t.Run(item.Name, func(t *testing.T) {
			decision := DeriveDecision(DecisionInputs{
				ClaimVerdict: item.ClaimVerdict, RequiredGap: item.RequiredGap,
				RequiredStale: item.RequiredStale, PrimaryConflict: item.PrimaryConflict,
			})
			confidence := DeriveConfidence(ConfidenceInputs{
				SupportingEvidence: item.SupportingEvidence, RequiredGap: item.RequiredGap,
				RequiredStale: item.RequiredStale, UnresolvedConflict: item.UnresolvedConflict,
				GuardrailsPassed: item.GuardrailsPassed,
			})
			if decision.State != item.DecisionState || confidence.Level != item.ConfidenceLevel {
				t.Fatalf("got decision=%q confidence=%q, want decision=%q confidence=%q", decision.State, confidence.Level, item.DecisionState, item.ConfidenceLevel)
			}
		})
	}
}

func TestDeriveDecision(t *testing.T) {
	falseValue := false
	tests := []struct {
		name string
		in   DecisionInputs
		want string
	}{
		{name: "supported", in: DecisionInputs{ClaimVerdict: agentplatform.ClaimVerdictSupported}, want: DecisionSupported},
		{name: "required gap", in: DecisionInputs{ClaimVerdict: agentplatform.ClaimVerdictSupported, RequiredGap: true}, want: DecisionSupportedWithGaps},
		{name: "contradicted", in: DecisionInputs{ClaimVerdict: agentplatform.ClaimVerdictContradicted}, want: DecisionBlocked},
		{name: "unknown", in: DecisionInputs{ClaimVerdict: agentplatform.ClaimVerdictUnknown}, want: DecisionInsufficientEvidence},
		{name: "explicit not applicable", in: DecisionInputs{ClaimVerdict: agentplatform.ClaimVerdictSupported, Applicable: &falseValue}, want: DecisionNotApplicable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeriveDecision(tt.in); got.State != tt.want {
				t.Fatalf("state = %q, want %q (%+v)", got.State, tt.want, got)
			}
		})
	}
}

func TestDeriveConfidenceCaps(t *testing.T) {
	tests := []struct {
		name string
		in   ConfidenceInputs
		want string
	}{
		{name: "no evidence", in: ConfidenceInputs{GuardrailsPassed: true}, want: ConfidenceUnknown},
		{name: "complete", in: ConfidenceInputs{SupportingEvidence: 2, GuardrailsPassed: true}, want: ConfidenceHigh},
		{name: "optional gap", in: ConfidenceInputs{SupportingEvidence: 2, GuardrailsPassed: true, OptionalGapMatters: true}, want: ConfidenceMedium},
		{name: "required stale", in: ConfidenceInputs{SupportingEvidence: 2, GuardrailsPassed: true, RequiredStale: true}, want: ConfidenceLow},
		{name: "required unverified", in: ConfidenceInputs{SupportingEvidence: 2, GuardrailsPassed: true, RequiredUnverified: true}, want: ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeriveConfidence(tt.in); got.Level != tt.want {
				t.Fatalf("level = %q, want %q (%+v)", got.Level, tt.want, got)
			}
		})
	}
}

func TestDetectContradictionsRequiresOverlappingValidity(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	common := ClaimObservation{TenantID: "tenant-1", SubjectURN: "urn:cerebro:tenant-1:asset:1", Predicate: "public", SourceID: "source-1", ValidFrom: start}
	left := common
	left.Value, left.Evidence = "true", EvidenceReference{ID: "evidence-1", Kind: "observation"}
	right := common
	right.Value, right.Evidence = "false", EvidenceReference{ID: "evidence-2", Kind: "observation"}
	if got := DetectContradictions([]ClaimObservation{right, left}); len(got) != 1 || got[0].ResolutionState != ContradictionUnresolved {
		t.Fatalf("contradictions = %+v, want one unresolved conflict", got)
	}

	left.ValidTo = start.Add(time.Hour)
	right.ValidFrom = left.ValidTo
	left.ObservedAt = start
	right.ObservedAt = start.Add(2 * time.Hour)
	if got := DetectContradictions([]ClaimObservation{left, right}); len(got) != 0 {
		t.Fatalf("superseded observations produced contradictions: %+v", got)
	}
	right.SourceID = "source-2"
	if got := DetectContradictions([]ClaimObservation{left, right}); len(got) != 1 {
		t.Fatalf("boundary observations from different sources = %+v, want one contradiction", got)
	}
}

func TestDetectContradictionsDistinguishesRepeatedEvidenceAcrossValidityWindows(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	common := ClaimObservation{TenantID: "tenant-1", SubjectURN: "urn:asset:1", Predicate: "public", ValidTo: start.Add(4 * time.Hour)}
	first := common
	first.Value, first.ValidFrom, first.Evidence = "true", start, EvidenceReference{ID: "evidence-1", Kind: "observation", ValidFrom: start}
	second := common
	second.Value, second.ValidFrom, second.Evidence = "false", start, EvidenceReference{ID: "evidence-2", Kind: "observation", ValidFrom: start}
	third := common
	third.Value, third.ValidFrom, third.Evidence = "true", start.Add(time.Hour), EvidenceReference{ID: "evidence-1", Kind: "observation", ValidFrom: start.Add(time.Hour)}
	got := DetectContradictions([]ClaimObservation{third, second, first})
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("contradictions = %+v, want two distinct content-addressed conflicts", got)
	}
	reordered := DetectContradictions([]ClaimObservation{first, second, third})
	leftJSON, _ := json.Marshal(got)
	rightJSON, _ := json.Marshal(reordered)
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("input order changed contradictions: first=%s reordered=%s", leftJSON, rightJSON)
	}
}

func TestNormalizeRequestBudgets(t *testing.T) {
	got, err := NormalizeRequest(Request{Workflow: " Triage ", FindingIDs: []string{"b", "a", "a"}})
	if err != nil {
		t.Fatalf("NormalizeRequest() error = %v", err)
	}
	if got.Workflow != "triage" || strings.Join(got.FindingIDs, ",") != "a,b" || got.Budgets.Evidence != 50 || got.Budgets.GraphDepth != 2 {
		t.Fatalf("normalized request = %+v", got)
	}
	_, err = NormalizeRequest(Request{Budgets: Budgets{Evidence: 101}})
	if !errors.Is(err, ErrInvalidBudget) {
		t.Fatalf("budget error = %v, want ErrInvalidBudget", err)
	}
}

func TestCanonicalizePacketIsStableAndContentAddressed(t *testing.T) {
	generatedAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	packet := Packet{
		GeneratedAt: generatedAt, Workflow: Workflow{ID: " Triage ", Question: " Review finding "},
		Scope:      Scope{TenantID: "tenant-1", ActorID: "analyst-1"},
		Decision:   Decision{State: DecisionSupported, Reasons: []string{"z", "a"}},
		Confidence: Confidence{Level: ConfidenceHigh, Basis: []string{"fresh_complete_nonconflicting_evidence"}},
		Evidence:   []EvidenceReference{{ID: "b", Kind: "finding"}, {ID: "a", Kind: "finding"}, {ID: "a", Kind: "finding"}},
	}
	first, firstJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket() error = %v", err)
	}
	second, secondJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket() second error = %v", err)
	}
	if first.ID != second.ID || string(firstJSON) != string(secondJSON) {
		t.Fatalf("canonical output changed: %q / %q", first.ID, second.ID)
	}
	if !strings.HasPrefix(first.ID, "dpr_") || len(first.ID) != 36 || len(first.Evidence) != 2 {
		t.Fatalf("canonical packet = %+v", first)
	}
	if strings.Contains(string(firstJSON), "0001-01-01") {
		t.Fatalf("canonical packet contains zero-time sentinels: %s", firstJSON)
	}
	packet.Decision.Reasons = append(packet.Decision.Reasons, "new_fact")
	changed, _, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket() changed error = %v", err)
	}
	if changed.ID == first.ID {
		t.Fatal("packet ID did not change with decision inputs")
	}
}

func TestCanonicalizePacketNormalizesFreshnessAndAuditTimesToUTC(t *testing.T) {
	instant := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	offset := time.FixedZone("test-offset", -7*60*60)
	packet := Packet{
		GeneratedAt: instant,
		Workflow:    Workflow{ID: "triage", Question: "Review finding"},
		Scope:       Scope{TenantID: "tenant-1", ActorID: "analyst-1"},
		Freshness: Freshness{
			State: " FRESH ", OldestObservedAt: instant.In(offset), NewestObservedAt: instant.Add(time.Hour).In(offset),
		},
		Contradictions: []Contradiction{{
			ID:    "conflict-1",
			Left:  EvidenceReference{ID: "left", Kind: " Finding ", ObservedAt: instant.In(offset)},
			Right: EvidenceReference{ID: "right", Kind: " Finding ", ObservedAt: instant.Add(time.Hour).In(offset)},
		}},
		AuditPackets: []AuditPacketReference{{ID: "audit-1", Digest: "sha256:test", GeneratedAt: instant.In(offset)}},
	}
	localPacket, localJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(local) error = %v", err)
	}
	packet.Freshness.OldestObservedAt = instant
	packet.Freshness.NewestObservedAt = instant.Add(time.Hour)
	packet.Freshness.State = "fresh"
	packet.Contradictions = []Contradiction{{
		ID:    "conflict-1",
		Left:  EvidenceReference{ID: "left", Kind: "finding", ObservedAt: instant},
		Right: EvidenceReference{ID: "right", Kind: "finding", ObservedAt: instant.Add(time.Hour)},
	}}
	packet.AuditPackets = []AuditPacketReference{{ID: "audit-1", Digest: "sha256:test", GeneratedAt: instant}}
	utcPacket, utcJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(UTC) error = %v", err)
	}
	if localPacket.ID != utcPacket.ID || string(localJSON) != string(utcJSON) {
		t.Fatalf("timezone changed canonical packet: local=%s UTC=%s", localJSON, utcJSON)
	}
	if localPacket.Freshness.State != "fresh" || localPacket.Contradictions[0].Left.Kind != "finding" || localPacket.Contradictions[0].Left.ObservedAt.Location() != time.UTC || localPacket.Freshness.OldestObservedAt.Location() != time.UTC || localPacket.Freshness.NewestObservedAt.Location() != time.UTC || localPacket.AuditPackets[0].GeneratedAt.Location() != time.UTC {
		t.Fatalf("canonical times are not UTC: freshness=%+v audit=%+v", localPacket.Freshness, localPacket.AuditPackets[0])
	}
}

func TestCanonicalizePacketNormalizesNestedDecisionFields(t *testing.T) {
	instant := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	packet := Packet{
		GeneratedAt: instant,
		Contradictions: []Contradiction{{
			ID: " conflict-1 ", SubjectURN: " urn:asset:1 ", Predicate: " Public ", ResolutionState: " UNRESOLVED ",
			Left: EvidenceReference{ID: " left ", Kind: " Finding "}, Right: EvidenceReference{ID: " right ", Kind: " Finding "},
		}},
		CoverageGaps: []CoverageGap{{ID: " gap-1 ", SourceID: " source-1 ", Dimension: " Coverage ", State: " PARTIAL ", Reason: " Missing data "}},
		Affected:     []SubjectReference{{URN: " urn:asset:1 ", Kind: " Resource ", Name: " Asset 1 "}},
		Controls:     []ControlReference{{ID: " control-1 ", Framework: " SOC 2 ", Applicability: " APPLICABLE "}},
		AuditPackets: []AuditPacketReference{{ID: " audit-1 ", ScopeURN: " urn:asset:1 ", Digest: " sha256:audit ", GeneratedAt: instant, Freshness: " FRESH "}},
		Actions: []ActionProposal{{
			ID: " proposal-1 ", ActionID: " action-1 ", State: " PROPOSAL ", TargetURNs: []string{" urn:asset:1 "},
			Rationale: " Investigate ", ApprovalRequirements: []string{" security "}, CatalogVersion: " v1 ", ProposalDigest: " sha256:proposal ",
		}},
		Provenance: Provenance{TraceID: " trace-1 ", ResolverIDs: []string{" resolver-1 "}, SourceIDs: []string{" source-1 "}, EvidenceDigest: " sha256:evidence ", CoverageDigest: " sha256:coverage "},
	}
	canonical, canonicalJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(spaced) error = %v", err)
	}

	packet.Contradictions[0] = Contradiction{ID: "conflict-1", SubjectURN: "urn:asset:1", Predicate: "public", ResolutionState: "unresolved", Left: EvidenceReference{ID: "left", Kind: "finding"}, Right: EvidenceReference{ID: "right", Kind: "finding"}}
	packet.CoverageGaps[0] = CoverageGap{ID: "gap-1", SourceID: "source-1", Dimension: "coverage", State: "partial", Reason: "Missing data"}
	packet.Affected[0] = SubjectReference{URN: "urn:asset:1", Kind: "resource", Name: "Asset 1"}
	packet.Controls[0] = ControlReference{ID: "control-1", Framework: "SOC 2", Applicability: "applicable"}
	packet.AuditPackets[0] = AuditPacketReference{ID: "audit-1", ScopeURN: "urn:asset:1", Digest: "sha256:audit", GeneratedAt: instant, Freshness: "fresh"}
	packet.Actions[0] = ActionProposal{ID: "proposal-1", ActionID: "action-1", State: "proposal", TargetURNs: []string{"urn:asset:1"}, Rationale: "Investigate", ApprovalRequirements: []string{"security"}, CatalogVersion: "v1", ProposalDigest: "sha256:proposal"}
	packet.Provenance = Provenance{TraceID: "trace-1", ResolverIDs: []string{"resolver-1"}, SourceIDs: []string{"source-1"}, EvidenceDigest: "sha256:evidence", CoverageDigest: "sha256:coverage"}
	plain, plainJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(plain) error = %v", err)
	}
	if canonical.ID != plain.ID || string(canonicalJSON) != string(plainJSON) {
		t.Fatalf("nested formatting changed canonical packet: spaced=%s plain=%s", canonicalJSON, plainJSON)
	}
}

func TestCanonicalizePacketUsesTotalOrderingForDuplicateKeys(t *testing.T) {
	packet := Packet{
		GeneratedAt: time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC),
		Evidence: []EvidenceReference{
			{ID: "evidence-1", Kind: "finding", Value: "z"},
			{ID: "evidence-1", Kind: "finding", Value: "a"},
		},
		Affected: []SubjectReference{
			{URN: "urn:asset:1", Kind: "service", Name: "Zulu"},
			{URN: "urn:asset:1", Kind: "resource", Name: "Alpha"},
		},
	}
	first, firstJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(first order) error = %v", err)
	}
	packet.Evidence[0], packet.Evidence[1] = packet.Evidence[1], packet.Evidence[0]
	packet.Affected[0], packet.Affected[1] = packet.Affected[1], packet.Affected[0]
	second, secondJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(reverse order) error = %v", err)
	}
	if first.ID != second.ID || string(firstJSON) != string(secondJSON) {
		t.Fatalf("duplicate-key input order changed canonical packet: first=%s second=%s", firstJSON, secondJSON)
	}
}

func TestCanonicalizePacketTreatsNilAndEmptyResultSlicesEqually(t *testing.T) {
	packet := Packet{GeneratedAt: time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)}
	withNil, nilJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(nil) error = %v", err)
	}
	packet.Contradictions = []Contradiction{}
	packet.CoverageGaps = []CoverageGap{}
	packet.Affected = []SubjectReference{}
	packet.Controls = []ControlReference{}
	packet.AuditPackets = []AuditPacketReference{}
	packet.Actions = []ActionProposal{}
	withEmpty, emptyJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(empty) error = %v", err)
	}
	if withNil.ID != withEmpty.ID || string(nilJSON) != string(emptyJSON) {
		t.Fatalf("nil and empty slices changed canonical packet: nil=%s empty=%s", nilJSON, emptyJSON)
	}
}

func TestCanonicalizePacketNormalizesEmbeddedAgentContracts(t *testing.T) {
	packet := Packet{
		GeneratedAt: time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC),
		Guardrails: agentplatform.AgentDecisionGuardrails{
			Version:           " v1 ",
			Readiness:         agentplatform.AgentReadinessAssessment{State: " READY ", Reasons: []string{" warning-b ", "warning-a", "warning-a"}},
			RequiredWriteBack: []string{" event-b ", "event-a", "event-a"},
			VerifierResults:   []agentplatform.AgentVerifierResult{{ID: " verifier-1 ", Status: " PASS ", Evidence: nil}},
		},
		Claim: agentplatform.ClaimVerification{Claim: " Asset is public ", Verdict: " SUPPORTED ", SupportingEvidence: nil, Warnings: []string{" warning-b ", "warning-a", "warning-a"}, RequiredWriteBack: nil},
	}
	spaced, spacedJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(spaced agent contracts) error = %v", err)
	}
	packet.Guardrails.Version = "v1"
	packet.Guardrails.Readiness = agentplatform.AgentReadinessAssessment{State: "ready", Reasons: []string{"warning-a", "warning-b"}}
	packet.Guardrails.RequiredWriteBack = []string{"event-a", "event-b"}
	packet.Guardrails.VerifierResults[0] = agentplatform.AgentVerifierResult{ID: "verifier-1", Status: "pass", Evidence: []string{}}
	packet.Claim = agentplatform.ClaimVerification{Claim: "Asset is public", Verdict: "supported", SupportingEvidence: []agentplatform.EvidenceReference{}, RequiredWriteBack: []string{}, Blockers: []agentplatform.CapabilityDecisionBlocker{}, Warnings: []string{"warning-a", "warning-b"}, CounterEvidence: []agentplatform.EvidenceReference{}, MissingEvidence: []string{}, VerifierResults: []agentplatform.AgentVerifierResult{}}
	plain, plainJSON, err := CanonicalizePacket(packet)
	if err != nil {
		t.Fatalf("CanonicalizePacket(plain agent contracts) error = %v", err)
	}
	if spaced.ID != plain.ID || string(spacedJSON) != string(plainJSON) {
		t.Fatalf("agent contract formatting changed canonical packet: spaced=%s plain=%s", spacedJSON, plainJSON)
	}
}

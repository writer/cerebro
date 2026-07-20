package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrInvalidProofObligation = errors.New("invalid proof obligation")

type ProofMethod string

const (
	ProofMethodAutomated ProofMethod = "automated"
	ProofMethodManual    ProofMethod = "manual"
	ProofMethodHybrid    ProofMethod = "hybrid"
)

type AssuranceStrength string

const (
	AssuranceDocumented  AssuranceStrength = "documented"
	AssuranceObserved    AssuranceStrength = "observed"
	AssuranceTested      AssuranceStrength = "tested"
	AssuranceIndependent AssuranceStrength = "independently_reviewed"
)

// ProofObligation is the complete predicate that evidence must satisfy before
// it can be reused for another requirement. Similar control text is not enough.
type ProofObligation struct {
	TenantID               string            `json:"tenant_id"`
	RequirementID          string            `json:"requirement_id"`
	ControlID              string            `json:"control_id"`
	FrameworkID            string            `json:"framework_id"`
	FrameworkVersion       string            `json:"framework_version"`
	ImplementationRevision string            `json:"implementation_revision"`
	ScopeRevision          string            `json:"scope_revision"`
	SubjectKinds           []string          `json:"subject_kinds"`
	PopulationDigest       string            `json:"population_digest"`
	PeriodStart            time.Time         `json:"period_start"`
	PeriodEnd              time.Time         `json:"period_end"`
	Method                 ProofMethod       `json:"method"`
	Strength               AssuranceStrength `json:"assurance_strength"`
	Frequency              string            `json:"frequency"`
	ReviewerRequired       bool              `json:"reviewer_required"`
	Digest                 string            `json:"digest"`
}

type ReuseState string

const (
	ReuseExact        ReuseState = "exact"
	ReusePartial      ReuseState = "partial"
	ReuseIncompatible ReuseState = "incompatible"
)

type ReusePredicate string

const (
	PredicateTenant         ReusePredicate = "tenant"
	PredicateControl        ReusePredicate = "control"
	PredicateImplementation ReusePredicate = "implementation_revision"
	PredicateScope          ReusePredicate = "scope_revision"
	PredicateSubject        ReusePredicate = "subject_kinds"
	PredicatePopulation     ReusePredicate = "population"
	PredicatePeriod         ReusePredicate = "period"
	PredicateMethod         ReusePredicate = "method"
	PredicateStrength       ReusePredicate = "assurance_strength"
	PredicateFrequency      ReusePredicate = "frequency"
	PredicateReview         ReusePredicate = "reviewer_requirement"
)

type ReuseDecision struct {
	State            ReuseState       `json:"state"`
	SourceDigest     string           `json:"source_digest"`
	TargetDigest     string           `json:"target_digest"`
	FailedPredicates []ReusePredicate `json:"failed_predicates"`
	DecisionDigest   string           `json:"decision_digest"`
}

func NormalizeProofObligation(value ProofObligation) (ProofObligation, error) {
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.RequirementID = strings.TrimSpace(value.RequirementID)
	value.ControlID = strings.TrimSpace(value.ControlID)
	value.FrameworkID = strings.TrimSpace(value.FrameworkID)
	value.FrameworkVersion = strings.TrimSpace(value.FrameworkVersion)
	value.ImplementationRevision = strings.TrimSpace(value.ImplementationRevision)
	value.ScopeRevision = strings.TrimSpace(value.ScopeRevision)
	value.PopulationDigest = strings.TrimSpace(value.PopulationDigest)
	value.Frequency = strings.TrimSpace(value.Frequency)
	value.PeriodStart = value.PeriodStart.UTC()
	value.PeriodEnd = value.PeriodEnd.UTC()
	value.SubjectKinds = normalizedProofValues(value.SubjectKinds)
	value.Digest = ""
	if value.TenantID == "" || value.RequirementID == "" || value.ControlID == "" || value.FrameworkID == "" ||
		value.FrameworkVersion == "" || value.ImplementationRevision == "" || value.ScopeRevision == "" ||
		len(value.SubjectKinds) == 0 || ValidateContentDigest(ContentDigest(value.PopulationDigest)) != nil || value.PeriodStart.IsZero() ||
		!value.PeriodEnd.After(value.PeriodStart) || !validProofMethod(value.Method) || !validAssuranceStrength(value.Strength) || value.Frequency == "" {
		return ProofObligation{}, ErrInvalidProofObligation
	}
	digest, err := proofDigest(value)
	if err != nil {
		return ProofObligation{}, err
	}
	value.Digest = digest
	return value, nil
}

// EvaluateEvidenceReuse defaults ambiguity to incompatible. Partial reuse is
// reserved for a narrower target period over the exact same population while
// every semantic and assurance predicate remains identical.
func EvaluateEvidenceReuse(source ProofObligation, target ProofObligation) (ReuseDecision, error) {
	left, err := NormalizeProofObligation(source)
	if err != nil {
		return ReuseDecision{}, err
	}
	right, err := NormalizeProofObligation(target)
	if err != nil {
		return ReuseDecision{}, err
	}
	failed := make([]ReusePredicate, 0)
	add := func(predicate ReusePredicate, matches bool) {
		if !matches {
			failed = append(failed, predicate)
		}
	}
	add(PredicateTenant, left.TenantID == right.TenantID)
	add(PredicateControl, left.ControlID == right.ControlID)
	add(PredicateImplementation, left.ImplementationRevision == right.ImplementationRevision)
	add(PredicateScope, left.ScopeRevision == right.ScopeRevision)
	add(PredicateSubject, equalProofValues(left.SubjectKinds, right.SubjectKinds))
	populationMatches := left.PopulationDigest == right.PopulationDigest
	periodMatches := left.PeriodStart.Equal(right.PeriodStart) && left.PeriodEnd.Equal(right.PeriodEnd)
	periodSubset := targetWithinSourcePeriod(left, right)
	add(PredicateMethod, left.Method == right.Method)
	add(PredicateStrength, left.Strength == right.Strength)
	add(PredicateFrequency, left.Frequency == right.Frequency)
	add(PredicateReview, !right.ReviewerRequired || left.ReviewerRequired)
	if !populationMatches {
		failed = append(failed, PredicatePopulation)
	}
	if !periodMatches && !periodSubset {
		failed = append(failed, PredicatePeriod)
	}
	state := ReuseExact
	if len(failed) != 0 {
		state = ReuseIncompatible
	} else if !periodMatches {
		state = ReusePartial
	}
	sort.Slice(failed, func(i, j int) bool { return failed[i] < failed[j] })
	decision := ReuseDecision{State: state, SourceDigest: left.Digest, TargetDigest: right.Digest, FailedPredicates: failed}
	payload, err := json.Marshal(decision)
	if err != nil {
		return ReuseDecision{}, err
	}
	sum := sha256.Sum256(payload)
	decision.DecisionDigest = "sha256:" + hex.EncodeToString(sum[:])
	return decision, nil
}

func proofDigest(value ProofObligation) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func targetWithinSourcePeriod(source ProofObligation, target ProofObligation) bool {
	return !target.PeriodStart.Before(source.PeriodStart) && !target.PeriodEnd.After(source.PeriodEnd)
}

func normalizedProofValues(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalProofValues(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validProofMethod(value ProofMethod) bool {
	return value == ProofMethodAutomated || value == ProofMethodManual || value == ProofMethodHybrid
}

func validAssuranceStrength(value AssuranceStrength) bool {
	return value == AssuranceDocumented || value == AssuranceObserved || value == AssuranceTested || value == AssuranceIndependent
}

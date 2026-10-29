package cloudidentity

import (
	"fmt"
	"time"
)

// Assess evaluates one principal's bounded Evidence cohort into an
// Assessment. It assesses BOTH the declared and observed policy surfaces
// against the union of every known consumer's requirements, and only ever
// reports Supported — eligible for fully automatic promotion, no human
// review step exists — when every promotion gate independently holds for
// the side(s) carrying the excess:
//   - fresh, exact-pinned evidence (now - CollectedAt <= maxAge, and every
//     consumer/investigation Source is an exact immutable revision with a
//     real repository/revision, not just an Exact=true flag on an empty pin)
//   - every reviewed consumer bound to exactly one investigation, computed
//     against that SAME consumer's own pinned source (no missing coverage,
//     no duplicate/ambiguous investigations, no unmatched-ConsumerID
//     requirements leaking into the union)
//   - independently (deterministically, never model-) validated
//     investigations backing the requirement union
//   - a consumer inventory confirmed complete
//   - fully resolved role/managed-policy definitions and a known action
//     catalog for every grant contributing to the excess
//   - that side's PolicyState and Definitions both marked Complete, with a
//     self-consistent Definitions.Digest
//
// Clear is intentionally NOT symmetric with Supported: it requires BOTH
// sides to be independently complete with zero excess. A complete, clear
// side next to an unknown/incomplete side never closes out the unknown
// side's prior excess — that case is Incomplete.
func Assess(e Evidence, now time.Time, maxAge time.Duration) Assessment {
	if isUnresolvedCloudPrincipal(e.Principal) {
		return Assessment{Status: Incomplete, Gaps: []Gap{{
			Code:    "cloudidentity.unresolved_principal",
			Scope:   e.Principal.ID,
			Message: "principal is an unresolved Kubernetes service-account placeholder, not a confirmed cloud principal; excess cannot be assessed",
		}}}
	}
	var gaps []Gap
	gaps = append(gaps, e.Gaps...)
	gaps = append(gaps, e.Declared.Gaps...)
	gaps = append(gaps, e.Observed.Gaps...)
	gaps = append(gaps, e.Definitions.Gaps...)

	coverageOK, coverageGaps, boundInvestigations := assessConsumerCoverage(e)
	gaps = append(gaps, coverageGaps...)

	fresh, freshGaps := assessFreshness(e, now, maxAge, boundInvestigations)
	gaps = append(gaps, freshGaps...)

	validated, validationGaps := assessValidation(e, boundInvestigations)
	gaps = append(gaps, validationGaps...)

	trustCoverageOK, trustGaps := assessTrustCoverage(e)
	gaps = append(gaps, trustGaps...)

	definitionsOK := definitionsDigestConsistent(e.Definitions)
	if !definitionsOK {
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.definitions_digest_mismatch",
			Scope:   e.Principal.ID,
			Message: "Definitions.Digest does not match the canonical digest of its own content",
		})
	}

	if !e.ConsumerInventoryComplete {
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.incomplete_consumer_inventory",
			Scope:   e.Principal.ID,
			Message: "consumer inventory is not confirmed complete; unresolved consumers could still require currently-unused permissions",
		})
	}

	union := unionInvestigationRequirements(boundInvestigations)
	requirementsByAction := requirementsByActionForProvider(e.Principal.Provider, union)
	known := buildKnownActionsByService(e.Definitions)

	declaredExcess, declaredExcessGaps := computeExcess(e.Principal.Provider, e.Declared, e.Definitions, requirementsByAction, known, e.ResolvedIdentifiers)
	gaps = append(gaps, declaredExcessGaps...)
	declaredSurfaceComplete := e.Declared.Complete && e.Definitions.Complete &&
		!hasGapCode(declaredExcessGaps, gapMissingRoleDefinition) &&
		!hasGapCode(declaredExcessGaps, gapUnscopedResource) &&
		!hasGapCode(declaredExcessGaps, gapUnknownActionSurface) &&
		!hasGapCode(declaredExcessGaps, gapUnresolvedResourceComplement) &&
		!hasGapCode(declaredExcessGaps, gapUnknownEffectiveAccess) &&
		!hasGapCode(declaredExcessGaps, gapUnknownGrantCondition) &&
		!hasGapCode(declaredExcessGaps, gapUnresolvedEffectiveResource)

	observedExcess, observedExcessGaps := computeExcess(e.Principal.Provider, e.Observed, e.Definitions, requirementsByAction, known, e.ResolvedIdentifiers)
	gaps = append(gaps, observedExcessGaps...)
	observedSurfaceComplete := e.Observed.Complete && e.Definitions.Complete &&
		!hasGapCode(observedExcessGaps, gapMissingRoleDefinition) &&
		!hasGapCode(observedExcessGaps, gapUnscopedResource) &&
		!hasGapCode(observedExcessGaps, gapUnknownActionSurface) &&
		!hasGapCode(observedExcessGaps, gapUnresolvedResourceComplement) &&
		!hasGapCode(observedExcessGaps, gapUnknownEffectiveAccess) &&
		!hasGapCode(observedExcessGaps, gapUnknownGrantCondition) &&
		!hasGapCode(observedExcessGaps, gapUnresolvedEffectiveResource)

	drift, driftErr := computeDrift(e.Declared, e.Observed)
	if driftErr != nil {
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.drift_unavailable",
			Scope:   e.Principal.ID,
			Message: driftErr.Error(),
		})
	}

	hasDeclaredExcess := len(declaredExcess) > 0
	hasObservedExcess := len(observedExcess) > 0

	// Candidate sides retain tentative evidence. A Supported result below
	// includes only independently complete sides, even when the opposite
	// side also contains tentative excess.
	var side string
	switch {
	case hasDeclaredExcess && hasObservedExcess:
		side = "both"
	case hasDeclaredExcess:
		side = "iac"
	case hasObservedExcess:
		side = "live"
	}

	universalGatesOK := fresh && validated && e.ConsumerInventoryComplete && trustCoverageOK && coverageOK && definitionsOK && driftErr == nil

	status := Incomplete
	switch {
	case universalGatesOK && ((hasDeclaredExcess && declaredSurfaceComplete) || (hasObservedExcess && observedSurfaceComplete)):
		status = Supported
		if !declaredSurfaceComplete {
			declaredExcess = nil
			side = "live"
		}
		if !observedSurfaceComplete {
			observedExcess = nil
			side = "iac"
		}
	case hasDeclaredExcess || hasObservedExcess:
		status = Candidate
	default:
		if universalGatesOK && declaredSurfaceComplete && observedSurfaceComplete {
			status = Clear
		}
	}

	return Assessment{
		Status:         status,
		Side:           side,
		Drift:          drift,
		DeclaredExcess: declaredExcess,
		ObservedExcess: observedExcess,
		Gaps:           dedupeGaps(gaps),
	}
}

// assessFreshness enforces the maxAge boundary deterministically: evidence
// is fresh iff CollectedAt is known and now.Sub(CollectedAt) is in [0,
// maxAge] (inclusive of the boundary), and every consumer/bound-investigation
// Source is pinned to an exact immutable revision — Exact=true alone is not
// sufficient; Repository/Revision must actually be populated.
func assessFreshness(e Evidence, now time.Time, maxAge time.Duration, boundInvestigations []Investigation) (bool, []Gap) {
	var gaps []Gap
	ok := true

	if e.CollectedAt.IsZero() {
		ok = false
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.unknown_collection_time",
			Scope:   e.Principal.ID,
			Message: "evidence has no collection timestamp; freshness cannot be established",
		})
	} else if age := now.Sub(e.CollectedAt); age < 0 || age > maxAge {
		ok = false
		gaps = append(gaps, Gap{
			Code:    "cloudidentity.stale_evidence",
			Scope:   e.Principal.ID,
			Message: fmt.Sprintf("evidence is %s old, exceeding the %s freshness boundary", age, maxAge),
		})
	}

	for _, c := range e.Consumers {
		if !sourcePinExact(c.Source) {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.inexact_source_pin",
				Scope:   c.ID,
				Message: "consumer source is not pinned to an exact immutable revision",
			})
		}
	}
	for _, inv := range boundInvestigations {
		if !sourcePinExact(inv.Source) {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.inexact_source_pin",
				Scope:   inv.ConsumerID,
				Message: "investigation source is not pinned to an exact immutable revision",
			})
		}
	}

	return ok, gaps
}

// assessValidation requires every investigation safely bound to a reviewed
// consumer (see assessConsumerCoverage) to carry deterministic,
// code-verified citations/operations/scope — never a model-reported
// completeness flag, regardless of whether Investigation.Model is set. A
// principal with zero reviewed consumers has nothing to validate.
func assessValidation(e Evidence, boundInvestigations []Investigation) (bool, []Gap) {
	if len(e.Consumers) == 0 {
		return true, nil
	}
	if len(boundInvestigations) == 0 {
		return false, []Gap{{
			Code:    "cloudidentity.no_investigations",
			Scope:   e.Principal.ID,
			Message: "no safely-bound requirement investigations are present; required-permission coverage is unknown",
		}}
	}
	var gaps []Gap
	ok := true
	for _, inv := range boundInvestigations {
		v := inv.Validation
		if !v.CitationsVerified || !v.OperationsVerified || !v.ScopeComplete {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.unvalidated_investigation",
				Scope:   inv.ConsumerID,
				Message: "investigation citations/operations/scope are not independently verified complete",
			})
		}
	}
	return ok, gaps
}

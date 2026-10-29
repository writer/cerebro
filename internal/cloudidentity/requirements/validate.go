package requirements

import (
	"regexp"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// requirementsScopeImpactingGapCodes are gap codes that mean "some part of
// the pinned source/config could not be reviewed, or could not be proven
// complete, at all"; any of them keeps ScopeComplete false. Gap codes about
// model-claim quality (unknown operation from a claim, bad citation,
// uncorroborated claim, a rejected model response) do not — the code *was*
// reviewed, the model just proposed something unverifiable about it.
// GapConditionalPermission is deliberately NOT here: an unresolved
// conditional permission is conservatively promoted as a wildcard
// Requirement instead of dropped (see Validate), so it does not represent
// missing coverage. ScopeComplete also independently requires no
// repository/Definitions incompleteness and a matching source digest; see
// Validate's final computation, not just this map.
var requirementsScopeImpactingGapCodes = map[string]bool{
	GapGoParseError:                    true,
	GapUnsupportedDynamicCall:          true,
	GapUnsupportedPattern:              true,
	GapUnreviewedPath:                  true,
	GapUnapprovedDependency:            true,
	GapSourceMappingMismatch:           true,
	GapUnreviewablePackageInit:         true,
	GapOperationDependenciesIncomplete: true,
	GapAmbiguousGCPOperation:           true,
	GapUnresolvedChainMethod:           true,
	GapBuildProfileExcluded:            true,
}

var requirementsGitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$`)

type requirementsOperationKey struct {
	provider  ci.Provider
	service   string
	operation string
}

// Validate deterministically derives one workload's ci.Investigation from
// independently extracted static findings, the live Definitions vocabulary,
// and a model's proposed (never trusted) claims. Re-running Validate on the
// same inputs always produces the same Investigation (modulo the Gaps slice
// order, which is itself deterministic by construction order).
func Validate(input ValidateInput) ci.Investigation {
	analyzer := input.Analyzer
	if analyzer == "" {
		analyzer = Analyzer
	}

	static := ExtractStatic(input.Repository.Files)
	files := make(map[string]ci.SourceFile, len(input.Repository.Files))
	for _, f := range input.Repository.Files {
		files[f.Path] = f
	}

	var gaps []ci.Gap
	gaps = append(gaps, static.Gaps...)
	// Any gap the repository adapter itself reported (budget exceeded, file
	// denied, symlink/submodule skipped, ...) means the pinned content we
	// reasoned over is incomplete, regardless of what code that gap uses:
	// it always blocks ScopeComplete, never just gets echoed through.
	repositoryIncomplete := len(input.Repository.Gaps) > 0
	gaps = append(gaps, input.Repository.Gaps...)
	// A source review can never be more complete than the IAM operation/
	// permission catalog it is checked against: if Definitions.Complete is
	// false (the broad catalog fetch itself was incomplete), a clean
	// static review must not be reported as scope-complete, since a called
	// operation might not even be in the known vocabulary. Definitions.Gaps
	// alone does NOT globally block: those commonly describe unused/
	// uncalled operation mappings irrelevant to this source, so they are
	// still surfaced for visibility but judged per actually-used operation
	// via DependenciesComplete below, not as a blanket block.
	definitionsIncomplete := !input.Definitions.Complete
	gaps = append(gaps, input.Definitions.Gaps...)

	consumerID := strings.TrimSpace(input.Workload.ID)

	var reqs []ci.Requirement
	promoted := map[requirementsOperationKey][]int{}
	citationsOK := true
	operationsOK := true

	// 1. Promote every static finding that maps through Definitions. This
	// is the real positive path: it does not need, and is not improved by,
	// any model claim.
	for _, op := range static.Operations {
		def, found := requirementsFindOperationByToken(input.Definitions, op.Provider, op.Service, op.Token)
		if !found {
			operationsOK = false
			gaps = append(gaps, ci.Gap{
				Code:       GapUnknownOperation,
				Scope:      op.Path,
				Message:    "static call to \"" + op.Token + "\" has no matching operation in Definitions for " + string(op.Provider) + "/" + op.Service,
				References: []ci.Reference{requirementsStaticReference(op, files)},
			})
			continue
		}
		if !def.DependenciesComplete {
			operationsOK = false
			gaps = append(gaps, ci.Gap{
				Code:       GapOperationDependenciesIncomplete,
				Scope:      op.Path,
				Message:    "operation " + def.Operation + " definition does not confirm its dependent/conditional permission set is complete (DependenciesComplete=false); the promoted Requirement(s) may still be missing a real downstream permission",
				References: []ci.Reference{requirementsStaticReference(op, files)},
			})
		}
		resources := op.Resources
		if len(resources) == 0 {
			resources = []string{"*"}
			gaps = append(gaps, ci.Gap{
				Code:       GapResourceScopeUnresolved,
				Scope:      op.Path,
				Message:    "operation " + def.Operation + " resource scope could not be independently and semantically extracted from source; recorded as wildcard-unknown, never narrowed by an unverified claim or a generic literal guess",
				References: []ci.Reference{requirementsStaticReference(op, files)},
			})
		}
		key := requirementsOperationKey{def.Provider, def.Service, def.Operation}
		for _, permission := range def.Permissions {
			reqs = append(reqs, ci.Requirement{
				Provider:    op.Provider,
				Service:     op.Service,
				Operation:   def.Operation,
				Action:      permission,
				Resources:   append([]string{}, resources...),
				ConsumerIDs: []string{consumerID},
				References:  []ci.Reference{requirementsStaticReference(op, files)},
			})
			promoted[key] = append(promoted[key], len(reqs)-1)
		}
		// A conditional permission's exact triggering condition cannot be
		// resolved from source, so its resource scope is never narrowed
		// from the literal values extracted for the base operation (the
		// condition may apply to a different resource entirely) — but it
		// is still conservatively promoted as a wildcard Requirement rather
		// than dropped, because omitting a permission the code may
		// genuinely need would make a real grant for it look like
		// unexplained excess downstream. The gap keeps this visible as
		// conservative/unconfirmed, without blocking ScopeComplete: the
		// known permission vocabulary itself is not incomplete here, only
		// the applicability of one optional action within it.
		for _, conditional := range def.ConditionalPermissions {
			reqs = append(reqs, ci.Requirement{
				Provider:    op.Provider,
				Service:     op.Service,
				Operation:   def.Operation,
				Action:      conditional,
				Resources:   []string{"*"},
				ConsumerIDs: []string{consumerID},
				References:  []ci.Reference{requirementsStaticReference(op, files)},
			})
			promoted[key] = append(promoted[key], len(reqs)-1)
			gaps = append(gaps, ci.Gap{
				Code:       GapConditionalPermission,
				Scope:      op.Path,
				Message:    "operation " + def.Operation + " has conditional permission \"" + conditional + "\" whose triggering condition could not be resolved from source; conservatively included as a wildcard-resource Requirement rather than dropped",
				References: []ci.Reference{requirementsStaticReference(op, files)},
			})
		}
	}

	// 2. Evaluate every model claim as a candidate. A claim can only ever
	// attach additional citation evidence to an already-promoted
	// Requirement; it can never introduce a Requirement, an action, or a
	// resource/condition value on its own authority.
	for _, claim := range input.ModelClaims {
		verifiedRefs, citationErr := requirementsVerifyCitations(claim.Citations, files)
		if citationErr != "" {
			citationsOK = false
			gaps = append(gaps, ci.Gap{Code: GapCitationMismatch, Scope: requirementsClaimScope(claim), Message: citationErr})
			continue
		}
		def, found := requirementsFindOperation(input.Definitions, claim.Provider, claim.Service, claim.Operation)
		if !found {
			operationsOK = false
			gaps = append(gaps, ci.Gap{
				Code:       GapUnknownOperation,
				Scope:      requirementsClaimScope(claim),
				Message:    "claimed operation \"" + claim.Operation + "\" has no matching definition for " + string(claim.Provider) + "/" + claim.Service,
				References: verifiedRefs,
			})
			continue
		}
		key := requirementsOperationKey{def.Provider, def.Service, def.Operation}
		indices, known := promoted[key]
		if !known || !requirementsClaimOverlapsStatic(claim, static.Operations, input.Definitions, def) {
			gaps = append(gaps, ci.Gap{
				Code:       GapUncorroboratedClaim,
				Scope:      requirementsClaimScope(claim),
				Message:    "model claim for " + def.Operation + " has no independently-extracted static call site corroborating it at the cited location; preserved as a candidate, not promoted",
				References: verifiedRefs,
			})
			continue
		}
		for _, idx := range indices {
			reqs[idx].References = append(reqs[idx].References, verifiedRefs...)
		}
	}

	sort.Slice(reqs, func(i, j int) bool {
		a, b := reqs[i], reqs[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Operation != b.Operation {
			return a.Operation < b.Operation
		}
		return a.Action < b.Action
	})

	// Resolve Investigation.Source before computing ScopeComplete, since a
	// source-mapping-mismatch gap must itself be able to block completeness
	// rather than being appended after the decision was already made.
	source := input.Workload.Source
	switch {
	case source.Repository == "" && source.Revision == "":
		source = input.Repository.Pin
	case input.Repository.Pin.Repository != "" &&
		(source.Repository != input.Repository.Pin.Repository || source.Revision != input.Repository.Pin.Revision):
		gaps = append(gaps, ci.Gap{
			Code:    GapSourceMappingMismatch,
			Scope:   consumerID,
			Message: "workload-declared source provenance disagrees with the repository actually read; preserved separately rather than silently overridden",
		})
	}
	// An Exact=true claim is only trustworthy when the revision is actually
	// shaped like an immutable git SHA (40 hex chars for SHA-1, 64 for
	// SHA-256); a short/synthetic revision string cannot be independently
	// proven immutable, so it is downgraded rather than propagated as-is.
	if source.Exact && !requirementsGitSHAPattern.MatchString(source.Revision) {
		source.Exact = false
		gaps = append(gaps, ci.Gap{
			Code:    GapSourceRevisionNotImmutable,
			Scope:   consumerID,
			Message: "source claims Exact=true but revision \"" + source.Revision + "\" is not a 40/64-character git SHA; downgraded rather than trusting an unverifiable immutability claim",
		})
	}

	sourceDigest, digestMatchesClaim := requirementsResolveSourceDigest(input.Repository.Pin, input.Repository.Files)
	if !digestMatchesClaim {
		gaps = append(gaps, ci.Gap{
			Code:    GapSourceDigestMismatch,
			Scope:   consumerID,
			Message: "the repository pin's claimed content digest does not match the digest independently recomputed from the actual pinned file bytes",
		})
	}

	scopeComplete := !repositoryIncomplete && !definitionsIncomplete && digestMatchesClaim && len(static.CoveredFiles) > 0
	if scopeComplete {
		for _, g := range gaps {
			if requirementsScopeImpactingGapCodes[g.Code] {
				scopeComplete = false
				break
			}
		}
	}

	return ci.Investigation{
		ConsumerID:   consumerID,
		Source:       source,
		Requirements: reqs,
		Validation: ci.Validation{
			Analyzer:           analyzer,
			SourceDigest:       sourceDigest,
			CitationsVerified:  citationsOK,
			OperationsVerified: operationsOK,
			ScopeComplete:      scopeComplete,
			CoveredFiles:       static.CoveredFiles,
			Gaps:               gaps,
		},
		Model: input.Model,
	}
}

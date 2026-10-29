package iac

import (
	"context"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// run carries state shared across the whole (possibly multi-module) static
// evaluation: the global principal accumulator, a cross-module identifier
// lookup table used to attribute grants declared in one module/resource to a
// principal declared in another, and the accumulated gap list.
type run struct {
	ctx     context.Context
	modules ci.ModuleReader

	account string
	project string
	region  string

	// resolvedIdentifiers narrowly binds specific provider-computed values a
	// prior live collection pass already resolved (TerraformInput.ResolvedIdentifiers).
	// Only a small, reviewed set of key families is ever consulted (see
	// computed.go); nothing else is interpreted from this map, and an absent
	// or empty map degrades gracefully to the existing scoped-gap behavior.
	resolvedIdentifiers map[string]string

	// metadataBindings mirrors TerraformInput.MetadataBindings: a raw HCL
	// traversal string (e.g.
	// "data.terraform_remote_state.bootstrap.outputs.project_id") bound to
	// one of "project_id"/"project_number"/"region"/"account_id". Only
	// consulted by terraformRemoteStateValue (gcp.go); state is never read,
	// and a traversal with no entry here stays an explicit unresolved gap.
	metadataBindings map[string]string

	gaps []ci.Gap

	principals map[string]*principalAccum // Principal.ID -> accumulator
	lookup     map[string]string          // identifier (arn/name/email/id) -> Principal.ID
	policies   map[string]*localPolicy    // module-qualified resource address -> locally declared policy document

	// incompleteDocs records aws_iam_policy_document data source addresses
	// (module-qualified) whose own statement/condition/principals rendering
	// hit an internal gap (e.g. a dynamic block that failed to expand).
	// Consumers of that document's .json output (assume_role_policy, inline
	// policy, ...) check this so a reference like
	// data.aws_iam_policy_document.foo.json still marks the attaching
	// declaration incomplete even though evaluating the already-rendered
	// JSON string itself raises no new diagnostic.
	incompleteDocs map[string]bool

	groups      map[string]*groupAccum // module-qualified aws_iam_group resource address -> accumulator
	groupLookup map[string]string      // identifier (id/addr/name) -> group resource address

	moduleStack map[string]bool // cycle guard keyed by canonical module source+version
}

type principalAccum struct {
	principal  ci.Principal
	grants     []ci.Grant
	trust      []ci.Grant
	boundaries [][]ci.Grant
	refs       []ci.Reference
	incomplete bool
}

type localPolicy struct {
	grants     []ci.Grant
	refs       []ci.Reference
	incomplete bool
}

// groupAccum tracks an AWS IAM group's declared grants and resolved member
// principal IDs; groups themselves never surface as a ci.Declaration.
type groupAccum struct {
	id          string
	identifiers []string
	grants      []ci.Grant
	refs        []ci.Reference
	members     []string // resolved member Principal.ID values
	incomplete  bool
}

func newRun(ctx context.Context, modules ci.ModuleReader, in ci.TerraformInput) *run {
	return &run{
		ctx:                 ctx,
		modules:             modules,
		account:             in.Account,
		project:             in.Project,
		region:              in.Region,
		resolvedIdentifiers: in.ResolvedIdentifiers,
		metadataBindings:    in.MetadataBindings,
		principals:          map[string]*principalAccum{},
		lookup:              map[string]string{},
		policies:            map[string]*localPolicy{},
		incompleteDocs:      map[string]bool{},
		groups:              map[string]*groupAccum{},
		groupLookup:         map[string]string{},
		moduleStack:         map[string]bool{},
	}
}

func (r *run) addGap(g ci.Gap) {
	r.gaps = append(r.gaps, g)
}

// gapMark/gapsSince let a caller detect whether any gap (of any code, from
// any nested helper -- unresolved expressions, unsupported functions,
// PartialContent/dynblock expansion errors, ...) was recorded while it built
// one specific fact, so it can mark the right declaration/policy/group
// incomplete without threading a bool through every helper signature.
func (r *run) gapMark() int {
	return len(r.gaps)
}

func (r *run) gapsSince(mark int) bool {
	return len(r.gaps) > mark
}

// registerPrincipal creates (or returns the existing) accumulator for a
// declared AWS/GCP identity and indexes every known identifier string that
// other resources may use to reference it (ARN, friendly name, path-form
// name, email).
func (r *run) registerPrincipal(p ci.Principal, identifiers []string, ref ci.Reference) *principalAccum {
	acc, ok := r.principals[p.ID]
	if !ok {
		acc = &principalAccum{principal: p}
		r.principals[p.ID] = acc
	}
	acc.refs = append(acc.refs, ref)
	for _, id := range identifiers {
		if id == "" {
			continue
		}
		r.lookup[id] = p.ID
	}
	return acc
}

// resolvePrincipal looks up a previously registered principal by any known
// identifier string (ARN, name, email, id). ok is false when the identifier
// is unknown within the scanned scope (e.g. an externally managed role).
func (r *run) resolvePrincipal(identifier string) (*principalAccum, bool) {
	id, ok := r.lookup[identifier]
	if !ok {
		return nil, false
	}
	acc, ok := r.principals[id]
	return acc, ok
}

// markModuleScopeIncomplete marks every already-registered principal
// declared directly inside mf's own module scope (never a descendant
// module reached via a nested module call) incomplete. Used by
// processModule when mf's directory contains a ".tf.json" configuration
// file (R14 finding 2) whose block structure was never statically parsed:
// any identity declared alongside it in that same directory could be the
// target of a grant/trust/boundary attachment this reader could not see,
// so it must never look falsely Complete.
func (r *run) markModuleScopeIncomplete(mf moduleFiles) {
	prefix := mf.addr + "."
	for _, acc := range r.principals {
		for _, ref := range acc.refs {
			rest, ok := strings.CutPrefix(ref.Scope, prefix)
			if !ok || strings.HasPrefix(rest, "module.") {
				continue
			}
			acc.incomplete = true
			break
		}
	}
}

// declarations flattens the accumulator into the public ci.Declaration slice,
// deterministically ordered by principal ID for stable output.
func (r *run) declarations() []ci.Declaration {
	ids := make([]string, 0, len(r.principals))
	for id := range r.principals {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]ci.Declaration, 0, len(ids))
	for _, id := range ids {
		acc := r.principals[id]
		out = append(out, ci.Declaration{
			Principal: acc.principal,
			Policy: ci.PolicyState{
				Grants:     acc.grants,
				Boundaries: acc.boundaries,
				Trust:      acc.trust,
				Complete:   !acc.incomplete,
				References: acc.refs,
			},
		})
	}
	return out
}

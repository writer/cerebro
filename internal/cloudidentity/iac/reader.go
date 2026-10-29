// Package iac parses pinned Terraform source statically (HCL/cty) to extract
// declared AWS and GCP cloud-identity principals and policy state. It performs
// no filesystem, network, or provider I/O of its own: every byte of source
// comes from the injected ci.Repository/ci.ModuleReader, so this package can
// run entirely offline against already-materialized source.
//
// Most provider-computed attributes (account IDs absent from TerraformInput,
// data sources other than aws_iam_policy_document/aws_eks_cluster, unpinned
// module versions, provider-side functions such as file()/timestamp()/uuid())
// are surfaced as scoped ci.Gap values rather than fabricated. A narrow
// exception is TerraformInput.ResolvedIdentifiers (see computed.go): two
// reviewed key families let a prior live collection pass hand back an EKS
// cluster's OIDC issuer or a GCP project's numeric ID, both of which are
// otherwise only knowable live, so ordinary HCL evaluation of the role trust
// policies/workload-identity bindings that reference them resolves exactly
// as it would against live state. No other computed value is ever accepted
// through that map, and its absence degrades gracefully to a scoped gap.
package iac

import (
	"context"
	"fmt"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// Bounds are defensive limits against pathological input; the adapter that
// supplies ci.Repository/ci.ModuleReader already enforces byte/file budgets,
// these are a second, cheap backstop local to static analysis.
const (
	maxModuleDepth    = 10
	maxResourceCount  = 4096
	maxDynamicNesting = 16
)

// reader implements ci.DeclarationReader using only the injected ModuleReader
// for any out-of-repository (public module) source.
type reader struct {
	modules ci.ModuleReader
}

// NewDeclarationReader returns a ci.DeclarationReader that parses Terraform
// HCL statically. modules resolves pinned public module sources; it may be
// nil only if the caller guarantees no non-local module blocks are present
// (a nil ModuleReader turns every remote module reference into a scoped gap
// instead of panicking).
func NewDeclarationReader(modules ci.ModuleReader) ci.DeclarationReader {
	return &reader{modules: modules}
}

// ReadDeclarations statically evaluates the Terraform root named by
// in.Root within in.Repository, descending into local and pinned public
// module calls, and returns one ci.Declaration per declared AWS/GCP identity
// principal (IAM role/user, GCP service account) found reachable from that
// root. Declarations accumulate grants/trust/boundaries contributed by any
// resource in scope (inline policies, attachments, group membership, IAM
// bindings) regardless of which module declared the contributing resource.
func (r *reader) ReadDeclarations(ctx context.Context, in ci.TerraformInput) ([]ci.Declaration, []ci.Gap, error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("cloudidentity/iac: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	files := indexFiles(in.Repository.Files)
	rn := newRun(ctx, r.modules, in)

	root := moduleFiles{
		pin:   in.Repository.Pin,
		dir:   normalizeDir(in.Root),
		addr:  "root",
		index: files,
	}
	root.files = filesUnderDir(files, root.dir)

	if len(root.files) == 0 {
		rn.addGap(ci.Gap{
			Code:    "iac.empty_root",
			Scope:   "module",
			Message: fmt.Sprintf("no .tf files found under root %q", in.Root),
			References: []ci.Reference{{
				Repository: in.Repository.Pin.Repository,
				Revision:   in.Repository.Pin.Revision,
				Path:       in.Root,
				Digest:     in.Repository.Pin.Digest,
			}},
		})
		return nil, append(append([]ci.Gap{}, in.Repository.Gaps...), rn.gaps...), nil
	}

	rootVars, varGaps := rn.resolveRootVariables(files, root.dir, root, in.Variables)
	rn.gaps = append(rn.gaps, varGaps...)

	rn.processModule(root, literalOverrides(rootVars), 0)
	rn.propagateGroupGrants()

	decls := rn.declarations()
	allGaps := append(append([]ci.Gap{}, in.Repository.Gaps...), rn.gaps...)
	return decls, allGaps, nil
}

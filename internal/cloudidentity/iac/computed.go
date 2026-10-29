package iac

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// Narrow, reviewed TerraformInput.ResolvedIdentifiers key families. These are
// the ONLY external bindings this reader ever consults; a value is always a
// plain resolved string (an OIDC issuer host, a GCP numeric project number)
// supplied by a prior live collection pass -- never an expression, and never
// evaluated or executed. Every other provider-computed attribute (anything
// not covered by these two families) remains an explicit scoped gap: this
// mechanism intentionally does not grow into general variable injection.
const (
	// key = resolvedKeyEKSOIDCIssuer + <statically-resolved aws_eks_cluster name>
	// value = the cluster's OIDC issuer host, with or without the "https://" scheme.
	// Matches the key the AWS live CloudReader emits on Observation.ResolvedIdentifiers.
	resolvedKeyEKSOIDCIssuer = "aws_eks_oidc_issuer:"
	// key = resolvedKeyGCPProjectNumber + <GCP project ID>
	// value = the numeric GCP project number as a decimal string.
	resolvedKeyGCPProjectNumber = "gcp_project_number:"
)

func (rn *run) resolvedEKSOIDCIssuer(clusterName string) (string, bool) {
	v, ok := rn.resolvedIdentifiers[resolvedKeyEKSOIDCIssuer+clusterName]
	return strings.TrimPrefix(v, "https://"), ok && v != ""
}

func (rn *run) resolvedGCPProjectNumber(projectID string) (string, bool) {
	v, ok := rn.resolvedIdentifiers[resolvedKeyGCPProjectNumber+projectID]
	return v, ok && v != ""
}

// eksClusterValue resolves aws_eks_cluster/data.aws_eks_cluster's ARN (fully
// derivable from TerraformInput.Account/Region plus the statically-known
// cluster name; no live resolution ever needed) and, when the collector
// supplied the matching ResolvedIdentifiers entry, its identity[0].oidc[0].issuer
// in the exact shape the AWS provider exposes it, so ordinary expression
// evaluation (replace(), string interpolation, jsonencode(), ...) resolves
// trust policies referencing it exactly as it would against live state.
// Without a matching entry the issuer stays unknown and every reference to
// it surfaces the existing iac.unresolved_computed_value gap untouched.
func (rn *run) eksClusterValue(scope string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	name := rn.firstString(ctx, mf, file, scope, body, "name")
	attrs := map[string]cty.Value{"name": cty.StringVal(name)}
	if name == "" {
		attrs["id"] = cty.UnknownVal(cty.String)
		attrs["arn"] = cty.UnknownVal(cty.String)
		attrs["identity"] = cty.UnknownVal(cty.List(cty.DynamicPseudoType))
		return cty.ObjectVal(attrs)
	}
	attrs["id"] = cty.StringVal(name)
	if rn.account != "" && rn.region != "" {
		attrs["arn"] = cty.StringVal(fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", rn.region, rn.account, name))
	} else {
		attrs["arn"] = cty.UnknownVal(cty.String)
	}

	issuer, ok := rn.resolvedEKSOIDCIssuer(name)
	if !ok {
		rn.addGap(ci.Gap{
			Code:  "iac.unresolved_live_identifier",
			Scope: scope,
			Message: fmt.Sprintf(
				"EKS cluster %q OIDC issuer is only known live; supply TerraformInput.ResolvedIdentifiers[%q] from a prior live EKS DescribeCluster read, or every reference to identity[0].oidc[0].issuer on this cluster stays an explicit unresolved gap",
				name, resolvedKeyEKSOIDCIssuer+name,
			),
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		attrs["identity"] = cty.UnknownVal(cty.List(cty.DynamicPseudoType))
		return cty.ObjectVal(attrs)
	}
	oidc := cty.ObjectVal(map[string]cty.Value{"issuer": cty.StringVal("https://" + issuer)})
	identity := cty.ObjectVal(map[string]cty.Value{"oidc": cty.TupleVal([]cty.Value{oidc})})
	attrs["identity"] = cty.TupleVal([]cty.Value{identity})
	return cty.ObjectVal(attrs)
}

// oidcProviderIdentity resolves aws_iam_openid_connect_provider's ARN. It
// does not need its own ResolvedIdentifiers entry: the provider's `url` is
// ordinary HCL (almost always a direct or templated reference to an
// aws_eks_cluster's issuer), so once eksClusterValue has made that issuer
// resolvable, normal expression evaluation already resolves `url` here; this
// just derives the deterministic ARN shape AWS assigns from account+issuer.
func (rn *run) oidcProviderIdentity(scope string, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	url := rn.firstString(ctx, mf, file, scope, body, "url")
	if url == "" || rn.account == "" {
		return cty.ObjectVal(map[string]cty.Value{
			"arn": cty.UnknownVal(cty.String),
			"id":  cty.UnknownVal(cty.String),
			"url": cty.StringVal(url),
		})
	}
	issuerPath := strings.TrimPrefix(url, "https://")
	arn := fmt.Sprintf("arn:aws:iam::%s:oidc-provider/%s", rn.account, issuerPath)
	return cty.ObjectVal(map[string]cty.Value{
		"arn": cty.StringVal(arn),
		"id":  cty.StringVal(arn),
		"url": cty.StringVal(url),
	})
}

// gcpWorkloadIdentityPoolValue resolves google_iam_workload_identity_pool's
// `name`/`id`, needed to construct workload-identity member strings
// (principalSet://iam.googleapis.com/<pool name>/...). The numeric GCP
// project number cannot be derived from the project ID statically; it comes
// from TerraformInput.ResolvedIdentifiers when a prior live Resource Manager
// read supplied it.
func (rn *run) gcpWorkloadIdentityPoolValue(scope string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	project := rn.resolveGoogleProject(mf, ctx, file, scope, body, "project")
	poolID := rn.firstString(ctx, mf, file, scope, body, "workload_identity_pool_id")
	attrs := map[string]cty.Value{"workload_identity_pool_id": cty.StringVal(poolID)}
	if poolID == "" {
		attrs["id"] = cty.UnknownVal(cty.String)
		attrs["name"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(attrs)
	}
	attrs["id"] = cty.StringVal(poolID)

	if project == "" {
		attrs["name"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(attrs)
	}
	number, ok := rn.resolvedGCPProjectNumber(project)
	if !ok {
		rn.addGap(ci.Gap{
			Code:  "iac.unresolved_live_identifier",
			Scope: scope,
			Message: fmt.Sprintf(
				"GCP project %q's numeric project number is only known live; supply TerraformInput.ResolvedIdentifiers[%q], or workload-identity member strings referencing this pool stay an explicit unresolved gap",
				project, resolvedKeyGCPProjectNumber+project,
			),
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		attrs["name"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(attrs)
	}
	attrs["name"] = cty.StringVal(fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", number, poolID))
	return cty.ObjectVal(attrs)
}

// gcpWorkloadIdentityPoolProviderValue resolves
// google_iam_workload_identity_pool_provider's `name`, the same way.
func (rn *run) gcpWorkloadIdentityPoolProviderValue(scope string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	project := rn.resolveGoogleProject(mf, ctx, file, scope, body, "project")
	poolID := rn.firstString(ctx, mf, file, scope, body, "workload_identity_pool_id")
	providerID := rn.firstString(ctx, mf, file, scope, body, "workload_identity_pool_provider_id")
	if project == "" || poolID == "" || providerID == "" {
		return cty.ObjectVal(map[string]cty.Value{"name": cty.UnknownVal(cty.String)})
	}
	number, ok := rn.resolvedGCPProjectNumber(project)
	if !ok {
		rn.addGap(ci.Gap{
			Code:  "iac.unresolved_live_identifier",
			Scope: scope,
			Message: fmt.Sprintf(
				"GCP project %q's numeric project number is only known live; supply TerraformInput.ResolvedIdentifiers[%q], or this provider's name stays an explicit unresolved gap",
				project, resolvedKeyGCPProjectNumber+project,
			),
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		return cty.ObjectVal(map[string]cty.Value{"name": cty.UnknownVal(cty.String)})
	}
	name := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", number, poolID, providerID)
	return cty.ObjectVal(map[string]cty.Value{"name": cty.StringVal(name)})
}

// awsCallerIdentityValue resolves data.aws_caller_identity, bounded
// strictly to TerraformInput.Account (finding 7): account_id is the only
// field this reader can ever know statically, since the caller's exact
// IAM ARN/user_id are only known live. An empty TerraformInput.Account
// leaves account_id unknown and an explicit unresolved gap -- never
// fabricated or defaulted.
func (rn *run) awsCallerIdentityValue(scope string, declRange hcl.Range, mf moduleFiles, file *ci.SourceFile) cty.Value {
	if rn.account == "" {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_identifier",
			Scope:      scope,
			Message:    "data.aws_caller_identity.account_id is only known from TerraformInput.Account, which is empty for this scan",
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		return cty.ObjectVal(map[string]cty.Value{
			"account_id": cty.UnknownVal(cty.String),
			"arn":        cty.UnknownVal(cty.String),
			"id":         cty.UnknownVal(cty.String),
			"user_id":    cty.UnknownVal(cty.String),
		})
	}
	return cty.ObjectVal(map[string]cty.Value{
		"account_id": cty.StringVal(rn.account),
		"arn":        cty.UnknownVal(cty.String),
		"id":         cty.StringVal(rn.account),
		"user_id":    cty.UnknownVal(cty.String),
	})
}

// awsRegionValue resolves data.aws_region, bounded strictly to
// TerraformInput.Region (finding 8's AWS region half): both the current
// `region` attribute and its deprecated `name` alias resolve to the same
// configured region string, mirroring how the AWS provider itself exposes
// data.aws_region.current.region in a configured EKS module's trust/OIDC
// expressions. Every other attribute (description, endpoint) stays
// unknown -- this mechanism never grows beyond the reviewed
// ResolvedIdentifiers/Account/Project/Region families. An empty
// TerraformInput.Region leaves region/name unknown and an explicit
// unresolved gap -- never fabricated or defaulted.
func (rn *run) awsRegionValue(scope string, declRange hcl.Range, mf moduleFiles, file *ci.SourceFile) cty.Value {
	if rn.region == "" {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_identifier",
			Scope:      scope,
			Message:    "data.aws_region.region/name is only known from TerraformInput.Region, which is empty for this scan",
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		return cty.ObjectVal(map[string]cty.Value{
			"region":      cty.UnknownVal(cty.String),
			"name":        cty.UnknownVal(cty.String),
			"description": cty.UnknownVal(cty.String),
			"endpoint":    cty.UnknownVal(cty.String),
			"id":          cty.UnknownVal(cty.String),
		})
	}
	return cty.ObjectVal(map[string]cty.Value{
		"region":      cty.StringVal(rn.region),
		"name":        cty.StringVal(rn.region),
		"description": cty.UnknownVal(cty.String),
		"endpoint":    cty.UnknownVal(cty.String),
		"id":          cty.StringVal(rn.region),
	})
}

// googleProjectValue resolves data.google_project, bounded to the block's
// own `project_id` attribute (or TerraformInput.Project when absent) for
// project_id/id, and TerraformInput.ResolvedIdentifiers["gcp_project_number:<project>"]
// for number (finding 7). Every other provider-computed attribute (name,
// labels, ...) stays unknown; this mechanism never grows beyond the two
// reviewed ResolvedIdentifiers families documented at the top of this file.
func (rn *run) googleProjectValue(scope string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	project := rn.resolveGoogleProject(mf, ctx, file, scope, body, "project_id")
	if project == "" {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_project",
			Scope:      scope,
			Message:    "data.google_project has no project_id attribute and TerraformInput.Project is empty",
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		return cty.ObjectVal(map[string]cty.Value{
			"project_id": cty.UnknownVal(cty.String),
			"number":     cty.UnknownVal(cty.String),
			"name":       cty.UnknownVal(cty.String),
			"id":         cty.UnknownVal(cty.String),
		})
	}
	attrs := map[string]cty.Value{
		"project_id": cty.StringVal(project),
		"id":         cty.StringVal(project),
		"name":       cty.UnknownVal(cty.String),
	}
	number, ok := rn.resolvedGCPProjectNumber(project)
	if !ok {
		rn.addGap(ci.Gap{
			Code:  "iac.unresolved_live_identifier",
			Scope: scope,
			Message: fmt.Sprintf(
				"GCP project %q's numeric project number is only known live; supply TerraformInput.ResolvedIdentifiers[%q], or references to data.google_project.number stay an explicit unresolved gap",
				project, resolvedKeyGCPProjectNumber+project,
			),
			References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
		})
		attrs["number"] = cty.UnknownVal(cty.String)
		return cty.ObjectVal(attrs)
	}
	attrs["number"] = cty.StringVal(number)
	return cty.ObjectVal(attrs)
}

// passComputedIdentity was superseded by the unified dependency-ordered
// resolver in symbols.go (resolveValueSymbols); computedIdentityValue below
// is reused from there.

// computedIdentityValue dispatches to the builder for one
// resolveComputedBlock symbol: the provider-computed value kinds
// (aws_eks_cluster, OIDC provider, GCP WIF pool/provider) and every
// declared-identity resource kind (aws_iam_role/user/group/policy,
// google_service_account, GCP custom roles), whose name/arn/email-shaped
// value now participates in the same dependency graph as locals/modules
// (finding 6) so a module call argument referencing e.g.
// aws_iam_policy.foo.arn resolves before that module is evaluated. Grant
// attachment for these identities (trust, inline/attached policies, group
// membership, IAM bindings) stays exclusively in the later
// passTrustAndBoundary/passGrants passes.
func (rn *run) computedIdentityValue(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, partial bool) cty.Value {
	switch kind {
	case "aws_eks_cluster":
		return rn.eksClusterValue(addr, declRange, body, ctx, mf, file)
	case "aws_iam_openid_connect_provider":
		return rn.oidcProviderIdentity(addr, body, ctx, mf, file)
	case "google_iam_workload_identity_pool":
		return rn.gcpWorkloadIdentityPoolValue(addr, declRange, body, ctx, mf, file)
	case "google_iam_workload_identity_pool_provider":
		return rn.gcpWorkloadIdentityPoolProviderValue(addr, declRange, body, ctx, mf, file)
	case "aws_iam_role", "aws_iam_user", "aws_iam_group":
		return rn.awsPrincipalIdentity(kind, addr, declRange, body, ctx, mf, file, partial)
	case "aws_iam_policy":
		return rn.awsPolicyIdentity(addr, declRange, body, ctx, mf, file)
	case "google_service_account":
		return rn.gcpServiceAccountIdentity(addr, declRange, body, ctx, mf, file, partial)
	case "google_project_iam_custom_role", "google_organization_iam_custom_role":
		return rn.gcpCustomRoleIdentity(kind, addr, declRange, body, ctx, mf, file)
	default:
		return cty.EmptyObjectVal
	}
}

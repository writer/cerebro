package iac

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// passIdentity was superseded by the unified dependency-ordered resolver in
// symbols.go (resolveValueSymbols/computedIdentityValue): declared AWS IAM
// role/user/group/policy and GCP service account/custom role identities are
// now resolved as part of that same symbol graph (finding 6), so a module
// call argument referencing e.g. aws_iam_policy.foo.arn is already resolved
// before that module is evaluated, while trust/grant attachment for those
// identities still runs exclusively in the later passTrustAndBoundary/
// passGrants passes.

// awsPrincipalIdentity resolves one aws_iam_role/aws_iam_user/aws_iam_group
// instance's name/path/ARN, registering roles and users as cloud-identity
// Principals (groups are tracked separately: they can't be assumed or used
// directly, only their attached policies flow to member users).
func (rn *run) awsPrincipalIdentity(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, partial bool) cty.Value {
	scope := addr
	mark := rn.gapMark()
	name := rn.firstString(ctx, mf, file, scope, body, "name")
	generatedSuffix := false
	if name == "" {
		if prefix := rn.firstString(ctx, mf, file, scope, body, "name_prefix"); prefix != "" {
			name = prefix
			generatedSuffix = true
		}
	}
	pathVal := rn.firstString(ctx, mf, file, scope, body, "path")
	if pathVal == "" {
		pathVal = "/"
	}

	entityType := map[string]string{"aws_iam_role": "role", "aws_iam_user": "user", "aws_iam_group": "group"}[kind]
	ref := rn.refFor(mf, file, declRange, scope)

	var arn, id string
	incomplete := partial
	switch {
	case name == "":
		incomplete = true
		rn.addGap(ci.Gap{Code: "iac.unresolved_identifier", Scope: scope, Message: fmt.Sprintf("%s name could not be statically resolved", kind), References: []ci.Reference{ref}})
		id = "aws:" + entityType + ":" + addr
	case rn.account == "":
		incomplete = true
		rn.addGap(ci.Gap{Code: "iac.unresolved_account", Scope: scope, Message: "TerraformInput.Account is empty; cannot build a canonical ARN for this principal", References: []ci.Reference{ref}})
		id = "aws:" + entityType + ":" + addr
	default:
		arn = fmt.Sprintf("arn:aws:iam::%s:%s%s%s", rn.account, entityType, pathVal, name)
		id = arn
	}
	if generatedSuffix {
		incomplete = true
		rn.addGap(ci.Gap{Code: "iac.generated_name_suffix", Scope: scope, Message: fmt.Sprintf("%s uses name_prefix %q; the live resource name carries a generated suffix not knowable statically", kind, name), References: []ci.Reference{ref}})
	}

	identifiers := []string{id, addr}
	if arn != "" {
		identifiers = append(identifiers, arn)
	}
	if name != "" {
		identifiers = append(identifiers, name)
	}
	if rn.gapsSince(mark) {
		incomplete = true
	}

	if kind == "aws_iam_group" {
		g := &groupAccum{id: id, identifiers: identifiers, incomplete: incomplete}
		rn.groups[addr] = g
		for _, idf := range identifiers {
			if idf != "" {
				rn.groupLookup[idf] = addr
			}
		}
	} else {
		p := ci.Principal{ID: id, Provider: ci.AWS, Kind: entityType, Account: rn.account}
		acc := rn.registerPrincipal(p, identifiers, ref)
		if incomplete {
			acc.incomplete = true
		}
	}

	attrs := map[string]cty.Value{
		"name": cty.StringVal(name),
		"id":   cty.StringVal(id),
		"path": cty.StringVal(pathVal),
	}
	if arn != "" {
		attrs["arn"] = cty.StringVal(arn)
	} else {
		attrs["arn"] = cty.UnknownVal(cty.String)
	}
	return cty.ObjectVal(attrs)
}

// awsPolicyIdentity resolves one aws_iam_policy instance's name/ARN and
// parses its document into Grants via the shared ci.ParseAWSPolicy, indexed
// so later attachment/boundary resolution can find it by resource address or
// resolved ARN.
func (rn *run) awsPolicyIdentity(addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	scope := addr
	mark := rn.gapMark()
	name := rn.firstString(ctx, mf, file, scope, body, "name")
	if name == "" {
		name = rn.firstString(ctx, mf, file, scope, body, "name_prefix")
	}
	pathVal := rn.firstString(ctx, mf, file, scope, body, "path")
	if pathVal == "" {
		pathVal = "/"
	}
	ref := rn.refFor(mf, file, declRange, scope)

	var arn string
	if rn.account != "" && name != "" {
		arn = fmt.Sprintf("arn:aws:iam::%s:policy%s%s", rn.account, pathVal, name)
	} else {
		rn.addGap(ci.Gap{Code: "iac.unresolved_account", Scope: scope, Message: "cannot build a canonical ARN for aws_iam_policy without TerraformInput.Account and a resolved name", References: []ci.Reference{ref}})
	}

	var grants []ci.Grant
	if expr, ok := rn.bodyAttr(mf, file, scope, body, "policy"); ok {
		if rn.referencesIncompleteDocument(expr, mf) {
			rn.addGap(ci.Gap{Code: "iac.policy_document_incomplete", Scope: scope, Message: "policy references an aws_iam_policy_document whose own rendering hit an internal gap", References: []ci.Reference{ref}})
		}
		if doc, ok2 := rn.evalString(expr, ctx, mf, file, scope); ok2 {
			g, err := ci.ParseAWSPolicy([]byte(doc), ref)
			if err != nil {
				rn.addGap(ci.Gap{Code: "iac.policy_parse_error", Scope: scope, Message: err.Error(), References: []ci.Reference{ref}})
			} else {
				grants = g
			}
		}
	}

	lp := &localPolicy{grants: grants, refs: []ci.Reference{ref}, incomplete: rn.gapsSince(mark)}
	rn.policies[addr] = lp
	if arn != "" {
		rn.policies[arn] = lp
	}

	attrs := map[string]cty.Value{"name": cty.StringVal(name), "path": cty.StringVal(pathVal)}
	if arn != "" {
		attrs["arn"] = cty.StringVal(arn)
		attrs["id"] = cty.StringVal(arn)
	} else {
		attrs["arn"] = cty.UnknownVal(cty.String)
		attrs["id"] = cty.UnknownVal(cty.String)
	}
	return cty.ObjectVal(attrs)
}

// firstString evaluates the named attribute (if present) to a string,
// returning "" when absent or unresolved; callers that need to distinguish
// "absent" from "unresolved" should call bodyAttr/evalString directly.
func (rn *run) firstString(ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string, body hcl.Body, attrName string) string {
	expr, ok := rn.bodyAttr(mf, file, scope, body, attrName)
	if !ok {
		return ""
	}
	v, ok := rn.evalString(expr, ctx, mf, file, scope)
	if !ok {
		return ""
	}
	return v
}

// principalForAddr looks up a previously registered principal by its own
// resource address (role/user identity passes index addr as an identifier).
func (rn *run) principalForAddr(addr string) *principalAccum {
	acc, _ := rn.resolvePrincipal(addr)
	return acc
}

func (rn *run) resolveGroup(identifier string) (*groupAccum, bool) {
	addr, ok := rn.groupLookup[identifier]
	if !ok {
		return nil, false
	}
	g, ok := rn.groups[addr]
	return g, ok
}

// referencesIncompleteDocument reports whether expr directly traverses into
// a data.aws_iam_policy_document whose own statement/condition/principals
// rendering hit an internal gap (see incompleteDocs). Evaluating the
// document's already-rendered .json string itself raises no new diagnostic,
// so without this check a policy attribute that merely forwards an
// incomplete document would look fully resolved.
func (rn *run) referencesIncompleteDocument(expr hcl.Expression, mf moduleFiles) bool {
	for _, tr := range expr.Variables() {
		if tr.RootName() != "data" || len(tr) < 3 {
			continue
		}
		typeStep, ok := tr[1].(hcl.TraverseAttr)
		if !ok || typeStep.Name != "aws_iam_policy_document" {
			continue
		}
		labelStep, ok := tr[2].(hcl.TraverseAttr)
		if !ok {
			continue
		}
		if rn.incompleteDocs[mf.addr+".data.aws_iam_policy_document."+labelStep.Name] {
			return true
		}
	}
	return false
}

// passTrustAndBoundary resolves assume_role_policy (trust), inline
// `inline_policy` blocks, managed_policy_arns, and permissions_boundary on
// every declared role/user, now that ctx.aws_iam_policy/aws_iam_role/... are
// populated by passIdentity so references like aws_iam_policy.foo.arn and
// data.aws_iam_policy_document.foo.json resolve.
func (rn *run) passTrustAndBoundary(pm parsedModule, ctx *hcl.EvalContext, mf moduleFiles) {
	for _, tb := range pm.resources {
		if len(tb.block.Labels) < 2 {
			continue
		}
		kind, label := tb.block.Labels[0], tb.block.Labels[1]
		if kind != "aws_iam_role" && kind != "aws_iam_user" {
			continue
		}
		scope := mf.addr + "." + kind + "." + label
		instances := rn.expandInstances(tb.block, ctx, mf, tb.file, scope)
		for _, inst := range instances {
			addr := scope + inst.addrSuffix
			wrapped := dynblock.Expand(tb.block.Body, inst.ctx)
			acc := rn.principalForAddr(addr)
			if acc == nil {
				continue
			}
			mark := rn.gapMark()

			if kind == "aws_iam_role" {
				if expr, ok := rn.bodyAttr(mf, tb.file, addr, wrapped, "assume_role_policy"); ok {
					if rn.referencesIncompleteDocument(expr, mf) {
						acc.incomplete = true
					}
					if doc, ok2 := rn.evalString(expr, inst.ctx, mf, tb.file, addr); ok2 {
						ref := rn.refFor(mf, tb.file, expr.Range(), addr)
						grants, err := ci.ParseAWSPolicy([]byte(doc), ref)
						if err != nil {
							rn.addGap(ci.Gap{Code: "iac.policy_parse_error", Scope: addr, Message: err.Error(), References: []ci.Reference{ref}})
						} else {
							acc.trust = append(acc.trust, grants...)
						}
					}
				}
			}

			if expr, ok := rn.bodyAttr(mf, tb.file, addr, wrapped, "permissions_boundary"); ok {
				if boundaryArn, ok2 := rn.evalString(expr, inst.ctx, mf, tb.file, addr); ok2 {
					ref := rn.refFor(mf, tb.file, expr.Range(), addr)
					if lp, found := rn.policies[boundaryArn]; found {
						acc.boundaries = append(acc.boundaries, lp.grants)
						if lp.incomplete {
							acc.incomplete = true
						}
					} else {
						acc.boundaries = append(acc.boundaries, []ci.Grant{{
							ID: addr + "#boundary", Effect: "Allow", Role: boundaryArn, References: []ci.Reference{ref},
						}})
					}
				}
			}

			for _, ib := range rn.expandBlocks(mf, tb.file, addr, wrapped, inst.ctx, "inline_policy") {
				attrs := rn.bodyAttrs(mf, tb.file, addr, ib.Body, "name", "policy")
				polAttr, hasPol := attrs["policy"]
				if !hasPol {
					continue
				}
				if rn.referencesIncompleteDocument(polAttr.Expr, mf) {
					acc.incomplete = true
				}
				doc, ok2 := rn.evalString(polAttr.Expr, inst.ctx, mf, tb.file, addr)
				if !ok2 {
					continue
				}
				ref := rn.refFor(mf, tb.file, polAttr.Expr.Range(), addr)
				grants, err := ci.ParseAWSPolicy([]byte(doc), ref)
				if err != nil {
					rn.addGap(ci.Gap{Code: "iac.policy_parse_error", Scope: addr, Message: err.Error(), References: []ci.Reference{ref}})
					continue
				}
				acc.grants = append(acc.grants, grants...)
			}

			if expr, ok := rn.bodyAttr(mf, tb.file, addr, wrapped, "managed_policy_arns"); ok {
				ref := rn.refFor(mf, tb.file, expr.Range(), addr)
				for _, arn := range rn.evalStringList(expr, inst.ctx, mf, tb.file, addr) {
					if lp, found := rn.policies[arn]; found {
						acc.grants = append(acc.grants, lp.grants...)
						if lp.incomplete {
							acc.incomplete = true
						}
					} else {
						acc.grants = append(acc.grants, ci.Grant{ID: addr + "#managed:" + arn, Effect: "Allow", Role: arn, References: []ci.Reference{ref}})
					}
				}
			}

			if rn.gapsSince(mark) {
				acc.incomplete = true
			}
		}
	}
}

// attachGrants attributes grants produced by an inline/attached policy
// resource to the role/user/group it declares as its target. target is the
// evaluated `role`/`user`/`group` attribute value (name or ARN); an
// identifier unknown within the scanned scope is a scoped gap, never a
// fabricated principal. incomplete marks the destination's PolicyState as
// not fully resolved (e.g. the policy document itself had an internal gap)
// even though a syntactically valid grant was still produced.
func (rn *run) attachGrants(sourceKind, targetKind, target string, grants []ci.Grant, ref ci.Reference, scope string, incomplete bool) {
	if targetKind == "group" {
		g, ok := rn.resolveGroup(target)
		if !ok {
			rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("%s references group %q, which is not a declared aws_iam_group in scope", sourceKind, target), References: []ci.Reference{ref}})
			return
		}
		g.grants = append(g.grants, grants...)
		g.refs = append(g.refs, ref)
		if incomplete {
			g.incomplete = true
		}
		return
	}
	acc, ok := rn.resolvePrincipal(target)
	if !ok {
		rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("%s references %q, which is not a declared principal in scope", sourceKind, target), References: []ci.Reference{ref}})
		return
	}
	acc.grants = append(acc.grants, grants...)
	acc.refs = append(acc.refs, ref)
	if incomplete {
		acc.incomplete = true
	}
}

var awsInlinePolicyTarget = map[string]string{
	"aws_iam_role_policy": "role", "aws_iam_user_policy": "user", "aws_iam_group_policy": "group",
}

func (rn *run) awsInlinePolicy(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	mark := rn.gapMark()
	targetKind := awsInlinePolicyTarget[kind]
	targetExpr, ok := rn.bodyAttr(mf, file, scope, body, targetKind)
	if !ok {
		return
	}
	target, ok := rn.evalString(targetExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	policyExpr, ok := rn.bodyAttr(mf, file, scope, body, "policy")
	if !ok {
		return
	}
	incomplete := rn.referencesIncompleteDocument(policyExpr, mf)
	doc, ok := rn.evalString(policyExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	ref := rn.refFor(mf, file, declRange, scope)
	grants, err := ci.ParseAWSPolicy([]byte(doc), ref)
	if err != nil {
		rn.addGap(ci.Gap{Code: "iac.policy_parse_error", Scope: scope, Message: err.Error(), References: []ci.Reference{ref}})
		return
	}
	rn.attachGrants(kind, targetKind, target, grants, ref, scope, incomplete || rn.gapsSince(mark))
}

var awsAttachmentTarget = map[string]string{
	"aws_iam_role_policy_attachment": "role", "aws_iam_user_policy_attachment": "user", "aws_iam_group_policy_attachment": "group",
}

func (rn *run) awsPolicyAttachment(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	mark := rn.gapMark()
	targetKind := awsAttachmentTarget[kind]
	targetExpr, ok := rn.bodyAttr(mf, file, scope, body, targetKind)
	if !ok {
		return
	}
	target, ok := rn.evalString(targetExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	arnExpr, ok := rn.bodyAttr(mf, file, scope, body, "policy_arn")
	if !ok {
		return
	}
	policyArn, ok := rn.evalString(arnExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	ref := rn.refFor(mf, file, declRange, scope)
	if lp, found := rn.policies[policyArn]; found {
		rn.attachGrants(kind, targetKind, target, lp.grants, ref, scope, lp.incomplete || rn.gapsSince(mark))
		return
	}
	grant := ci.Grant{ID: addr, Effect: "Allow", Role: policyArn, References: []ci.Reference{ref}}
	rn.attachGrants(kind, targetKind, target, []ci.Grant{grant}, ref, scope, rn.gapsSince(mark))
}

func (rn *run) awsGroupMembership(addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	groupExpr, ok := rn.bodyAttr(mf, file, scope, body, "group")
	if !ok {
		return
	}
	groupID, ok := rn.evalString(groupExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	usersExpr, ok := rn.bodyAttr(mf, file, scope, body, "users")
	if !ok {
		return
	}
	users := rn.evalStringList(usersExpr, ctx, mf, file, scope)
	ref := rn.refFor(mf, file, declRange, scope)

	g, found := rn.resolveGroup(groupID)
	if !found {
		rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("aws_iam_group_membership references group %q, which is not a declared aws_iam_group in scope", groupID), References: []ci.Reference{ref}})
		return
	}
	for _, u := range users {
		if acc, ok := rn.resolvePrincipal(u); ok {
			g.members = append(g.members, acc.principal.ID)
		} else {
			rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("group member %q is not a declared aws_iam_user in scope", u), References: []ci.Reference{ref}})
		}
	}
}

func (rn *run) awsUserGroupMembership(addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	userExpr, ok := rn.bodyAttr(mf, file, scope, body, "user")
	if !ok {
		return
	}
	userID, ok := rn.evalString(userExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	groupsExpr, ok := rn.bodyAttr(mf, file, scope, body, "groups")
	if !ok {
		return
	}
	groups := rn.evalStringList(groupsExpr, ctx, mf, file, scope)
	ref := rn.refFor(mf, file, declRange, scope)

	acc, found := rn.resolvePrincipal(userID)
	if !found {
		rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("aws_iam_user_group_membership references user %q, which is not a declared aws_iam_user in scope", userID), References: []ci.Reference{ref}})
		return
	}
	for _, gid := range groups {
		if g, ok := rn.resolveGroup(gid); ok {
			g.members = append(g.members, acc.principal.ID)
		} else {
			rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("group %q is not a declared aws_iam_group in scope", gid), References: []ci.Reference{ref}})
		}
	}
}

// grantProducingKinds names every resource kind passGrants attributes to an
// already-declared identity: AWS inline/attached policies and group
// membership, and GCP project/org/folder/service-account IAM member/
// binding resources. gcpResourceLevelKinds (resource-scoped GCP bindings)
// and gcpIAMMemberBindingPolicyPattern (everything else matching
// "google_*_iam_member/_iam_binding/_iam_policy") are handled alongside
// this set in passGrants and in resolveValueSymbols's reachability seeding
// (finding 8), but are kept in gcp.go next to their dedicated handlers.
var grantProducingKinds = map[string]bool{
	"aws_iam_role_policy": true, "aws_iam_user_policy": true, "aws_iam_group_policy": true,
	"aws_iam_role_policy_attachment": true, "aws_iam_user_policy_attachment": true, "aws_iam_group_policy_attachment": true,
	"aws_iam_group_membership": true, "aws_iam_user_group_membership": true,
	"google_project_iam_member": true, "google_project_iam_binding": true,
	"google_organization_iam_member": true, "google_organization_iam_binding": true,
	"google_folder_iam_member": true, "google_folder_iam_binding": true,
	"google_service_account_iam_member": true, "google_service_account_iam_binding": true,
}

// passGrants resolves every remaining grant-producing resource type: AWS
// inline/attached policies and group membership, GCP project/org/folder/
// service-account IAM bindings, the resource-scoped GCP IAM kinds in
// gcpResourceLevelKinds (finding 10), and any other
// "google_*_iam_member/_iam_binding/_iam_policy" kind this reader does not
// canonicalize (routed to gcpUnsupportedResourceIAM as an explicit gap
// rather than silently skipped). It runs after passTrustAndBoundary so
// every implicit cross-resource reference it may use is already resolved.
func (rn *run) passGrants(pm parsedModule, ctx *hcl.EvalContext, mf moduleFiles) {
	for _, tb := range pm.resources {
		if len(tb.block.Labels) < 2 {
			continue
		}
		kind, label := tb.block.Labels[0], tb.block.Labels[1]
		unsupportedGCPIAM := !grantProducingKinds[kind] && !gcpResourceLevelKinds[kind] && gcpIAMMemberBindingPolicyPattern.MatchString(kind)
		if !grantProducingKinds[kind] && !gcpResourceLevelKinds[kind] && !unsupportedGCPIAM {
			continue
		}
		scope := mf.addr + "." + kind + "." + label
		instances := rn.expandInstances(tb.block, ctx, mf, tb.file, scope)
		for _, inst := range instances {
			addr := scope + inst.addrSuffix
			wrapped := dynblock.Expand(tb.block.Body, inst.ctx)
			switch {
			case kind == "aws_iam_role_policy" || kind == "aws_iam_user_policy" || kind == "aws_iam_group_policy":
				rn.awsInlinePolicy(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case kind == "aws_iam_role_policy_attachment" || kind == "aws_iam_user_policy_attachment" || kind == "aws_iam_group_policy_attachment":
				rn.awsPolicyAttachment(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case kind == "aws_iam_group_membership":
				rn.awsGroupMembership(addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case kind == "aws_iam_user_group_membership":
				rn.awsUserGroupMembership(addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case kind == "google_project_iam_member" || kind == "google_project_iam_binding" ||
				kind == "google_organization_iam_member" || kind == "google_organization_iam_binding" ||
				kind == "google_folder_iam_member" || kind == "google_folder_iam_binding":
				rn.gcpResourceIAM(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case kind == "google_service_account_iam_member" || kind == "google_service_account_iam_binding":
				rn.gcpServiceAccountIAM(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case gcpResourceLevelKinds[kind]:
				rn.gcpResourceLevelIAM(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			case unsupportedGCPIAM:
				rn.gcpUnsupportedResourceIAM(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, mf, tb.file)
			}
		}
	}
}

// propagateGroupGrants copies every AWS group's accumulated grants onto its
// resolved member users. Groups themselves never become ci.Declaration
// principals (they cannot be assumed or used as a Kubernetes workload
// identity); only the derived per-user grant is evidence.
func (rn *run) propagateGroupGrants() {
	addrs := make([]string, 0, len(rn.groups))
	for a := range rn.groups {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		g := rn.groups[a]
		seen := map[string]bool{}
		members := make([]string, 0, len(g.members))
		for _, m := range g.members {
			if !seen[m] {
				seen[m] = true
				members = append(members, m)
			}
		}
		sort.Strings(members)
		for _, mid := range members {
			acc, ok := rn.principals[mid]
			if !ok {
				continue
			}
			acc.grants = append(acc.grants, g.grants...)
			acc.refs = append(acc.refs, g.refs...)
			if g.incomplete {
				acc.incomplete = true
			}
		}
	}
}

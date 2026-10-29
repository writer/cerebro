package iac

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// resolveGoogleProject resolves a google resource's effective project
// (R14 finding 3), in precedence order: (1) the resource's own attrName
// attribute (usually "project"), if present and resolvable; (2) otherwise,
// when the resource carries no `provider = google.<alias>` meta-argument
// and this module scope is not itself provider-ambiguous (entered via a
// module call with an explicit `providers = {...}` mapping), the default
// (non-aliased) `provider "google" { project = ... }` block's own project
// for this scope, if one was set and resolvable; (3) otherwise
// TerraformInput.Project, exactly as before this fix. An aliased/
// ambiguous provider situation never consults the default provider block.
func (rn *run) resolveGoogleProject(mf moduleFiles, ctx *hcl.EvalContext, file *ci.SourceFile, scope string, body hcl.Body, attrName string) string {
	if project := rn.firstString(ctx, mf, file, scope, body, attrName); project != "" {
		return project
	}
	if !mf.googleProjectAmbiguous && mf.defaultGoogleProject != "" {
		if _, aliased := rn.bodyAttr(mf, file, scope, body, "provider"); !aliased {
			return mf.defaultGoogleProject
		}
	}
	return rn.project
}

// gcpServiceAccountIdentity resolves one google_service_account instance's
// canonical email/name/member strings and registers it as a GCP Principal.
// account_id/project are the only inputs Terraform requires; the email is
// otherwise entirely deterministic from them, so an unresolved project
// (neither TerraformInput.Project nor a literal `project` attribute) is the
// only thing that can make this identity statically unknown.
func (rn *run) gcpServiceAccountIdentity(addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, partial bool) cty.Value {
	scope := addr
	mark := rn.gapMark()
	accountID := rn.firstString(ctx, mf, file, scope, body, "account_id")
	project := rn.resolveGoogleProject(mf, ctx, file, scope, body, "project")
	ref := rn.refFor(mf, file, declRange, scope)

	var email, name, member, id string
	incomplete := partial
	switch {
	case accountID == "":
		incomplete = true
		rn.addGap(ci.Gap{Code: "iac.unresolved_identifier", Scope: scope, Message: "google_service_account account_id could not be statically resolved", References: []ci.Reference{ref}})
		id = "gcp:sa:" + addr
	case project == "":
		incomplete = true
		rn.addGap(ci.Gap{Code: "iac.unresolved_project", Scope: scope, Message: "no project is known (TerraformInput.Project and the resource's own project attribute are both empty); cannot build a canonical service account email", References: []ci.Reference{ref}})
		id = "gcp:sa:" + addr
	default:
		email = fmt.Sprintf("%s@%s.iam.gserviceaccount.com", accountID, project)
		name = fmt.Sprintf("projects/%s/serviceAccounts/%s", project, email)
		member = "serviceAccount:" + email
		id = email
	}

	identifiers := []string{id, addr}
	if email != "" {
		identifiers = append(identifiers, email, name, member)
	}
	if accountID != "" {
		identifiers = append(identifiers, accountID)
	}

	p := ci.Principal{ID: id, Provider: ci.GCP, Kind: "service_account", Project: project}
	acc := rn.registerPrincipal(p, identifiers, ref)
	if incomplete || rn.gapsSince(mark) {
		acc.incomplete = true
	}

	attrs := map[string]cty.Value{
		"account_id": cty.StringVal(accountID),
		"project":    cty.StringVal(project),
		"id":         cty.StringVal(id),
	}
	if email != "" {
		attrs["email"] = cty.StringVal(email)
		attrs["name"] = cty.StringVal(name)
		attrs["member"] = cty.StringVal(member)
	} else {
		attrs["email"] = cty.UnknownVal(cty.String)
		attrs["name"] = cty.UnknownVal(cty.String)
		attrs["member"] = cty.UnknownVal(cty.String)
	}
	attrs["unique_id"] = cty.UnknownVal(cty.String) // provider-assigned, only known live
	return cty.ObjectVal(attrs)
}

// gcpServiceAccountResourceName returns the GCP IAM-canonical resource name
// for a declared service account ("projects/<project>/serviceAccounts/<email>"),
// falling back to the bare Principal.ID (email) when the project is unknown.
// Never fabricated: both inputs are either literal HCL or already-registered
// facts, never guessed.
func gcpServiceAccountResourceName(p ci.Principal) string {
	if p.Project != "" && strings.Contains(p.ID, "@") {
		return fmt.Sprintf("projects/%s/serviceAccounts/%s", p.Project, p.ID)
	}
	return p.ID
}

// gcpCustomRoleIdentity resolves a canonical "projects/.../roles/ID" or
// "organizations/.../roles/ID" name for a locally declared custom role. It is
// never registered as a Principal: custom roles are role definitions
// referenced unexpanded via Grant.Role, matching Definitions.Roles expansion
// happening elsewhere (ci.CloudReader.Define), not in this static reader.
func (rn *run) gcpCustomRoleIdentity(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) cty.Value {
	scope := addr
	roleID := rn.firstString(ctx, mf, file, scope, body, "role_id")

	var scopeVal string
	if kind == "google_project_iam_custom_role" {
		scopeVal = rn.resolveGoogleProject(mf, ctx, file, scope, body, "project")
	} else {
		scopeVal = rn.firstString(ctx, mf, file, scope, body, "org_id")
	}

	var name string
	switch {
	case roleID == "" || scopeVal == "":
		rn.addGap(ci.Gap{Code: "iac.unresolved_identifier", Scope: scope, Message: fmt.Sprintf("%s could not resolve a canonical role name statically", kind), References: []ci.Reference{rn.refFor(mf, file, declRange, scope)}})
	case kind == "google_project_iam_custom_role":
		name = fmt.Sprintf("projects/%s/roles/%s", scopeVal, roleID)
	default:
		name = fmt.Sprintf("organizations/%s/roles/%s", scopeVal, roleID)
	}

	attrs := map[string]cty.Value{"role_id": cty.StringVal(roleID)}
	if name != "" {
		attrs["id"] = cty.StringVal(name)
		attrs["name"] = cty.StringVal(name)
	} else {
		attrs["id"] = cty.UnknownVal(cty.String)
		attrs["name"] = cty.UnknownVal(cty.String)
	}
	return cty.ObjectVal(attrs)
}

// terraformRemoteStateValue resolves data.terraform_remote_state.<label>
// (finding 8's GCP remote-state half), honoring ONLY
// TerraformInput.MetadataBindings: a customer root's
// data.terraform_remote_state.bootstrap.outputs.project_id/project_number
// is bound by the caller to one of the scan's own project_id/
// project_number/region/account_id facts (ResolvedIdentifiers/Project/
// Region/Account). State itself is NEVER read -- the "backend"/"config"
// attributes on the block are never even inspected -- and an "outputs" key
// with no matching binding entry is left entirely absent from the exposed
// object, so referencing it surfaces the existing unresolved-expression
// gap exactly like any other unresolvable reference. A bound traversal
// whose underlying fact is unavailable for this scan is its own explicit
// unresolved gap, never fabricated or defaulted.
func (rn *run) terraformRemoteStateValue(scope string, declRange hcl.Range, label string, mf moduleFiles, file *ci.SourceFile) cty.Value {
	prefix := "data.terraform_remote_state." + label + ".outputs."
	outputs := map[string]cty.Value{}
	for traversal, fact := range rn.metadataBindings {
		key, ok := strings.CutPrefix(traversal, prefix)
		if !ok || key == "" {
			continue
		}
		v, resolved := rn.metadataFactValue(fact)
		if !resolved {
			rn.addGap(ci.Gap{
				Code:       "iac.unresolved_identifier",
				Scope:      scope,
				Message:    fmt.Sprintf("%s is bound to %q, which has no value for this scan", traversal, fact),
				References: []ci.Reference{rn.refFor(mf, file, declRange, scope)},
			})
			continue
		}
		outputs[key] = v
	}
	return cty.ObjectVal(map[string]cty.Value{"outputs": cty.ObjectVal(outputs)})
}

// metadataFactValue looks up one TerraformInput.MetadataBindings fact name
// against this scan's own inputs (never live state).
func (rn *run) metadataFactValue(fact string) (cty.Value, bool) {
	switch fact {
	case "project_id":
		if rn.project == "" {
			return cty.NilVal, false
		}
		return cty.StringVal(rn.project), true
	case "project_number":
		number, ok := rn.resolvedGCPProjectNumber(rn.project)
		if !ok {
			return cty.NilVal, false
		}
		return cty.StringVal(number), true
	case "region":
		if rn.region == "" {
			return cty.NilVal, false
		}
		return cty.StringVal(rn.region), true
	case "account_id":
		if rn.account == "" {
			return cty.NilVal, false
		}
		return cty.StringVal(rn.account), true
	default:
		return cty.NilVal, false
	}
}

// extractMembers reads either the singular `member` attribute (the
// *_iam_member resource family) or the `members` list attribute (the
// *_iam_binding family).
func (rn *run) extractMembers(body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) []string {
	if expr, ok := rn.bodyAttr(mf, file, scope, body, "member"); ok {
		if v, ok2 := rn.evalString(expr, ctx, mf, file, scope); ok2 && v != "" {
			return []string{v}
		}
		return nil
	}
	if expr, ok := rn.bodyAttr(mf, file, scope, body, "members"); ok {
		return rn.evalStringList(expr, ctx, mf, file, scope)
	}
	return nil
}

// extractGCPCondition reads an optional `condition { expression = ... }`
// block, preserving the raw CEL expression text verbatim (never evaluated or
// simplified) as the Condition's Expression.
func (rn *run) extractGCPCondition(body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) []ci.Condition {
	blocks := rn.expandBlocks(mf, file, scope, body, ctx, "condition")
	if len(blocks) == 0 {
		return nil
	}
	var out []ci.Condition
	for _, cb := range blocks {
		attrs := rn.bodyAttrs(mf, file, scope, cb.Body, "expression")
		exprAttr, ok := attrs["expression"]
		if !ok {
			continue
		}
		v, ok2 := rn.evalString(exprAttr.Expr, ctx, mf, file, scope)
		if !ok2 {
			continue
		}
		out = append(out, ci.Condition{Expression: v})
	}
	return out
}

// gcpResourceAttr names the attribute holding the resource a project/
// organization/folder-level IAM member/binding resource is scoped to.
var gcpResourceAttr = map[string]string{
	"google_project_iam_member": "project", "google_project_iam_binding": "project",
	"google_organization_iam_member": "org_id", "google_organization_iam_binding": "org_id",
	"google_folder_iam_member": "folder", "google_folder_iam_binding": "folder",
}

// gcpCanonicalResource builds the IAM-canonical resource name
// ("projects/P", "organizations/O", "folders/F") for a project/org/folder
// IAM binding from its already-resolved scope attribute value.
func gcpCanonicalResource(kind, value string) string {
	switch gcpResourceAttr[kind] {
	case "project":
		return "projects/" + value
	case "org_id":
		return "organizations/" + value
	case "folder":
		if strings.HasPrefix(value, "folders/") {
			return value
		}
		return "folders/" + value
	}
	return ""
}

// gcpResourceIAM resolves a project/organization/folder-level IAM
// member/binding resource. A binding granting a role to a declared service
// account's member string is that service account's OWN permission grant:
// it is resource-shaped (Role + Resources naming the project/org/folder),
// exactly like an AWS identity-policy statement, and never carries Members
// -- Members describes a trust/who-can-use-this-identity statement, and a
// core evaluator that sees Members on a grant correctly treats it as trust
// and skips it when assessing the identity's own permissions, so leaving
// Members populated here would make this grant invisible to that
// assessment. The evaluated member string is preserved on the Reference
// scope instead, for audit/citation. Members outside this analyzer's
// declared scope (users, groups, domains, allUsers/allAuthenticatedUsers)
// are not an error, just out of scope for a declared-principal evidence
// cohort. A member that is clearly meant to be a service account
// ("serviceAccount:...") but isn't a declared one in scope is a scoped gap,
// not a silent drop. An unresolved project/org/folder scope is a scoped gap
// and leaves Resources empty -- it is never defaulted to a wildcard.
func (rn *run) gcpResourceIAM(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	mark := rn.gapMark()
	roleExpr, ok := rn.bodyAttr(mf, file, scope, body, "role")
	if !ok {
		return
	}
	role, ok := rn.evalString(roleExpr, ctx, mf, file, scope)
	if !ok {
		return
	}

	attrName := gcpResourceAttr[kind]
	var resource string
	resourceResolved := false
	if attrName != "" {
		if rExpr, ok := rn.bodyAttr(mf, file, scope, body, attrName); ok {
			if v, ok2 := rn.evalString(rExpr, ctx, mf, file, scope); ok2 && v != "" {
				resource = gcpCanonicalResource(kind, v)
				resourceResolved = true
			}
		}
	}
	declRef := rn.refFor(mf, file, declRange, scope)
	if !resourceResolved {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_identifier",
			Scope:      scope,
			Message:    fmt.Sprintf("%s's %s attribute could not be statically resolved; the granted resource scope is unknown and is never assumed unrestricted", kind, attrName),
			References: []ci.Reference{declRef},
		})
	}

	members := rn.extractMembers(body, ctx, mf, file, scope)
	if len(members) == 0 {
		return
	}
	conditions := rn.extractGCPCondition(body, ctx, mf, file, scope)
	incomplete := rn.gapsSince(mark)

	for _, m := range members {
		if !strings.HasPrefix(m, "serviceAccount:") {
			// user:/group:/domain:/allUsers/allAuthenticatedUsers/principal(Set)://
			// members are legitimately outside this analyzer's declared-principal scope.
			continue
		}
		acc, ok := rn.resolvePrincipal(m)
		if !ok {
			rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("%s grants role %q to service account member %q, which is not a declared google_service_account in scope", kind, role, m), References: []ci.Reference{declRef}})
			continue
		}
		memberRef := declRef
		memberRef.Scope = scope + "#member:" + m
		var resources []string
		if resource != "" {
			resources = []string{resource}
		}
		acc.grants = append(acc.grants, ci.Grant{
			ID: addr + "#" + m, Effect: "Allow", Role: role, Resources: resources, Conditions: conditions, References: []ci.Reference{memberRef},
		})
		acc.refs = append(acc.refs, memberRef)
		if incomplete {
			acc.incomplete = true
		}
	}
}

// gcpServiceAccountIAM resolves google_service_account_iam_member/binding:
// who may impersonate/use this specific service account (workload identity,
// serviceAccountUser, serviceAccountTokenCreator, ...). This always lands in
// PolicyState.Trust on the target SA, resource-anchored on the target SA's
// own canonical name with Members naming who is trusted -- mirroring an AWS
// assume_role_policy. When a trusted member is itself a declared service
// account in this scan, the ability to use/impersonate the target is also
// that member's own outgoing permission, so it is additionally recorded as
// a resource-shaped Grant (no Members) on the member's own declaration --
// otherwise that capability would only be visible on the target's trust
// side and never show up when assessing the member SA's own excess.
func (rn *run) gcpServiceAccountIAM(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	mark := rn.gapMark()
	saExpr, ok := rn.bodyAttr(mf, file, scope, body, "service_account_id")
	if !ok {
		return
	}
	saID, ok := rn.evalString(saExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	roleExpr, ok := rn.bodyAttr(mf, file, scope, body, "role")
	if !ok {
		return
	}
	role, ok := rn.evalString(roleExpr, ctx, mf, file, scope)
	if !ok {
		return
	}
	members := rn.extractMembers(body, ctx, mf, file, scope)
	if len(members) == 0 {
		return
	}
	conditions := rn.extractGCPCondition(body, ctx, mf, file, scope)
	ref := rn.refFor(mf, file, declRange, scope)
	incomplete := rn.gapsSince(mark)

	targetAcc, ok := rn.resolvePrincipal(saID)
	if !ok {
		rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("%s references service_account_id %q, which is not a declared google_service_account in scope", kind, saID), References: []ci.Reference{ref}})
		return
	}
	targetResource := []string{gcpServiceAccountResourceName(targetAcc.principal)}
	if incomplete {
		targetAcc.incomplete = true
	}

	for _, m := range members {
		trustRef := ref
		trustRef.Scope = scope + "#member:" + m
		targetAcc.trust = append(targetAcc.trust, ci.Grant{
			ID: addr + "#" + m, Effect: "Allow", Role: role, Resources: targetResource, Members: []string{m}, Conditions: conditions, References: []ci.Reference{trustRef},
		})
		if strings.HasPrefix(m, "serviceAccount:") {
			if memberAcc, ok := rn.resolvePrincipal(m); ok && memberAcc != targetAcc {
				memberAcc.grants = append(memberAcc.grants, ci.Grant{
					ID: addr + "#outgoing:" + m, Effect: "Allow", Role: role, Resources: targetResource, Conditions: conditions, References: []ci.Reference{trustRef},
				})
				memberAcc.refs = append(memberAcc.refs, trustRef)
				if incomplete {
					memberAcc.incomplete = true
				}
			}
		}
	}
	targetAcc.refs = append(targetAcc.refs, ref)
}

// gcpResourceLevelKinds names the resource-level GCP IAM member/binding
// kinds this reader canonicalizes to a Cloud Asset Inventory-shaped full
// resource name (finding 10). These are the resource-level IAM types
// observed in deployed Terraform roots (pubsub topic/subscription, storage
// bucket, kms crypto key, secret manager grants are all actually configured
// there); any other "google_*_iam_member/_iam_binding/_iam_policy" kind is
// routed through gcpUnsupportedResourceIAM instead of being silently skipped.
var gcpResourceLevelKinds = map[string]bool{
	"google_pubsub_topic_iam_member": true, "google_pubsub_topic_iam_binding": true,
	"google_pubsub_subscription_iam_member": true, "google_pubsub_subscription_iam_binding": true,
	"google_storage_bucket_iam_member": true, "google_storage_bucket_iam_binding": true,
	"google_kms_crypto_key_iam_member": true, "google_kms_crypto_key_iam_binding": true,
	"google_secret_manager_secret_iam_member": true, "google_secret_manager_secret_iam_binding": true,
}

// gcpIAMMemberBindingPolicyPattern recognizes every GCP member/binding/
// whole-policy IAM resource kind, supported or not, so passGrants can route
// an unsupported one through gcpUnsupportedResourceIAM rather than silently
// dropping it (finding 10).
var gcpIAMMemberBindingPolicyPattern = regexp.MustCompile(`^google_.+_iam_(member|binding|policy)$`)

// gcpResourceLevelIAMAttr names the attribute holding the scoped resource
// identifier for each gcpResourceLevelKinds entry.
var gcpResourceLevelIAMAttr = map[string]string{
	"google_pubsub_topic_iam_member": "topic", "google_pubsub_topic_iam_binding": "topic",
	"google_pubsub_subscription_iam_member": "subscription", "google_pubsub_subscription_iam_binding": "subscription",
	"google_storage_bucket_iam_member": "bucket", "google_storage_bucket_iam_binding": "bucket",
	"google_kms_crypto_key_iam_member": "crypto_key_id", "google_kms_crypto_key_iam_binding": "crypto_key_id",
	"google_secret_manager_secret_iam_member": "secret_id", "google_secret_manager_secret_iam_binding": "secret_id",
}

// gcpCanonicalResourceLevelName builds the Cloud Asset Inventory full
// resource name ("//service.googleapis.com/...") for one
// gcpResourceLevelKinds attribute value, which Terraform accepts either as
// the resource's bare short name (requiring project for pubsub/secret
// manager; buckets are themselves project-less in Cloud Asset's naming) or
// already as a fully qualified "projects/..." id. ok is false when the
// value cannot be safely canonicalized (e.g. a bare pubsub/secret id with no
// known project) -- never defaulted to a wildcard or guessed project.
func gcpCanonicalResourceLevelName(kind, rawID, project string) (string, bool) {
	rawID = strings.TrimSpace(rawID)
	if rawID == "" {
		return "", false
	}
	switch kind {
	case "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding":
		name := rawID
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		// Cloud Asset Inventory names GCS buckets with a literal "_"
		// project wildcard segment: buckets are a globally unique,
		// project-independent namespace in that API.
		return "//storage.googleapis.com/projects/_/buckets/" + name, true
	case "google_pubsub_topic_iam_member", "google_pubsub_topic_iam_binding":
		return gcpQualifiedResourceName("pubsub.googleapis.com", "topics", rawID, project)
	case "google_pubsub_subscription_iam_member", "google_pubsub_subscription_iam_binding":
		return gcpQualifiedResourceName("pubsub.googleapis.com", "subscriptions", rawID, project)
	case "google_secret_manager_secret_iam_member", "google_secret_manager_secret_iam_binding":
		return gcpQualifiedResourceName("secretmanager.googleapis.com", "secrets", rawID, project)
	case "google_kms_crypto_key_iam_member", "google_kms_crypto_key_iam_binding":
		return gcpKMSCryptoKeyResourceName(rawID)
	}
	return "", false
}

// gcpQualifiedResourceName builds a Cloud Asset full resource name for a
// pubsub/secret-manager-style resource whose terraform attribute may
// already be the full "projects/<p>/<segment>/<id>" form, or just the bare
// id (which then needs a known project).
func gcpQualifiedResourceName(service, segment, rawID, project string) (string, bool) {
	if strings.HasPrefix(rawID, "projects/") {
		return "//" + service + "/" + rawID, true
	}
	if project == "" {
		return "", false
	}
	return fmt.Sprintf("//%s/projects/%s/%s/%s", service, project, segment, rawID), true
}

// gcpKMSCryptoKeyResourceName accepts crypto_key_id's two documented
// Terraform forms: the short "{project}/{location}/{key_ring}/{crypto_key}"
// or the full "projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{k}" path.
func gcpKMSCryptoKeyResourceName(rawID string) (string, bool) {
	if strings.HasPrefix(rawID, "projects/") {
		return "//cloudkms.googleapis.com/" + rawID, true
	}
	parts := strings.Split(rawID, "/")
	if len(parts) != 4 {
		return "", false
	}
	return fmt.Sprintf("//cloudkms.googleapis.com/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", parts[0], parts[1], parts[2], parts[3]), true
}

// gcpResourceLevelIAM resolves a pubsub topic/subscription, storage bucket,
// kms crypto key, or secret manager IAM member/binding resource (finding
// 10), mirroring gcpResourceIAM's project/org/folder handling but
// canonicalizing a Cloud Asset Inventory-shaped resource name instead of a
// bare "projects/P" scope.
func (rn *run) gcpResourceLevelIAM(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	mark := rn.gapMark()
	roleExpr, ok := rn.bodyAttr(mf, file, scope, body, "role")
	if !ok {
		return
	}
	role, ok := rn.evalString(roleExpr, ctx, mf, file, scope)
	if !ok {
		return
	}

	attrName := gcpResourceLevelIAMAttr[kind]
	var resource string
	resourceResolved := false
	if attrName != "" {
		if rExpr, ok := rn.bodyAttr(mf, file, scope, body, attrName); ok {
			if raw, ok2 := rn.evalString(rExpr, ctx, mf, file, scope); ok2 && raw != "" {
				project := rn.resolveGoogleProject(mf, ctx, file, scope, body, "project")
				if canon, ok3 := gcpCanonicalResourceLevelName(kind, raw, project); ok3 {
					resource = canon
					resourceResolved = true
				}
			}
		}
	}
	declRef := rn.refFor(mf, file, declRange, scope)
	if !resourceResolved {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_identifier",
			Scope:      scope,
			Message:    fmt.Sprintf("%s's %s attribute could not be statically resolved to a canonical resource name; the granted resource scope is unknown and is never assumed unrestricted", kind, attrName),
			References: []ci.Reference{declRef},
		})
	}

	members := rn.extractMembers(body, ctx, mf, file, scope)
	if len(members) == 0 {
		return
	}
	conditions := rn.extractGCPCondition(body, ctx, mf, file, scope)
	incomplete := rn.gapsSince(mark)

	for _, m := range members {
		if !strings.HasPrefix(m, "serviceAccount:") {
			continue
		}
		acc, ok := rn.resolvePrincipal(m)
		if !ok {
			rn.addGap(ci.Gap{Code: "iac.unattributed_grant", Scope: scope, Message: fmt.Sprintf("%s grants role %q to service account member %q, which is not a declared google_service_account in scope", kind, role, m), References: []ci.Reference{declRef}})
			continue
		}
		memberRef := declRef
		memberRef.Scope = scope + "#member:" + m
		var resources []string
		if resource != "" {
			resources = []string{resource}
		}
		acc.grants = append(acc.grants, ci.Grant{
			ID: addr + "#" + m, Effect: "Allow", Role: role, Resources: resources, Conditions: conditions, References: []ci.Reference{memberRef},
		})
		acc.refs = append(acc.refs, memberRef)
		if incomplete {
			acc.incomplete = true
		}
	}
}

// gcpUnsupportedResourceIAM handles any google_*_iam_member/_iam_binding/
// _iam_policy resource kind this reader does not canonicalize (finding 10):
// the grant is real but its resource scope cannot be safely modeled here,
// so it is always an explicit declaration gap, never silently skipped. An
// "_iam_policy" resource replaces a whole IAM policy with no per-member
// attribute this reader can statically attribute, so it is gapped
// unconditionally; "_iam_member"/"_iam_binding" resources are gapped only
// when one of their members matches a declared principal in scope.
func (rn *run) gcpUnsupportedResourceIAM(kind, addr string, declRange hcl.Range, body hcl.Body, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile) {
	scope := addr
	ref := rn.refFor(mf, file, declRange, scope)
	if strings.HasSuffix(kind, "_iam_policy") {
		rn.addGap(ci.Gap{
			Code:       "iac.unsupported_gcp_iam_resource",
			Scope:      scope,
			Message:    fmt.Sprintf("%s replaces an entire IAM policy, which this reader does not statically parse; any grants/trust it sets on principals in scope are an explicit incomplete gap", kind),
			References: []ci.Reference{ref},
		})
		return
	}
	members := rn.extractMembers(body, ctx, mf, file, scope)
	for _, m := range members {
		if !strings.HasPrefix(m, "serviceAccount:") {
			continue
		}
		acc, ok := rn.resolvePrincipal(m)
		if !ok {
			continue
		}
		acc.incomplete = true
		memberRef := ref
		memberRef.Scope = scope + "#member:" + m
		acc.refs = append(acc.refs, memberRef)
		rn.addGap(ci.Gap{
			Code:       "iac.unsupported_gcp_iam_resource",
			Scope:      scope,
			Message:    fmt.Sprintf("%s is not a resource kind this reader canonicalizes; it may grant a role to declared service account %q that is not reflected in its policy", kind, m),
			References: []ci.Reference{memberRef},
		})
	}
}

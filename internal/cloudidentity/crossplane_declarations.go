package cloudidentity

import "strings"

// DeclarationsFromManifests extracts IAM declarations from Crossplane-composed
// resources among already-rendered manifests (the output of a Composition
// pipeline's function-patch-and-transform/function-go-templating steps). It
// recognizes the common upbound/crossplane-contrib AWS IAM Role/RolePolicy/
// RolePolicyAttachment kinds (both the cluster-scoped "iam.aws.upbound.io"/
// "iam.aws.crossplane.io" groups and the namespaced "iam.aws.m.upbound.io"
// group the deployed XRole Composition actually emits) and Google Config
// Connector / upbound GCP ServiceAccount/IAM member kinds (including the
// namespaced "cloudplatform.gcp.m.upbound.io" group); any other apparent IAM
// resource kind under a recognized provider group is a scoped gap, never
// silently skipped. It performs no I/O.
func DeclarationsFromManifests(manifests []Manifest, account, project string) ([]Declaration, []Gap) {
	var gaps []Gap

	awsRoles := map[string]*Declaration{}
	var awsPolicyAttachments []map[string]any
	var awsInlinePolicies []map[string]any

	gcpAccounts := map[string]*Declaration{}
	var gcpTrustBindings []map[string]any
	var gcpProjectGrants []map[string]any
	// gcpCustomRoles indexes well-formed, non-DISABLED ProjectIAMCustomRole
	// definitions by their canonical "projects/<project>/roles/<roleId>"
	// name -> declared permissions, so a ProjectIAMMember binding to one of
	// this batch's own custom roles can be resolved from the declared
	// definition itself (never a live-cloud guess, never waiting on
	// Definitions.Roles).
	gcpCustomRoles := map[string][]string{}
	// gcpDisabledCustomRoles holds the same canonical names for roles
	// declared with `stage: DISABLED`: IAM grants nothing through a binding
	// to a disabled role (binding semantic 3), so such a binding is inert
	// -- no grant, no gap -- rather than falling through to an unresolved
	// Grant.Role reference.
	gcpDisabledCustomRoles := map[string]bool{}

	for _, m := range manifests {
		apiVersion := manifestInventoryStringField(m.Object, "apiVersion")
		kind := manifestInventoryStringField(m.Object, "kind")
		group := manifestInventoryAPIGroup(apiVersion)

		switch group {
		case "iam.aws.upbound.io", "iam.aws.crossplane.io", "iam.aws.m.upbound.io":
			switch kind {
			case "Role":
				d, g := crossplaneAWSRoleDeclaration(m, account)
				gaps = append(gaps, g...)
				if d != nil {
					awsRoles[crossplaneResourceName(m.Object)] = d
				}
			case "RolePolicy":
				awsInlinePolicies = append(awsInlinePolicies, m.Object)
			case "RolePolicyAttachment":
				awsPolicyAttachments = append(awsPolicyAttachments, m.Object)
			case "Policy":
				// A standalone managed policy with no attachment in this
				// batch declares no principal by itself; nothing to attach
				// it to yet. Not a gap: it is valid, just not evidence of a
				// grant until an attachment references it.
			default:
				gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.unsupported_kind", Scope: group + "/" + kind, Message: "Crossplane-composed AWS IAM resource kind is not recognized"})
			}
		case "iam.cnrm.cloud.google.com", "cloudplatform.gcp.upbound.io", "iam.gcp.upbound.io", "cloudplatform.gcp.m.upbound.io":
			switch kind {
			case "IAMServiceAccount", "ServiceAccount":
				d, g := crossplaneGCPServiceAccountDeclaration(m, project)
				gaps = append(gaps, g...)
				if d != nil {
					gcpAccounts[crossplaneResourceName(m.Object)] = d
				}
			case "IAMPolicyMember", "IAMMember", "ServiceAccountIAMMember":
				gcpTrustBindings = append(gcpTrustBindings, m.Object)
			case "ProjectIAMMember":
				gcpProjectGrants = append(gcpProjectGrants, m.Object)
			case "ProjectIAMCustomRole":
				// A project-scoped custom role definition minted once per
				// cluster (templates/gcp-custom-roles.yaml), not a
				// principal. A well-formed one (roleId + permissions) is
				// indexed for ProjectIAMMember resolution below; a
				// malformed one is a gap, never silently ignored.
				name, permissions, disabled, ok := crossplaneGCPCustomRoleFields(m.Object)
				if !ok {
					gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_definition_malformed", Scope: crossplaneResourceName(m.Object), Message: "ProjectIAMCustomRole is missing its roleId (crossplane.io/external-name annotation), project, or permissions"})
					continue
				}
				if disabled {
					gcpDisabledCustomRoles[name] = true
					continue
				}
				gcpCustomRoles[name] = permissions
			default:
				gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.unsupported_kind", Scope: group + "/" + kind, Message: "Crossplane-composed GCP IAM resource kind is not recognized"})
			}
		}
	}

	for _, obj := range awsInlinePolicies {
		scope := crossplaneResourceName(obj)
		roleName, selector := crossplaneAWSRoleRef(obj)
		if selector {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_selector_unsupported", Scope: scope, Message: "RolePolicy selects its role via roleSelector, which is not statically resolvable"})
			continue
		}
		decl, ok := awsRoles[roleName]
		if !ok {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_not_found", Scope: roleName, Message: "RolePolicy references a role not present among the composed resources"})
			continue
		}
		policyDoc, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "policy")
		if policyDoc == "" {
			continue
		}
		grants, err := ParseAWSPolicy([]byte(policyDoc), Reference{})
		if err != nil {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.policy_unparseable", Scope: roleName, Message: err.Error()})
			continue
		}
		decl.Policy.Grants = append(decl.Policy.Grants, grants...)
	}
	for _, obj := range awsPolicyAttachments {
		scope := crossplaneResourceName(obj)
		roleName, selector := crossplaneAWSRoleRef(obj)
		if selector {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_selector_unsupported", Scope: scope, Message: "RolePolicyAttachment selects its role via roleSelector, which is not statically resolvable"})
			continue
		}
		decl, ok := awsRoles[roleName]
		if !ok {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_not_found", Scope: roleName, Message: "RolePolicyAttachment references a role not present among the composed resources"})
			continue
		}
		policyARN, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "policyArn")
		if policyARN == "" {
			continue
		}
		decl.Policy.Grants = append(decl.Policy.Grants, Grant{ID: policyARN, Effect: "Allow", Role: policyARN})
	}

	// Trust: who may assume/impersonate this service account (Workload
	// Identity bindings on the service account resource itself).
	for _, obj := range gcpTrustBindings {
		targetName, role, member, ok := crossplaneGCPBindingFields(obj)
		if !ok {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.binding_unresolved", Scope: crossplaneResourceName(obj), Message: "IAM policy member/binding is missing role, member, or a resolvable service-account target"})
			continue
		}
		decl, found := gcpAccounts[targetName]
		if !found {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_not_found", Scope: targetName, Message: "IAM policy member references a service account not present among the composed resources"})
			continue
		}
		decl.Policy.Trust = append(decl.Policy.Trust, Grant{ID: role + ":" + member, Effect: "Allow", Role: role, Members: []string{member}})
	}

	// Grants: permissions a composed service account holds on the project
	// resource it is additively bound to (ProjectIAMMember), attributed by
	// its own "serviceAccount:<email>" member rather than a target field.
	for _, obj := range gcpProjectGrants {
		scope := crossplaneResourceName(obj)
		projectID, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "project")
		role, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "role")
		member, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "member")
		if projectID == "" || role == "" || member == "" {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.binding_unresolved", Scope: scope, Message: "ProjectIAMMember is missing project, role, or member"})
			continue
		}
		if !strings.HasPrefix(member, "serviceAccount:") {
			// user:/group:/domain:/allUsers/allAuthenticatedUsers members are
			// legitimately outside this analyzer's declared-principal scope,
			// matching the live GCP collector's own convention.
			continue
		}
		accountKey := crossplaneGCPServiceAccountKeyFromMember(member)
		decl, found := gcpAccounts[accountKey]
		if !found {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.role_not_found", Scope: scope, Message: "ProjectIAMMember's member service account is not present among the composed resources"})
			continue
		}
		if gcpDisabledCustomRoles[role] {
			// stage: DISABLED => binding semantic 3: the declared binding
			// is inert. IAM grants nothing through a disabled custom role,
			// so neither a grant nor an unresolved-role gap is produced.
			continue
		}
		resource := "//cloudresourcemanager.googleapis.com/projects/" + projectID
		if permissions, ok := gcpCustomRoles[role]; ok {
			// A custom role declared in this same manifest batch: the
			// permission set is known precisely from the declaration
			// itself, so it is inlined directly (Grant.Role left empty)
			// rather than left as a reference the evaluator can only
			// expand once a live Definitions.Roles lookup also resolves
			// it -- matching how a Role-less Grant already passes through
			// expandGrantLayer unchanged.
			decl.Policy.Grants = append(decl.Policy.Grants, Grant{ID: scope, Effect: "Allow", Actions: append([]string{}, permissions...), Resources: []string{resource}})
		} else {
			decl.Policy.Grants = append(decl.Policy.Grants, Grant{ID: scope, Effect: "Allow", Role: role, Resources: []string{resource}})
		}
	}

	var declarations []Declaration
	for _, d := range awsRoles {
		declarations = append(declarations, *d)
	}
	for _, d := range gcpAccounts {
		declarations = append(declarations, *d)
	}
	return declarations, gaps
}

func crossplaneResourceName(obj map[string]any) string {
	if name, ok := manifestInventoryNestedString(obj, "metadata", "name"); ok && name != "" {
		return name
	}
	name, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "name")
	return name
}

func manifestInventoryAPIGroup(apiVersion string) string {
	if idx := strings.LastIndexByte(apiVersion, '/'); idx >= 0 {
		return apiVersion[:idx]
	}
	return apiVersion
}

// crossplaneAWSRoleRef resolves the role an AWS RolePolicy/RolePolicyAttachment
// attaches to: the deployed XRole Composition emits `forProvider.roleRef.name`
// (the current upbound schema); older fixtures/providers may still emit the
// literal `forProvider.role` name. A `roleSelector` (match-by-labels) is not
// statically resolvable and is reported back as such rather than guessed.
func crossplaneAWSRoleRef(obj map[string]any) (name string, selector bool) {
	if ref, ok := manifestInventoryNestedString(obj, "spec", "forProvider", "roleRef", "name"); ok && ref != "" {
		return ref, false
	}
	if _, ok := manifestInventoryNestedMap(obj, "spec", "forProvider", "roleSelector"); ok {
		return "", true
	}
	name, _ = manifestInventoryNestedString(obj, "spec", "forProvider", "role")
	return name, false
}

func crossplaneAWSRoleDeclaration(m Manifest, account string) (*Declaration, []Gap) {
	name := crossplaneResourceName(m.Object)
	var gaps []Gap
	id := name
	if account != "" {
		id = "arn:aws:iam::" + account + ":role/" + name
	} else {
		gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.unresolved_account", Scope: name, Message: "AWS account was not supplied; role ARN could not be constructed"})
	}
	decl := &Declaration{
		Principal: Principal{ID: id, Provider: AWS, Kind: manifestInventoryKindAWSRole, Account: account},
		Policy:    PolicyState{Complete: true, References: []Reference{m.Reference}},
	}
	assumeDoc, _ := manifestInventoryNestedString(m.Object, "spec", "forProvider", "assumeRolePolicy")
	if assumeDoc != "" {
		grants, err := ParseAWSPolicy([]byte(assumeDoc), m.Reference)
		if err != nil {
			gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.policy_unparseable", Scope: name, Message: err.Error()})
		} else {
			decl.Policy.Trust = grants
		}
	}
	// A permissions boundary caps everything above it, exactly like
	// Terraform's `aws_iam_role.permissions_boundary`: when it is an opaque
	// external ARN (not itself a declared Policy in this batch) it is
	// recorded as an unresolved boundary layer rather than silently
	// dropped, so definition expansion can still enforce the ceiling.
	if boundaryARN, ok := manifestInventoryNestedString(m.Object, "spec", "forProvider", "permissionsBoundary"); ok && boundaryARN != "" {
		decl.Policy.Boundaries = append(decl.Policy.Boundaries, []Grant{{
			ID: name + "#boundary", Effect: "Allow", Role: boundaryARN, References: []Reference{m.Reference},
		}})
	}
	return decl, gaps
}

func crossplaneGCPServiceAccountDeclaration(m Manifest, project string) (*Declaration, []Gap) {
	name := crossplaneResourceName(m.Object)
	accountID, _ := manifestInventoryNestedString(m.Object, "spec", "forProvider", "accountId")
	if accountID == "" {
		accountID, _ = manifestInventoryNestedString(m.Object, "spec", "accountId")
	}
	if accountID == "" {
		accountID = name
	}
	var gaps []Gap
	id := accountID
	if project != "" {
		id = accountID + "@" + project + ".iam.gserviceaccount.com"
	} else {
		gaps = append(gaps, Gap{Code: "cloud_identity.crossplane_declaration.unresolved_project", Scope: name, Message: "GCP project was not supplied; service account email could not be constructed"})
	}
	decl := &Declaration{
		Principal: Principal{ID: id, Provider: GCP, Kind: manifestInventoryKindGCPServiceAccount, Project: project},
		Policy:    PolicyState{Complete: true, References: []Reference{m.Reference}},
	}
	return decl, gaps
}

// crossplaneGCPBindingFields extracts (target service account name, role,
// member) from an IAMPolicyMember/IAMMember/ServiceAccountIAMMember-shaped
// composed resource across the Config Connector and upbound schema
// variants. The deployed upbound ServiceAccountIAMMember identifies its
// target through a full `projects/<project>/serviceAccounts/<email>` path
// rather than a synthetic resourceRef, so that form is normalized back to
// the service account's own composed resource name (key into gcpAccounts).
func crossplaneGCPBindingFields(obj map[string]any) (target, role, member string, ok bool) {
	role, _ = manifestInventoryNestedString(obj, "spec", "role")
	if role == "" {
		role, _ = manifestInventoryNestedString(obj, "spec", "forProvider", "role")
	}
	member, _ = manifestInventoryNestedString(obj, "spec", "member")
	if member == "" {
		member, _ = manifestInventoryNestedString(obj, "spec", "forProvider", "member")
	}
	if serviceAccountID, ok2 := manifestInventoryNestedString(obj, "spec", "forProvider", "serviceAccountId"); ok2 && serviceAccountID != "" {
		target = crossplaneGCPServiceAccountKeyFromID(serviceAccountID)
	} else {
		target, _ = manifestInventoryNestedString(obj, "spec", "resourceRef", "name")
	}
	if role == "" || member == "" || target == "" {
		return "", "", "", false
	}
	return target, role, member, true
}

// crossplaneGCPServiceAccountKeyFromID normalizes a full
// "projects/<project>/serviceAccounts/<accountID>@<project>.iam.gserviceaccount.com"
// path down to "<accountID>", matching the key gcpAccounts is indexed under
// (the composed ServiceAccount's own metadata.name).
func crossplaneGCPServiceAccountKeyFromID(id string) string {
	const marker = "/serviceAccounts/"
	idx := strings.LastIndex(id, marker)
	email := id
	if idx >= 0 {
		email = id[idx+len(marker):]
	}
	return crossplaneGCPServiceAccountKeyFromMember("serviceAccount:" + email)
}

// crossplaneGCPServiceAccountKeyFromMember normalizes a
// "serviceAccount:<accountID>@<project>.iam.gserviceaccount.com" member down
// to "<accountID>".
func crossplaneGCPServiceAccountKeyFromMember(member string) string {
	email := strings.TrimPrefix(member, "serviceAccount:")
	if at := strings.IndexByte(email, '@'); at >= 0 {
		return email[:at]
	}
	return email
}

// crossplaneGCPCustomRoleFields extracts the canonical
// "projects/<project>/roles/<roleId>" name and declared permissions from a
// ProjectIAMCustomRole-shaped composed resource. roleId lives on the
// "crossplane.io/external-name" annotation (the provider maps this kind's
// external name onto the roleId, since a roleId may contain underscores an
// object name may not); permissions live under spec.forProvider.permissions.
// A role missing any of roleId, project, or at least one permission is
// reported back as malformed rather than guessed. disabled reports whether
// spec.forProvider.stage is "DISABLED": IAM treats bindings to a disabled
// custom role as granting nothing (binding semantic 3), matching the live
// GCP collector's own DISABLED handling.
func crossplaneGCPCustomRoleFields(obj map[string]any) (name string, permissions []string, disabled bool, ok bool) {
	roleID, _ := manifestInventoryNestedString(obj, "metadata", "annotations", "crossplane.io/external-name")
	projectID, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "project")
	permsRaw, _ := manifestInventoryNestedSlice(obj, "spec", "forProvider", "permissions")
	stage, _ := manifestInventoryNestedString(obj, "spec", "forProvider", "stage")
	if roleID == "" || projectID == "" || len(permsRaw) == 0 {
		return "", nil, false, false
	}
	for _, p := range permsRaw {
		if s, ok2 := manifestInventoryAsString(p); ok2 && s != "" {
			permissions = append(permissions, s)
		}
	}
	if len(permissions) == 0 {
		return "", nil, false, false
	}
	return "projects/" + projectID + "/roles/" + roleID, sortedCopy(permissions), stage == "DISABLED", true
}

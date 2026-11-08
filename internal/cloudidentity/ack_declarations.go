package cloudidentity

import (
	"fmt"
	"sort"
	"strings"
)

const (
	ackIAMAPIGroup = "iam.services.k8s.aws"
	ackEKSAPIGroup = "eks.services.k8s.aws"
)

// UnresolvedValueMarkerPrefix names every unknown-value marker the manifest
// renderer binds into a ManifestInput's composed Helm values for each key
// named in ManifestInput/ManifestRequest.UnresolvedValues (Terraform-
// contract values, such as an ACK permissions-boundary ARN sourced from
// remote state, this scan never evaluates).
const UnresolvedValueMarkerPrefix = "cloudidentity:unresolved-terraform-value:"

// unresolvedValueMarkerAccount is the all-zero AWS account id: never
// allocated to a real account, so an ARN built from it can never collide
// with a genuine identifier.
const unresolvedValueMarkerAccount = "000000000000"

// UnresolvedValueMarker returns the unmistakable sentinel the renderer
// binds for key, so a chart template's required(...) on that key still
// renders instead of refusing the whole chart. A chart may validate a
// bound value's shape before accepting it -- for example requiring an
// ACK permissions-boundary value to look like a real IAM policy ARN
// (`^arn:aws[a-z-]*:iam::[0-9]{12}:policy/.+$`) -- so a bare non-empty
// string is not always enough. The marker is therefore itself a
// syntactically valid, but never-allocated, IAM policy ARN (all-zero
// account) carrying UnresolvedValueMarkerPrefix in its policy path: a
// chart-side ARN-shape check still passes and the chart still renders,
// while UnresolvedValueMarkerKey (and any other consumer) recognizes the
// value as unresolved by substring, not shape.
func UnresolvedValueMarker(key string) string {
	return "arn:aws:iam::" + unresolvedValueMarkerAccount + ":policy/" + UnresolvedValueMarkerPrefix + key
}

// UnresolvedValueMarkerKey reports the Terraform-contract value key a
// rendered field derives from, when value is -- or contains, for a marker
// interpolated into a larger templated string -- an UnresolvedValueMarker.
func UnresolvedValueMarkerKey(value string) (string, bool) {
	idx := strings.Index(value, UnresolvedValueMarkerPrefix)
	if idx < 0 {
		return "", false
	}
	return value[idx+len(UnresolvedValueMarkerPrefix):], true
}

// PodIdentityDeclaration is one declared ACK PodIdentityAssociation binding:
// an in-repo assertion that a Kubernetes namespace/service account is bound
// to an IAM role, as opposed to a live EKS Pod Identity association
// observed from the AWS API. It is collection evidence, not an assessed
// finding: RoleARN is derived the same documented way
// DeclarationsFromACK derives Role declarations, and its presence (or
// absence) is never itself proof that AWS actually created the
// association -- that confirmation happens by joining against live reads
// elsewhere.
type PodIdentityDeclaration struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
	RoleARN        string
	References     []Reference
}

// ackRoleIdentityFromSpec derives an ACK-managed IAM Role's ARN from the
// rendered Role object's own spec: the ACK IAM controller's Role CRD
// carries the real IAM role name in the required spec.name field and an
// optional spec.path (AWS defaults an unset path to "/"). A path must
// start and end with "/" per IAM's path syntax; a path that does not is
// reported as a scoped gap rather than silently producing a malformed
// ARN. An account must also be known to build an ARN at all.
func ackRoleIdentityFromSpec(m Manifest, account, scope, specName, specPath string) (string, []Gap) {
	var gaps []Gap
	if specName == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.role_spec_name_missing", Scope: scope, Message: "ACK Role has no spec.name; role ARN could not be derived", References: []Reference{m.Reference}})
		return "", gaps
	}
	path := specPath
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.role_path_invalid", Scope: scope, Message: "ACK Role's spec.path %q is not a valid IAM path (must start and end with \"/\")", References: []Reference{m.Reference}})
		return "", gaps
	}
	if account == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.unresolved_account", Scope: scope, Message: "AWS account was not supplied; role ARN could not be derived"})
		return "", gaps
	}
	return "arn:aws:iam::" + account + ":role" + path + specName, gaps
}

// DeclarationsFromACK extracts IAM role declarations and declared EKS Pod
// Identity association bindings from ACK-managed Kubernetes custom
// resources among already-rendered manifests: iam.services.k8s.aws/v1alpha1
// Role (inline statements, managedPolicyArns, trust, path, boundary) and
// eks.services.k8s.aws/v1alpha1 PodIdentityAssociation (cluster, namespace,
// service account, role). It performs no I/O: role ARNs are derived from
// the rendered Role's own spec.name/spec.path or read verbatim from an
// explicit spec.roleARN; live IAM confirmation happens when the derived ID
// joins an independently observed principal. Any other apparent resource
// kind under a recognized ACK group is a scoped gap, never silently
// skipped.
func DeclarationsFromACK(manifests []Manifest, cluster, account string) ([]Declaration, []PodIdentityDeclaration, []Gap) {
	var gaps []Gap
	roles := map[string]*Declaration{}
	var podIdentityObjects []map[string]any
	var podIdentityRefs []Reference

	for _, m := range manifests {
		apiVersion := manifestInventoryStringField(m.Object, "apiVersion")
		kind := manifestInventoryStringField(m.Object, "kind")
		group := manifestInventoryAPIGroup(apiVersion)

		switch group {
		case ackIAMAPIGroup:
			switch kind {
			case "Role":
				name, _ := manifestInventoryNestedString(m.Object, "metadata", "name")
				namespace, _ := manifestInventoryNestedString(m.Object, "metadata", "namespace")
				d, g := ackIAMRoleDeclaration(m, account, name, namespace)
				gaps = append(gaps, g...)
				if d != nil {
					roles[namespace+"/"+name] = d
				}
			default:
				gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.unsupported_kind", Scope: group + "/" + kind, Message: "ACK IAM resource kind is not recognized", References: []Reference{m.Reference}})
			}
		case ackEKSAPIGroup:
			switch kind {
			case "PodIdentityAssociation":
				podIdentityObjects = append(podIdentityObjects, m.Object)
				podIdentityRefs = append(podIdentityRefs, m.Reference)
			default:
				gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.unsupported_kind", Scope: group + "/" + kind, Message: "ACK EKS resource kind is not recognized", References: []Reference{m.Reference}})
			}
		}
	}

	declarations := make([]Declaration, 0, len(roles))
	roleKeys := make([]string, 0, len(roles))
	for k := range roles {
		roleKeys = append(roleKeys, k)
	}
	sort.Strings(roleKeys)
	for _, k := range roleKeys {
		declarations = append(declarations, *roles[k])
	}

	var podIdentities []PodIdentityDeclaration
	for i, obj := range podIdentityObjects {
		pid, g := ackPodIdentityDeclaration(obj, podIdentityRefs[i], cluster, roles)
		gaps = append(gaps, g...)
		if pid != nil {
			podIdentities = append(podIdentities, *pid)
		}
	}
	return declarations, podIdentities, gaps
}

// ackIAMRoleDeclaration converts one rendered ACK Role object into a
// Declaration: spec.name and spec.path derive the role's ARN,
// spec.assumeRolePolicyDocument becomes Trust, spec.inlinePolicies
// becomes Grants, spec.policies (managed policy ARNs) become unresolved
// Grant.Role references for live expansion, and spec.permissionsBoundary
// becomes an unresolved boundary layer -- the same representation
// crossplaneAWSRoleDeclaration uses for an opaque external ARN not itself
// declared in this batch.
func ackIAMRoleDeclaration(m Manifest, account, name, namespace string) (*Declaration, []Gap) {
	var gaps []Gap
	if name == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.role_name_missing", Scope: namespace, Message: "ACK Role has no metadata.name", References: []Reference{m.Reference}})
		return nil, gaps
	}
	scope := namespace + "/" + name
	if namespace == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.role_namespace_missing", Scope: name, Message: "ACK Role has no metadata.namespace"})
	}

	specName, _ := manifestInventoryNestedString(m.Object, "spec", "name")
	specPath, _ := manifestInventoryNestedString(m.Object, "spec", "path")
	id, identityGaps := ackRoleIdentityFromSpec(m, account, scope, specName, specPath)
	gaps = append(gaps, identityGaps...)
	if id == "" {
		id = name
	}

	decl := &Declaration{
		Principal: Principal{ID: id, Provider: AWS, Kind: manifestInventoryKindAWSRole, Account: account},
		Policy:    PolicyState{Complete: true, References: []Reference{m.Reference}},
	}

	trustDoc, _ := manifestInventoryNestedString(m.Object, "spec", "assumeRolePolicyDocument")
	switch trustDoc {
	case "":
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.trust_missing", Scope: scope, Message: "ACK Role has no spec.assumeRolePolicyDocument"})
	default:
		grants, err := ParseAWSPolicy([]byte(trustDoc), m.Reference)
		if err != nil {
			gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.policy_unparseable", Scope: scope, Message: err.Error()})
		} else {
			decl.Policy.Trust = grants
		}
	}

	if spec, ok := manifestInventoryNestedMap(m.Object, "spec"); ok {
		if inline, ok := manifestInventoryAsMap(spec["inlinePolicies"]); ok {
			names := make([]string, 0, len(inline))
			for polName := range inline {
				names = append(names, polName)
			}
			sort.Strings(names)
			for _, polName := range names {
				doc, _ := manifestInventoryAsString(inline[polName])
				if doc == "" {
					continue
				}
				grants, err := ParseAWSPolicy([]byte(doc), m.Reference)
				if err != nil {
					gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.policy_unparseable", Scope: scope + "/" + polName, Message: err.Error()})
					continue
				}
				decl.Policy.Grants = append(decl.Policy.Grants, grants...)
			}
		}
		if arns, ok := manifestInventoryAsSlice(spec["policies"]); ok {
			for _, raw := range arns {
				arn, _ := raw.(string)
				if arn == "" {
					continue
				}
				decl.Policy.Grants = append(decl.Policy.Grants, Grant{ID: scope + "#managed:" + arn, Effect: "Allow", Role: arn, References: []Reference{m.Reference}})
			}
		}
	}

	if boundaryARN, ok := manifestInventoryNestedString(m.Object, "spec", "permissionsBoundary"); ok && boundaryARN != "" {
		if key, unresolved := UnresolvedValueMarkerKey(boundaryARN); unresolved {
			// The boundary is a Terraform-contract value this scan could not
			// resolve (for example a permissions boundary's AWS-generated
			// name_prefix ARN, known only after apply): the manifest
			// renderer still bound required() to an unmistakable marker so
			// the rest of the Role rendered, but that marker is never a
			// real boundary ARN. Keep the declared side explicitly
			// incomplete -- never silently unbounded -- rather than either
			// dropping the boundary layer or trusting the marker text.
			decl.Policy.Complete = false
			boundaryGap := Gap{Code: "cloud_identity.ack_declaration.boundary_unresolved", Scope: scope, Message: "ACK Role's permissions boundary is the unresolved Terraform-contract value \"" + key + "\"; the declared boundary is unknown, not absent", References: []Reference{m.Reference}}
			decl.Policy.Gaps = append(decl.Policy.Gaps, boundaryGap)
			gaps = append(gaps, boundaryGap)
		} else {
			decl.Policy.Boundaries = append(decl.Policy.Boundaries, []Grant{{
				ID: scope + "#boundary", Effect: "Allow", Role: boundaryARN, References: []Reference{m.Reference},
			}})
		}
	}
	return decl, gaps
}

// ackPodIdentityDeclaration converts one rendered PodIdentityAssociation
// object into a declared binding. The bound role is read from spec.roleARN
// when set (an explicit, already-pinned ARN); otherwise spec.roleRef.from
// names an ACK Role object (same namespace unless roleRef.from.namespace
// overrides it), resolved against Roles already collected in this batch.
// A referenced Role that was not itself rendered, or whose own identity
// could not be derived, is a scoped gap and never a binding -- this
// package never synthesizes a role ARN for a reference it cannot confirm.
// spec.clusterName, when declared, must agree with the scan target's own
// cluster -- a declared Pod Identity association naming a different
// cluster is reported, never silently trusted or dropped.
func ackPodIdentityDeclaration(obj map[string]any, ref Reference, targetCluster string, roles map[string]*Declaration) (*PodIdentityDeclaration, []Gap) {
	var gaps []Gap
	scope, _ := manifestInventoryNestedString(obj, "metadata", "name")
	piaNamespace, _ := manifestInventoryNestedString(obj, "metadata", "namespace")
	namespace, _ := manifestInventoryNestedString(obj, "spec", "namespace")
	serviceAccount, _ := manifestInventoryNestedString(obj, "spec", "serviceAccount")
	if namespace == "" || serviceAccount == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.pod_identity_association_malformed", Scope: scope, Message: "PodIdentityAssociation is missing spec.namespace or spec.serviceAccount", References: []Reference{ref}})
		return nil, gaps
	}

	cluster := targetCluster
	if declaredCluster, _ := manifestInventoryNestedString(obj, "spec", "clusterName"); declaredCluster != "" {
		cluster = declaredCluster
		if targetCluster != "" && declaredCluster != targetCluster {
			gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.pod_identity_cluster_mismatch", Scope: scope, Message: fmt.Sprintf("PodIdentityAssociation declares spec.clusterName %q, which does not match the scan target's cluster %q", declaredCluster, targetCluster), References: []Reference{ref}})
		}
	}

	roleARN, _ := manifestInventoryNestedString(obj, "spec", "roleARN")
	if roleARN == "" {
		refName, _ := manifestInventoryNestedString(obj, "spec", "roleRef", "from", "name")
		if refName == "" {
			gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.pod_identity_role_unresolved", Scope: scope, Message: "PodIdentityAssociation has neither spec.roleARN nor spec.roleRef.from.name", References: []Reference{ref}})
			return nil, gaps
		}
		refNamespace, _ := manifestInventoryNestedString(obj, "spec", "roleRef", "from", "namespace")
		if refNamespace == "" {
			refNamespace = piaNamespace
		}
		decl, found := roles[refNamespace+"/"+refName]
		if !found || !strings.HasPrefix(decl.Principal.ID, "arn:") {
			gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.role_not_found", Scope: scope, Message: "PodIdentityAssociation references ACK Role \"" + refNamespace + "/" + refName + "\", which is not present among the rendered manifests or whose own identity could not be resolved", References: []Reference{ref}})
			return nil, gaps
		}
		roleARN = decl.Principal.ID
	}

	return &PodIdentityDeclaration{Cluster: cluster, Namespace: namespace, ServiceAccount: serviceAccount, RoleARN: roleARN, References: []Reference{ref}}, gaps
}

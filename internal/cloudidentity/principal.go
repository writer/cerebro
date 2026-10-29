package cloudidentity

import "strings"

// isUnresolvedCloudPrincipal reports whether an Evidence cohort's Principal
// is still just a Kubernetes service-account placeholder ("k8s://<cluster>/
// <namespace>/sa/<name>") rather than a confirmed cloud principal. A bare
// KSA is merely *eligible* for direct pod-identity (AWS has no EKS Pod
// Identity association configured) or workload-identity-federation binding
// — it is not proven to actually be, or map to, any real AWS role or GCP
// service account until that binding is resolved (at which point the
// collection pipeline rewrites Principal.ID to the real ARN or the
// canonical "principal://iam.googleapis.com/..." form). Treating an
// unresolved placeholder as a real principal would let both excess and
// sharing findings talk about a cloud identity that may not exist.
func isUnresolvedCloudPrincipal(p Principal) bool {
	return strings.HasPrefix(p.ID, "k8s://") ||
		p.Kind == "aws_kubernetes_service_account" ||
		p.Kind == "gcp_kubernetes_service_account"
}

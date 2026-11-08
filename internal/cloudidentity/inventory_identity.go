package cloudidentity

import (
	"fmt"
	"regexp"
	"strings"
)

// Principal.Kind conventions produced by manifest inventory. Annotation-based
// kinds reflect an explicit, in-repo opt-in ("configured" trust) and are
// emitted whenever the annotation is present and well-formed. The bare
// Kubernetes-service-account kinds are emitted only as a fallback, when no
// such annotation is present, so a live reader can check for an actual
// direct pod-identity/workload-identity-federation association rather than
// a generically "eligible" subject stacked alongside an already-configured
// one.
const (
	manifestInventoryKindAWSRole           = "aws_iam_role"
	manifestInventoryKindGCPServiceAccount = "gcp_service_account"
	manifestInventoryKindAWSKubernetesSA   = "aws_kubernetes_service_account"
	manifestInventoryKindGCPKubernetesSA   = "gcp_kubernetes_service_account"
)

const (
	manifestInventoryAnnotationIRSARole = "eks.amazonaws.com/role-arn"
	manifestInventoryAnnotationGCPGSA   = "iam.gke.io/gcp-service-account"
)

var manifestInventoryGSAEmailPattern = regexp.MustCompile(`^[^@\s]+@([a-z0-9-]+)\.iam\.gserviceaccount\.com$`)

// manifestInventoryParseIRSARoleARN extracts the AWS account id from an IRSA
// role ARN of the form arn:aws:iam::<account>:role/<path>. It reports false
// when the value is not a well-formed IAM role ARN.
func manifestInventoryParseIRSARoleARN(arn string) (account string, ok bool) {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" || parts[2] != "iam" {
		return "", false
	}
	if !strings.HasPrefix(parts[5], "role/") {
		return "", false
	}
	if parts[4] == "" {
		return "", false
	}
	return parts[4], true
}

// manifestInventoryParseGSAEmail extracts the GCP project id from a Google
// service account email of the form <name>@<project-id>.iam.gserviceaccount.com.
func manifestInventoryParseGSAEmail(email string) (project string, ok bool) {
	m := manifestInventoryGSAEmailPattern.FindStringSubmatch(strings.TrimSpace(email))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// manifestInventoryKSASubject builds the stable identifier used for a bare
// Kubernetes service account acting as an "eligible" cloud-identity subject.
func manifestInventoryKSASubject(cluster, namespace, name string) string {
	return fmt.Sprintf("k8s://%s/%s/sa/%s", cluster, namespace, name)
}

// manifestInventoryAWSPrincipals builds exactly one AWS principal per
// service account: the configured IRSA role when the annotation is present
// and well-formed, otherwise a bare-KSA fallback subject for the caller's
// live reader to check for an actual EKS Pod Identity association. The two
// are mutually exclusive -- emitting both would let a live reader treat a
// generically "eligible" KSA as a second, independent finding alongside the
// one actually configured identity, double-counting the same access path.
func manifestInventoryAWSPrincipals(cluster, namespace, saName string, annotations map[string]string, requestAccount string) ([]Principal, []Gap) {
	var gaps []Gap
	if raw, present := annotations[manifestInventoryAnnotationIRSARole]; present {
		if account, ok := manifestInventoryParseIRSARoleARN(raw); ok {
			return []Principal{{ID: raw, Provider: AWS, Kind: manifestInventoryKindAWSRole, Account: account}}, nil
		}
		gaps = append(gaps, Gap{Code: "cloud_identity.inventory.irsa_annotation_invalid", Scope: namespace + "/" + saName, Message: "eks.amazonaws.com/role-arn annotation is not a well-formed IAM role ARN"})
	}
	if requestAccount == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.inventory.unresolved_account", Scope: namespace + "/" + saName, Message: "AWS account could not be resolved from the IRSA annotation or the scan target"})
	}
	principal := Principal{ID: manifestInventoryKSASubject(cluster, namespace, saName), Provider: AWS, Kind: manifestInventoryKindAWSKubernetesSA, Account: requestAccount}
	return []Principal{principal}, gaps
}

// manifestInventoryGCPPrincipals builds exactly one GCP principal per
// service account: the configured GSA when the Workload Identity annotation
// is present and well-formed, otherwise a bare-KSA fallback subject for the
// caller's live reader to check for an actual direct Workload Identity
// Federation binding. Mutually exclusive for the same reason as AWS.
func manifestInventoryGCPPrincipals(cluster, namespace, saName string, annotations map[string]string, requestProject string) ([]Principal, []Gap) {
	var gaps []Gap
	if raw, present := annotations[manifestInventoryAnnotationGCPGSA]; present {
		if project, ok := manifestInventoryParseGSAEmail(raw); ok {
			return []Principal{{ID: raw, Provider: GCP, Kind: manifestInventoryKindGCPServiceAccount, Project: project}}, nil
		}
		gaps = append(gaps, Gap{Code: "cloud_identity.inventory.gsa_annotation_invalid", Scope: namespace + "/" + saName, Message: "iam.gke.io/gcp-service-account annotation is not a well-formed service account email"})
	}
	if requestProject == "" {
		gaps = append(gaps, Gap{Code: "cloud_identity.inventory.unresolved_project", Scope: namespace + "/" + saName, Message: "GCP project could not be resolved from the GSA annotation or the scan target"})
	}
	principal := Principal{ID: manifestInventoryKSASubject(cluster, namespace, saName), Provider: GCP, Kind: manifestInventoryKindGCPKubernetesSA, Project: requestProject}
	return []Principal{principal}, gaps
}

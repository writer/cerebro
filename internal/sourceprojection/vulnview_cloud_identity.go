package sourceprojection

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

// VulnView is the sole detection authority for cloud-identity
// excess-privilege and shared-principal posture (Contract C8): Cerebro no
// longer collects cloud-identity evidence itself (the native collector and
// its internal/cloudidentity model moved to VulnView, Contract C1), it
// only imports VulnView's standardized vulnview.finding events
// (source=cloud_identity) and joins them to the SAME canonical AWS role /
// GCP service account entities the AWS/GCP provider projections already
// mint. This file keeps only the canonical-principal-resolution helpers
// vulnview.go's cloud_identity linking needs; the removed
// internal/cloudidentity evidence model, its principal_evidence/coverage
// projections, and the vulnview.cloud_identity_finding/_run/_assessment
// entity kinds are gone.

// vulnViewCloudIdentityAWSRoleARNPattern matches the well-formed
// "arn:<partition>:iam::<12-digit-account>:role/<path>" shape VulnView AWS
// cloud-identity principals always carry.
var vulnViewCloudIdentityAWSRoleARNPattern = regexp.MustCompile(`^arn:aws[a-z0-9-]*:iam::\d{12}:role/.+$`)

// vulnViewCloudIdentityGCPServiceAccountPattern matches the well-formed
// "<name>@<project>.iam.gserviceaccount.com" shape VulnView GCP
// cloud-identity principals always carry when not already a resolved
// principal:// subject.
var vulnViewCloudIdentityGCPServiceAccountPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$`)

// vulnViewCloudIdentityCanonicalPrincipalURN resolves a VulnView
// cloud-identity provider/principal pair to the same canonical URN other
// provider projections already mint for that AWS role / GCP service
// account, using the shared identityPrincipalURN helper. A GCP
// principal:// direct federated form (no intermediary service account)
// canonicalizes through the same "service_account" URN kind, keyed on its
// own stable string, so the exact same principal:// value always resolves
// to the same tenant-scoped URN.
func vulnViewCloudIdentityCanonicalPrincipalURN(tenantID, provider, principalID string) string {
	principalID = strings.TrimSpace(principalID)
	if principalID == "" {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return identityPrincipalURN(tenantID, "aws", "role", principalID, "")
	case "gcp":
		return identityPrincipalURN(tenantID, "gcp", "service_account", principalID, "")
	default:
		return ""
	}
}

// vulnViewCloudIdentityUnresolvedPrincipalSubject reports whether
// provider/principalKind/principalID describe a subject the projector must
// never canonicalize into a has_evidence join: a raw k8s:// placeholder
// subject or a Kubernetes-placeholder kind (VulnView could not yet join
// this consumer to a cloud principal), or an ARN/email that is not
// well-formed for its claimed provider. A fully resolved GCP principal://
// subject always passes (that scheme IS the canonical resolved subject,
// not a placeholder).
func vulnViewCloudIdentityUnresolvedPrincipalSubject(provider, principalKind, principalID string) bool {
	id := strings.TrimSpace(principalID)
	if id == "" || strings.HasPrefix(id, "k8s://") {
		return true
	}
	kind := strings.ToLower(strings.TrimSpace(principalKind))
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		return kind == "aws_kubernetes_service_account" || !vulnViewCloudIdentityAWSRoleARNPattern.MatchString(id)
	case "gcp":
		if kind == "gcp_kubernetes_service_account" {
			return true
		}
		if strings.HasPrefix(id, "principal://") {
			return false
		}
		return !vulnViewCloudIdentityGCPServiceAccountPattern.MatchString(id)
	default:
		return true
	}
}

// cloudIdentityUpsertCanonicalPrincipalEntity materializes the minimal
// canonical AWS role / GCP service account entity a vulnview.finding
// has_evidence join's principal side needs, using the SAME entity type and
// minimal attribute shape the existing provider projections use (
// aws_compute.go's addAWSComputeRoleLink for AWS, identity.go's
// gcpServiceAccountProjections/"gcp.service_account" for GCP), so a later
// provider-connector projection for the same account merges into this
// exact node instead of leaving it unreachable when no aws/gcp connector
// covers the account yet. The entity is CreateOnly (F05): a store creates
// it only when absent, so it never overwrites a richer provider-owned
// entity's label, domain, typed source/runtime ownership, or attributes
// for the same URN -- a stub only guarantees the join's principal side
// exists, it never asserts provider-managed facts. principalURN must
// already be resolved by the caller
// (vulnViewCloudIdentityCanonicalPrincipalURN); an unresolved URN upserts
// nothing. accountOrProject is the AWS account id for an AWS principal or
// the GCP project id for a GCP principal.
func cloudIdentityUpsertCanonicalPrincipalEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, provider string, principalID string, accountOrProject string, principalURN string) {
	if principalURN == "" {
		return
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "aws":
		roleARN := strings.TrimSpace(principalID)
		roleName := awsRoleNameFromARN(roleARN)
		attrs := map[string]string{
			"role_arn": roleARN,
			"provider": "aws",
		}
		if roleName != "" {
			attrs["role_name"] = roleName
		}
		if account := strings.TrimSpace(accountOrProject); account != "" {
			attrs["account_id"] = account
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        principalURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "aws.role",
			Label:      firstNonEmpty(roleName, roleARN),
			Attributes: attrs,
			CreateOnly: true,
		})
	case "gcp":
		email := strings.TrimSpace(principalID)
		attrs := map[string]string{
			"email":    email,
			"provider": "gcp",
		}
		if project := strings.TrimSpace(accountOrProject); project != "" {
			attrs["domain"] = project
			attrs["project_id"] = project
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        principalURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "gcp.service_account",
			Label:      email,
			Attributes: attrs,
			CreateOnly: true,
		})
	}
}

// vulnViewFindingConsumer is one Kubernetes consumer service account a
// cloud_identity vulnview.finding's details.consumers array names
// (Contract C7: cluster, namespace, serviceAccount, cloudAccount,
// cloudProject, service).
type vulnViewFindingConsumer struct {
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	CloudAccount   string `json:"cloudAccount,omitempty"`
	CloudProject   string `json:"cloudProject,omitempty"`
	Service        string `json:"service,omitempty"`
}

// vulnViewFindingDetailsPayload decodes the raw vulnview.finding payload's
// "details" object far enough to reach the cloud_identity consumer list
// and its completeness flag; other details fields are read from the
// event's bounded attributes instead (see vulnview.go attributesFor).
// Consumers is *[]*vulnViewFindingConsumer (a pointer to a slice of
// pointers) so decodeVulnViewFindingConsumers can distinguish three
// distinct JSON shapes the export can emit: the key absent or explicit
// JSON null (outer pointer nil, R04: never authorizes a reduced set), a
// genuinely empty array (outer pointer non-nil, zero elements, R04:
// complete-empty stays authoritative), and an array containing an
// explicit JSON null member (that element's pointer nil, R04: also
// incomplete -- a malformed member must never silently drop out of an
// otherwise-authoritative set).
type vulnViewFindingDetailsPayload struct {
	Details struct {
		Consumers         *[]*vulnViewFindingConsumer `json:"consumers"`
		ConsumersComplete bool                        `json:"consumersComplete"`
	} `json:"details"`
}

// vulnViewFindingCanonicalConsumer is one consumer member
// decodeVulnViewFindingConsumers has already canonicalized: the raw
// consumer payload, the kubernetesClusterIdentity attribute map
// vulnViewFindingConsumerKSAAttrs derived from it, and the resolved
// kubernetes_service_account URN kubernetesServiceAccountURN minted from
// those attrs. Callers (vulnViewFindingLinkSetProjections) consume this
// directly instead of recomputing the same canonicalization a second
// time, so there is exactly one place a member can be accepted or
// rejected (RR03: a second recomputation that silently "continue"s on
// failure would reintroduce the exact fail-open shape RR03 fixed, even
// though decode's own all-or-nothing check makes that branch
// unreachable today).
type vulnViewFindingCanonicalConsumer struct {
	Consumer vulnViewFindingConsumer
	K8sAttrs map[string]string
	KSAURN   string
}

// decodeVulnViewFindingConsumers decodes a cloud_identity vulnview.finding
// payload's consumer list, returning ok=false when the payload is
// undecodable, the export did not mark the list complete, the consumers
// container is absent/null, a member is null, or any member cannot
// canonicalize to an actual kubernetes_service_account URN (R04/RR03: an
// incomplete/malformed container or member -- including a qualifier that
// passes vulnViewFindingConsumerKSAAttrs's nonblank-field gate but still
// fails the real canonicalizer, e.g. an AWS cloudAccount that is not a
// 12-digit account id -- must never authorize a reduced complete set;
// callers must treat any of these exactly like "no consumers known", not
// retract a previously observed complete list). A genuinely complete,
// empty array ("consumers": []) still returns ok=true with zero
// consumers, since that is explicitly authoritative.
// kubernetesServiceAccountURN (via vulnViewFindingConsumerKSAAttrs) is
// the sole canonicalization check, applied exactly once here; each
// returned vulnViewFindingCanonicalConsumer already carries its
// canonicalized k8sAttrs/URN so no caller ever recomputes or re-checks
// canonicalization a second time.
func decodeVulnViewFindingConsumers(tenantID string, payload []byte) (consumers []vulnViewFindingCanonicalConsumer, complete bool) {
	var decoded vulnViewFindingDetailsPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, false
	}
	if !decoded.Details.ConsumersComplete || decoded.Details.Consumers == nil {
		return nil, false
	}
	raw := *decoded.Details.Consumers
	result := make([]vulnViewFindingCanonicalConsumer, 0, len(raw))
	for _, member := range raw {
		if member == nil {
			return nil, false
		}
		k8sAttrs, ok := vulnViewFindingConsumerKSAAttrs(*member)
		if !ok {
			return nil, false
		}
		ksaURN := kubernetesServiceAccountURN(tenantID, k8sAttrs)
		if ksaURN == "" {
			return nil, false
		}
		result = append(result, vulnViewFindingCanonicalConsumer{Consumer: *member, K8sAttrs: k8sAttrs, KSAURN: ksaURN})
	}
	return result, true
}

// vulnViewFindingConsumerKSAAttrs builds the kubernetesClusterIdentity
// inputs for one consumer: never a bare cluster_id (two clusters that
// share a name in different accounts/projects would otherwise collide).
// The owning account prefers consumer.CloudAccount (EKS), else
// consumer.CloudProject (GKE); with neither known, ok is false so the
// caller mints no KSA URN for this consumer (a collision-prone
// cluster-name-only URN is never minted).
func vulnViewFindingConsumerKSAAttrs(consumer vulnViewFindingConsumer) (map[string]string, bool) {
	cluster := strings.TrimSpace(consumer.Cluster)
	namespace := strings.TrimSpace(consumer.Namespace)
	serviceAccount := strings.TrimSpace(consumer.ServiceAccount)
	if cluster == "" || namespace == "" || serviceAccount == "" {
		return nil, false
	}
	attrs := map[string]string{
		"cluster_name":         cluster,
		"namespace":            namespace,
		"service_account_name": serviceAccount,
	}
	switch {
	case strings.TrimSpace(consumer.CloudAccount) != "":
		account := strings.TrimSpace(consumer.CloudAccount)
		attrs["cloud_provider"] = "aws"
		attrs["account_id"] = account
	case strings.TrimSpace(consumer.CloudProject) != "":
		project := strings.TrimSpace(consumer.CloudProject)
		attrs["cloud_provider"] = "gcp"
		attrs["gcp_project_id"] = project
	default:
		return nil, false
	}
	return attrs, true
}

// vulnViewFindingConsumerKSAEntity builds the minimal CreateOnly
// kubernetes.service_account stub one consumer names, for use as a
// Contract C9 ProjectedLinkSet.Endpoints member (R06): the store creates
// it only inside the same guarded operation that accepts the owning
// finding's winning associated_with set, before asserting Links, so a
// stale or losing observation can never materialize it. ksaURN must
// already be resolved by the caller (kubernetesServiceAccountURN); k8sAttrs
// is the exact map vulnViewFindingConsumerKSAAttrs returned for consumer.
// runtimeID is the event's source-runtime identity: Endpoints bypass the
// ordinary entities/links slices stampProjectionRuntime normally stamps,
// so this constructor carries exactly the same RuntimeID field and
// ports.EventAttributeSourceRuntimeID attribute an ordinary projected
// entity would receive, instead of leaving it blank.
func vulnViewFindingConsumerKSAEntity(tenantID string, sourceID string, runtimeID string, consumer vulnViewFindingConsumer, k8sAttrs map[string]string, ksaURN string) *ports.ProjectedEntity {
	return &ports.ProjectedEntity{
		URN:        ksaURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		RuntimeID:  runtimeID,
		EntityType: "kubernetes.service_account",
		Label:      firstNonEmpty(consumer.ServiceAccount, "default"),
		Attributes: map[string]string{
			"cluster_name":                      k8sAttrs["cluster_name"],
			"cloud_provider":                    k8sAttrs["cloud_provider"],
			"account_id":                        k8sAttrs["account_id"],
			"gcp_project_id":                    k8sAttrs["gcp_project_id"],
			"namespace":                         k8sAttrs["namespace"],
			"service_account_name":              k8sAttrs["service_account_name"],
			ports.EventAttributeSourceRuntimeID: runtimeID,
		},
		CreateOnly: true,
	}
}

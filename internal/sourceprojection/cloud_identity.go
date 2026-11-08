package sourceprojection

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// cloudIdentityIACSourceEntityType/URNKind and cloudIdentityCoverageEntityType/URNKind
// name the two graph-level facts this source still owns directly. There is
// no scan-scoped "cloud_identity.principal" entity kind: VulnView is the
// detection authority for excess-privilege and shared-principal posture
// (see docs/domains/source-runtime-guide.md "Cloud identity scan" and
// sources/vulnview's cloud_identity_finding/cloud_identity_assessment
// families), and the canonical cloud principal this evidence is about is
// whatever AWS role / GCP service account entity the AWS/GCP provider
// projections already own.
const (
	cloudIdentityIACSourceEntityType = "cloud_identity.iac_source"
	cloudIdentityIACSourceURNKind    = "cloud_identity_iac_source"
	cloudIdentityCoverageEntityType  = "cloud_identity.coverage"
	cloudIdentityCoverageURNKind     = "cloud_identity_coverage"
)

// cloudIdentityPrincipalEvidenceProjections joins one principal/scope
// evidence cohort into the canonical graph. It is pure evidence-to-graph
// context: no excess-privilege or shared-principal decision logic lives in
// this package. Canonical cloud principals resolve through the shared
// identityPrincipalURN helper so this projector's URNs are byte-identical
// to the URNs other provider projections already mint for the same AWS
// role / GCP service account (for example aws_compute.go's EKS Pod
// Identity association projection, or the GCP Workload Identity
// projection in cloud.go).
func cloudIdentityPrincipalEvidenceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	evidence, ok := cloudIdentityDecodeEvidence(event)
	if !ok {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sourceID := event.GetSourceId()
	eventID := event.GetId()

	principalURN := cloudIdentityCanonicalPrincipalURN(tenantID, evidence.Principal)
	cloudIdentityAddCanonicalPrincipalEntity(entities, tenantID, sourceID, evidence.Principal, principalURN)
	for _, workload := range evidence.Consumers {
		cloudIdentityAddConsumerLinks(entities, links, tenantID, sourceID, eventID, principalURN, evidence, workload)
	}
	if principalURN != "" {
		cloudIdentityAddIACSourceLinks(entities, links, tenantID, sourceID, eventID, principalURN, evidence.Declared.References)
	}

	entitiesOut, linksOut := entitiesAndLinks(entities, links)
	return entitiesOut, linksOut, nil
}

// cloudIdentityCanonicalPrincipalURN resolves evidence.Principal to the
// SAME canonical URN other provider projections already mint for that AWS
// role / GCP service account, so the cloud-identity evidence graph and the
// AWS/GCP provider graph describe one principal, not two. An unresolved
// Kubernetes-service-account placeholder (the collector could not yet join
// this consumer to a cloud principal) projects no principal-level entity
// or link; its consumers still project through cloudIdentityAddConsumerLinks.
// A direct Workload Identity Federation principal (kind
// "gcp_workload_identity_principal") already carries the exact canonical
// "principal://iam.googleapis.com/..." subject the collector resolved (see
// collectionResolvedPrincipal), so it canonicalizes through the same GCP
// helper vulnViewCloudIdentityCanonicalPrincipalURN uses, keeping native
// evidence and imported VulnView findings on the same graph node.
func cloudIdentityCanonicalPrincipalURN(tenantID string, principal cloudidentity.Principal) string {
	id := strings.TrimSpace(principal.ID)
	if id == "" || strings.HasPrefix(id, "k8s://") {
		return ""
	}
	switch principal.Provider {
	case cloudidentity.AWS:
		if principal.Kind == "aws_kubernetes_service_account" {
			return ""
		}
		return identityPrincipalURN(tenantID, "aws", "role", id, "")
	case cloudidentity.GCP:
		if principal.Kind == "gcp_kubernetes_service_account" {
			return ""
		}
		return identityPrincipalURN(tenantID, "gcp", "service_account", id, "")
	default:
		return ""
	}
}

// cloudIdentityAddCanonicalPrincipalEntity upserts the canonical AWS
// role / GCP service account entity this evidence is about, using the
// SAME entity type and minimal attribute shape the existing provider
// projections use (aws_compute.go's addAWSComputeRoleLink for AWS,
// identity.go's gcpServiceAccountProjections/"gcp.service_account" for
// GCP), so a later provider-connector projection for the same account
// merges into this exact node instead of leaving it unreachable when no
// aws/gcp connector covers the account yet (for example a newly onboarded
// cell account). Never a scan- or scope-keyed principal: the URN is the
// same cloudIdentityCanonicalPrincipalURN every join in this file uses.
func cloudIdentityAddCanonicalPrincipalEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, principal cloudidentity.Principal, principalURN string) {
	if principalURN == "" {
		return
	}
	switch principal.Provider {
	case cloudidentity.AWS:
		roleARN := strings.TrimSpace(principal.ID)
		roleName := awsRoleNameFromARN(roleARN)
		attrs := map[string]string{
			"role_arn": roleARN,
			"provider": "aws",
		}
		if roleName != "" {
			attrs["role_name"] = roleName
		}
		if account := strings.TrimSpace(principal.Account); account != "" {
			attrs["account_id"] = account
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        principalURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "aws.role",
			Label:      firstNonEmpty(roleName, roleARN),
			Attributes: attrs,
		})
	case cloudidentity.GCP:
		email := strings.TrimSpace(principal.ID)
		attrs := map[string]string{
			"email":    email,
			"provider": "gcp",
		}
		if project := strings.TrimSpace(principal.Project); project != "" {
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
		})
	}
}

// cloudIdentityAddConsumerLinks projects one consumer workload: Workload
// -[runs_as]-> Kubernetes service account (existing helpers), then KSA ->
// canonical principal. The KSA-to-principal edge is can_assume (AWS) /
// can_impersonate (GCP) ONLY when evidence carries an observed provider
// binding of the same kind the existing provider projections already
// treat as access; otherwise it is associated_with with basis/verified
// attributes. Access is never inferred from a declaration alone.
func cloudIdentityAddConsumerLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, principalURN string, evidence cloudidentity.Evidence, workload cloudidentity.Workload) {
	k8sAttrs := cloudIdentityWorkloadAttrs(workload)
	workloadURN := kubernetesWorkloadURN(tenantID, k8sAttrs)
	serviceAccountURN := kubernetesServiceAccountURN(tenantID, k8sAttrs)
	if workloadURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        workloadURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.workload",
			Label:      firstNonEmpty(workload.Name, workload.ID),
			Attributes: map[string]string{
				"cluster_name":   strings.TrimSpace(workload.Cluster),
				"cloud_provider": k8sAttrs["cloud_provider"],
				"account_id":     k8sAttrs["account_id"],
				"gcp_project_id": k8sAttrs["gcp_project_id"],
				"namespace":      strings.TrimSpace(workload.Namespace),
				"workload_kind":  strings.TrimSpace(workload.Kind),
				"workload_name":  strings.TrimSpace(workload.Name),
				"service":        strings.TrimSpace(workload.Service),
				"environment":    strings.TrimSpace(workload.Environment),
				"image":          strings.TrimSpace(workload.Image),
				"image_digest":   strings.TrimSpace(workload.ImageDigest),
			},
		})
	}
	if serviceAccountURN != "" {
		addEntity(entities, &ports.ProjectedEntity{
			URN:        serviceAccountURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: "kubernetes.service_account",
			Label:      firstNonEmpty(workload.ServiceAccount, "default"),
			Attributes: map[string]string{
				"cluster_name":         strings.TrimSpace(workload.Cluster),
				"cloud_provider":       k8sAttrs["cloud_provider"],
				"account_id":           k8sAttrs["account_id"],
				"gcp_project_id":       k8sAttrs["gcp_project_id"],
				"namespace":            strings.TrimSpace(workload.Namespace),
				"service_account_name": strings.TrimSpace(workload.ServiceAccount),
			},
		})
	}
	if workloadURN != "" && serviceAccountURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, workloadURN, serviceAccountURN, relationRunsAs, map[string]string{"event_id": eventID, "consumer_id": workload.ID}))
	}
	if principalURN == "" {
		return
	}
	switch {
	case serviceAccountURN != "":
		attrs := map[string]string{"event_id": eventID, "consumer_id": workload.ID}
		switch {
		case evidence.Principal.Provider == cloudidentity.AWS && cloudIdentityHasLiveAWSPodIdentityAssociation(evidence, workload):
			addLink(links, projectedLink(tenantID, sourceID, serviceAccountURN, principalURN, relationCanAssume, attrs))
		case evidence.Principal.Provider == cloudidentity.GCP && cloudidentity.GCPWorkloadIdentityUserBindingIsLive(evidence, strings.TrimSpace(workload.CloudProject), strings.TrimSpace(workload.Namespace), strings.TrimSpace(workload.ServiceAccount)):
			addLink(links, projectedLink(tenantID, sourceID, serviceAccountURN, principalURN, relationCanImpersonate, attrs))
		default:
			addLink(links, projectedLink(tenantID, sourceID, serviceAccountURN, principalURN, relationAssociatedWith, cloudIdentityAssociationAttrs(eventID, workload.ID, evidence.Principal.Provider, workload)))
		}
	case workloadURN != "":
		// No resolvable service account identity; still join the workload
		// directly so the consumer stays visible on the evidence graph. A
		// workload with no resolved KSA never carries a confirmed binding,
		// so this is always associated_with/verified=false.
		addLink(links, projectedLink(tenantID, sourceID, workloadURN, principalURN, relationAssociatedWith, cloudIdentityAssociationAttrs(eventID, workload.ID, evidence.Principal.Provider, workload)))
	}
}

// cloudIdentityAssociationAttrs builds the associated_with link attributes
// for a declaration-only consumer: basis names the identity declaration
// mechanism collection observed and verified is always "false", since this
// branch is reached only when no live provider binding was found.
func cloudIdentityAssociationAttrs(eventID string, consumerID string, provider cloudidentity.Provider, workload cloudidentity.Workload) map[string]string {
	return map[string]string{
		"event_id":    eventID,
		"consumer_id": consumerID,
		"basis":       cloudIdentityAssociationBasis(provider, workload),
		"verified":    "false",
	}
}

// cloudIdentityAssociationBasis names the identity declaration mechanism
// collection observed for a consumer with no confirmed live binding.
// Collectors may record a precise mechanism in
// Workload.Configuration["identity_binding_kind"] (for example
// "pod_identity_declaration" or "ack_pod_identity_association"); absent
// that, the provider's conventional annotation mechanism is used.
func cloudIdentityAssociationBasis(provider cloudidentity.Provider, workload cloudidentity.Workload) string {
	if basis := strings.TrimSpace(workload.Configuration["identity_binding_kind"]); basis != "" {
		return basis
	}
	switch provider {
	case cloudidentity.AWS:
		return "irsa_annotation"
	case cloudidentity.GCP:
		return "gke_workload_identity_annotation"
	default:
		return "declared"
	}
}

// cloudIdentityHasLiveAWSPodIdentityAssociation reports whether evidence
// carries a live EKS Pod Identity association for workload naming exactly
// this principal's role, keyed by the same collector resolvedIdentifier
// contract ("aws_pod_identity_role:k8s://<cluster>/<namespace>/sa/<serviceAccount>")
// the existing EKS Pod Identity provider projection
// (awsEKSPodIdentityAssociationProjections in aws_compute.go) uses to
// decide the same fact. A Declared-only or missing association never
// satisfies this.
func cloudIdentityHasLiveAWSPodIdentityAssociation(evidence cloudidentity.Evidence, workload cloudidentity.Workload) bool {
	cluster := strings.TrimSpace(workload.Cluster)
	namespace := strings.TrimSpace(workload.Namespace)
	serviceAccount := strings.TrimSpace(workload.ServiceAccount)
	if cluster == "" || namespace == "" || serviceAccount == "" {
		return false
	}
	subject := "k8s://" + cluster + "/" + namespace + "/sa/" + serviceAccount
	role := strings.TrimSpace(evidence.ResolvedIdentifiers["aws_pod_identity_role:"+subject])
	return role != "" && role == evidence.Principal.ID
}

// cloudIdentityAddIACSourceLinks (below) is the only remaining local GCP
// member-form helper in this file: live workloadIdentityUser binding
// admission (the can_impersonate gate above) reuses
// cloudidentity.GCPWorkloadIdentityUserBindingIsLive, the single
// validated gate (review finding #3), instead of a locally duplicated
// role-substring/member-parsing check.

func cloudIdentityAddIACSourceLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, principalURN string, references []cloudidentity.Reference) {
	seen := map[string]struct{}{}
	for _, ref := range references {
		repository := strings.TrimSpace(ref.Repository)
		revision := strings.TrimSpace(ref.Revision)
		if repository == "" || revision == "" {
			continue
		}
		key := repository + "@" + revision
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		iacURN := cloudIdentityIACSourceURN(tenantID, repository, revision)
		if iacURN == "" {
			continue
		}
		addEntity(entities, &ports.ProjectedEntity{
			URN:        iacURN,
			TenantID:   tenantID,
			SourceID:   sourceID,
			EntityType: cloudIdentityIACSourceEntityType,
			Label:      key,
			Attributes: map[string]string{
				"repository": repository,
				"revision":   revision,
			},
		})
		addLink(links, projectedLink(tenantID, sourceID, principalURN, iacURN, relationOwnedBy, map[string]string{"event_id": eventID}))
	}
}

// cloudIdentityCoverageProjections projects the per-scan Collection coverage
// metadata (scope, inventory completeness, gap counts, and the VulnView
// evidence handoff status) without the per-principal evidence array the
// collector strips from this event kind. It stays a durable, inspectable
// fact rather than a posture verdict.
func cloudIdentityCoverageProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	if len(event.GetPayload()) == 0 {
		return nil, nil, nil
	}
	var coverage cloudidentity.CollectionCoverage
	if err := json.Unmarshal(event.GetPayload(), &coverage); err != nil {
		return nil, nil, nil //nolint:nilerr // undecodable coverage payload projects nothing, not an error.
	}
	scope := firstNonEmpty(coverage.Scope, event.GetAttributes()["scope"])
	if scope == "" {
		return nil, nil, nil
	}
	coverageURN, err := cerebrourn.Mint(tenantID, cloudIdentityCoverageURNKind, cerebrourn.EncodeSegment(scope))
	if err != nil {
		return nil, nil, nil //nolint:nilerr // an unmintable URN means nothing to project, not an error.
	}
	gapCodes := make([]string, 0, len(coverage.Gaps))
	seenCode := map[string]struct{}{}
	for _, gap := range coverage.Gaps {
		code := strings.TrimSpace(gap.Code)
		if code == "" {
			continue
		}
		if _, ok := seenCode[code]; ok {
			continue
		}
		seenCode[code] = struct{}{}
		gapCodes = append(gapCodes, code)
	}
	attributes := map[string]string{
		"scope":              scope,
		"inventory_complete": strconv.FormatBool(coverage.InventoryComplete),
		"gap_count":          strconv.Itoa(coverage.GapCount),
		"gaps_truncated":     strconv.FormatBool(coverage.GapsTruncated),
		"gap_codes":          strings.Join(gapCodes, ","),
		"collected_at":       coverage.CollectedAt.UTC().Format(time.RFC3339),
		"event_id":           event.GetId(),
	}
	if status := strings.TrimSpace(coverage.Handoff.Status); status != "" {
		attributes["handoff_status"] = status
		attributes["handoff_bucket"] = strings.TrimSpace(coverage.Handoff.Bucket)
		attributes["handoff_key"] = strings.TrimSpace(coverage.Handoff.Key)
		attributes["handoff_sha256"] = strings.TrimSpace(coverage.Handoff.SHA256)
		attributes["handoff_size_bytes"] = strconv.FormatInt(coverage.Handoff.SizeBytes, 10)
		attributes["handoff_stream"] = strings.TrimSpace(coverage.Handoff.Stream)
		if errorCode := strings.TrimSpace(coverage.Handoff.ErrorCode); errorCode != "" {
			attributes["handoff_error_code"] = errorCode
		}
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        coverageURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: cloudIdentityCoverageEntityType,
		Label:      scope,
		Attributes: attributes,
	})
	entitiesOut, linksOut := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return entitiesOut, linksOut, nil
}

// cloudIdentityDecodeEvidence decodes the event payload into the pure core
// Evidence model and rejects ambiguous evidence whose bounded attributes do
// not match the decoded principal/scope, rather than trusting either side
// alone.
func cloudIdentityDecodeEvidence(event *cerebrov1.EventEnvelope) (cloudidentity.Evidence, bool) {
	var evidence cloudidentity.Evidence
	if len(event.GetPayload()) == 0 {
		return cloudidentity.Evidence{}, false
	}
	if err := json.Unmarshal(event.GetPayload(), &evidence); err != nil {
		return cloudidentity.Evidence{}, false
	}
	attrs := event.GetAttributes()
	if strings.TrimSpace(attrs["principal_id"]) != strings.TrimSpace(evidence.Principal.ID) {
		return cloudidentity.Evidence{}, false
	}
	if strings.TrimSpace(attrs["resource_id"]) != strings.TrimSpace(evidence.Principal.ID) {
		return cloudidentity.Evidence{}, false
	}
	if !strings.EqualFold(strings.TrimSpace(attrs["cloud_provider"]), strings.TrimSpace(string(evidence.Principal.Provider))) {
		return cloudidentity.Evidence{}, false
	}
	if strings.TrimSpace(attrs["scope"]) != strings.TrimSpace(evidence.Scope) {
		return cloudidentity.Evidence{}, false
	}
	if strings.TrimSpace(evidence.Principal.ID) == "" || strings.TrimSpace(evidence.Scope) == "" {
		return cloudidentity.Evidence{}, false
	}
	return evidence, true
}

// cloudIdentityWorkloadAttrs builds the kubernetesClusterIdentity inputs
// for a consumer workload: never a bare cluster_id (two clusters that
// share a name in different accounts/projects would otherwise collide,
// and the same cluster would mint a second node next to the
// account-qualified KSA the aws EKS Pod Identity projection already
// mints via awsEKSKubernetesAttributes). The owning account prefers
// Workload.CloudAccount (EKS, including AWS cell targets that also carry
// a paired GCP project), else Workload.CloudProject (GKE); with neither
// known, cloud_provider/account attributes are omitted and
// kubernetesClusterIdentity resolves empty, so callers mint no
// workload/service-account URN for this consumer.
func cloudIdentityWorkloadAttrs(workload cloudidentity.Workload) map[string]string {
	attrs := map[string]string{
		"cluster_name":         strings.TrimSpace(workload.Cluster),
		"namespace":            strings.TrimSpace(workload.Namespace),
		"workload_kind":        strings.TrimSpace(workload.Kind),
		"workload_name":        strings.TrimSpace(workload.Name),
		"service_account_name": strings.TrimSpace(workload.ServiceAccount),
	}
	switch {
	case strings.TrimSpace(workload.CloudAccount) != "":
		account := strings.TrimSpace(workload.CloudAccount)
		attrs["cloud_provider"] = "aws"
		attrs["account_id"] = account
		attrs["cloud_account_id"] = account
	case strings.TrimSpace(workload.CloudProject) != "":
		project := strings.TrimSpace(workload.CloudProject)
		attrs["cloud_provider"] = "gcp"
		attrs["gcp_project_id"] = project
		attrs["project_id"] = project
	}
	return attrs
}

func cloudIdentityIACSourceURN(tenantID string, repository string, revision string) string {
	tenantID = strings.TrimSpace(tenantID)
	repository = strings.TrimSpace(repository)
	revision = strings.TrimSpace(revision)
	if tenantID == "" || repository == "" || revision == "" {
		return ""
	}
	value, err := cerebrourn.Mint(
		tenantID,
		cloudIdentityIACSourceURNKind,
		cerebrourn.EncodeSegment(repository),
		cerebrourn.EncodeSegment(revision),
	)
	if err != nil {
		return ""
	}
	return value
}

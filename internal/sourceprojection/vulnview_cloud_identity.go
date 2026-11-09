package sourceprojection

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// vulnview.cloud_identity_finding/_run/_assessment are new entity kinds:
// VulnView is the detection authority for cloud-identity excess-privilege
// and shared-principal posture, and these events must never be folded into
// vulnview.finding, vulnview.dns_alert, or external.asset, nor matched by
// any registered finding rule (Cerebro's own rule engine does not
// re-derive VulnView's verdict).
const (
	vulnViewCloudIdentityFindingEntityType    = "vulnview.cloud_identity_finding"
	vulnViewCloudIdentityFindingURNKind       = "vulnview_cloud_identity_finding"
	vulnViewCloudIdentityRunEntityType        = "vulnview.cloud_identity_run"
	vulnViewCloudIdentityRunURNKind           = "vulnview_cloud_identity_run"
	vulnViewCloudIdentityAssessmentEntityType = "vulnview.cloud_identity_assessment"
	vulnViewCloudIdentityAssessmentURNKind    = "vulnview_cloud_identity_assessment"
)

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

// vulnViewCloudIdentityAWSRoleARNPattern matches the well-formed
// "arn:<partition>:iam::<12-digit-account>:role/<path>" shape VulnView AWS
// cloud-identity principals always carry.
var vulnViewCloudIdentityAWSRoleARNPattern = regexp.MustCompile(`^arn:aws[a-z0-9-]*:iam::\d{12}:role/.+$`)

// vulnViewCloudIdentityGCPServiceAccountPattern matches the well-formed
// "<name>@<project>.iam.gserviceaccount.com" shape VulnView GCP
// cloud-identity principals always carry when not already a resolved
// principal:// subject.
var vulnViewCloudIdentityGCPServiceAccountPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.iam\.gserviceaccount\.com$`)

// vulnViewCloudIdentityUnresolvedPrincipalSubject reports whether
// provider/principalKind/principalID describe a subject the projector must
// never canonicalize into a has_evidence join: a raw k8s:// placeholder
// subject or a Kubernetes-placeholder kind (the collector could not yet
// join this consumer to a cloud principal), or an ARN/email that is not
// well-formed for its claimed provider. A fully resolved GCP principal://
// subject always passes (that scheme IS the canonical resolved subject,
// not a placeholder). Kept as a separate guard -- rather than folded into
// vulnViewCloudIdentityCanonicalPrincipalURN -- so that function's
// (tenantID, provider, principalID) signature stays stable for callers
// outside this file that canonicalize an already-known-resolved subject.
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

// vulnViewCloudIdentityFindingProjections joins one VulnView cloud-identity
// finding into the graph: canonical principal -[has_evidence]->
// vulnview.cloud_identity_finding (URN by the upstream findingId), plus
// finding -[belongs_to]-> the vulnview.cloud_identity_run that last
// evaluated it (URN by lastScanId+lastRunId) so a role-centric query can
// reach the run's bundle freshness and coverage. A missing or
// unrecognized provider/principal subject never fabricates a canonical
// join; it is surfaced as a gap_codes attribute on the finding entity
// instead.
func vulnViewCloudIdentityFindingProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	findingID := firstAttribute(attrs, "finding_id")
	if findingID == "" {
		return nil, nil, nil
	}
	findingURN := projectionURN(tenantID, vulnViewCloudIdentityFindingURNKind, findingID)
	if findingURN == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sourceID := event.GetSourceId()

	provider := firstAttribute(attrs, "cloud_provider")
	principalID := firstAttribute(attrs, "principal_id")
	var gapCodes []string
	if upstream := firstAttribute(attrs, "gap_codes"); upstream != "" {
		gapCodes = append(gapCodes, strings.Split(upstream, ",")...)
	}
	principalURN := ""
	if !vulnViewCloudIdentityUnresolvedPrincipalSubject(provider, firstAttribute(attrs, "principal_kind"), principalID) {
		principalURN = vulnViewCloudIdentityCanonicalPrincipalURN(tenantID, provider, principalID)
	}
	if principalURN == "" {
		gapCodes = append(gapCodes, "missing_or_invalid_principal_subject")
	}

	addEntity(entities, &ports.ProjectedEntity{
		URN:        findingURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: vulnViewCloudIdentityFindingEntityType,
		Label:      firstAttribute(attrs, "title", "check_id", "finding_id"),
		Attributes: map[string]string{
			"finding_id":                         findingID,
			"check_id":                           firstAttribute(attrs, "check_id"),
			"check_version":                      firstAttribute(attrs, "check_version"),
			"detector_version":                   firstAttribute(attrs, "detector_version"),
			"status":                             firstAttribute(attrs, "status"),
			"source_severity":                    firstAttribute(attrs, "severity", "source_severity"),
			"cloud_provider":                     provider,
			"account_id":                         firstAttribute(attrs, "account_id"),
			"project_id":                         firstAttribute(attrs, "project_id"),
			"principal_id":                       principalID,
			"principal_kind":                     firstAttribute(attrs, "principal_kind"),
			"cohort_scope":                       firstAttribute(attrs, "cohort_scope"),
			"evidence_stream":                    firstAttribute(attrs, "evidence_stream"),
			"version":                            firstAttribute(attrs, "version"),
			"updated_at":                         firstAttribute(attrs, "updated_at"),
			"last_scan_id":                       firstAttribute(attrs, "last_scan_id"),
			"last_run_id":                        firstAttribute(attrs, "last_run_id"),
			"side":                               firstAttribute(attrs, "side"),
			"drift":                              firstAttribute(attrs, "drift"),
			"evidence_bundle_key":                firstAttribute(attrs, "evidence_bundle_key"),
			"evidence_bundle_sha256":             firstAttribute(attrs, "evidence_bundle_sha256"),
			"evidence_principal_evidence_sha256": firstAttribute(attrs, "evidence_principal_evidence_sha256"),
			"evidence_collected_at":              firstAttribute(attrs, "evidence_collected_at"),
			"consumers":                          firstAttribute(attrs, "consumers"),
			"gap_codes":                          strings.Join(gapCodes, ","),
			"event_id":                           event.GetId(),
			// Contract G: VulnView's per-finding version orders writes, so a
			// replayed older finding version never regresses the stored one.
			"at":                     vulnViewCloudIdentityFindingVersionAt(attrs, event),
			"observation_precedence": "strict",
			"observation_version":    firstAttribute(attrs, "version"),
		},
	})
	if principalURN != "" {
		// Materialize the minimal canonical principal endpoint this
		// has_evidence join needs: the Neo4j link upsert MATCHes both
		// endpoints and silently drops the link if either is missing, so a
		// finding projected into a tenant with no prior AWS/GCP connector
		// coverage of this account must mint the same stub evidence
		// already does (cloudIdentityUpsertCanonicalPrincipalEntity),
		// never leave the join unmaterialized.
		cloudIdentityUpsertCanonicalPrincipalEntity(entities, tenantID, sourceID, provider, principalID, firstAttribute(attrs, "account_id", "project_id"), principalURN)
		addLink(links, projectedLink(tenantID, sourceID, principalURN, findingURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	if lastScanID, lastRunID := firstAttribute(attrs, "last_scan_id"), firstAttribute(attrs, "last_run_id"); lastScanID != "" && lastRunID != "" {
		if runURN := projectionURN(tenantID, vulnViewCloudIdentityRunURNKind, lastScanID, lastRunID); runURN != "" {
			// Same rationale as the principal stub above, for the other
			// endpoint: a finding can arrive before (or long after,
			// replayed) its run event, and the belongs_to link must not
			// silently drop just because the run hasn't landed yet.
			vulnViewCloudIdentityAddMinimalRunEntity(entities, tenantID, sourceID, lastScanID, lastRunID, runURN)
			addLink(links, projectedLink(tenantID, sourceID, findingURN, runURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

// vulnViewCloudIdentityFindingVersionAt is the finding version's own write
// time: VulnView sets updatedAt on every version bump (observation, miss,
// triage), while OccurredAt can stay on an unchanged evaluation time across
// versions. It does not order versions -- VulnView samples updatedAt before
// its conditional write commits, so a concurrent writer can commit a higher
// version with an earlier updatedAt -- observation_version does.
func vulnViewCloudIdentityFindingVersionAt(attrs map[string]string, event *cerebrov1.EventEnvelope) string {
	at := event.GetOccurredAt().AsTime()
	if updatedAt, err := time.Parse(time.RFC3339Nano, firstAttribute(attrs, "updated_at")); err == nil {
		at = updatedAt
	}
	return at.UTC().Format(time.RFC3339Nano)
}

// vulnViewCloudIdentityRunProjections projects one VulnView cloud-identity
// detector run as a coverage entity (URN by scanId+runId), carrying the
// contracted run context (reconciliation reasons, bundle collection time,
// per-status counts, and collection coverage) so a role-centric query can
// reach bundle freshness and coverage without a second lookup.
func vulnViewCloudIdentityRunProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	scanID := firstAttribute(attrs, "scan_id")
	runID := firstAttribute(attrs, "run_id")
	if scanID == "" || runID == "" {
		return nil, nil, nil
	}
	runURN := projectionURN(tenantID, vulnViewCloudIdentityRunURNKind, scanID, runID)
	if runURN == "" {
		return nil, nil, nil
	}
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        runURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: vulnViewCloudIdentityRunEntityType,
		Label:      scanID + "/" + runID,
		Attributes: map[string]string{
			"scan_id":                       scanID,
			"run_id":                        runID,
			"cohort_scope":                  firstAttribute(attrs, "cohort_scope"),
			"evidence_stream":               firstAttribute(attrs, "evidence_stream"),
			"authoritative":                 firstAttribute(attrs, "authoritative"),
			"evaluated_at":                  firstAttribute(attrs, "evaluated_at"),
			"completed_at":                  firstAttribute(attrs, "completed_at"),
			"finished_at":                   firstAttribute(attrs, "finished_at"),
			"assessments_state":             firstAttribute(attrs, "assessments_state"),
			"detector_version":              firstAttribute(attrs, "detector_version"),
			"bundle_key":                    firstAttribute(attrs, "bundle_key"),
			"bundle_sha256":                 firstAttribute(attrs, "bundle_sha256"),
			"bundle_collected_at":           firstAttribute(attrs, "bundle_collected_at"),
			"bundle_principal_count":        firstAttribute(attrs, "bundle_principal_count"),
			"reasons":                       firstAttribute(attrs, "reasons"),
			"count_supported":               firstAttribute(attrs, "count_supported"),
			"count_candidate":               firstAttribute(attrs, "count_candidate"),
			"count_incomplete":              firstAttribute(attrs, "count_incomplete"),
			"count_clear":                   firstAttribute(attrs, "count_clear"),
			"collection_coverage_complete":  firstAttribute(attrs, "collection_coverage_complete"),
			"collection_coverage_gap_codes": firstAttribute(attrs, "collection_coverage_gap_codes"),
			"collection_coverage_gap_count": firstAttribute(attrs, "collection_coverage_gap_count"),
			"event_id":                      event.GetId(),
		},
	})
	entitiesOut, linksOut := entitiesAndLinks(entities, map[string]*ports.ProjectedLink{})
	return entitiesOut, linksOut, nil
}

// vulnViewCloudIdentityAddMinimalRunEntity upserts the minimal
// vulnview.cloud_identity_run stub a finding/assessment projection's
// belongs_to link needs as its endpoint when the run event has not (yet,
// or ever will, if it fell outside the collector's reconciliation window)
// arrived: the Neo4j link upsert MATCHes both endpoints and silently
// drops the link when either is missing (store.go
// mergeProjectedLinksQuery), so a belongs_to join must never depend on
// event arrival order. It carries only the run identity (scan_id/run_id)
// and never claims observation precedence, so in either arrival order it
// can only add those two keys to -- never regress -- the richer run
// entity vulnViewCloudIdentityRunProjections projects once the run event
// itself lands.
func vulnViewCloudIdentityAddMinimalRunEntity(entities map[string]*ports.ProjectedEntity, tenantID string, sourceID string, scanID string, runID string, runURN string) {
	if runURN == "" {
		return
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        runURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: vulnViewCloudIdentityRunEntityType,
		Label:      scanID + "/" + runID,
		Attributes: map[string]string{
			"scan_id": scanID,
			"run_id":  runID,
		},
	})
}

// vulnViewCloudIdentityAssessmentPayload decodes the bounded consumer list
// plus two other payload-only facts the bounded attributes do not carry:
// truncated (a raw-payload flag distinct from the consumers_truncated
// attribute -- it reports the detector's own evidence record was cut, not
// just this row's consumer list) and principalEvidenceSha256 (the
// evidence bundle hash for this specific assessment row, distinct from
// the finding event's evidence.principalEvidenceSha256 attribute). The
// field tags match Contract B's camelCase assessment wire shape (cluster,
// namespace, serviceAccount, cloudAccount, cloudProject, service for each
// consumer), which is distinct from the legacy /exports/findings consumer
// shape. cloudAccount / cloudProject are omitted when the detector
// report's evidence workload had neither (the consumer then projects no
// KSA link, never a collision-prone cluster-name-only URN).
type vulnViewCloudIdentityAssessmentPayload struct {
	Consumers []struct {
		Cluster        string `json:"cluster"`
		Namespace      string `json:"namespace"`
		ServiceAccount string `json:"serviceAccount"`
		CloudAccount   string `json:"cloudAccount,omitempty"`
		CloudProject   string `json:"cloudProject,omitempty"`
		Service        string `json:"service,omitempty"`
	} `json:"consumers"`
	Truncated               bool   `json:"truncated"`
	PrincipalEvidenceSha256 string `json:"principalEvidenceSha256"`
}

// vulnViewCloudIdentityAssessmentProjections joins one VulnView
// cloud-identity per-check-per-principal assessment row into the graph:
// canonical principal -[has_evidence]-> vulnview.cloud_identity_assessment
// (URN by the same identity tuple as the VulnView finding id: check_id,
// provider, principal_id, cohort_scope -- so a later finding event and the
// assessment that produced it resolve to related, discoverable entities),
// plus links to each cluster-qualified Kubernetes consumer service account
// the assessment names.
func vulnViewCloudIdentityAssessmentProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	attrs := event.GetAttributes()
	checkID := firstAttribute(attrs, "check_id")
	provider := firstAttribute(attrs, "cloud_provider")
	principalID := firstAttribute(attrs, "principal_id")
	cohortScope := firstAttribute(attrs, "cohort_scope")
	var gapCodes []string
	if upstream := firstAttribute(attrs, "gap_codes"); upstream != "" {
		gapCodes = append(gapCodes, strings.Split(upstream, ",")...)
	}
	if checkID == "" || cohortScope == "" {
		gapCodes = append(gapCodes, "missing_assessment_identity_field")
	}
	assessmentURN := ""
	if checkID != "" && cohortScope != "" {
		assessmentURN = projectionURN(tenantID, vulnViewCloudIdentityAssessmentURNKind, checkID, provider, principalID, cohortScope)
	}
	if assessmentURN == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sourceID := event.GetSourceId()

	principalURN := ""
	if !vulnViewCloudIdentityUnresolvedPrincipalSubject(provider, firstAttribute(attrs, "principal_kind"), principalID) {
		principalURN = vulnViewCloudIdentityCanonicalPrincipalURN(tenantID, provider, principalID)
	}
	if principalURN == "" {
		gapCodes = append(gapCodes, "missing_or_invalid_principal_subject")
	}

	scanID := firstAttribute(attrs, "scan_id")
	runID := firstAttribute(attrs, "run_id")

	var payload vulnViewCloudIdentityAssessmentPayload
	payloadDecoded := json.Unmarshal(event.GetPayload(), &payload) == nil

	assessmentAttributes := map[string]string{
		"scan_id":         scanID,
		"run_id":          runID,
		"check_id":        checkID,
		"check_version":   firstAttribute(attrs, "check_version"),
		"status":          firstAttribute(attrs, "status"),
		"source_severity": firstAttribute(attrs, "severity", "source_severity"),
		"side":            firstAttribute(attrs, "side"),
		"drift":           firstAttribute(attrs, "drift"),
		"cloud_provider":  provider,
		"account_id":      firstAttribute(attrs, "account_id"),
		"project_id":      firstAttribute(attrs, "project_id"),
		"principal_id":    principalID,
		"principal_kind":  firstAttribute(attrs, "principal_kind"),
		"cohort_scope":    cohortScope,
		"finding_id":      firstAttribute(attrs, "finding_id"),
		"evidence_fresh":  firstAttribute(attrs, "evidence_fresh"),
		"gap_codes":       strings.Join(gapCodes, ","),
		"event_id":        event.GetId(),
		// consumers_truncated is already a bounded event attribute
		// (Contract B's consumersTruncated). truncated and
		// principal_evidence_sha256 below are raw-payload-only facts (see
		// vulnViewCloudIdentityAssessmentPayload) previously dropped on
		// the floor; surfaced with the same naming convention the finding
		// entity already uses for its own evidence sha256 attribute.
		"consumers_truncated": firstAttribute(attrs, "consumers_truncated"),
		// Contract G/H: the stable assessment entity opts into strict
		// observation-time precedence so a late-arriving older run
		// never regresses it with stale posture.
		"at":                     event.GetOccurredAt().AsTime().UTC().Format(time.RFC3339),
		"observation_precedence": "strict",
	}
	if payloadDecoded {
		assessmentAttributes["truncated"] = strconv.FormatBool(payload.Truncated)
		if sha := strings.TrimSpace(payload.PrincipalEvidenceSha256); sha != "" {
			assessmentAttributes["principal_evidence_sha256"] = sha
		}
	}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        assessmentURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: vulnViewCloudIdentityAssessmentEntityType,
		Label:      firstAttribute(attrs, "title", "check_id"),
		Attributes: assessmentAttributes,
	})
	if principalURN != "" {
		// Same endpoint-materialization rationale as the finding
		// projection: the Neo4j link upsert silently drops a has_evidence
		// join whose principal node does not exist yet.
		cloudIdentityUpsertCanonicalPrincipalEntity(entities, tenantID, sourceID, provider, principalID, firstAttribute(attrs, "account_id", "project_id"), principalURN)
		addLink(links, projectedLink(tenantID, sourceID, principalURN, assessmentURN, relationHasEvidence, map[string]string{"event_id": event.GetId()}))
	}
	if scanID != "" && runID != "" {
		if runURN := projectionURN(tenantID, vulnViewCloudIdentityRunURNKind, scanID, runID); runURN != "" {
			vulnViewCloudIdentityAddMinimalRunEntity(entities, tenantID, sourceID, scanID, runID, runURN)
			addLink(links, projectedLink(tenantID, sourceID, assessmentURN, runURN, relationBelongsTo, map[string]string{"event_id": event.GetId()}))
		}
	}

	if payloadDecoded {
		for _, consumer := range payload.Consumers {
			cluster, namespace, serviceAccount := strings.TrimSpace(consumer.Cluster), strings.TrimSpace(consumer.Namespace), strings.TrimSpace(consumer.ServiceAccount)
			if cluster == "" || namespace == "" || serviceAccount == "" {
				continue
			}
			k8sAttrs := map[string]string{
				"cluster_name":         cluster,
				"namespace":            namespace,
				"service_account_name": serviceAccount,
			}
			switch {
			case strings.TrimSpace(consumer.CloudAccount) != "":
				account := strings.TrimSpace(consumer.CloudAccount)
				k8sAttrs["cloud_provider"] = "aws"
				k8sAttrs["account_id"] = account
				k8sAttrs["cloud_account_id"] = account
			case strings.TrimSpace(consumer.CloudProject) != "":
				project := strings.TrimSpace(consumer.CloudProject)
				k8sAttrs["cloud_provider"] = "gcp"
				k8sAttrs["gcp_project_id"] = project
				k8sAttrs["project_id"] = project
			default:
				// Neither account nor project is known for this consumer:
				// never mint a collision-prone cluster-name-only KSA URN.
				continue
			}
			ksaURN := kubernetesServiceAccountURN(tenantID, k8sAttrs)
			if ksaURN == "" {
				continue
			}
			addEntity(entities, &ports.ProjectedEntity{
				URN:        ksaURN,
				TenantID:   tenantID,
				SourceID:   sourceID,
				EntityType: "kubernetes.service_account",
				Label:      serviceAccount,
				Attributes: map[string]string{
					"cluster_name":         cluster,
					"cloud_provider":       k8sAttrs["cloud_provider"],
					"account_id":           k8sAttrs["account_id"],
					"gcp_project_id":       k8sAttrs["gcp_project_id"],
					"namespace":            namespace,
					"service_account_name": serviceAccount,
				},
			})
			addLink(links, projectedLink(tenantID, sourceID, assessmentURN, ksaURN, relationAssociatedWith, map[string]string{"event_id": event.GetId()}))
		}
	}

	projectedEntities, projectedLinks := entitiesAndLinks(entities, links)
	return projectedEntities, projectedLinks, nil
}

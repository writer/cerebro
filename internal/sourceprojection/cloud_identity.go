package sourceprojection

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// cloudIdentityProjector holds cloudIdentityPrincipalEvidenceProjections'
// trusted evaluation clock as an explicit dependency instead of a
// package-level mutable hook. Clock judges evidence freshness for both the
// excess and sharing assessments and is never derived from
// EventEnvelope.OccurredAt (an attacker/source-controlled field, and
// replayed evidence is expected to carry an old OccurredAt): production
// always uses cloudIdentityDefaultProjector (time.Now), and tests construct
// their own cloudIdentityProjector with a fixed Clock to pin a
// deterministic "now".
type cloudIdentityProjector struct {
	Clock func() time.Time
}

// cloudIdentityDefaultProjector is the production dependency set registered
// in builtinRegistry; its Clock is never reassigned.
var cloudIdentityDefaultProjector = &cloudIdentityProjector{Clock: func() time.Time { return time.Now().UTC() }}

// cloudIdentityPrincipalEntityType and cloudIdentityPrincipalURNKind must stay
// byte-identical to the literals used by internal/findings' cloud_identity
// rules (internal/findings/cloud_identity_shared.go). The two packages cannot
// share an unexported Go constant, so the contract is this comment plus the
// behavior tests that assert a finding's resource URNs resolve against this
// projector's output.
const (
	cloudIdentityPrincipalEntityType = "cloud_identity.principal"
	cloudIdentityPrincipalURNKind    = "cloud_identity_principal"
	cloudIdentityIACSourceEntityType = "cloud_identity.iac_source"
	cloudIdentityIACSourceURNKind    = "cloud_identity_iac_source"
	cloudIdentityCoverageEntityType  = "cloud_identity.coverage"
	cloudIdentityCoverageURNKind     = "cloud_identity_coverage"

	// cloudIdentityProjectionMaxAge mirrors
	// internal/findings.cloudIdentityAssessmentMaxAge so the graph's displayed
	// assessment_status/sharing_status always match what the native rules
	// would compute for the same event.
	cloudIdentityProjectionMaxAge = 48 * time.Hour
)

// cloudIdentityPrincipalEvidenceProjections joins one principal/scope
// evidence cohort into the canonical graph: each consumer workload runs as a
// Kubernetes service account that represents the cloud principal's identity,
// and the principal is owned by the Terraform/IaC location that declared its
// policy. The projected principal entity also carries the same deterministic
// Assess/AssessSharing verdict the native rules compute, so Candidate and
// Incomplete evidence stay inspectable on the graph without ever being
// represented as a passing control.
func cloudIdentityPrincipalEvidenceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return cloudIdentityDefaultProjector.evidenceProjections(event)
}

func (p *cloudIdentityProjector) evidenceProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	tenantID, err := tenantID(event)
	if err != nil {
		return nil, nil, err
	}
	evidence, ok := cloudIdentityDecodeEvidence(event)
	if !ok {
		return nil, nil, nil
	}
	principalURN := cloudIdentityPrincipalURN(tenantID, evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	if principalURN == "" {
		return nil, nil, nil
	}

	entities := map[string]*ports.ProjectedEntity{}
	links := map[string]*ports.ProjectedLink{}
	sourceID := event.GetSourceId()
	eventID := event.GetId()
	now := p.Clock()
	assessment := cloudidentity.Assess(evidence, now, cloudIdentityProjectionMaxAge)
	sharing := cloudidentity.AssessSharing(evidence)
	if !cloudIdentityEvidenceIsFresh(evidence, now) {
		// cloudidentity.AssessSharing takes no freshness input, so the
		// projection applies the same 48h gate the native
		// cloud_identity_shared_principal_rule.go applies externally via
		// cloudIdentityEvidenceIsFresh: stale or future-dated evidence can
		// neither open (Supported) nor close (Clear) a sharing verdict on
		// the graph, and instead projects using the existing
		// Incomplete/Candidate vocabulary.
		sharing = cloudidentity.Sharing{
			Status: cloudidentity.Incomplete,
			Gaps:   append(append([]cloudidentity.Gap{}, sharing.Gaps...), cloudIdentityStalenessGap(evidence, now)),
		}
	}
	gapCodes, gapMessages := cloudIdentityGapSummary(evidence.Gaps, assessment.Gaps, sharing.Gaps)
	addEntity(entities, &ports.ProjectedEntity{
		URN:        principalURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: cloudIdentityPrincipalEntityType,
		Label:      evidence.Principal.ID,
		Attributes: map[string]string{
			"account":                     strings.TrimSpace(evidence.Principal.Account),
			"project":                     strings.TrimSpace(evidence.Principal.Project),
			"principal_kind":              strings.TrimSpace(evidence.Principal.Kind),
			"provider":                    string(evidence.Principal.Provider),
			"scope":                       evidence.Scope,
			"assessment_status":           string(assessment.Status),
			"assessment_side":             assessment.Side,
			"assessment_drift":            strconv.FormatBool(assessment.Drift),
			"sharing_status":              string(sharing.Status),
			"consumer_count":              strconv.Itoa(len(evidence.Consumers)),
			"consumer_inventory_complete": strconv.FormatBool(evidence.ConsumerInventoryComplete),
			"declared_complete":           strconv.FormatBool(evidence.Declared.Complete),
			"observed_complete":           strconv.FormatBool(evidence.Observed.Complete),
			"collected_at":                evidence.CollectedAt.UTC().Format(time.RFC3339),
			"gap_count":                   strconv.Itoa(len(evidence.Gaps) + len(assessment.Gaps) + len(sharing.Gaps)),
			"gap_codes":                   gapCodes,
			"gap_messages":                gapMessages,
			"event_id":                    eventID,
			"event_kind":                  event.GetKind(),
		},
	})

	for _, workload := range evidence.Consumers {
		cloudIdentityAddConsumerLinks(entities, links, tenantID, sourceID, eventID, principalURN, workload)
	}
	cloudIdentityAddIACSourceLinks(entities, links, tenantID, sourceID, eventID, principalURN, evidence.Declared.References)

	entitiesOut, linksOut := entitiesAndLinks(entities, links)
	return entitiesOut, linksOut, nil
}

func cloudIdentityAddConsumerLinks(entities map[string]*ports.ProjectedEntity, links map[string]*ports.ProjectedLink, tenantID string, sourceID string, eventID string, principalURN string, workload cloudidentity.Workload) {
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
				"cluster_id":    strings.TrimSpace(workload.Cluster),
				"namespace":     strings.TrimSpace(workload.Namespace),
				"workload_kind": strings.TrimSpace(workload.Kind),
				"workload_name": strings.TrimSpace(workload.Name),
				"service":       strings.TrimSpace(workload.Service),
				"environment":   strings.TrimSpace(workload.Environment),
				"image":         strings.TrimSpace(workload.Image),
				"image_digest":  strings.TrimSpace(workload.ImageDigest),
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
				"cluster_id":           strings.TrimSpace(workload.Cluster),
				"namespace":            strings.TrimSpace(workload.Namespace),
				"service_account_name": strings.TrimSpace(workload.ServiceAccount),
			},
		})
	}
	if workloadURN != "" && serviceAccountURN != "" {
		addLink(links, projectedLink(tenantID, sourceID, workloadURN, serviceAccountURN, relationRunsAs, map[string]string{"event_id": eventID, "consumer_id": workload.ID}))
	}
	switch {
	case serviceAccountURN != "":
		addLink(links, projectedLink(tenantID, sourceID, serviceAccountURN, principalURN, relationRepresentsIdentity, map[string]string{"event_id": eventID, "consumer_id": workload.ID}))
	case workloadURN != "":
		// No resolvable service account identity; still join the workload
		// directly so the consumer stays visible on the evidence graph.
		addLink(links, projectedLink(tenantID, sourceID, workloadURN, principalURN, relationAssociatedWith, map[string]string{"event_id": eventID, "consumer_id": workload.ID}))
	}
}

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
		if principalURN != "" {
			addLink(links, projectedLink(tenantID, sourceID, principalURN, iacURN, relationOwnedBy, map[string]string{"event_id": eventID}))
		}
	}
}

// cloudIdentityCoverageProjections projects the per-scan Collection coverage
// metadata (scope, inventory completeness, and gap counts) without the
// per-principal evidence array the collector strips from this event kind.
// It stays a durable, inspectable fact rather than a posture verdict.
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
	entities := map[string]*ports.ProjectedEntity{}
	addEntity(entities, &ports.ProjectedEntity{
		URN:        coverageURN,
		TenantID:   tenantID,
		SourceID:   event.GetSourceId(),
		EntityType: cloudIdentityCoverageEntityType,
		Label:      scope,
		Attributes: map[string]string{
			"scope":              scope,
			"inventory_complete": strconv.FormatBool(coverage.InventoryComplete),
			"gap_count":          strconv.Itoa(coverage.GapCount),
			"gaps_truncated":     strconv.FormatBool(coverage.GapsTruncated),
			"gap_codes":          strings.Join(gapCodes, ","),
			"collected_at":       coverage.CollectedAt.UTC().Format(time.RFC3339),
			"event_id":           event.GetId(),
		},
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

// cloudIdentityEvidenceIsFresh mirrors the freshness boundary
// cloudidentity.Assess applies for excess: evidence is fresh iff CollectedAt
// is known and now.Sub(CollectedAt) is in [0, cloudIdentityProjectionMaxAge].
// cloudidentity.AssessSharing takes no freshness input, so this is used
// directly to gate the projected sharing_status, matching
// internal/findings.cloudIdentityEvidenceIsFresh.
func cloudIdentityEvidenceIsFresh(e cloudidentity.Evidence, now time.Time) bool {
	if e.CollectedAt.IsZero() {
		return false
	}
	age := now.Sub(e.CollectedAt)
	return age >= 0 && age <= cloudIdentityProjectionMaxAge
}

// cloudIdentityStalenessGap reuses the same gap codes/messages
// cloudidentity.assessFreshness emits for excess so a stale/future-dated
// sharing verdict carries a consistent, inspectable WHY on the graph.
func cloudIdentityStalenessGap(e cloudidentity.Evidence, now time.Time) cloudidentity.Gap {
	if e.CollectedAt.IsZero() {
		return cloudidentity.Gap{
			Code:    "cloudidentity.unknown_collection_time",
			Scope:   e.Principal.ID,
			Message: "evidence has no collection timestamp; freshness cannot be established",
		}
	}
	age := now.Sub(e.CollectedAt)
	return cloudidentity.Gap{
		Code:    "cloudidentity.stale_evidence",
		Scope:   e.Principal.ID,
		Message: fmt.Sprintf("evidence is %s old, exceeding the %s freshness boundary", age, cloudIdentityProjectionMaxAge),
	}
}

func cloudIdentityWorkloadAttrs(workload cloudidentity.Workload) map[string]string {
	return map[string]string{
		"cluster_id":           strings.TrimSpace(workload.Cluster),
		"cluster_name":         strings.TrimSpace(workload.Cluster),
		"namespace":            strings.TrimSpace(workload.Namespace),
		"workload_kind":        strings.TrimSpace(workload.Kind),
		"workload_name":        strings.TrimSpace(workload.Name),
		"service_account_name": strings.TrimSpace(workload.ServiceAccount),
	}
}

// cloudIdentityPrincipalURN is the canonical tenant-safe anchor for one
// principal+scope cohort. It intentionally excludes declared/observed state
// so the same URN is reused across evidence revisions for the same principal
// and scope, matching internal/findings.cloudIdentityPrincipalScopeURN.
func cloudIdentityPrincipalURN(tenantID string, provider cloudidentity.Provider, principalID string, scope string) string {
	tenantID = strings.TrimSpace(tenantID)
	principalID = strings.TrimSpace(principalID)
	scope = strings.TrimSpace(scope)
	if tenantID == "" || principalID == "" || scope == "" {
		return ""
	}
	value, err := cerebrourn.Mint(
		tenantID,
		cloudIdentityPrincipalURNKind,
		cerebrourn.EncodeSegment(string(provider)),
		cerebrourn.EncodeSegment(principalID),
		cerebrourn.EncodeSegment(scope),
	)
	if err != nil {
		return ""
	}
	return value
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

// cloudIdentityMaxGapMessages bounds how many gap messages are surfaced on
// the projected principal entity so a pathological evidence cohort cannot
// produce an unbounded attribute value.
const cloudIdentityMaxGapMessages = 10

// cloudIdentityGapSummary gives Candidate/Incomplete evidence a concrete WHY
// on the graph (deduplicated gap codes plus a bounded list of messages)
// instead of only an assessment_status/sharing_status enum.
func cloudIdentityGapSummary(gapLists ...[]cloudidentity.Gap) (codes string, messages string) {
	seenCode := map[string]struct{}{}
	var codeList []string
	var messageList []string
	for _, gaps := range gapLists {
		for _, gap := range gaps {
			code := strings.TrimSpace(gap.Code)
			if code != "" {
				if _, ok := seenCode[code]; !ok {
					seenCode[code] = struct{}{}
					codeList = append(codeList, code)
				}
			}
			if message := strings.TrimSpace(gap.Message); message != "" && len(messageList) < cloudIdentityMaxGapMessages {
				if code != "" {
					messageList = append(messageList, code+": "+message)
				} else {
					messageList = append(messageList, message)
				}
			}
		}
	}
	return strings.Join(codeList, ","), strings.Join(messageList, "; ")
}

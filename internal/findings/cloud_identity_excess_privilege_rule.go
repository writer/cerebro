package findings

import (
	"context"
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

const (
	cloudIdentityExcessPrivilegeRuleID    = "cloud-identity-excess-privilege"
	cloudIdentityExcessPrivilegeTitle     = "Cloud Identity Excess Privilege"
	cloudIdentityExcessPrivilegeCheckID   = "cloud-identity-excess-privilege-current"
	cloudIdentityExcessPrivilegeCheckName = "Cloud Identity Excess Privilege (current state)"

	// cloudIdentityAssessmentMaxAge bounds how stale collected evidence may be
	// before the deterministic evaluator treats it as unknown freshness. The
	// source scan trigger is daily-only; this allows one missed cycle of slack
	// before evidence is no longer trusted to clear or confirm an excess.
	cloudIdentityAssessmentMaxAge = 48 * time.Hour
)

var cloudIdentityExcessPrivilegeControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.3"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"},
}

type cloudIdentityExcessPrivilegeRule struct {
	Rule
	definition RuleDefinition
	clock      func() time.Time
}

var cloudIdentityExcessPrivilegeDefinition = RuleDefinition{
	ID:                 cloudIdentityExcessPrivilegeRuleID,
	Name:               cloudIdentityExcessPrivilegeTitle,
	Description:        "Detect Kubernetes-workload cloud identities (AWS IAM roles or GCP service accounts) whose declared or live-observed IAM grants exceed the union of their consumers' validated operation requirements.",
	SourceID:           cloudidentity.SourceID,
	EventKinds:         []string{cloudidentity.EventKind},
	OutputKind:         "finding.cloud_identity_excess_privilege",
	Severity:           "dynamic",
	Status:             findingStatusOpen,
	Maturity:           RuleMaturityTest,
	Tags:               []string{"cloud-identity", "kubernetes", "iam", "least-privilege", "drift", "aws", "gcp"},
	FalsePositives:     []string{"A consumer workload was decommissioned but its requirement evidence has not yet been re-collected, or the investigator could not resolve a newly added consumer's actual API usage.", "The excess permission is intentionally reserved for a documented, not-yet-deployed consumer."},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/domains/source-runtime-guide.md#cloud-identity-scan"},
	Runbook:            "Review the declared and observed excess grants against the unioned consumer requirements, remove the unused actions/resources from the identity's IAM policy or Terraform declaration, and re-run the scan to confirm the finding clears.",
	RequiredAttributes: []string{"principal_id", "cloud_provider", "scope", "resource_id"},
	FingerprintFields:  []string{"cloud_identity_principal_scope_urn"},
	ControlRefs:        cloudIdentityExcessPrivilegeControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var cloudIdentityPrincipalEvidenceKindMatcher = eventKindMatcher(cloudidentity.EventKind)

func newCloudIdentityExcessPrivilegeRule() Rule {
	return newCloudIdentityExcessPrivilegeRuleWithClock(time.Now)
}

// newCloudIdentityExcessPrivilegeRuleWithClock lets tests inject a trusted
// evaluation clock. Freshness is never derived from EventEnvelope.OccurredAt
// (an attacker/source-controlled field); it is always measured against this
// clock, defaulting to time.Now in production.
func newCloudIdentityExcessPrivilegeRuleWithClock(clock func() time.Time) Rule {
	if clock == nil {
		clock = time.Now
	}
	build := func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
		return buildCloudIdentityExcessPrivilegeFinding(ctx, runtime, event, clock)
	}
	rule := newEventRule(eventRuleConfig{
		definition: cloudIdentityExcessPrivilegeDefinition,
		match:      matchesCloudIdentityExcessPrivilege,
		build:      build,
	})
	return &cloudIdentityExcessPrivilegeRule{
		Rule:       rule,
		definition: cloudIdentityExcessPrivilegeDefinition,
		clock:      clock,
	}
}

func (r *cloudIdentityExcessPrivilegeRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *cloudIdentityExcessPrivilegeRule) OpenAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"cloud_identity_principal_scope_urn": strings.TrimSpace(attributes["cloud_identity_principal_scope_urn"]),
	}, "cloud_identity_principal_scope_urn")
}

// CloseOnEvent closes the open excess-privilege finding only when a later,
// explicitly fresh and complete evidence cohort for the same tenant-scoped
// principal+scope resolves to Clear. Partial, stale, candidate, or unknown
// reassessments never close a previously supported finding.
func (r *cloudIdentityExcessPrivilegeRule) CloseOnEvent(event Event) (string, bool) {
	if !cloudIdentityPrincipalEvidenceKindMatcher(event) || !hasRequiredAttributes(event, cloudIdentityExcessPrivilegeDefinition.RequiredAttributes...) {
		return "", false
	}
	evidence, ok := decodeCloudIdentityEvidence(event)
	if !ok {
		return "", false
	}
	now := r.clock()
	assessment := cloudidentity.Assess(evidence, now, cloudIdentityAssessmentMaxAge)
	if assessment.Status != cloudidentity.Clear {
		return "", false
	}
	principalScopeURN := cloudIdentityPrincipalScopeURN(event.GetTenantId(), evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	anchor := r.OpenAnchor(map[string]string{"cloud_identity_principal_scope_urn": principalScopeURN})
	return anchor, anchor != ""
}

func matchesCloudIdentityExcessPrivilege(event *cerebrov1.EventEnvelope) bool {
	if !cloudIdentityPrincipalEvidenceKindMatcher(event) || !hasRequiredAttributes(event, cloudIdentityExcessPrivilegeDefinition.RequiredAttributes...) {
		return false
	}
	return true
}

// buildCloudIdentityExcessPrivilegeFinding only ever returns a record for a
// Supported assessment. Candidate and Incomplete evidence stay inspectable
// through the projected graph (coverage surface) without becoming a
// production finding, and Clear evidence is handled by CloseOnEvent.
func buildCloudIdentityExcessPrivilegeFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, clock func() time.Time) (*ports.FindingRecord, error) {
	evidence, ok := decodeCloudIdentityEvidence(event)
	if !ok {
		return nil, fmt.Errorf("cloud_identity: event %q payload does not match its declared attributes", event.GetId())
	}
	now := clock()
	assessment := cloudidentity.Assess(evidence, now, cloudIdentityAssessmentMaxAge)
	if assessment.Status != cloudidentity.Supported {
		return nil, nil
	}
	tenantID := strings.TrimSpace(event.GetTenantId())
	principalScopeURN := cloudIdentityPrincipalScopeURN(tenantID, evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	if principalScopeURN == "" {
		return nil, nil
	}
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryEntityType:  cloudIdentityPrincipalEntityType,
		CollectAllEntities: true,
		CollectAllLinkURNs: true,
		ResourceFallbacks:  []string{principalScopeURN},
	})
	if err != nil {
		return nil, fmt.Errorf("project cloud identity excess privilege finding context for event %q: %w", event.GetId(), err)
	}
	resourceURNs := projectedContext.ResourceURNs
	if len(resourceURNs) == 0 {
		resourceURNs = []string{principalScopeURN}
	}
	severity := cloudIdentityExcessPrivilegeSeverity(assessment)
	attrs := eventAttributes(event)
	evidenceDigest, err := cloudIdentityDigest(evidence)
	if err != nil {
		return nil, fmt.Errorf("digest cloud identity evidence for event %q: %w", event.GetId(), err)
	}
	assessmentDigest, err := cloudIdentityDigest(assessment)
	if err != nil {
		return nil, fmt.Errorf("digest cloud identity assessment for event %q: %w", event.GetId(), err)
	}
	attributes := map[string]string{
		"cloud_identity_principal_scope_urn": principalScopeURN,
		"primary_resource_urn":               principalScopeURN,
		"cloud_identity_evidence_digest":     evidenceDigest,
		"cloud_identity_assessment_digest":   assessmentDigest,
		"principal_id":                       evidence.Principal.ID,
		"cloud_provider":                     string(evidence.Principal.Provider),
		"principal_kind":                     evidence.Principal.Kind,
		"account_id":                         evidence.Principal.Account,
		"project_id":                         evidence.Principal.Project,
		"scope":                              evidence.Scope,
		"side":                               assessment.Side,
		"drift":                              strconv.FormatBool(assessment.Drift),
		"declared_excess_count":              strconv.Itoa(len(assessment.DeclaredExcess)),
		"observed_excess_count":              strconv.Itoa(len(assessment.ObservedExcess)),
		"declared_excess":                    cloudIdentityMarshalExcess(assessment.DeclaredExcess),
		"observed_excess":                    cloudIdentityMarshalExcess(assessment.ObservedExcess),
		"declared_citations":                 cloudIdentityMarshalReferences(evidence.Declared.References),
		"observed_citations":                 cloudIdentityMarshalReferences(evidence.Observed.References),
		"resolved_identifiers":               cloudIdentityMarshalStringMap(evidence.ResolvedIdentifiers),
		"consumer_count":                     strconv.Itoa(len(evidence.Consumers)),
		"consumer_inventory_complete":        strconv.FormatBool(evidence.ConsumerInventoryComplete),
		"collected_at":                       evidence.CollectedAt.UTC().Format(time.RFC3339),
		"gaps":                               cloudIdentityMarshalGaps(append(append([]cloudidentity.Gap{}, evidence.Gaps...), assessment.Gaps...)),
		"event_id":                           strings.TrimSpace(event.GetId()),
		"source_runtime_id":                  firstNonEmpty(strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]), strings.TrimSpace(runtime.GetId())),
	}
	for key, value := range cloudIdentityExcessPrivilegeDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := now
	fingerprint := hashFindingFingerprint(cloudIdentityExcessPrivilegeRuleID, principalScopeURN)
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("cloud_identity_principal", map[string]string{
			"principal_id": evidence.Principal.ID,
			"scope":        evidence.Scope,
			"side":         assessment.Side,
			"drift":        strconv.FormatBool(assessment.Drift),
		}, cloudIdentityGraphCitationPaths(projectedContext)...),
	}
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  strings.TrimSpace(runtime.GetId()),
		RuleID:                     cloudIdentityExcessPrivilegeRuleID,
		Title:                      cloudIdentityExcessPrivilegeTitle,
		Severity:                   severity,
		Status:                     findingStatusOpen,
		Summary:                    cloudIdentityExcessPrivilegeSummary(evidence, assessment),
		ResourceURNs:               resourceURNs,
		EventIDs:                   []string{strings.TrimSpace(event.GetId())},
		PolicyID:                   principalScopeURN,
		PolicyName:                 evidence.Principal.ID,
		CheckID:                    cloudIdentityExcessPrivilegeCheckID,
		CheckName:                  cloudIdentityExcessPrivilegeCheckName,
		ControlRefs:                cloneFindingControlRefs(cloudIdentityExcessPrivilegeDefinition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            observedAt,
		LastObservedAt:             observedAt,
	}, nil
}
func cloudIdentityExcessPrivilegeSeverity(assessment cloudidentity.Assessment) string {
	switch {
	case assessment.Drift, assessment.Side == "both":
		return "HIGH"
	case assessment.Side == "iac", assessment.Side == "live":
		return "MEDIUM"
	default:
		return "MEDIUM"
	}
}

func cloudIdentityExcessPrivilegeSummary(evidence cloudidentity.Evidence, assessment cloudidentity.Assessment) string {
	excessCount := len(assessment.DeclaredExcess) + len(assessment.ObservedExcess)
	driftNote := ""
	if assessment.Drift {
		driftNote = " with live/declared drift"
	}
	sideNote := ""
	if strings.TrimSpace(assessment.Side) != "" {
		sideNote = fmt.Sprintf(" (%s)", assessment.Side)
	}
	return fmt.Sprintf(
		"%s cloud identity %s in scope %s has %d excess permission grant(s) beyond its unioned consumer requirements%s%s",
		strings.ToUpper(string(evidence.Principal.Provider)),
		firstNonEmpty(evidence.Principal.ID, "unknown principal"),
		firstNonEmpty(evidence.Scope, "unknown scope"),
		excessCount,
		sideNote,
		driftNote,
	)
}

// decodeCloudIdentityEvidence decodes the event payload into the pure core
// Evidence model and rejects ambiguous evidence whose attributes do not match
// the decoded principal/scope. The event's bounded attributes are a fast
// pre-filter; the payload is always the source of truth for what gets
// assessed, so a mismatch is treated as unusable rather than trusted.
func decodeCloudIdentityEvidence(event *cerebrov1.EventEnvelope) (cloudidentity.Evidence, bool) {
	var evidence cloudidentity.Evidence
	if len(event.GetPayload()) == 0 {
		return cloudidentity.Evidence{}, false
	}
	if err := json.Unmarshal(event.GetPayload(), &evidence); err != nil {
		return cloudidentity.Evidence{}, false
	}
	attrs := eventAttributes(event)
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

func cloudIdentityAssessmentNow(event *cerebrov1.EventEnvelope) time.Time {
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		return timestamp.AsTime().UTC()
	}
	return time.Now().UTC()
}

// cloudIdentityEvidenceIsFresh mirrors the freshness boundary cloudidentity.Assess
// applies for excess: evidence is fresh iff CollectedAt is known and now.Sub(CollectedAt)
// is in [0, cloudIdentityAssessmentMaxAge]. It is used directly for sharing
// (cloudidentity.AssessSharing takes no freshness input) so stale or future-dated
// evidence can neither open nor close a sharing finding either, consistent with excess.
func cloudIdentityEvidenceIsFresh(evidence cloudidentity.Evidence, now time.Time) bool {
	if evidence.CollectedAt.IsZero() {
		return false
	}
	age := now.Sub(evidence.CollectedAt)
	return age >= 0 && age <= cloudIdentityAssessmentMaxAge
}

// cloudIdentityPrincipalScopeURN is the canonical tenant-safe anchor for one
// principal+scope cohort. It intentionally excludes declared/observed state so
// the same URN - and therefore the same finding fingerprint - is reused across
// open/close/reopen transitions for the same principal and scope.
func cloudIdentityPrincipalScopeURN(tenantID string, provider cloudidentity.Provider, principalID string, scope string) string {
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

func cloudIdentityMarshalExcess(items []cloudidentity.Excess) string {
	if len(items) == 0 {
		return ""
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func cloudIdentityMarshalReferences(refs []cloudidentity.Reference) string {
	if len(refs) == 0 {
		return ""
	}
	encoded, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func cloudIdentityMarshalGaps(gaps []cloudidentity.Gap) string {
	if len(gaps) == 0 {
		return ""
	}
	encoded, err := json.Marshal(gaps)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func cloudIdentityMarshalStringMap(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// cloudIdentityGraphCitationPaths converts the joined projection graph
// (workload -> service account -> cloud principal -> owning IaC source) into
// finding graph-evidence paths so the finding carries real graph citations
// instead of a restated attribute blob.
func cloudIdentityGraphCitationPaths(projectedContext findingProjectionContext) []*cerebrov1.GraphEvidencePath {
	if len(projectedContext.Links) == 0 {
		return nil
	}
	entityByURN := make(map[string]*ports.ProjectedEntity, len(projectedContext.Entities))
	for _, entity := range projectedContext.Entities {
		if entity == nil || strings.TrimSpace(entity.URN) == "" {
			continue
		}
		entityByURN[strings.TrimSpace(entity.URN)] = entity
	}
	paths := make([]*cerebrov1.GraphEvidencePath, 0, len(projectedContext.Links))
	for _, link := range projectedContext.Links {
		if link == nil {
			continue
		}
		from := entityByURN[strings.TrimSpace(link.FromURN)]
		to := entityByURN[strings.TrimSpace(link.ToURN)]
		fromLabel, fromType := "", ""
		if from != nil {
			fromLabel, fromType = from.Label, from.EntityType
		}
		toLabel, toType := "", ""
		if to != nil {
			toLabel, toType = to.Label, to.EntityType
		}
		paths = append(paths, newGraphEvidencePath(link.FromURN, fromLabel, fromType, link.Relation, link.ToURN, toLabel, toType, link.Attributes))
	}
	return paths
}

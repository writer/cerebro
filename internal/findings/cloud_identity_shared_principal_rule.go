package findings

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/ports"
)

const (
	cloudIdentitySharedPrincipalRuleID    = "cloud-identity-shared-principal"
	cloudIdentitySharedPrincipalTitle     = "Cloud Identity Shared Across Unrelated Services"
	cloudIdentitySharedPrincipalCheckID   = "cloud-identity-shared-principal-current"
	cloudIdentitySharedPrincipalCheckName = "Cloud Identity Shared Across Unrelated Services (current state)"
	// cloudIdentitySharedPrincipalBroadServiceCount is the distinct-service
	// threshold at which an already-confirmed sharing condition is treated as
	// broad enough to raise severity from the default MEDIUM to HIGH.
	cloudIdentitySharedPrincipalBroadServiceCount = 3
)

var cloudIdentitySharedPrincipalControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.3"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.3"},
}

type cloudIdentitySharedPrincipalRule struct {
	Rule
	definition RuleDefinition
	clock      func() time.Time
}

var cloudIdentitySharedPrincipalDefinition = RuleDefinition{
	ID:                 cloudIdentitySharedPrincipalRuleID,
	Name:               cloudIdentitySharedPrincipalTitle,
	Description:        "Detect one AWS IAM role or GCP service account whose validated consumer inventory spans multiple distinct logical services rather than replicas of the same service, breaking blast-radius isolation if the identity is compromised or over-permissioned for any one consumer.",
	SourceID:           cloudidentity.SourceID,
	EventKinds:         []string{cloudidentity.EventKind},
	OutputKind:         "finding.cloud_identity_shared_principal",
	Severity:           "dynamic",
	Status:             findingStatusOpen,
	Maturity:           RuleMaturityTest,
	Tags:               []string{"cloud-identity", "kubernetes", "iam", "sharing", "blast-radius", "aws", "gcp"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/domains/source-runtime-guide.md#cloud-identity-scan"},
	FalsePositives:     []string{"The services are intentionally co-deployed replicas of the same logical application under different image tags or namespaces.", "The investigator could not resolve consumer service identity for one or more workloads, understating or overstating distinct services."},
	Runbook:            "Split the shared identity into one principal per logical service (or scope its policy to the narrowest shared need), then re-run the scan to confirm the finding clears.",
	RequiredAttributes: []string{"principal_id", "cloud_provider", "scope", "resource_id"},
	FingerprintFields:  []string{"cloud_identity_principal_scope_urn"},
	ControlRefs:        cloudIdentitySharedPrincipalControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

func newCloudIdentitySharedPrincipalRule() Rule {
	return newCloudIdentitySharedPrincipalRuleWithClock(time.Now)
}

// newCloudIdentitySharedPrincipalRuleWithClock lets tests inject a trusted
// evaluation clock. Freshness is never derived from EventEnvelope.OccurredAt
// (an attacker/source-controlled field); it is always measured against this
// clock, defaulting to time.Now in production.
func newCloudIdentitySharedPrincipalRuleWithClock(clock func() time.Time) Rule {
	if clock == nil {
		clock = time.Now
	}
	build := func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
		return buildCloudIdentitySharedPrincipalFinding(ctx, runtime, event, clock)
	}
	rule := newEventRule(eventRuleConfig{
		definition: cloudIdentitySharedPrincipalDefinition,
		match:      matchesCloudIdentitySharedPrincipal,
		build:      build,
	})
	return &cloudIdentitySharedPrincipalRule{
		Rule:       rule,
		definition: cloudIdentitySharedPrincipalDefinition,
		clock:      clock,
	}
}

func (r *cloudIdentitySharedPrincipalRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *cloudIdentitySharedPrincipalRule) OpenAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"cloud_identity_principal_scope_urn": strings.TrimSpace(attributes["cloud_identity_principal_scope_urn"]),
	}, "cloud_identity_principal_scope_urn")
}

// CloseOnEvent closes the open sharing finding only when a later, explicitly
// fresh and complete evidence cohort resolves sharing to Clear. Partial,
// stale, candidate, or unknown reassessments never close a previously
// supported finding.
func (r *cloudIdentitySharedPrincipalRule) CloseOnEvent(event Event) (string, bool) {
	if !cloudIdentityPrincipalEvidenceKindMatcher(event) || !hasRequiredAttributes(event, cloudIdentitySharedPrincipalDefinition.RequiredAttributes...) {
		return "", false
	}
	evidence, ok := decodeCloudIdentityEvidence(event)
	if !ok {
		return "", false
	}
	if !cloudIdentityEvidenceIsFresh(evidence, r.clock()) {
		return "", false
	}
	sharing := cloudidentity.AssessSharing(evidence)
	if sharing.Status != cloudidentity.Clear {
		return "", false
	}
	principalScopeURN := cloudIdentityPrincipalScopeURN(event.GetTenantId(), evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	anchor := r.OpenAnchor(map[string]string{"cloud_identity_principal_scope_urn": principalScopeURN})
	return anchor, anchor != ""
}

func matchesCloudIdentitySharedPrincipal(event *cerebrov1.EventEnvelope) bool {
	return cloudIdentityPrincipalEvidenceKindMatcher(event) && hasRequiredAttributes(event, cloudIdentitySharedPrincipalDefinition.RequiredAttributes...)
}

// buildCloudIdentitySharedPrincipalFinding only ever returns a record for a
// Supported sharing assessment. Candidate and Incomplete evidence stay
// inspectable through the projected graph without becoming a production
// finding, and Clear evidence is handled by CloseOnEvent.
func buildCloudIdentitySharedPrincipalFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, clock func() time.Time) (*ports.FindingRecord, error) {
	evidence, ok := decodeCloudIdentityEvidence(event)
	if !ok {
		return nil, fmt.Errorf("cloud_identity: event %q payload does not match its declared attributes", event.GetId())
	}
	if !cloudIdentityEvidenceIsFresh(evidence, clock()) {
		return nil, nil
	}
	sharing := cloudidentity.AssessSharing(evidence)
	if sharing.Status != cloudidentity.Supported {
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
		return nil, fmt.Errorf("project cloud identity shared principal finding context for event %q: %w", event.GetId(), err)
	}
	resourceURNs := projectedContext.ResourceURNs
	if len(resourceURNs) == 0 {
		resourceURNs = []string{principalScopeURN}
	}
	services := uniqueSortedStrings(sharing.Services)
	consumerIDs := uniqueSortedStrings(sharing.ConsumerIDs)
	severity := cloudIdentitySharedPrincipalSeverity(services)
	attrs := eventAttributes(event)
	attributes := map[string]string{
		"cloud_identity_principal_scope_urn": principalScopeURN,
		"primary_resource_urn":               principalScopeURN,
		"cloud_identity_evidence_digest":     cloudidentity.Digest(evidence),
		"cloud_identity_assessment_digest":   cloudidentity.Digest(sharing),
		"principal_id":                       evidence.Principal.ID,
		"cloud_provider":                     string(evidence.Principal.Provider),
		"account_id":                         evidence.Principal.Account,
		"project_id":                         evidence.Principal.Project,
		"scope":                              evidence.Scope,
		"shared_service_count":               strconv.Itoa(len(services)),
		"shared_services":                    strings.Join(services, ","),
		"shared_consumer_count":              strconv.Itoa(len(consumerIDs)),
		"shared_consumer_ids":                strings.Join(consumerIDs, ","),
		"consumer_inventory_complete":        strconv.FormatBool(evidence.ConsumerInventoryComplete),
		"collected_at":                       evidence.CollectedAt.UTC().Format(time.RFC3339),
		"gaps":                               cloudIdentityMarshalGaps(append(append([]cloudidentity.Gap{}, evidence.Gaps...), sharing.Gaps...)),
		"event_id":                           strings.TrimSpace(event.GetId()),
		"source_runtime_id":                  firstNonEmpty(strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]), strings.TrimSpace(runtime.GetId())),
	}
	for key, value := range cloudIdentitySharedPrincipalDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := cloudIdentityAssessmentNow(event)
	fingerprint := hashFindingFingerprint(cloudIdentitySharedPrincipalRuleID, principalScopeURN)
	graphRows := []*cerebrov1.GraphEvidenceRow{
		newGraphEvidenceRow("cloud_identity_shared_principal", map[string]string{
			"principal_id":    evidence.Principal.ID,
			"scope":           evidence.Scope,
			"shared_services": strings.Join(services, ","),
		}, cloudIdentityGraphCitationPaths(projectedContext)...),
	}
	return &ports.FindingRecord{
		ID:                         fingerprint,
		Fingerprint:                fingerprint,
		TenantID:                   tenantID,
		RuntimeID:                  strings.TrimSpace(runtime.GetId()),
		RuleID:                     cloudIdentitySharedPrincipalRuleID,
		Title:                      cloudIdentitySharedPrincipalTitle,
		Severity:                   severity,
		Status:                     findingStatusOpen,
		Summary:                    cloudIdentitySharedPrincipalSummary(evidence, services),
		ResourceURNs:               resourceURNs,
		EventIDs:                   []string{strings.TrimSpace(event.GetId())},
		PolicyID:                   principalScopeURN,
		PolicyName:                 evidence.Principal.ID,
		CheckID:                    cloudIdentitySharedPrincipalCheckID,
		CheckName:                  cloudIdentitySharedPrincipalCheckName,
		ControlRefs:                cloneFindingControlRefs(cloudIdentitySharedPrincipalDefinition.ControlRefs),
		FindingPersistenceEnvelope: ports.FindingPersistenceEnvelope{GraphEvidenceRows: graphRows},
		Attributes:                 attributes,
		FirstObservedAt:            observedAt,
		LastObservedAt:             observedAt,
	}, nil
}

func cloudIdentitySharedPrincipalSeverity(services []string) string {
	if len(services) >= cloudIdentitySharedPrincipalBroadServiceCount {
		return "HIGH"
	}
	return "MEDIUM"
}

func cloudIdentitySharedPrincipalSummary(evidence cloudidentity.Evidence, services []string) string {
	return fmt.Sprintf(
		"%s cloud identity %s in scope %s is shared by %d distinct logical service(s): %s",
		strings.ToUpper(string(evidence.Principal.Provider)),
		firstNonEmpty(evidence.Principal.ID, "unknown principal"),
		firstNonEmpty(evidence.Scope, "unknown scope"),
		len(services),
		firstNonEmpty(strings.Join(services, ", "), "unspecified"),
	)
}

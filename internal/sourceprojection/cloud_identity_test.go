package sourceprojection

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func cloudIdentityProjectionTestEvidence(baseTime time.Time) cloudidentity.Evidence {
	principal := cloudidentity.Principal{
		ID:       "arn:aws:iam::222222222222:role/billing-worker",
		Provider: cloudidentity.AWS,
		Kind:     "role",
		Account:  "222222222222",
	}
	scope := principal.ID
	consumer := cloudidentity.Workload{
		ID:             "billing/billing-worker",
		Service:        "billing-worker",
		Environment:    "prod",
		Cluster:        "prod-use1",
		Namespace:      "billing",
		Name:           "billing-worker",
		Kind:           "Deployment",
		ServiceAccount: "billing-worker",
		Image:          "222222222222.dkr.ecr.us-east-1.amazonaws.com/billing-worker:9.9.9",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/billing-worker",
			Revision:   "f6a7b8c9",
			Exact:      true,
		},
		Principals: []cloudidentity.Principal{principal},
	}
	grant := cloudidentity.Grant{
		ID:        "grant-billing",
		Effect:    "Allow",
		Actions:   []string{"dynamodb:GetItem"},
		Resources: []string{"arn:aws:dynamodb:us-east-1:222222222222:table/billing"},
		References: []cloudidentity.Reference{{
			Repository: "example-org/infra",
			Revision:   "a7b8c9d0",
			Path:       "modules/billing/iam.tf",
			StartLine:  3,
			EndLine:    9,
			Digest:     "sha256:iacdigest-billing",
		}},
	}
	return cloudidentity.Evidence{
		Schema:                    cloudidentity.SchemaVersion,
		Principal:                 principal,
		Scope:                     scope,
		Consumers:                 []cloudidentity.Workload{consumer},
		ConsumerInventoryComplete: true,
		Declared: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{grant},
			Complete:   true,
			ObservedAt: baseTime,
			References: grant.References,
		},
		Observed: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{grant},
			Complete:   true,
			ObservedAt: baseTime,
		},
		Definitions: cloudidentity.Definitions{Complete: true, Digest: "sha256:defsdigest-billing"},
		Gaps: []cloudidentity.Gap{{
			Code:    "unvalidated_investigation",
			Scope:   scope,
			Message: "consumer requirement investigation not yet validated",
		}},
		CollectedAt: baseTime,
	}
}

func cloudIdentityProjectionTestEvent(t *testing.T, id string, tenant string, evidence cloudidentity.Evidence) *cerebrov1.EventEnvelope {
	t.Helper()
	payload, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return &cerebrov1.EventEnvelope{
		Id:       id,
		TenantId: tenant,
		SourceId: cloudidentity.SourceID,
		Kind:     cloudidentity.EventKind,
		Payload:  payload,
		Attributes: map[string]string{
			"principal_id":   evidence.Principal.ID,
			"resource_id":    evidence.Principal.ID,
			"cloud_provider": string(evidence.Principal.Provider),
			"scope":          evidence.Scope,
		},
		OccurredAt: timestamppb.New(evidence.CollectedAt),
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsJoinsGraph(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityProjectionTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-1", "writer", evidence)

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}

	entityByType := map[string]*struct {
		urn   string
		label string
		attrs map[string]string
	}{}
	for _, entity := range entities {
		entityByType[entity.EntityType] = &struct {
			urn   string
			label string
			attrs map[string]string
		}{urn: entity.URN, label: entity.Label, attrs: entity.Attributes}
	}
	for _, wantType := range []string{cloudIdentityPrincipalEntityType, "kubernetes.workload", "kubernetes.service_account", cloudIdentityIACSourceEntityType} {
		if _, ok := entityByType[wantType]; !ok {
			t.Fatalf("missing projected entity type %q; got types %v", wantType, entityTypes(entities))
		}
	}

	principal := entityByType[cloudIdentityPrincipalEntityType]
	wantPrincipalURN := cloudIdentityPrincipalURN("writer", evidence.Principal.Provider, evidence.Principal.ID, evidence.Scope)
	if principal.urn != wantPrincipalURN {
		t.Fatalf("principal URN = %q, want %q", principal.urn, wantPrincipalURN)
	}
	validStatuses := map[string]bool{"supported": true, "candidate": true, "clear": true, "incomplete": true}
	if status := principal.attrs["assessment_status"]; !validStatuses[status] {
		t.Fatalf("assessment_status = %q, want one of supported/candidate/clear/incomplete", status)
	}
	if status := principal.attrs["sharing_status"]; !validStatuses[status] {
		t.Fatalf("sharing_status = %q, want one of supported/candidate/clear/incomplete", status)
	}
	if !strings.Contains(principal.attrs["gap_codes"], "unvalidated_investigation") {
		t.Fatalf("gap_codes = %q, want to include the fixture's source gap code so incomplete evidence stays inspectable", principal.attrs["gap_codes"])
	}
	if principal.attrs["gap_messages"] == "" {
		t.Fatal("gap_messages must carry the WHY behind a non-passing assessment, not just a status enum")
	}

	iacSource := entityByType[cloudIdentityIACSourceEntityType]
	if iacSource.attrs["repository"] != "example-org/infra" || iacSource.attrs["revision"] != "a7b8c9d0" {
		t.Fatalf("iac_source attrs = %+v, want example-org/infra@a7b8c9d0", iacSource.attrs)
	}

	workload := entityByType["kubernetes.workload"]
	serviceAccount := entityByType["kubernetes.service_account"]
	var sawRunsAs, sawRepresentsIdentity, sawOwnedBy bool
	for _, link := range links {
		switch {
		case link.FromURN == workload.urn && link.ToURN == serviceAccount.urn && link.Relation == relationRunsAs:
			sawRunsAs = true
		case link.FromURN == serviceAccount.urn && link.ToURN == principal.urn && link.Relation == relationRepresentsIdentity:
			sawRepresentsIdentity = true
		case link.FromURN == principal.urn && link.ToURN == iacSource.urn && link.Relation == relationOwnedBy:
			sawOwnedBy = true
		}
	}
	if !sawRunsAs {
		t.Fatal("missing workload -runs_as-> service_account join")
	}
	if !sawRepresentsIdentity {
		t.Fatal("missing service_account -represents_identity-> principal join")
	}
	if !sawOwnedBy {
		t.Fatal("missing principal -owned_by-> iac_source join")
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsRejectsMismatchedAttributes(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityProjectionTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-mismatch", "writer", evidence)
	event.Attributes["scope"] = "arn:aws:iam::222222222222:role/unrelated-role"

	entities, links, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v, want nil (soft-skip ambiguous evidence)", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("got %d entities / %d links for mismatched attrs, want none", len(entities), len(links))
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsMissingTenant(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityProjectionTestEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-no-tenant", "", evidence)

	if _, _, err := cloudIdentityPrincipalEvidenceProjections(event); err == nil {
		t.Fatal("cloudIdentityPrincipalEvidenceProjections() error = nil, want error for a blank tenant")
	}
}

func TestCloudIdentityPrincipalEvidenceProjectionsTenantIsolation(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	evidence := cloudIdentityProjectionTestEvidence(baseTime)

	eventA := cloudIdentityProjectionTestEvent(t, "event-tenant-a", "tenant-a", evidence)
	entitiesA, linksA, err := cloudIdentityPrincipalEvidenceProjections(eventA)
	if err != nil {
		t.Fatalf("tenant-a projection error = %v", err)
	}
	eventB := cloudIdentityProjectionTestEvent(t, "event-tenant-b", "tenant-b", evidence)
	entitiesB, linksB, err := cloudIdentityPrincipalEvidenceProjections(eventB)
	if err != nil {
		t.Fatalf("tenant-b projection error = %v", err)
	}
	if len(entitiesA) == 0 || len(entitiesB) == 0 {
		t.Fatal("expected projected entities for both tenants")
	}

	urnsA := map[string]struct{}{}
	for _, entity := range entitiesA {
		if entity.TenantID != "tenant-a" {
			t.Fatalf("tenant-a entity %q has TenantID = %q, want tenant-a", entity.URN, entity.TenantID)
		}
		if cerebrourn.TenantID(entity.URN) != "tenant-a" {
			t.Fatalf("tenant-a entity URN %q does not embed tenant-a", entity.URN)
		}
		urnsA[entity.URN] = struct{}{}
	}
	for _, entity := range entitiesB {
		if entity.TenantID != "tenant-b" {
			t.Fatalf("tenant-b entity %q has TenantID = %q, want tenant-b", entity.URN, entity.TenantID)
		}
		if cerebrourn.TenantID(entity.URN) != "tenant-b" {
			t.Fatalf("tenant-b entity URN %q does not embed tenant-b", entity.URN)
		}
		if _, collide := urnsA[entity.URN]; collide {
			t.Fatalf("tenant-b entity URN %q collides with a tenant-a URN for identical payload; tenant isolation violated", entity.URN)
		}
	}
	for _, link := range linksA {
		if link.TenantID != "tenant-a" {
			t.Fatalf("tenant-a link has TenantID = %q, want tenant-a", link.TenantID)
		}
	}
	for _, link := range linksB {
		if link.TenantID != "tenant-b" {
			t.Fatalf("tenant-b link has TenantID = %q, want tenant-b", link.TenantID)
		}
	}
}

func TestCloudIdentityCoverageProjectionsFactsNotVerdict(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema: cloudidentity.SchemaVersion,
		Scope:  "org:writer",
		Gaps: []cloudidentity.Gap{{
			Code:    "budget_exceeded",
			Scope:   "org:writer",
			Message: "cohort exceeded the 768KiB per-principal budget",
		}},
		CollectedAt:       baseTime,
		InventoryComplete: false,
		GapCount:          1,
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "event-coverage-1",
		TenantId:   "writer",
		SourceId:   cloudidentity.SourceID,
		Kind:       cloudidentity.CoverageEventKind,
		Payload:    payload,
		Attributes: map[string]string{"scope": coverage.Scope},
		OccurredAt: timestamppb.New(baseTime),
	}

	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	entity := entities[0]
	if entity.EntityType != cloudIdentityCoverageEntityType {
		t.Fatalf("EntityType = %q, want %q", entity.EntityType, cloudIdentityCoverageEntityType)
	}
	if entity.Attributes["inventory_complete"] != "false" {
		t.Fatalf("inventory_complete = %q, want false", entity.Attributes["inventory_complete"])
	}
	if entity.Attributes["gap_count"] != "1" {
		t.Fatalf("gap_count = %q, want 1", entity.Attributes["gap_count"])
	}
	if entity.Attributes["gaps_truncated"] != "false" {
		t.Fatalf("gaps_truncated = %q, want false", entity.Attributes["gaps_truncated"])
	}
	if !strings.Contains(entity.Attributes["gap_codes"], "budget_exceeded") {
		t.Fatalf("gap_codes = %q, want budget_exceeded", entity.Attributes["gap_codes"])
	}
}

// TestCloudIdentityCoverageProjectionsPreservesTruncatedGapCount reproduces a
// collection whose coverage payload dropped its Gaps slice to stay under the
// bounded event size budget (sources/internal/cloudidentity.CollectionEvents
// does this for an oversized cohort): GapCount and GapsTruncated must still
// surface the real, non-zero gap total rather than silently reporting 0.
func TestCloudIdentityCoverageProjectionsPreservesTruncatedGapCount(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 11, 0, 0, 0, time.UTC)
	coverage := cloudidentity.CollectionCoverage{
		Schema:            cloudidentity.SchemaVersion,
		Scope:             "org:writer",
		CollectedAt:       baseTime,
		InventoryComplete: false,
		GapCount:          1,
		GapsTruncated:     true,
	}
	payload, err := json.Marshal(coverage)
	if err != nil {
		t.Fatalf("marshal coverage: %v", err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         "event-coverage-2",
		TenantId:   "writer",
		SourceId:   cloudidentity.SourceID,
		Kind:       cloudidentity.CoverageEventKind,
		Payload:    payload,
		Attributes: map[string]string{"scope": coverage.Scope},
		OccurredAt: timestamppb.New(baseTime),
	}

	entities, _, err := cloudIdentityCoverageProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityCoverageProjections() error = %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("got %d coverage entities, want 1", len(entities))
	}
	entity := entities[0]
	if entity.Attributes["gap_count"] != "1" {
		t.Fatalf("gap_count = %q, want 1 (wire gap_count must survive even with an empty gaps array)", entity.Attributes["gap_count"])
	}
	if entity.Attributes["gaps_truncated"] != "true" {
		t.Fatalf("gaps_truncated = %q, want true", entity.Attributes["gaps_truncated"])
	}
}

func entityTypes(entities []*ports.ProjectedEntity) []string {
	types := make([]string, 0, len(entities))
	for _, entity := range entities {
		types = append(types, entity.EntityType)
	}
	return types
}

// --- R17 freshness fixtures (mirrors internal/findings fixtures so a
// fresh cohort is genuinely Supported/Clear, isolating the freshness gate
// under test from unrelated Incomplete/Candidate gaps). ---

func cloudIdentityProjectionExcessSupportedEvidence(baseTime time.Time) cloudidentity.Evidence {
	principal := cloudidentity.Principal{
		ID:       "arn:aws:iam::111111111111:role/payments-processor",
		Provider: cloudidentity.AWS,
		Kind:     "role",
		Account:  "111111111111",
	}
	scope := principal.ID
	consumer := cloudidentity.Workload{
		ID:             "payments/payments-processor",
		Service:        "payments-processor",
		Environment:    "prod",
		Cluster:        "prod-use1",
		Namespace:      "payments",
		Name:           "payments-processor",
		Kind:           "Deployment",
		ServiceAccount: "payments-processor",
		Image:          "111111111111.dkr.ecr.us-east-1.amazonaws.com/payments-processor:1.2.3",
		Source: cloudidentity.SourcePin{
			Repository: "example-org/payments-processor",
			Revision:   "a1b2c3d4",
			Exact:      true,
			Digest:     "sha256:appdigest",
		},
		Principals: []cloudidentity.Principal{principal},
		References: []cloudidentity.Reference{{
			Repository: "example-org/payments-processor",
			Revision:   "a1b2c3d4",
			Path:       "deploy/deployment.yaml",
			Digest:     "sha256:manifestdigest",
		}},
	}
	declaredGrant := cloudidentity.Grant{
		ID:        "grant-s3-access",
		Effect:    "Allow",
		Actions:   []string{"s3:GetObject", "s3:DeleteBucket"},
		Resources: []string{"arn:aws:s3:::payments-bucket/*"},
		References: []cloudidentity.Reference{{
			Repository: "example-org/infra",
			Revision:   "d4e5f6a7",
			Path:       "modules/payments/iam.tf",
			StartLine:  10,
			EndLine:    24,
			Digest:     "sha256:iacdigest",
		}},
	}
	observedGrant := declaredGrant
	observedGrant.References = []cloudidentity.Reference{{
		API:        "iam:GetRolePolicy",
		Scope:      scope,
		ObservedAt: baseTime,
		Digest:     "sha256:livedigest",
	}}
	trust := []cloudidentity.Grant{{
		ID: "workload-trust", Effect: "Allow", Actions: []string{"sts:AssumeRoleWithWebIdentity"},
		Members:    []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Conditions: []cloudidentity.Condition{{Operator: "StringEquals", Key: "oidc.eks.example.com/id/EX:sub", Values: []string{"system:serviceaccount:payments:payments-processor"}}},
	}}
	return cloudidentity.Evidence{
		Schema:                    cloudidentity.SchemaVersion,
		Principal:                 principal,
		Scope:                     scope,
		Consumers:                 []cloudidentity.Workload{consumer},
		ConsumerInventoryComplete: true,
		ResolvedIdentifiers:       map[string]string{"aws_eks_oidc_provider_arn:prod-use1": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Declared: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{declaredGrant},
			Trust:      trust,
			Complete:   true,
			ObservedAt: baseTime,
			References: declaredGrant.References,
		},
		Observed: cloudidentity.PolicyState{
			Grants:     []cloudidentity.Grant{observedGrant},
			Trust:      trust,
			Complete:   true,
			ObservedAt: baseTime,
			References: observedGrant.References,
		},
		Definitions: cloudidentity.MergeDefinitions(cloudidentity.Definitions{
			Complete: true,
			Actions:  []cloudidentity.ActionDefinition{{Name: "s3:GetObject"}, {Name: "s3:DeleteBucket"}},
		}),
		Investigations: []cloudidentity.Investigation{{
			ConsumerID: consumer.ID,
			Source:     consumer.Source,
			Requirements: []cloudidentity.Requirement{{
				Provider:    cloudidentity.AWS,
				Service:     "s3",
				Operation:   "GetObject",
				Action:      "s3:GetObject",
				Resources:   []string{"arn:aws:s3:::payments-bucket/*"},
				ConsumerIDs: []string{consumer.ID},
				References: []cloudidentity.Reference{{
					Repository: consumer.Source.Repository,
					Revision:   consumer.Source.Revision,
					Path:       "internal/storage/client.go",
					StartLine:  40,
					EndLine:    44,
					Digest:     "sha256:appdigest",
				}},
			}},
			Validation: cloudidentity.Validation{
				Analyzer:           "go-ast",
				SourceDigest:       "sha256:appdigest",
				CitationsVerified:  true,
				OperationsVerified: true,
				ScopeComplete:      true,
				CoveredFiles:       []string{"internal/storage/client.go"},
			},
		}},
		CollectedAt: baseTime,
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsStaleEvidenceProjectsNotCurrent
// reproduces R17: a replayed event's OccurredAt is attacker/source
// controlled and can equal CollectedAt even when the evaluation clock has
// moved far past it. Before the fix, cloudIdentityProjectionNow trusted
// EventEnvelope.OccurredAt (== CollectedAt here, so "fresh") and
// AssessSharing had no freshness gate at all, so a cohort that is genuinely
// Supported/Clear once fresh would misleadingly project as
// Supported/Clear while 72h stale. After the fix, the trusted
// cloudIdentityProjectionClock sees the evidence as 72h old (> the 48h
// boundary) and both assessment_status and sharing_status fall back to the
// existing Candidate/Incomplete vocabulary instead of Supported/Clear.
func TestCloudIdentityPrincipalEvidenceProjectionsStaleEvidenceProjectsNotCurrent(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	trustedNow := baseTime.Add(72 * time.Hour)
	evidence := cloudIdentityProjectionExcessSupportedEvidence(baseTime)

	// Sanity: this cohort is genuinely Supported when fresh, so the test
	// exercises the freshness gate, not an unrelated Incomplete gap.
	if assessment := cloudidentity.Assess(evidence, baseTime, cloudIdentityProjectionMaxAge); assessment.Status != cloudidentity.Supported {
		t.Fatalf("fixture assessment.Status = %q, want %q; keep this fixture in sync with cloudidentity.Assess", assessment.Status, cloudidentity.Supported)
	}

	event := cloudIdentityProjectionTestEvent(t, "event-stale", "writer", evidence)
	event.OccurredAt = timestamppb.New(evidence.CollectedAt) // attacker/source-controlled, == CollectedAt

	original := cloudIdentityProjectionClock
	cloudIdentityProjectionClock = func() time.Time { return trustedNow }
	defer func() { cloudIdentityProjectionClock = original }()

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	var principal *ports.ProjectedEntity
	for _, entity := range entities {
		if entity.EntityType == cloudIdentityPrincipalEntityType {
			principal = entity
		}
	}
	if principal == nil {
		t.Fatal("missing projected principal entity")
	}
	if status := principal.Attributes["assessment_status"]; status == string(cloudidentity.Supported) || status == string(cloudidentity.Clear) {
		t.Fatalf("assessment_status = %q for 72h-stale evidence (OccurredAt == CollectedAt), want Candidate/Incomplete, never Supported/Clear", status)
	}
	if status := principal.Attributes["sharing_status"]; status == string(cloudidentity.Supported) || status == string(cloudidentity.Clear) {
		t.Fatalf("sharing_status = %q for 72h-stale evidence (OccurredAt == CollectedAt), want Candidate/Incomplete, never Supported/Clear", status)
	}
	if !strings.Contains(principal.Attributes["gap_codes"], "cloudidentity.stale_evidence") {
		t.Fatalf("gap_codes = %q, want cloudidentity.stale_evidence to explain the non-current sharing status", principal.Attributes["gap_codes"])
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsFutureEvidenceProjectsNotCurrent
// pins the symmetric case: evidence collected in the future relative to the
// trusted clock (negative age) must also neither open nor close.
func TestCloudIdentityPrincipalEvidenceProjectionsFutureEvidenceProjectsNotCurrent(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	trustedNow := baseTime.Add(-72 * time.Hour)
	evidence := cloudIdentityProjectionExcessSupportedEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-future", "writer", evidence)
	event.OccurredAt = timestamppb.New(evidence.CollectedAt)

	original := cloudIdentityProjectionClock
	cloudIdentityProjectionClock = func() time.Time { return trustedNow }
	defer func() { cloudIdentityProjectionClock = original }()

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	var principal *ports.ProjectedEntity
	for _, entity := range entities {
		if entity.EntityType == cloudIdentityPrincipalEntityType {
			principal = entity
		}
	}
	if principal == nil {
		t.Fatal("missing projected principal entity")
	}
	if status := principal.Attributes["assessment_status"]; status == string(cloudidentity.Supported) || status == string(cloudidentity.Clear) {
		t.Fatalf("assessment_status = %q for future-dated evidence, want Candidate/Incomplete, never Supported/Clear", status)
	}
	if status := principal.Attributes["sharing_status"]; status == string(cloudidentity.Supported) || status == string(cloudidentity.Clear) {
		t.Fatalf("sharing_status = %q for future-dated evidence, want Candidate/Incomplete, never Supported/Clear", status)
	}
}

// TestCloudIdentityPrincipalEvidenceProjectionsFreshEvidenceUnchanged pins
// the non-regression side of R17: a genuinely fresh, Supported cohort must
// still project as Supported once the trusted clock (not OccurredAt) agrees
// it is within the 48h boundary.
func TestCloudIdentityPrincipalEvidenceProjectionsFreshEvidenceUnchanged(t *testing.T) {
	baseTime := time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC)
	trustedNow := baseTime.Add(time.Hour)
	evidence := cloudIdentityProjectionExcessSupportedEvidence(baseTime)
	event := cloudIdentityProjectionTestEvent(t, "event-fresh", "writer", evidence)
	// OccurredAt is deliberately far in the past; only the trusted clock
	// below should determine freshness.
	event.OccurredAt = timestamppb.New(baseTime.Add(-30 * 24 * time.Hour))

	original := cloudIdentityProjectionClock
	cloudIdentityProjectionClock = func() time.Time { return trustedNow }
	defer func() { cloudIdentityProjectionClock = original }()

	entities, _, err := cloudIdentityPrincipalEvidenceProjections(event)
	if err != nil {
		t.Fatalf("cloudIdentityPrincipalEvidenceProjections() error = %v", err)
	}
	var principal *ports.ProjectedEntity
	for _, entity := range entities {
		if entity.EntityType == cloudIdentityPrincipalEntityType {
			principal = entity
		}
	}
	if principal == nil {
		t.Fatal("missing projected principal entity")
	}
	if status := principal.Attributes["assessment_status"]; status != string(cloudidentity.Supported) {
		t.Fatalf("assessment_status = %q, want %q for fresh evidence judged by the trusted clock", status, cloudidentity.Supported)
	}
}

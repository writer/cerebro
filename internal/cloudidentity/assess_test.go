package cloudidentity

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const testMaxAge = 24 * time.Hour

// testSourceDigest is shared between exactPin and validInvestigationValidation
// so test fixtures naturally satisfy the per-consumer investigation binding
// (Investigation.Source must match the consumer's own Source, and
// Validation.SourceDigest must match that same Source.Digest).
const testSourceDigest = "sha256:pinned"

func exactPin() SourcePin {
	return SourcePin{Repository: "example/repo", Revision: "abc123", Digest: testSourceDigest, Exact: true}
}

func validInvestigationValidation() Validation {
	return Validation{
		Analyzer:           "test-analyzer",
		SourceDigest:       testSourceDigest,
		CitationsVerified:  true,
		OperationsVerified: true,
		ScopeComplete:      true,
	}
}

func baseConsumer() Workload {
	return Workload{
		ID: "w1", Service: "checkout", Name: "checkout-1", Namespace: "ns1",
		ServiceAccount: "sa1", Kind: "Deployment", Cluster: "cluster1",
		Source: exactPin(),
	}
}

func baseInvestigation(consumerID, action string, resources []string) Investigation {
	return Investigation{
		ConsumerID: consumerID,
		Source:     exactPin(),
		Requirements: []Requirement{{
			Provider: AWS, Service: "s3", Operation: "GetObject", Action: action,
			Resources: resources, ConsumerIDs: []string{consumerID},
		}},
		Validation: validInvestigationValidation(),
	}
}

func s3Definitions() Definitions {
	return Definitions{
		Actions: []ActionDefinition{
			{Name: "s3:GetObject"}, {Name: "s3:PutObject"}, {Name: "s3:ListBucket"}, {Name: "s3:DeleteObject"},
		},
		Complete: true,
	}
}

// excessEvidence builds a baseline where the declared and observed grants
// are identical and both allow s3:GetObject+s3:PutObject on a bucket-wide
// wildcard, but only s3:GetObject on one concrete object is required. This
// produces one narrowing Excess (GetObject) and one unused-action Excess
// (PutObject) per side.
func excessEvidence(now time.Time) Evidence {
	grant := Grant{
		ID: "g1", Effect: "Allow",
		Actions:    []string{"s3:GetObject", "s3:PutObject"},
		Resources:  []string{"arn:aws:s3:::bucket/*"},
		References: []Reference{{Digest: "sha256:policy"}},
	}
	return Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "role-a", Provider: AWS, Kind: "aws_iam_role"},
		Scope:                     "account:111111111111",
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Definitions:               s3Definitions(),
		Investigations:            []Investigation{baseInvestigation("w1", "s3:GetObject", []string{"arn:aws:s3:::bucket/obj1"})},
		CollectedAt:               now,
	}
}

// cleanEvidence builds a baseline where declared and observed grants exactly
// match the required action+resource with no wildcard, so neither side has
// any excess.
func cleanEvidence(now time.Time) Evidence {
	grant := Grant{
		ID: "g1", Effect: "Allow",
		Actions:    []string{"s3:GetObject"},
		Resources:  []string{"arn:aws:s3:::bucket/obj1"},
		References: []Reference{{Digest: "sha256:policy"}},
	}
	return Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "role-a", Provider: AWS, Kind: "aws_iam_role"},
		Scope:                     "account:111111111111",
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Definitions:               s3Definitions(),
		Investigations:            []Investigation{baseInvestigation("w1", "s3:GetObject", []string{"arn:aws:s3:::bucket/obj1"})},
		CollectedAt:               now,
	}
}

func findExcess(items []Excess, action string) (Excess, bool) {
	for _, it := range items {
		if it.Action == action {
			return it, true
		}
	}
	return Excess{}, false
}

func TestAssessBothSidesExcessIsSupported(t *testing.T) {
	a := Assess(excessEvidence(testNow), testNow, testMaxAge)
	if a.Status != Supported {
		t.Fatalf("Status = %v, want Supported; gaps=%+v", a.Status, a.Gaps)
	}
	if a.Side != "both" {
		t.Fatalf("Side = %q, want both", a.Side)
	}
	if a.Drift {
		t.Error("Drift should be false: declared and observed are identical")
	}
	put, ok := findExcess(a.DeclaredExcess, "s3:PutObject")
	if !ok || len(put.RequiredResources) != 0 {
		t.Errorf("expected s3:PutObject fully excess on declared side, got %+v (found=%v)", put, ok)
	}
	get, ok := findExcess(a.DeclaredExcess, "s3:GetObject")
	if !ok || len(get.RequiredResources) != 1 || get.RequiredResources[0] != "arn:aws:s3:::bucket/obj1" {
		t.Errorf("expected s3:GetObject narrowing excess on declared side, got %+v (found=%v)", get, ok)
	}
	if len(a.ObservedExcess) != len(a.DeclaredExcess) {
		t.Errorf("observed excess should mirror declared excess here, got %+v vs %+v", a.ObservedExcess, a.DeclaredExcess)
	}
}

func TestAssessDeclaredOnlyExcessSideIac(t *testing.T) {
	e := excessEvidence(testNow)
	e.Observed = PolicyState{Grants: nil, Complete: true}
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Supported {
		t.Fatalf("Status = %v, want Supported; gaps=%+v", a.Status, a.Gaps)
	}
	if a.Side != "iac" {
		t.Fatalf("Side = %q, want iac", a.Side)
	}
	if len(a.ObservedExcess) != 0 {
		t.Errorf("ObservedExcess should be empty, got %+v", a.ObservedExcess)
	}
}

// TestAssessLiveExcessSupportedWithMissingIaC is the key regression for
// Main's correction: a positively-demonstrated live-side excess must be
// Supported even when the declared/IaC side is entirely absent
// (PolicyState zero-value, Complete=false — exactly what the pipeline
// reports when no owning IaC was resolved for this principal).
func TestAssessLiveExcessSupportedWithMissingIaC(t *testing.T) {
	e := excessEvidence(testNow)
	e.Declared = PolicyState{} // no owning IaC resolved
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Supported {
		t.Fatalf("Status = %v, want Supported despite missing declared/IaC side; gaps=%+v", a.Status, a.Gaps)
	}
	if a.Side != "live" {
		t.Fatalf("Side = %q, want live", a.Side)
	}
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("DeclaredExcess should be empty (no grants to evaluate), got %+v", a.DeclaredExcess)
	}
}

func TestAssessNoExcessBothSidesCompleteIsClear(t *testing.T) {
	a := Assess(cleanEvidence(testNow), testNow, testMaxAge)
	if a.Status != Clear {
		t.Fatalf("Status = %v, want Clear; gaps=%+v", a.Status, a.Gaps)
	}
	if a.Side != "" {
		t.Errorf("Side = %q, want empty for Clear", a.Side)
	}
}

// TestAssessNoExcessOneSideUnknownIsIncomplete is the Clear-asymmetry
// regression: a clear, complete side next to an unknown/incomplete side must
// never promote to Clear.
func TestAssessNoExcessOneSideUnknownIsIncomplete(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Observed = PolicyState{} // unresolved/incomplete live read
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete when one side is unknown even though the other is clean", a.Status)
	}
}

func TestAssessDenySuppressesExcessClaim(t *testing.T) {
	e := excessEvidence(testNow)
	e.Declared.Grants = append(e.Declared.Grants, Grant{
		ID: "deny-put", Effect: "Deny",
		Actions: []string{"s3:PutObject"}, Resources: []string{"arn:aws:s3:::bucket/*"},
	})
	e.Observed = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
	}}, Complete: true}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:PutObject"); ok {
		t.Errorf("s3:PutObject should be suppressed by the Deny grant, got %+v", a.DeclaredExcess)
	}
	if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); !ok {
		t.Error("s3:GetObject narrowing excess should still be reported")
	}
}

func TestAssessBoundaryIntersectionSuppressesUnreachableExcess(t *testing.T) {
	grant := Grant{ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::secret-bucket/*"}}

	t.Run("withoutBoundary", func(t *testing.T) {
		e := cleanEvidence(testNow)
		e.Declared = PolicyState{Grants: []Grant{grant}, Complete: true}
		a := Assess(e, testNow, testMaxAge)
		if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); !ok {
			t.Fatal("expected s3:GetObject to be flagged excess without a restricting boundary")
		}
	})

	t.Run("withBoundary", func(t *testing.T) {
		e := cleanEvidence(testNow)
		e.Declared = PolicyState{
			Grants:     []Grant{grant},
			Boundaries: [][]Grant{{{ID: "b1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::public-bucket/*"}}}},
			Complete:   true,
		}
		a := Assess(e, testNow, testMaxAge)
		if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); ok {
			t.Fatalf("boundary restricts to a disjoint resource; grant is not effectively allowed, so it must not be flagged excess: %+v", a.DeclaredExcess)
		}
	})
}

// TestAssessNotActionExpandsAgainstCatalog is the R01 counterexample: a
// NotAction-only grant's positive complement spans every AWS service, not
// just the services its own NotAction patterns name. Before the fix this
// complement was computed service-locally (scoped only to "s3", the
// service NotAction mentions), so unused EC2 access from the same grant
// was never surfaced. With a complete, multi-service catalog asserted via
// AWSServiceCatalogComplete, the exact complement must span EC2 too.
func TestAssessNotActionExpandsAgainstCatalog(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		NotActions: []string{"s3:DeleteObject"},
		Resources:  []string{"*"},
	}}, Complete: true}
	e.Definitions = Definitions{
		Actions: []ActionDefinition{
			{Name: "s3:GetObject"}, {Name: "s3:PutObject"}, {Name: "s3:ListBucket"}, {Name: "s3:DeleteObject"},
			{Name: "ec2:TerminateInstances"}, {Name: "ec2:DescribeInstances"},
		},
		Complete:                  true,
		AWSServiceCatalogComplete: true,
	}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:DeleteObject"); ok {
		t.Error("s3:DeleteObject is excluded by NotAction and must never appear")
	}
	if _, ok := findExcess(a.DeclaredExcess, "s3:PutObject"); !ok {
		t.Error("s3:PutObject should be flagged fully excess (included by NotAction complement, never required)")
	}
	if _, ok := findExcess(a.DeclaredExcess, "ec2:TerminateInstances"); !ok {
		t.Error("ec2:TerminateInstances should be flagged fully excess: the NotAction complement spans every service, not just s3")
	}
	if _, ok := findExcess(a.DeclaredExcess, "ec2:DescribeInstances"); !ok {
		t.Error("ec2:DescribeInstances should be flagged fully excess")
	}
	if get, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); !ok || len(get.RequiredResources) != 1 {
		t.Errorf("s3:GetObject should be a narrowing excess, got %+v (found=%v)", get, ok)
	}
	if a.Status != Supported {
		t.Errorf("expected Supported with a complete catalog and complete surfaces, got %v (gaps=%+v)", a.Status, a.Gaps)
	}
}

// TestAssessNotActionWithoutCompleteCatalogStaysIncomplete asserts the
// R01 safety side: without AWSServiceCatalogComplete, a NotAction-only
// (cross-service) grant's exact action surface cannot be computed from
// whatever partial catalog happens to be present — it must never be
// approximated as "just the services mentioned" (that's the original bug)
// NOR fabricated as "every known service" from an unverified partial
// catalog. It stays an explicit unknown_action_surface gap, never Clear.
func TestAssessNotActionWithoutCompleteCatalogStaysIncomplete(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		NotActions: []string{"s3:DeleteObject"},
		Resources:  []string{"*"},
	}}, Complete: true}
	e.Definitions = s3Definitions() // AWSServiceCatalogComplete left false

	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("expected no excess asserted from an unresolvable cross-service complement, got %+v", a.DeclaredExcess)
	}
	if !hasGapCode(a.Gaps, gapUnknownActionSurface) {
		t.Errorf("expected an unknown_action_surface gap, got %+v", a.Gaps)
	}
	if a.Status == Clear {
		t.Error("an unresolved cross-service action surface must never close out as Clear")
	}
}

func TestAssessConditionExcludesOnlyKnownConsumer(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"},
		Conditions: []Condition{{Operator: "StringEquals", Key: "aws:RequestTag/env", Values: []string{"prod"}}},
	}}, Complete: true}
	e.Investigations[0].Requirements[0].Conditions = []Condition{{Operator: "StringEquals", Key: "aws:RequestTag/env", Values: []string{"staging"}}}

	a := Assess(e, testNow, testMaxAge)
	get, ok := findExcess(a.DeclaredExcess, "s3:GetObject")
	if !ok {
		t.Fatal("expected s3:GetObject to be flagged excess: the only known consumer's condition contradicts the grant's")
	}
	if get.Reason == "" {
		t.Error("expected a Reason explaining the condition mismatch")
	}
}

func TestAssessConditionMatchesKnownConsumerIsNarrowingNotFullExcess(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"},
		Conditions: []Condition{{Operator: "StringEquals", Key: "aws:RequestTag/env", Values: []string{"prod"}}},
	}}, Complete: true}
	e.Investigations[0].Requirements[0].Conditions = []Condition{{Operator: "StringEquals", Key: "aws:RequestTag/env", Values: []string{"prod"}}}

	a := Assess(e, testNow, testMaxAge)
	get, ok := findExcess(a.DeclaredExcess, "s3:GetObject")
	if !ok || len(get.RequiredResources) == 0 {
		t.Fatalf("expected a narrowing excess (matching condition, narrower resource), got %+v (found=%v)", get, ok)
	}
}

func TestAssessUnsupportedConditionOperatorNeverFabricatesExcess(t *testing.T) {
	e := cleanEvidence(testNow) // grant resource already exactly matches the requirement
	e.Declared.Grants[0].Conditions = []Condition{{Operator: "IpAddress", Key: "aws:SourceIp", Values: []string{"10.0.0.0/8"}}}

	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("an unsupported condition operator must never fabricate excess from ambiguity, got %+v", a.DeclaredExcess)
	}
}

func TestAssessMissingRoleDefinitionIsIncompleteNotClear(t *testing.T) {
	e := cleanEvidence(testNow)
	grant := Grant{ID: "g1", Effect: "Allow", Role: "arn:aws:iam::aws:policy/Unknown"}
	e.Declared = PolicyState{Grants: []Grant{grant}, Complete: true}
	e.Observed = PolicyState{Grants: []Grant{grant}, Complete: true}

	a := Assess(e, testNow, testMaxAge)
	if a.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete when a role/policy definition cannot be resolved", a.Status)
	}
	if !hasGapCode(a.Gaps, "cloudidentity.missing_role_definition") {
		t.Errorf("expected missing_role_definition gap, got %+v", a.Gaps)
	}
	if len(a.DeclaredExcess) != 0 || len(a.ObservedExcess) != 0 {
		t.Error("an unresolved role must never be asserted as excess")
	}
}

func TestAssessGCPMissingRoleDefinitionIsIncomplete(t *testing.T) {
	grant := Grant{ID: "g1", Effect: "Allow", Role: "roles/unknown.custom", Resources: []string{"projects/proj1/buckets/b1"}}
	e := Evidence{
		Principal:                 Principal{ID: "gsa-a", Provider: GCP},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Definitions:               Definitions{Complete: true}, // no matching role catalog entry
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{Provider: GCP, Action: "storage.objects.get", Resources: []string{"projects/proj1/buckets/b1"}, ConsumerIDs: []string{"w1"}}},
			Validation:   validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete when a GCP role definition cannot be resolved", a.Status)
	}
	if !hasGapCode(a.Gaps, "cloudidentity.missing_role_definition") {
		t.Errorf("expected missing_role_definition gap, got %+v", a.Gaps)
	}
}

func TestAssessGCPRoleExpansionFlagsUnusedPermission(t *testing.T) {
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP, Kind: "gcp_service_account"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Role: "roles/storage.objectViewer",
			Resources: []string{"projects/proj1/buckets/b1"},
		}}, Complete: true},
		Observed: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Role: "roles/storage.objectViewer",
			Resources: []string{"projects/proj1/buckets/b1"},
		}}, Complete: true},
		Definitions: Definitions{
			Roles:    []RoleDefinition{{Name: "roles/storage.objectViewer", Permissions: []string{"storage.objects.get", "storage.objects.list"}}},
			Complete: true,
		},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Service: "storage", Action: "storage.objects.get",
				Resources: []string{"projects/proj1/buckets/b1"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.list"); !ok {
		t.Errorf("expected storage.objects.list flagged fully excess, got %+v", a.DeclaredExcess)
	}
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.get"); ok {
		t.Errorf("storage.objects.get is required at the exact granted resource and must not be flagged, got %+v", a.DeclaredExcess)
	}
	if a.Status != Supported {
		t.Fatalf("Status = %v, want Supported; gaps=%+v", a.Status, a.Gaps)
	}
}

func TestAssessUnionOfConsumerRequirements(t *testing.T) {
	grant := Grant{
		ID: "g1", Effect: "Allow",
		Actions: []string{"s3:GetObject", "s3:PutObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
	}
	base := func() Evidence {
		return Evidence{
			Schema:                    SchemaVersion,
			Principal:                 Principal{ID: "role-a", Provider: AWS},
			Consumers:                 []Workload{baseConsumer(), {ID: "w2", Service: "billing", Name: "billing-1", Namespace: "ns1", ServiceAccount: "sa2", Source: exactPin()}},
			ConsumerInventoryComplete: true,
			Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
			Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
			Definitions:               s3Definitions(),
			CollectedAt:               testNow,
		}
	}
	investigationA := Investigation{
		ConsumerID: "w1", Source: exactPin(),
		Requirements: []Requirement{{Provider: AWS, Action: "s3:GetObject", Resources: []string{"arn:aws:s3:::bucket/obj1"}, ConsumerIDs: []string{"w1"}}},
		Validation:   validInvestigationValidation(),
	}
	investigationB := Investigation{
		ConsumerID: "w2", Source: exactPin(),
		Requirements: []Requirement{{Provider: AWS, Action: "s3:PutObject", Resources: []string{"arn:aws:s3:::bucket/obj1"}, ConsumerIDs: []string{"w2"}}},
		Validation:   validInvestigationValidation(),
	}

	t.Run("onlyOneConsumerKnown", func(t *testing.T) {
		e := base()
		e.Investigations = []Investigation{investigationA}
		a := Assess(e, testNow, testMaxAge)
		if _, ok := findExcess(a.DeclaredExcess, "s3:PutObject"); !ok {
			t.Error("s3:PutObject should look excess when only consumer w1's requirements are known")
		}
	})

	t.Run("unionOfBothConsumers", func(t *testing.T) {
		e := base()
		e.Investigations = []Investigation{investigationA, investigationB}
		a := Assess(e, testNow, testMaxAge)
		if len(a.DeclaredExcess) != 0 {
			t.Errorf("neither action should be excess once both consumers' requirements are unioned, got %+v", a.DeclaredExcess)
		}
	})
}

func TestAssessMaxAgeBoundary(t *testing.T) {
	t.Run("exactlyAtBoundaryIsFresh", func(t *testing.T) {
		e := cleanEvidence(testNow.Add(-testMaxAge))
		a := Assess(e, testNow, testMaxAge)
		if a.Status != Clear {
			t.Fatalf("Status = %v, want Clear at exactly the maxAge boundary; gaps=%+v", a.Status, a.Gaps)
		}
	})
	t.Run("justOverBoundaryIsStale", func(t *testing.T) {
		e := cleanEvidence(testNow.Add(-testMaxAge - time.Nanosecond))
		a := Assess(e, testNow, testMaxAge)
		if a.Status == Clear {
			t.Fatalf("Status = %v, evidence 1ns past maxAge must not be treated as fresh", a.Status)
		}
		if !hasGapCode(a.Gaps, "cloudidentity.stale_evidence") {
			t.Errorf("expected stale_evidence gap, got %+v", a.Gaps)
		}
	})
}

func TestAssessInexactSourcePinBlocksSupported(t *testing.T) {
	e := excessEvidence(testNow)
	e.Consumers[0].Source.Exact = false
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Candidate {
		t.Fatalf("Status = %v, want Candidate when a consumer source pin is not exact", a.Status)
	}
	if a.Side != "both" {
		t.Errorf("Side should still be reported (%q) even though promotion is gated", a.Side)
	}
	if !hasGapCode(a.Gaps, "cloudidentity.inexact_source_pin") {
		t.Errorf("expected inexact_source_pin gap, got %+v", a.Gaps)
	}
}

func TestAssessUnvalidatedInvestigationBlocksSupported(t *testing.T) {
	e := excessEvidence(testNow)
	e.Investigations[0].Validation.CitationsVerified = false
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Candidate {
		t.Fatalf("Status = %v, want Candidate when citations are not independently verified", a.Status)
	}
}

func TestAssessIncompleteConsumerInventory(t *testing.T) {
	t.Run("withExcessBecomesCandidate", func(t *testing.T) {
		e := excessEvidence(testNow)
		e.ConsumerInventoryComplete = false
		a := Assess(e, testNow, testMaxAge)
		if a.Status != Candidate {
			t.Fatalf("Status = %v, want Candidate", a.Status)
		}
	})
	t.Run("withoutExcessBecomesIncomplete", func(t *testing.T) {
		e := cleanEvidence(testNow)
		e.ConsumerInventoryComplete = false
		a := Assess(e, testNow, testMaxAge)
		if a.Status != Incomplete {
			t.Fatalf("Status = %v, want Incomplete (cannot prove Clear on an unconfirmed inventory)", a.Status)
		}
	})
}

func TestAssessNoDuplicateExcessFromOverlappingPatterns(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions:   []string{"s3:PutObject"},
		Resources: []string{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/*"},
	}}, Complete: true}

	a := Assess(e, testNow, testMaxAge)
	count := 0
	for _, it := range a.DeclaredExcess {
		if it.Action == "s3:PutObject" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 deduplicated excess entry for s3:PutObject, got %d: %+v", count, a.DeclaredExcess)
	}
}

func TestAssessDriftFalseWhenGrantsSemanticallyIdentical(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Observed.Grants[0].ID = "a-totally-different-id"
	e.Observed.Grants[0].References = []Reference{{Digest: "different", ObservedAt: testNow}}
	a := Assess(e, testNow, testMaxAge)
	if a.Drift {
		t.Error("Drift must be false: only ID/References differ, not semantic content")
	}
}

func TestAssessDriftTrueWhenGrantsDiffer(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Observed.Grants[0].Actions = []string{"s3:GetObject", "s3:DeleteObject"}
	a := Assess(e, testNow, testMaxAge)
	if !a.Drift {
		t.Error("Drift must be true: observed grants a materially different action set")
	}
}

func TestAssessTrustCoverageBlocksClearOnBroadFederatedPrincipal(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared.Trust = []Grant{{
		ID: "trust1", Effect: "Allow",
		Members:    []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Conditions: []Condition{{Operator: "StringLike", Key: "oidc.eks.example.com/id/EX:sub", Values: []string{"system:serviceaccount:ns1:*"}}},
	}}
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("a wildcard trust subject pattern must block Clear: unseen consumers could match it")
	}
	if !hasGapCode(a.Gaps, "cloudidentity.unresolved_trust_consumer") {
		t.Errorf("expected unresolved_trust_consumer gap, got %+v", a.Gaps)
	}
}

func TestAssessTrustCoverageExactMatchAllowsClear(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared.Trust = []Grant{{
		ID: "trust1", Effect: "Allow",
		Members:    []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX"},
		Conditions: []Condition{{Operator: "StringEquals", Key: "oidc.eks.example.com/id/EX:sub", Values: []string{"system:serviceaccount:ns1:sa1"}}},
	}}
	e.ResolvedIdentifiers = map[string]string{
		"aws_eks_oidc_provider_arn:cluster1": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX",
	}
	a := Assess(e, testNow, testMaxAge)
	if a.Status != Clear {
		t.Fatalf("Status = %v, want Clear: trust is exactly scoped to the known reviewed consumer; gaps=%+v", a.Status, a.Gaps)
	}
}

func TestAssessTrustCoverageWrongClusterIsFlagged(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared.Trust = []Grant{{
		ID: "trust1", Effect: "Allow",
		Members:    []string{"Federated:arn:aws:iam::111111111111:oidc-provider/oidc.eks.OTHER.example.com/id/EX"},
		Conditions: []Condition{{Operator: "StringEquals", Key: "oidc.eks.OTHER.example.com/id/EX:sub", Values: []string{"system:serviceaccount:ns1:sa1"}}},
	}}
	e.ResolvedIdentifiers = map[string]string{
		"aws_eks_oidc_provider_arn:cluster1": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.example.com/id/EX",
	}
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatal("a subject match whose OIDC provider does not match the consumer's resolved cluster issuer must not be trusted")
	}
}

func TestAssessMalformedRequirementResourceNeverFabricatesExcessOrNarrowing(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"},
	}}, Complete: true}
	// A less careful extractor emitted a raw field name instead of a
	// canonical ARN.
	e.Investigations[0].Requirements[0].Resources = []string{"bucket"}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); ok {
		t.Errorf("a malformed/non-canonical requirement resource must never fabricate excess (it conservatively covers), got %+v", a.DeclaredExcess)
	}
}

func TestAssessMalformedResourceDoesNotBlockOtherActionsExcess(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions:   []string{"s3:GetObject", "s3:DeleteObject"},
		Resources: []string{"arn:aws:s3:::bucket/*"},
	}}, Complete: true}
	e.Investigations[0].Requirements[0].Resources = []string{"bucket"} // malformed, for GetObject

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); ok {
		t.Errorf("malformed resource on the GetObject requirement must not itself be flagged excess, got %+v", a.DeclaredExcess)
	}
	if _, ok := findExcess(a.DeclaredExcess, "s3:DeleteObject"); !ok {
		t.Error("s3:DeleteObject has no requirement at all and must still be flagged excess independently of the malformed GetObject requirement")
	}
}

func TestAssessExplicitWildcardRequirementResourceCoversGrantedPattern(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"},
	}}, Complete: true}
	e.Investigations[0].Requirements[0].Resources = []string{"*"}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); ok {
		t.Errorf("an explicit wildcard requirement resource is canonical and covers the granted pattern; got %+v", a.DeclaredExcess)
	}
}

// TestAssessGCPProjectAncestorOverlapStillFlagsUnusedActions is the
// explicit regression Main asked for: a project-level GCP role grant whose
// expanded permissions include an action actually used (at a bucket-level
// resource using GCS's "_" project placeholder, which conservatively
// overlaps the project-level grant pattern) alongside actions that are
// never required anywhere. The conservative-overlap fix for ancestry
// ambiguity must not blanket-suppress unused-action detection — only the
// genuinely-covered action should be spared.
func TestAssessGCPProjectAncestorOverlapStillFlagsUnusedActions(t *testing.T) {
	grant := Grant{ID: "g1", Effect: "Allow", Role: "roles/storage.objectAdmin", Resources: []string{"projects/myproj"}}
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Definitions: Definitions{
			Roles: []RoleDefinition{{
				Name:        "roles/storage.objectAdmin",
				Permissions: []string{"storage.objects.delete", "storage.objects.create", "storage.objects.get"},
			}},
			Complete: true,
		},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Action: "storage.objects.delete",
				Resources: []string{"projects/_/buckets/mybucket"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.delete"); ok {
		t.Errorf("storage.objects.delete is used (conservatively covered via project/placeholder ancestry) and must not be flagged, got %+v", a.DeclaredExcess)
	}
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.create"); !ok {
		t.Error("storage.objects.create is never required and must still be flagged excess")
	}
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.get"); !ok {
		t.Error("storage.objects.get is never required and must still be flagged excess")
	}
}

func TestAssessUnresolvedKubernetesPrincipalNeverPromotes(t *testing.T) {
	e := excessEvidence(testNow) // would otherwise be a clean Supported/both case
	e.Principal.ID = "k8s://cluster-a/payments/sa/worker"
	e.Principal.Kind = "aws_kubernetes_service_account"

	a := Assess(e, testNow, testMaxAge)
	if a.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete for an unresolved KSA placeholder principal", a.Status)
	}
	if len(a.DeclaredExcess) != 0 || len(a.ObservedExcess) != 0 {
		t.Error("an unresolved principal must never produce excess findings")
	}
	if !hasGapCode(a.Gaps, "cloudidentity.unresolved_principal") {
		t.Errorf("expected unresolved_principal gap, got %+v", a.Gaps)
	}
}

func TestAssessSharingUnresolvedKubernetesPrincipalNeverPromotes(t *testing.T) {
	e := Evidence{
		Principal: Principal{ID: "k8s://cluster-a/payments/sa/worker", Kind: "aws_kubernetes_service_account"},
		Consumers: []Workload{
			consumerWorkload("w1", "checkout", "checkout-1"),
			consumerWorkload("w2", "billing", "billing-1"),
		},
		ConsumerInventoryComplete: true,
	}
	s := AssessSharing(e)
	if s.Status != Incomplete {
		t.Fatalf("Status = %v, want Incomplete: principal is an unresolved placeholder even though >=2 distinct services are present", s.Status)
	}
	if !hasGapCode(s.Gaps, "cloudidentity.unresolved_principal") {
		t.Errorf("expected unresolved_principal gap, got %+v", s.Gaps)
	}
}

func TestAssessSharingGCPCanonicalResolvedPrincipalIsValid(t *testing.T) {
	e := Evidence{
		Principal: Principal{
			ID:       "principal://iam.googleapis.com/projects/111111111111/locations/global/workloadIdentityPools/example-project.svc.id.goog/subject/ns/apps/sa/default",
			Provider: GCP,
			Kind:     "gcp_workload_identity_principal",
		},
		Consumers: []Workload{
			{ID: "w1", Service: "checkout", Name: "checkout-1", Namespace: "apps", ServiceAccount: "default", Kind: "Deployment"},
			{ID: "w2", Service: "billing", Name: "billing-1", Namespace: "apps", ServiceAccount: "default", Kind: "Deployment"},
		},
		ConsumerInventoryComplete: true,
	}
	s := AssessSharing(e)
	if s.Status != Supported {
		t.Fatalf("Status = %v, want Supported: a resolved canonical GCP principal:// ID is a valid cloud principal; gaps=%+v", s.Status, s.Gaps)
	}
}

func TestIncompleteOppositePolicyDoesNotSuppressProvenExcess(t *testing.T) {
	for _, incomplete := range []string{"iac", "live"} {
		t.Run(incomplete, func(t *testing.T) {
			e := excessEvidence(testNow)
			want := "live"
			if incomplete == "iac" {
				e.Declared.Complete = false
			} else {
				e.Observed.Complete = false
				want = "iac"
			}
			got := Assess(e, testNow, testMaxAge)
			if got.Status != Supported || got.Side != want {
				t.Fatalf("complete side lost proven excess: %#v", got)
			}
			if incomplete == "iac" && len(got.DeclaredExcess) != 0 {
				t.Fatal("unproven IaC excess was promoted with live evidence")
			}
			if incomplete == "live" && len(got.ObservedExcess) != 0 {
				t.Fatal("unproven live excess was promoted with IaC evidence")
			}
		})
	}
}

// TestAssessGCPLiveBindingWithMembersStillEvaluatesExcess mirrors the Grant
// shape gcpGrantFromBinding emits for a live observed binding (Role +
// Resources + the matched Members for this principal). Members must never
// cause a permission grant to be skipped as if it were a trust statement.
func TestAssessGCPLiveBindingWithMembersStillEvaluatesExcess(t *testing.T) {
	liveGrant := Grant{
		ID:     "//storage.googleapis.com/projects/_/buckets/mybucket#roles/storage.objectAdmin#0",
		Effect: "Allow", Role: "roles/storage.objectAdmin",
		Resources: []string{"//storage.googleapis.com/projects/_/buckets/mybucket"},
		Members:   []string{"serviceAccount:gsa-a@proj.iam.gserviceaccount.com"},
	}
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP, Kind: "gcp_service_account"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Complete: true},
		Observed:                  PolicyState{Grants: []Grant{liveGrant}, Complete: true},
		Definitions: Definitions{
			Roles:    []RoleDefinition{{Name: "roles/storage.objectAdmin", Permissions: []string{"storage.objects.get", "storage.objects.delete"}}},
			Complete: true,
		},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Action: "storage.objects.get",
				Resources: []string{"//storage.googleapis.com/projects/_/buckets/mybucket"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.ObservedExcess, "storage.objects.delete"); !ok {
		t.Fatalf("expected storage.objects.delete flagged as live excess despite the grant carrying Members, got %+v (status=%v gaps=%+v)", a.ObservedExcess, a.Status, a.Gaps)
	}
	if a.Status != Supported || a.Side != "live" {
		t.Fatalf("Status=%v Side=%v, want Supported/live; gaps=%+v", a.Status, a.Side, a.Gaps)
	}
}

// TestAssessAWSNotResourceOnlyAllowIsNotClear covers a valid Allow with
// NotResource but no Resource: its positive resource complement cannot be
// enumerated, so it must never silently evaluate to zero patterns and Clear.
func TestAssessAWSNotResourceOnlyAllowIsNotClear(t *testing.T) {
	grant := Grant{ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, NotResources: []string{"arn:aws:s3:::excluded/*"}}
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "role-a", Provider: AWS, Kind: "aws_iam_role"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Observed:                  PolicyState{Grants: []Grant{grant}, Complete: true},
		Definitions:               s3Definitions(),
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(), Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatalf("a NotResource-only allow's positive resource complement cannot be enumerated and must never resolve to Clear, got %+v", a)
	}
	if !hasGapCode(a.Gaps, gapUnresolvedResourceComplement) {
		t.Errorf("expected unresolved_resource_complement gap, got %+v", a.Gaps)
	}
}

// TestAssessNarrowDenyDoesNotFullySuppressAllow covers Allow bucket/* + Deny
// bucket/private/*: the narrower deny only removes part of the allow's
// surface and must never be treated as eliminating it entirely.
func TestAssessNarrowDenyDoesNotFullySuppressAllow(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{
		{ID: "allow1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}},
		{ID: "deny1", Effect: "Deny", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/private/*"}},
	}, Complete: true}
	e.Observed = e.Declared
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatalf("a narrower-resource Deny does not eliminate the full Allow surface; must never resolve to Clear, got %+v", a)
	}
}

// TestAssessConditionalDenyDoesNotFullySuppressAllow covers an unconditional
// Allow plus a conditional Deny on the same resource: the condition means
// non-matching requests remain allowed, so full suppression is never proven.
func TestAssessConditionalDenyDoesNotFullySuppressAllow(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{
		{ID: "allow1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"}},
		{
			ID: "deny1", Effect: "Deny", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
			Conditions: []Condition{{Operator: "StringEquals", Key: "aws:PrincipalTag/env", Values: []string{"prod"}}},
		},
	}, Complete: true}
	e.Observed = e.Declared
	a := Assess(e, testNow, testMaxAge)
	if a.Status == Clear {
		t.Fatalf("a conditional Deny only removes matching requests; must never resolve to Clear, got %+v", a)
	}
}

// TestAssessBoundaryConditionContradictionBlocksEffectiveAccess covers an
// identity Allow conditioned on env=prod intersected with a boundary Allow
// conditioned on env=staging: the contradictory conjunction can never be
// satisfied by a single request, so no Supported excess may be asserted.
func TestAssessBoundaryConditionContradictionBlocksEffectiveAccess(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{
		Grants: []Grant{{
			ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
			Conditions: []Condition{{Operator: "StringEquals", Key: "aws:PrincipalTag/env", Values: []string{"prod"}}},
		}},
		Boundaries: [][]Grant{{{
			ID: "b1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
			Conditions: []Condition{{Operator: "StringEquals", Key: "aws:PrincipalTag/env", Values: []string{"staging"}}},
		}}},
		Complete: true,
	}
	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Fatalf("contradictory identity/boundary conditions make the grant never effectively allowed; must not report Supported excess, got %+v", a.DeclaredExcess)
	}
}

// TestAssessBoundaryExactObjectSuppressesNarrowingExcess is the R10(a)
// counterexample: a broad S3 identity grant (bucket/*) intersected by a
// boundary that allows exactly the one required object must not produce a
// "narrow this down" recommendation — the boundary has already narrowed
// effective access to exactly that object, so there is nothing left to
// narrow. Before the fix, narrowing/excess was evaluated against the raw,
// still-wildcarded identity pattern, producing a false narrowing Excess.
func TestAssessBoundaryExactObjectSuppressesNarrowingExcess(t *testing.T) {
	e := cleanEvidence(testNow) // requires s3:GetObject on arn:aws:s3:::bucket/obj1
	e.Declared = PolicyState{
		Grants: []Grant{{ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*"}}},
		Boundaries: [][]Grant{{{
			ID: "b1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"},
		}}},
		Complete: true,
	}

	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "s3:GetObject"); ok {
		t.Errorf("boundary already narrows effective access to exactly the required object; no narrowing excess should be reported, got %+v", a.DeclaredExcess)
	}
}

// TestAssessBoundaryPartialOverlapIsUncertainNotGuessed covers the
// unprovable side of R10(a): a boundary resource that overlaps the running
// identity pattern but neither contains nor is contained by it (two
// different single-trailing-wildcard patterns) cannot be reduced to one
// effective pattern. cloudidentity must surface this as an incomplete gap,
// never guess a narrower or wider effective resource.
func TestAssessBoundaryPartialOverlapIsUncertainNotGuessed(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{
		Grants: []Grant{{ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/a*"}}},
		Boundaries: [][]Grant{{{
			ID: "b1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/*1"},
		}}},
		Complete: true,
	}
	e.Investigations[0].Requirements[0].Resources = []string{"arn:aws:s3:::bucket/a1"}

	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("an unprovable boundary intersection must never be guessed into an excess finding, got %+v", a.DeclaredExcess)
	}
	if !hasGapCode(a.Gaps, gapUnresolvedEffectiveResource) {
		t.Errorf("expected an unresolved_effective_resource gap, got %+v", a.Gaps)
	}
	if a.Status == Clear {
		t.Error("an unresolved boundary intersection must never close out as Clear")
	}
}

// TestAssessGCPCELFalseConditionIsInertNoExcessNoGap is the R10(b)
// counterexample: a GCP Allow bound with a literal CEL `false` condition
// never actually applies (inert), so it must never be flagged as an unused
// permission (which would be real excess) — and since the binding is
// definitively inert, not merely unresolved, it raises no gap either.
func TestAssessGCPCELFalseConditionIsInertNoExcessNoGap(t *testing.T) {
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP, Kind: "gcp_service_account"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Actions: []string{"storage.objects.get"},
			Resources:  []string{"projects/proj1/buckets/b1"},
			Conditions: []Condition{{Expression: "false"}},
		}}, Complete: true},
		Observed:    PolicyState{Complete: true},
		Definitions: Definitions{Complete: true},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Service: "storage", Action: "storage.objects.list",
				Resources: []string{"projects/proj1/buckets/b1"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("a CEL-false binding never applies; it must never be flagged excess, got %+v", a.DeclaredExcess)
	}
	if hasGapCode(a.Gaps, gapUnknownGrantCondition) {
		t.Errorf("a CEL literal false is inert, not unknown; it must not raise a condition gap, got %+v", a.Gaps)
	}
}

// TestAssessAWSPrincipalBoundConditionIsUnknownNotExcess covers the other
// half of binding semantic 2: a condition on a principal-bound key (here
// aws:PrincipalTag/*) is never provably satisfiable or unsatisfiable from
// the request side alone, so the grant's applicability is unknown — no
// excess may be asserted from it, and the result must never be Clear.
func TestAssessAWSPrincipalBoundConditionIsUnknownNotExcess(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared.Grants[0].Conditions = []Condition{{Operator: "StringEquals", Key: "aws:PrincipalTag/env", Values: []string{"prod"}}}

	a := Assess(e, testNow, testMaxAge)
	if len(a.DeclaredExcess) != 0 {
		t.Errorf("a principal-bound condition's applicability is unknown; it must never fabricate excess, got %+v", a.DeclaredExcess)
	}
	if !hasGapCode(a.Gaps, gapUnknownGrantCondition) {
		t.Errorf("expected an unknown_grant_condition gap for a principal-bound key, got %+v", a.Gaps)
	}
	if a.Status == Clear {
		t.Error("an unresolved grant condition must never close out as Clear")
	}
}

// TestAssessGCPProjectIDNumberAliasKnownMappingSuppressesFalseExcess is the
// R10(c) counterexample: a project-ID grant and a numeric-project
// requirement for the SAME project (a known ResolvedIdentifiers
// "gcp_project_number:<id>" mapping) were treated as disjoint literal
// strings and produced a false excess finding.
func TestAssessGCPProjectIDNumberAliasKnownMappingSuppressesFalseExcess(t *testing.T) {
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP, Kind: "gcp_service_account"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Actions: []string{"storage.objects.get"},
			Resources: []string{"projects/example-project/buckets/b1"},
		}}, Complete: true},
		Observed:            PolicyState{Complete: true},
		Definitions:         Definitions{Complete: true},
		ResolvedIdentifiers: map[string]string{"gcp_project_number:example-project": "123456789012"},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Service: "storage", Action: "storage.objects.get",
				Resources: []string{"projects/123456789012/buckets/b1"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if _, ok := findExcess(a.DeclaredExcess, "storage.objects.get"); ok {
		t.Errorf("project-ID grant and numeric-project requirement for the SAME project (known mapping) must overlap, not be flagged excess, got %+v", a.DeclaredExcess)
	}
}

// TestAssessGCPKnownInactiveRoleIsInertAndAllowsClear is the R11
// counterexample: a resolved GCP role with zero Permissions (a
// disabled/deleted custom role) was expanded into a Grant with empty
// Actions, which concreteActionsForGrant then treated as an unknown action
// surface — a gap that blocked Clear forever even though the role is
// confirmed inactive, not unresolved.
func TestAssessGCPKnownInactiveRoleIsInertAndAllowsClear(t *testing.T) {
	e := Evidence{
		Schema:                    SchemaVersion,
		Principal:                 Principal{ID: "gsa-a", Provider: GCP, Kind: "gcp_service_account"},
		Consumers:                 []Workload{baseConsumer()},
		ConsumerInventoryComplete: true,
		Declared: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Role: "roles/disabled.custom",
			Resources: []string{"projects/proj1/buckets/b1"},
		}}, Complete: true},
		Observed: PolicyState{Grants: []Grant{{
			ID: "g1", Effect: "Allow", Role: "roles/disabled.custom",
			Resources: []string{"projects/proj1/buckets/b1"},
		}}, Complete: true},
		Definitions: Definitions{
			Roles:    []RoleDefinition{{Name: "roles/disabled.custom", Permissions: nil}},
			Complete: true,
		},
		Investigations: []Investigation{{
			ConsumerID: "w1", Source: exactPin(),
			Requirements: []Requirement{{
				Provider: GCP, Service: "storage", Action: "storage.objects.get",
				Resources: []string{"projects/proj1/buckets/b1"}, ConsumerIDs: []string{"w1"},
			}},
			Validation: validInvestigationValidation(),
		}},
		CollectedAt: testNow,
	}
	a := Assess(e, testNow, testMaxAge)
	if hasGapCode(a.Gaps, "cloudidentity.missing_role_definition") {
		t.Errorf("a known (if empty) role must not be treated as a missing definition, got %+v", a.Gaps)
	}
	if hasGapCode(a.Gaps, gapUnknownActionSurface) {
		t.Errorf("a known-empty role must expand to no grant, never an unknown-action-surface gap, got %+v", a.Gaps)
	}
	if len(a.DeclaredExcess) != 0 || len(a.ObservedExcess) != 0 {
		t.Errorf("an inert (empty-permission) role grants nothing, so it can never itself be excess, got declared=%+v observed=%+v", a.DeclaredExcess, a.ObservedExcess)
	}
	if a.Status != Clear {
		t.Fatalf("Status = %v, want Clear: a known-empty role is inert, not an unresolved gap; gaps=%+v", a.Status, a.Gaps)
	}
}

// TestAssessDriftSuppressedWhenLiveSideIncomplete is the R17
// counterexample: complete IaC excess plus an absent/incomplete live side
// returned side=iac, drift=true. Drift is only ever asserted between two
// KNOWN (PolicyState.Complete) sides; an absent/incomplete side can neither
// open nor close a drift finding.
func TestAssessDriftSuppressedWhenLiveSideIncomplete(t *testing.T) {
	e := excessEvidence(testNow) // declared+observed both carry an s3:PutObject excess
	e.Observed = PolicyState{Complete: false}

	a := Assess(e, testNow, testMaxAge)
	if a.Drift {
		t.Errorf("an absent/incomplete live side must never be reported as drift against a complete IaC side, got drift=%v side=%q", a.Drift, a.Side)
	}
	if a.Side != "iac" {
		t.Errorf("expected side=iac (declared excess, unknown observed side), got %q", a.Side)
	}
}

// TestAssessDriftGenuineCompleteEmptyVsCompleteNonempty is the R17
// control: Complete alone never suppresses a real difference — when BOTH
// sides are confirmed complete, a complete-empty side next to a
// complete-nonempty side is still genuine drift.
func TestAssessDriftGenuineCompleteEmptyVsCompleteNonempty(t *testing.T) {
	e := cleanEvidence(testNow)
	e.Declared = PolicyState{Grants: []Grant{{ID: "g1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"arn:aws:s3:::bucket/obj1"}}}, Complete: true}
	e.Observed = PolicyState{Complete: true}

	a := Assess(e, testNow, testMaxAge)
	if !a.Drift {
		t.Error("a confirmed-complete empty live side next to a confirmed-complete nonempty declared side is genuine drift")
	}
}

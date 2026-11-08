package cloudidentity

import (
	"context"
	"errors"
	"testing"
	"time"
)

// inputAssertionScopeFailingRepositoryReader fails ReadRepository only for
// the one pin matching failRepository, succeeding (with no materialized
// files) for every other pin -- so every manifest repository still reads
// normally while one target's own input_assertion source repository is
// unreadable.
type inputAssertionScopeFailingRepositoryReader struct {
	failRepository string
}

func (r inputAssertionScopeFailingRepositoryReader) ReadRepository(_ context.Context, pin SourcePin) (Repository, error) {
	if pin.Repository == r.failRepository {
		return Repository{}, errors.New("repository temporarily unavailable")
	}
	return Repository{Pin: pin}, nil
}

// inputAssertionScopeTargets builds two AWS targets in different accounts
// and clusters, each hosting its own distinct IRSA-role workload with no
// relationship to the other target's cluster/account -- so a gap confined
// to target A's own input_assertions/known_gaps can only ever demote
// target A's own cohort if the scoping machinery is working, never
// target B's.
func inputAssertionScopeTargets() (ScanTarget, ScanTarget, map[string][]Manifest) {
	depA := deploymentManifest("api-a", "team-a", "sa-a",
		[]map[string]any{{"name": "app", "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/api-a:v1"}}, nil)
	saA := serviceAccountManifest("sa-a", "team-a", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::111111111111:role/api-a-role",
	})
	depB := deploymentManifest("api-b", "team-b", "sa-b",
		[]map[string]any{{"name": "app", "image": "222222222222.dkr.ecr.us-east-1.amazonaws.com/api-b:v1"}}, nil)
	saB := serviceAccountManifest("sa-b", "team-b", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::222222222222:role/api-b-role",
	})
	targetA := ScanTarget{Name: "target-a", Environment: "prod", Cluster: "cluster-a", Provider: AWS, Account: "111111111111", Region: "us-east-1",
		Manifests: []ManifestInput{collectionTestManifestInput("a")}}
	targetB := ScanTarget{Name: "target-b", Environment: "prod", Cluster: "cluster-b", Provider: AWS, Account: "222222222222", Region: "us-east-1",
		Manifests: []ManifestInput{collectionTestManifestInput("b")}}
	render := map[string][]Manifest{"a": {depA, saA}, "b": {depB, saB}}
	return targetA, targetB, render
}

func inputAssertionScopePlan(targetA, targetB ScanTarget) ScanPlan {
	return ScanPlan{
		Scope:   "org:example-org",
		Targets: []ScanTarget{targetA, targetB},
		Services: []ServiceMapping{
			{Service: "api-a", ImagePrefixes: []string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/api-a"}, Repository: "github.com/example/api-a"},
			{Service: "api-b", ImagePrefixes: []string{"222222222222.dkr.ecr.us-east-1.amazonaws.com/api-b"}, Repository: "github.com/example/api-b"},
		},
	}
}

// TestCollectTargetInputAssertionFailureDemotesOnlyRelatedTargetCohorts
// covers invariant (a): a failing target-level input_assertion demotes
// Collection.InventoryComplete and the ConsumerInventoryComplete of
// cohorts related to the declaring target only -- an unrelated target in
// a different account/cluster, with no trust relationship to the first,
// stays fully complete.
func TestCollectTargetInputAssertionFailureDemotesOnlyRelatedTargetCohorts(t *testing.T) {
	targetA, targetB, render := inputAssertionScopeTargets()
	// fakeRepositoryReader materializes no files for any pin, so a
	// file_digest assertion against any path is guaranteed to fail with
	// "not found among the pinned repository's materialized files".
	targetA.InputAssertions = []InputAssertion{{
		Source: SourcePin{Repository: "github.com/example/infra", Revision: "main"},
		Path:   "modules/role/main.tf",
		Kind:   "file_digest",
		Digest: "0000000000000000000000000000000000000000000000000000000000000000",
	}}
	plan := inputAssertionScopePlan(targetA, targetB)
	ports := collectionTestPorts(render)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, InputAssertionFailedGapCode) {
		t.Fatalf("expected an %s gap, got %+v", InputAssertionFailedGapCode, result.Gaps)
	}
	if result.InventoryComplete {
		t.Fatalf("Collection.InventoryComplete must be false: a failing target input_assertion was produced")
	}
	related := collectionFindEvidence(t, result, "api-a")
	if related.ConsumerInventoryComplete {
		t.Fatalf("the declaring target's own cohort must be demoted by its failed input_assertion: %+v", related)
	}
	if !hasGapCode(related.Gaps, "target_inventory_incomplete") {
		t.Fatalf("expected target_inventory_incomplete on the related cohort, got %+v", related.Gaps)
	}
	unrelated := collectionFindEvidence(t, result, "api-b")
	if !unrelated.ConsumerInventoryComplete {
		t.Fatalf("an unrelated target in a different account/cluster must stay complete: %+v", unrelated)
	}
}

// TestCollectTargetInputAssertionUnreadableRepositoryIsFailure covers
// invariant (c): when the assertion's own pinned repository cannot be
// read at all, that is itself an assertion failure (never silently
// skipped), reported with the same gap code and target scope as a
// verified-but-failing assertion.
func TestCollectTargetInputAssertionUnreadableRepositoryIsFailure(t *testing.T) {
	targetA, targetB, render := inputAssertionScopeTargets()
	const unreadableRepository = "github.com/example/unreadable-infra"
	targetA.InputAssertions = []InputAssertion{{
		Source: SourcePin{Repository: unreadableRepository, Revision: "main"},
		Path:   "modules/role/main.tf",
		Kind:   "file_digest",
		Digest: "0000000000000000000000000000000000000000000000000000000000000000",
	}}
	plan := inputAssertionScopePlan(targetA, targetB)
	ports := collectionTestPorts(render)
	ports.Repositories = inputAssertionScopeFailingRepositoryReader{failRepository: unreadableRepository}

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, InputAssertionFailedGapCode) {
		t.Fatalf("expected an %s gap when the assertion's own repository could not be read, got %+v", InputAssertionFailedGapCode, result.Gaps)
	}
	related := collectionFindEvidence(t, result, "api-a")
	if related.ConsumerInventoryComplete {
		t.Fatalf("an unreadable assertion repository must demote the declaring target's own cohort: %+v", related)
	}
}

// TestCollectTargetKnownGapDemotesLikeTargetGapRegardlessOfSuppliedCode
// covers invariant (d): a target's own known_gaps entry becomes a
// cloud_identity.plan_known_gap inventory gap, which is target-scoped
// regardless of what code the plan generator supplied -- even a supplied
// code that happens to match an actual workload-scoped gap code must
// still demote the declaring target's own cohort, because the supplied
// code is never used for scoping.
func TestCollectTargetKnownGapDemotesLikeTargetGapRegardlessOfSuppliedCode(t *testing.T) {
	targetA, targetB, render := inputAssertionScopeTargets()
	targetA.KnownGaps = []KnownGap{{
		// This code is a real workload-scoped gap code elsewhere in this
		// package; it must still produce target-scoped demotion here,
		// because cloud_identity.plan_known_gap is the gap's own code, not
		// this one.
		Code:    "cloud_identity.inventory.unmapped_service",
		Message: "upstream input was incomplete for this target",
	}}
	plan := inputAssertionScopePlan(targetA, targetB)
	ports := collectionTestPorts(render)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !hasGapCode(result.Gaps, "cloud_identity.plan_known_gap") {
		t.Fatalf("expected a cloud_identity.plan_known_gap gap, got %+v", result.Gaps)
	}
	if result.InventoryComplete {
		t.Fatalf("Collection.InventoryComplete must be false: a known_gaps entry was produced")
	}
	related := collectionFindEvidence(t, result, "api-a")
	if related.ConsumerInventoryComplete {
		t.Fatalf("the declaring target's own cohort must be demoted by its known_gaps entry despite the supplied code, got %+v", related)
	}
	unrelated := collectionFindEvidence(t, result, "api-b")
	if !unrelated.ConsumerInventoryComplete {
		t.Fatalf("an unrelated target must never be demoted by another target's known_gaps entry: %+v", unrelated)
	}
}

// TestCollectTargetServicesApplyOnlyToOwnTargetAppendedAfterPlanServices
// covers invariant (e): a target's own Services are appended AFTER the
// plan's own Services, for that target's own inventory passes only --
// never visible to another target, and never replacing the plan's own
// mappings.
func TestCollectTargetServicesApplyOnlyToOwnTargetAppendedAfterPlanServices(t *testing.T) {
	targetA, targetB, render := inputAssertionScopeTargets()
	// A target-scoped mapping for target A's own image, absent from the
	// plan's own Services: without it, target A's workload would be
	// unmapped_service-gapped.
	targetA.Services = []ServiceMapping{
		{Service: "api-a", ImagePrefixes: []string{"111111111111.dkr.ecr.us-east-1.amazonaws.com/api-a"}, Repository: "github.com/example/api-a"},
	}
	plan := ScanPlan{
		Scope:   "org:example-org",
		Targets: []ScanTarget{targetA, targetB},
		// The plan's own Services covers only target B's image; target A's
		// own mapping comes exclusively from its own target.Services.
		Services: []ServiceMapping{
			{Service: "api-b", ImagePrefixes: []string{"222222222222.dkr.ecr.us-east-1.amazonaws.com/api-b"}, Repository: "github.com/example/api-b"},
		},
	}
	ports := collectionTestPorts(render)

	result, err := Collect(context.Background(), plan, ports, time.Now())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if hasGapCode(result.Gaps, "cloud_identity.inventory.unmapped_service") {
		t.Fatalf("target A's own Services mapping must apply to target A's own workload, got %+v", result.Gaps)
	}
	related := collectionFindEvidence(t, result, "api-a")
	if !related.ConsumerInventoryComplete {
		t.Fatalf("target A's own workload must be fully mapped via its own target.Services, got %+v", related)
	}
	// target B never declares its own Services, so its mapping must still
	// come from the plan's own Services -- target A's Services must never
	// leak onto a different target.
	unrelated := collectionFindEvidence(t, result, "api-b")
	if !unrelated.ConsumerInventoryComplete {
		t.Fatalf("target B must still resolve via the plan's own Services, unaffected by target A's own Services: %+v", unrelated)
	}
}

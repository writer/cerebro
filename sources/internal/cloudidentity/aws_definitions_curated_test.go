package cloudidentitysource

import (
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func TestAWSApplyCuratedOperationProfilePutObject(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{
		Provider:    ci.AWS,
		Service:     "s3",
		Operation:   "PutObject",
		Permissions: []string{"s3:PutObject"},
		SDKMethods:  []string{"PutObject", "put_object"},
	}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if !got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=true for a curated operation")
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap when the primary permission is present, got %+v", gaps)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != "s3:PutObject" {
		t.Fatalf("expected the live unconditional permission to survive unchanged, got %+v", got.Permissions)
	}
	for _, want := range []string{"kms:GenerateDataKey", "kms:Decrypt", "s3express:CreateSession"} {
		found := false
		for _, have := range got.ConditionalPermissions {
			if have == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected curated conditional permission %q, got %+v", want, got.ConditionalPermissions)
		}
	}
	if len(got.References) != 1 || got.References[0].API != "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html" {
		t.Fatalf("expected a reference citing the primary API doc, got %+v", got.References)
	}
}

// TestAWSApplyCuratedOperationProfileListBucketsEmptyAuthorizedActionsStaysIncomplete
// reproduces the exercised counterexample: the live Service Reference feed
// returning ListBuckets with no AuthorizedActions (empty Permissions) must
// never be read, via the curated row alone, as a dependency-complete,
// zero-permission operation. s3:ListAllMyBuckets is ListBuckets' confirmed
// primary permission; its absence from the live-fed Permissions keeps
// DependenciesComplete=false and raises a scoped gap.
func TestAWSApplyCuratedOperationProfileListBucketsEmptyAuthorizedActionsStaysIncomplete(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{
		Provider:  ci.AWS,
		Service:   "s3",
		Operation: "ListBuckets",
		// Empty Permissions: the live feed published ListBuckets with no
		// AuthorizedActions data (the exercised failure mode).
	}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=false when the live feed did not supply the confirmed primary permission, got true (permissions=%+v)", got.Permissions)
	}
	if len(got.Permissions) != 0 {
		t.Fatalf("expected no fabricated permissions, got %+v", got.Permissions)
	}
	found := false
	for _, gap := range gaps {
		if gap.Code == "aws_curated_primary_permissions_missing" && gap.Scope == "s3:ListBuckets" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a scoped aws_curated_primary_permissions_missing gap, got %+v", gaps)
	}
}

func TestAWSApplyCuratedOperationProfileListBucketsNoAdditions(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{
		Provider:    ci.AWS,
		Service:     "s3",
		Operation:   "ListBuckets",
		Permissions: []string{"s3:ListAllMyBuckets"},
	}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if !got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=true: the primary doc confirms this is the complete set")
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap when the primary permission is present, got %+v", gaps)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != "s3:ListAllMyBuckets" {
		t.Fatalf("expected no fabricated additions, got %+v", got.Permissions)
	}
	if len(got.ConditionalPermissions) != 0 {
		t.Fatalf("expected no conditional permissions for ListBuckets, got %+v", got.ConditionalPermissions)
	}
}

func TestAWSApplyCuratedOperationProfileDeleteObjectMergesWithoutDuplicates(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{
		Provider:    ci.AWS,
		Service:     "s3",
		Operation:   "DeleteObject",
		Permissions: []string{"s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion"},
	}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if !got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=true")
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap when all primary permissions are present, got %+v", gaps)
	}
	if len(got.Permissions) != 3 {
		t.Fatalf("expected the live permissions untouched (curation only adds conditional s3express:CreateSession), got %+v", got.Permissions)
	}
	if len(got.ConditionalPermissions) != 1 || got.ConditionalPermissions[0] != "s3express:CreateSession" {
		t.Fatalf("expected exactly one curated conditional permission, got %+v", got.ConditionalPermissions)
	}
}

// TestAWSApplyCuratedOperationProfileDeleteObjectPartialPrimaryStaysIncomplete
// covers a partial (not merely empty) AuthorizedActions set: the live feed
// supplying only one of DeleteObject's three confirmed primary permissions
// must not be curated into DependenciesComplete=true either.
func TestAWSApplyCuratedOperationProfileDeleteObjectPartialPrimaryStaysIncomplete(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{
		Provider:    ci.AWS,
		Service:     "s3",
		Operation:   "DeleteObject",
		Permissions: []string{"s3:DeleteObject"},
	}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=false for a partial primary permission set, got true (permissions=%+v)", got.Permissions)
	}
	if len(gaps) != 1 || gaps[0].Code != "aws_curated_primary_permissions_missing" {
		t.Fatalf("expected one aws_curated_primary_permissions_missing gap, got %+v", gaps)
	}
}

func TestAWSApplyCuratedOperationProfileNoProfileLeavesDependenciesIncomplete(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := ci.OperationDefinition{Provider: ci.AWS, Service: "eks", Operation: "UpdateAddon", Permissions: []string{"eks:UpdateAddon"}}
	got, gaps := awsApplyCuratedOperationProfile(live, now)
	if got.DependenciesComplete {
		t.Fatalf("expected DependenciesComplete=false for an operation with no curated profile")
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap when no curated profile applies, got %+v", gaps)
	}
	if len(got.References) != 0 {
		t.Fatalf("expected no reference added when no profile applies, got %+v", got.References)
	}
}

func TestAWSAppendDeduped(t *testing.T) {
	got := awsAppendDeduped([]string{"a", "b"}, []string{"b", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
}

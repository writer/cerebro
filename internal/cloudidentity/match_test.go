package cloudidentity

import "testing"

func TestResourcePatternsOverlapGCPProjectCoversPlaceholderDescendant(t *testing.T) {
	// GCS encodes the owning project as a literal "_" placeholder, so the
	// string never reveals which project actually owns the bucket. A
	// project-level pattern must conservatively overlap it rather than be
	// proven disjoint from naive string inequality.
	if !resourcePatternsOverlap(GCP, "projects/myproj", "projects/_/buckets/mybucket", nil) {
		t.Fatal("expected conservative overlap: GCS placeholder path hides the owning project")
	}
}

func TestResourcePatternsOverlapGCPDistinctPlaceholderBucketsAreDisjoint(t *testing.T) {
	// Two different, fully-specified placeholder-form bucket resources are
	// genuinely unrelated to each other; the placeholder ambiguity only
	// matters for project-level ancestry, not direct sibling comparisons.
	if resourcePatternsOverlap(GCP, "projects/_/buckets/bucket-a", "projects/_/buckets/bucket-b", nil) {
		t.Fatal("expected two distinct, fully-named buckets to be disjoint")
	}
}

func TestResourcePatternsOverlapGCPDifferingResourceNameSchemesConservative(t *testing.T) {
	// Short canonical name vs full resource name: a project ID string and a
	// project NUMBER can alias the same project with no shared text.
	if !resourcePatternsOverlap(GCP, "projects/myproj", "//cloudresourcemanager.googleapis.com/projects/123456789", nil) {
		t.Fatal("expected conservative overlap across differing GCP resource-name schemes")
	}
}

func TestResourcePatternsOverlapGCPKnownHierarchyStillPrecise(t *testing.T) {
	if !resourcePatternsOverlap(GCP, "projects/myproj", "projects/myproj/buckets/mybucket", nil) {
		t.Fatal("expected a genuine same-scheme ancestor/descendant pair to overlap")
	}
	if resourcePatternsOverlap(GCP, "projects/proj-a", "projects/proj-b", nil) {
		t.Fatal("expected two distinct, fully-named projects to be disjoint")
	}
	if resourcePatternsOverlap(GCP, "projects/proj-a/buckets/b1", "projects/proj-b/buckets/b1", nil) {
		t.Fatal("expected buckets under two distinct, fully-named projects to be disjoint")
	}
}

func TestResourcePatternsOverlapAWSAccessPointAliasConservative(t *testing.T) {
	// An S3 access point ARN never names its underlying bucket in text, so
	// a plain bucket ARN and an access-point ARN cannot be proven disjoint.
	if !resourcePatternsOverlap(AWS, "arn:aws:s3:::my-bucket/*", "arn:aws:s3:us-east-1:111122223333:accesspoint/my-ap/object/*", nil) {
		t.Fatal("expected conservative overlap between a bucket ARN and an access-point ARN")
	}
}

func TestResourcePatternsOverlapAWSTwoAccessPointsStillPrecise(t *testing.T) {
	// Both sides being access points is not the alias-ambiguous case; two
	// distinct access point names remain genuinely comparable/disjoint.
	if resourcePatternsOverlap(AWS, "arn:aws:s3:us-east-1:111122223333:accesspoint/ap-one/object/*", "arn:aws:s3:us-east-1:111122223333:accesspoint/ap-two/object/*", nil) {
		t.Fatal("expected two distinct access points to be disjoint")
	}
}

func TestResourcePatternsOverlapAWSPlainBucketsStillPrecise(t *testing.T) {
	if resourcePatternsOverlap(AWS, "arn:aws:s3:::bucket-a/*", "arn:aws:s3:::bucket-b/*", nil) {
		t.Fatal("expected two distinct plain bucket ARNs to be disjoint")
	}
}

func TestNarrowRecommendationNeverEmitsForGCP(t *testing.T) {
	// Even in the hypothetical case of a wildcard-bearing GCP resource
	// string, GCP Grant.Resources is an attachment point, not a filterable
	// pattern — narrowing must never be recommended for GCP.
	covering := []Requirement{{Resources: []string{"projects/myproj/buckets/specific-bucket"}}}
	if got := narrowRecommendation(GCP, "projects/myproj/buckets/*", covering); got != nil {
		t.Fatalf("expected nil narrowing recommendation for GCP, got %v", got)
	}
}

package cloudidentitysource

import "testing"

// TestGCPMethodReferenceObjectAttrsIncludesIAMPolicyPermission guards
// RequirementsReview finding 8: the supported Go client issues Object.Attrs
// with Projection("full"), which the primary Objects.get doc confirms can
// additionally require storage.objects.getIamPolicy. Omitting it would let
// a real downstream permission be reported as unexplained excess.
func TestGCPMethodReferenceObjectAttrsIncludesIAMPolicyPermission(t *testing.T) {
	var found bool
	for _, op := range gcpMethodReferenceOperations() {
		if op.Operation != "storage.objects.get.attrs" {
			continue
		}
		found = true
		if !op.DependenciesComplete {
			t.Fatalf("storage.objects.get.attrs must confirm its full upper bound (base + conditional) is complete, got %+v", op)
		}
		if !containsPermission(op.ConditionalPermissions, "storage.objects.getIamPolicy") {
			t.Fatalf("want storage.objects.getIamPolicy as a conditional permission for Object.Attrs, got %+v", op.ConditionalPermissions)
		}
	}
	if !found {
		t.Fatalf("want storage.objects.get.attrs operation definition")
	}
}

// TestGCPMethodReferenceBucketAttrsIncludesIAMPolicyAndIPFilterPermissions
// guards the Bucket.Attrs half of finding 8: full bucket metadata can
// additionally require storage.buckets.getIamPolicy and
// storage.buckets.getIpFilter.
func TestGCPMethodReferenceBucketAttrsIncludesIAMPolicyAndIPFilterPermissions(t *testing.T) {
	var found bool
	for _, op := range gcpMethodReferenceOperations() {
		if op.Operation != "storage.buckets.get.attrs" {
			continue
		}
		found = true
		if !op.DependenciesComplete {
			t.Fatalf("storage.buckets.get.attrs must confirm its full upper bound (base + conditional) is complete, got %+v", op)
		}
		for _, want := range []string{"storage.buckets.getIamPolicy", "storage.buckets.getIpFilter"} {
			if !containsPermission(op.ConditionalPermissions, want) {
				t.Fatalf("want %s as a conditional permission for Bucket.Attrs, got %+v", want, op.ConditionalPermissions)
			}
		}
	}
	if !found {
		t.Fatalf("want storage.buckets.get.attrs operation definition")
	}
}

// TestGCPMethodReferenceFirestoreLoggingSpannerUseRealAccessorChains guards
// RequirementsReview finding 9: Firestore document methods, Cloud Logging's
// Log, and Spanner's Query are each reached through a real, compiling SDK
// accessor chain (Doc, Logger, Single respectively), so the definition's
// SDKMethods token must be the qualified "<Accessor>.<Method>" form the
// extractor actually records for that chain, never a bare method name that
// does not exist directly on the client type.
func TestGCPMethodReferenceFirestoreLoggingSpannerUseRealAccessorChains(t *testing.T) {
	wantTokens := map[string]string{
		"datastore.documents.set":    "Doc.Set",
		"datastore.documents.create": "Doc.Create",
		"datastore.documents.get":    "Doc.Get",
		"datastore.documents.delete": "Doc.Delete",
		"logging.entries.create":     "Logger.Log",
		"spanner.databases.select":   "Single.Query",
	}
	seen := map[string]bool{}
	for _, op := range gcpMethodReferenceOperations() {
		want, relevant := wantTokens[op.Operation]
		if !relevant {
			continue
		}
		seen[op.Operation] = true
		if !containsPermission(op.SDKMethods, want) {
			t.Fatalf("operation %s must list SDKMethods token %q matching the real compiling accessor chain, got %+v", op.Operation, want, op.SDKMethods)
		}
	}
	for op := range wantTokens {
		if !seen[op] {
			t.Fatalf("missing expected operation definition %s", op)
		}
	}
}

func containsPermission(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

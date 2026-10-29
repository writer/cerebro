package cloudidentity

import "testing"

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// TestCollectionDefinitionRequestNotActionOnlyRequestsFullCatalog is the
// R01 counterexample: a NotAction-only grant's positive complement spans
// every AWS service, not just the services its own NotAction patterns
// name. collectionDefinitionRequest must request the bare "*" service
// (the full catalog) for it, never just "s3" (the service the single
// NotAction pattern happens to mention) — a service-local request would
// let concreteActionsForGrant silently under-acquire the catalog needed to
// compute an exact, cross-service complement.
func TestCollectionDefinitionRequestNotActionOnlyRequestsFullCatalog(t *testing.T) {
	policy := PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		NotActions: []string{"s3:DeleteObject"},
		Resources:  []string{"*"},
	}}}
	req := collectionDefinitionRequest(policy)
	if !containsString(req.AWSServices, "*") {
		t.Fatalf("expected a NotAction-only grant to request the bare \"*\" service, got %v", req.AWSServices)
	}
	if containsString(req.AWSServices, "s3") && len(req.AWSServices) == 1 {
		t.Fatalf("expected the request to span every service, not just s3 (service-local complement), got %v", req.AWSServices)
	}
}

// TestCollectionDefinitionRequestWildcardedServiceRequestsFullCatalog
// covers the other cross-service shape: an Action pattern whose service
// component is itself wildcarded (e.g. "*:Get*", or a bare "*").
func TestCollectionDefinitionRequestWildcardedServiceRequestsFullCatalog(t *testing.T) {
	policy := PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions:   []string{"*:Get*"},
		Resources: []string{"*"},
	}}}
	req := collectionDefinitionRequest(policy)
	if !containsString(req.AWSServices, "*") {
		t.Fatalf("expected a wildcarded-service action pattern to request the bare \"*\" service, got %v", req.AWSServices)
	}
}

// TestCollectionDefinitionRequestOrdinaryActionRequestsOnlyItsService is
// the control: an ordinary, single-service Action pattern must request
// only that service, never the full catalog.
func TestCollectionDefinitionRequestOrdinaryActionRequestsOnlyItsService(t *testing.T) {
	policy := PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions:   []string{"s3:GetObject"},
		Resources: []string{"arn:aws:s3:::bucket/*"},
	}}}
	req := collectionDefinitionRequest(policy)
	if containsString(req.AWSServices, "*") {
		t.Fatalf("expected an ordinary single-service grant to never request the full catalog, got %v", req.AWSServices)
	}
	if !containsString(req.AWSServices, "s3") || len(req.AWSServices) != 1 {
		t.Fatalf("expected exactly [s3], got %v", req.AWSServices)
	}
}

// TestCollectionDefinitionRequestGCPPermissionsNeverTreatedCrossService
// guards against a regression where a GCP permission string (dotted, no
// colon) is mistaken for a cross-service AWS pattern.
func TestCollectionDefinitionRequestGCPPermissionsNeverTreatedCrossService(t *testing.T) {
	policy := PolicyState{Grants: []Grant{{
		ID: "g1", Effect: "Allow",
		Actions:   []string{"storage.objects.get"},
		Resources: []string{"projects/example-project/buckets/b1"},
	}}}
	req := collectionDefinitionRequest(policy)
	if len(req.AWSServices) != 0 {
		t.Fatalf("expected a GCP permission string to never populate AWSServices, got %v", req.AWSServices)
	}
}

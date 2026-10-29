package cloudidentity

import "testing"

// TestInventoryAmbiguousEqualPrefixMappingsProduceAmbiguityGap reproduces
// three mappings sharing one Envoy image prefix silently resolving to the
// first service in the slice (a false Clear for sharing that was never
// positively established). The workload must get an empty Service plus the
// ambiguity gap, never a guessed winner.
func TestInventoryAmbiguousEqualPrefixMappingsProduceAmbiguityGap(t *testing.T) {
	mappings := []ServiceMapping{
		{Service: "checkout-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}},
		{Service: "billing-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}},
		{Service: "inventory-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}},
	}
	dep := deploymentManifest("checkout-api", "shop", "default",
		[]map[string]any{{"name": "envoy", "image": "envoyproxy/envoy:v1.28"}}, nil)

	workloads, gaps := Inventory(InventoryRequest{
		Manifests: []Manifest{dep}, Environment: "prod", Cluster: "eks-prod",
		Provider: AWS, Account: "111111111111", Services: mappings,
	})

	w := findWorkload(t, workloads, "envoy")
	if w.Service != "" {
		t.Fatalf("ambiguous mapping must leave Service empty, got %q", w.Service)
	}
	if !hasGapCode(gaps, "cloud_identity.inventory.ambiguous_service_mapping") {
		t.Fatalf("expected ambiguous_service_mapping gap, got %+v", gaps)
	}
	if hasGapCode(gaps, "cloud_identity.inventory.unmapped_service") {
		t.Fatalf("ambiguous match must not also report unmapped_service, got %+v", gaps)
	}
}

// TestInventoryWorkloadQualifiedMappingResolvesEnvoyStyleTie reproduces the
// same equal-prefix tie, but one mapping is qualified to this workload's
// controller name: the qualified mapping must win over the unqualified
// catch-all(s), splitting the shared base image into its real distinct
// logical service.
func TestInventoryWorkloadQualifiedMappingResolvesEnvoyStyleTie(t *testing.T) {
	mappings := []ServiceMapping{
		{Service: "checkout-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}},
		{Service: "billing-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}},
		{Service: "payments-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}, Workloads: []string{"payments-api"}},
	}
	dep := deploymentManifest("payments-api", "payments", "default",
		[]map[string]any{{"name": "envoy", "image": "envoyproxy/envoy:v1.28"}}, nil)

	workloads, gaps := Inventory(InventoryRequest{
		Manifests: []Manifest{dep}, Environment: "prod", Cluster: "eks-prod",
		Provider: AWS, Account: "111111111111", Services: mappings,
	})

	w := findWorkload(t, workloads, "envoy")
	if w.Service != "payments-envoy" {
		t.Fatalf("workload-qualified mapping must win the tie, got Service=%q", w.Service)
	}
	if hasGapCode(gaps, "cloud_identity.inventory.ambiguous_service_mapping") {
		t.Fatalf("workload qualifier must resolve the tie without an ambiguity gap, got %+v", gaps)
	}
}

// TestInventoryLongerPrefixWinsOverWorkloadQualifiedShorterPrefix confirms
// prefix length still takes precedence over the Workloads qualifier: the
// qualifier only breaks ties at equal prefix length, it never overrides a
// more specific image-prefix match for an unrelated service.
func TestInventoryLongerPrefixWinsOverWorkloadQualifiedShorterPrefix(t *testing.T) {
	mappings := []ServiceMapping{
		{Service: "generic-envoy", ImagePrefixes: []string{"envoyproxy/envoy"}, Workloads: []string{"payments-api"}},
		{Service: "payments", ImagePrefixes: []string{"envoyproxy/envoy:v1.28"}},
	}
	dep := deploymentManifest("payments-api", "payments", "default",
		[]map[string]any{{"name": "envoy", "image": "envoyproxy/envoy:v1.28"}}, nil)

	workloads, _ := Inventory(InventoryRequest{
		Manifests: []Manifest{dep}, Environment: "prod", Cluster: "eks-prod",
		Provider: AWS, Account: "111111111111", Services: mappings,
	})

	w := findWorkload(t, workloads, "envoy")
	if w.Service != "payments" {
		t.Fatalf("longer prefix must win regardless of qualifier, got Service=%q", w.Service)
	}
}

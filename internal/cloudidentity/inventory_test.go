package cloudidentity

import (
	"sort"
	"testing"
)

func deploymentManifest(name, namespace, saName string, containers, initContainers []map[string]any) Manifest {
	spec := map[string]any{
		"serviceAccountName": saName,
		"containers":         toAnySlice(containers),
	}
	if len(initContainers) > 0 {
		spec["initContainers"] = toAnySlice(initContainers)
	}
	return Manifest{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": name, "namespace": namespace},
			"spec":       map[string]any{"template": map[string]any{"spec": spec}},
		},
		Reference: Reference{Repository: "github.com/example/gitops", Revision: "abc123", Path: "deploy/" + name + ".yaml"},
	}
}

func toAnySlice(ms []map[string]any) []any {
	out := make([]any, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func serviceAccountManifest(name, namespace string, annotations map[string]string) Manifest {
	ann := map[string]any{}
	for k, v := range annotations {
		ann[k] = v
	}
	return Manifest{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]any{"name": name, "namespace": namespace, "annotations": ann},
	}}
}

func TestInventoryDeploymentSidecarsAndInitContainers(t *testing.T) {
	sa := serviceAccountManifest("payments-sa", "payments", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::123456789012:role/payments-role",
	})
	dep := deploymentManifest("payments-api", "payments", "payments-sa",
		[]map[string]any{
			{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments:v1"},
			{"name": "envoy-sidecar", "image": "envoyproxy/envoy:v1.28"},
		},
		[]map[string]any{
			{"name": "migrate", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments-migrate:v1"},
		},
	)

	workloads, gaps := Inventory(InventoryRequest{
		Manifests:   []Manifest{sa, dep},
		Environment: "prod",
		Cluster:     "eks-prod",
		Provider:    AWS,
		Account:     "123456789012",
	})

	if len(workloads) != 3 {
		t.Fatalf("expected 3 workloads (app, sidecar, init), got %d: %+v", len(workloads), workloads)
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.irsa_annotation_invalid" {
			t.Fatalf("unexpected gap: %+v", g)
		}
	}
	app := findWorkload(t, workloads, "app")
	if app.Image != "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments:v1" {
		t.Fatalf("unexpected app image: %s", app.Image)
	}
	if app.Configuration["container_type"] != "container" {
		t.Fatalf("expected container_type=container, got %q", app.Configuration["container_type"])
	}
	if app.ServiceAccount != "payments-sa" {
		t.Fatalf("expected service account payments-sa, got %s", app.ServiceAccount)
	}
	if len(app.Principals) != 1 {
		t.Fatalf("expected exactly 1 principal (configured role only, mutually exclusive with the bare-KSA fallback), got %+v", app.Principals)
	}
	role := app.Principals[0]
	if role.Kind != manifestInventoryKindAWSRole {
		t.Fatalf("expected the configured aws_iam_role principal, got %+v", role)
	}
	if role.ID != "arn:aws:iam::123456789012:role/payments-role" {
		t.Fatalf("unexpected role ARN: %s", role.ID)
	}
	if role.Account != "123456789012" {
		t.Fatalf("expected account 123456789012, got %s", role.Account)
	}

	sidecar := findWorkload(t, workloads, "envoy-sidecar")
	if sidecar.Image != "envoyproxy/envoy:v1.28" {
		t.Fatalf("unexpected sidecar image: %s", sidecar.Image)
	}
	if sidecar.ID == app.ID {
		t.Fatalf("sidecar and app workloads must have distinct IDs")
	}

	initWL := findWorkload(t, workloads, "migrate")
	if initWL.Configuration["container_type"] != "init" {
		t.Fatalf("expected container_type=init, got %q", initWL.Configuration["container_type"])
	}
}

func findWorkload(t *testing.T, workloads []Workload, container string) Workload {
	t.Helper()
	for _, w := range workloads {
		// container identity is embedded in the ID suffix ":<container>"
		if len(w.ID) >= len(container) && w.ID[len(w.ID)-len(container):] == container {
			return w
		}
	}
	t.Fatalf("workload for container %q not found", container)
	return Workload{}
}

func TestInventoryGCPAnnotationConfiguredAndEligible(t *testing.T) {
	sa := serviceAccountManifest("billing-sa", "billing", map[string]string{
		manifestInventoryAnnotationGCPGSA: "billing-gsa@my-project.iam.gserviceaccount.com",
	})
	dep := deploymentManifest("billing-api", "billing", "billing-sa",
		[]map[string]any{{"name": "app", "image": "gcr.io/my-project/billing:v1"}}, nil)

	workloads, gaps := Inventory(InventoryRequest{
		Manifests: []Manifest{sa, dep},
		Cluster:   "gke-prod",
		Provider:  GCP,
	})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unresolved_project" {
			t.Fatalf("project should resolve from GSA email, unexpected gap: %+v", g)
		}
	}
	w := workloads[0]
	if len(w.Principals) != 1 {
		t.Fatalf("expected exactly 1 principal (configured GSA only, mutually exclusive with the bare-KSA fallback), got %+v", w.Principals)
	}
	gsa := w.Principals[0]
	if gsa.Kind != manifestInventoryKindGCPServiceAccount {
		t.Fatalf("expected the configured gcp_service_account principal, got %+v", gsa)
	}
	if gsa.ID != "billing-gsa@my-project.iam.gserviceaccount.com" || gsa.Project != "my-project" {
		t.Fatalf("unexpected GSA principal: %+v", gsa)
	}
}

func TestInventoryEligibleOnlyWithoutAnnotationGapsUnresolvedAccount(t *testing.T) {
	dep := deploymentManifest("worker", "jobs", "default",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker:v1"}}, nil)

	workloads, gaps := Inventory(InventoryRequest{
		Manifests: []Manifest{dep},
		Cluster:   "eks-prod",
		Provider:  AWS,
	})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}
	if len(workloads[0].Principals) != 1 || workloads[0].Principals[0].Kind != manifestInventoryKindAWSKubernetesSA {
		t.Fatalf("expected only the eligible KSA principal, got %+v", workloads[0].Principals)
	}
	foundGap := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unresolved_account" {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatalf("expected unresolved_account gap, got %+v", gaps)
	}
}

func TestInventoryServiceMappingGroupsReplicasNotDistinctApps(t *testing.T) {
	mapping := []ServiceMapping{{Service: "checkout", ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout"}}}
	dep1 := deploymentManifest("checkout-primary", "shop", "default",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v1"}}, nil)
	dep2 := deploymentManifest("checkout-canary", "shop", "default",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v2"}}, nil)
	unrelated := deploymentManifest("inventory-service", "shop", "default",
		[]map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/inventory:v1"}}, nil)

	workloads, _ := Inventory(InventoryRequest{
		Manifests: []Manifest{dep1, dep2, unrelated},
		Cluster:   "eks-prod",
		Provider:  AWS,
		Account:   "123456789012",
		Services:  mapping,
	})
	if len(workloads) != 3 {
		t.Fatalf("expected 3 workloads, got %d", len(workloads))
	}
	services := map[string]int{}
	for _, w := range workloads {
		services[w.Service]++
	}
	if services["checkout"] != 2 {
		t.Fatalf("expected both checkout replicas grouped under service 'checkout', got %+v", services)
	}
	if services[""] != 1 {
		t.Fatalf("expected the unmapped image to get an empty Service (never a fabricated per-object identity), got %+v", services)
	}
}

func TestInventoryImagePreservesDigestSuffixAndSourceFromServiceMapping(t *testing.T) {
	mapping := []ServiceMapping{{
		Service:       "checkout",
		ImagePrefixes: []string{"123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout"},
		Repository:    "github.com/example/checkout-service",
		SourceRoot:    "services/checkout",
	}}
	const digestHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
	fullImage := "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v1@sha256:" + digestHex
	dep := deploymentManifest("checkout-primary", "shop", "default", []map[string]any{{"name": "app", "image": fullImage}}, nil)

	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{dep}, Cluster: "eks-prod", Provider: AWS, Account: "123456789012", Services: mapping})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}
	w := workloads[0]
	if w.Image != fullImage {
		t.Fatalf("expected the full original image reference (with digest) preserved on Workload.Image, got %q", w.Image)
	}
	if w.ImageDigest != "sha256:"+digestHex {
		t.Fatalf("expected the digest suffix extracted into ImageDigest, got %q", w.ImageDigest)
	}
	if w.Source.Repository != "github.com/example/checkout-service" || w.Source.Root != "services/checkout" {
		t.Fatalf("expected Source populated from the matched ServiceMapping's Repository/SourceRoot, got %+v", w.Source)
	}
	if w.Source.Revision != "" || w.Source.Digest != "" {
		t.Fatalf("expected no fabricated revision/digest on an unresolved app source pin, got %+v", w.Source)
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unmapped_service" {
			t.Fatalf("a matched ServiceMapping must never produce an unmapped_service gap, got %+v", g)
		}
	}
}

func TestInventoryUnmappedServiceGapAndEmptySource(t *testing.T) {
	dep := deploymentManifest("orphan-app", "shop", "default", []map[string]any{{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/unmapped:v1"}}, nil)
	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{dep}, Cluster: "eks-prod", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}
	w := workloads[0]
	if w.Service != "" {
		t.Fatalf("expected an empty Service for an unmapped image, got %q", w.Service)
	}
	if w.Name != "orphan-app" {
		t.Fatalf("expected the K8s object name preserved on Name regardless of mapping, got %q", w.Name)
	}
	if w.Source != (SourcePin{}) {
		t.Fatalf("expected an empty Source when no ServiceMapping matched (never disguise the manifest's own IaC ref as an app source), got %+v", w.Source)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unmapped_service" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unmapped_service gap, got %+v", gaps)
	}
}

func TestInventoryStatefulSetDaemonSetJobCronJobPod(t *testing.T) {
	manifests := []Manifest{
		{Object: map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": map[string]any{"name": "db", "namespace": "data"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "default", "containers": toAnySlice([]map[string]any{{"name": "db", "image": "postgres:16"}})}}}}},
		{Object: map[string]any{"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": map[string]any{"name": "agent", "namespace": "monitoring"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "default", "containers": toAnySlice([]map[string]any{{"name": "agent", "image": "agent:v1"}})}}}}},
		{Object: map[string]any{"apiVersion": "batch/v1", "kind": "Job", "metadata": map[string]any{"name": "migrate", "namespace": "jobs"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "default", "containers": toAnySlice([]map[string]any{{"name": "migrate", "image": "migrate:v1"}})}}}}},
		{Object: map[string]any{"apiVersion": "batch/v1", "kind": "CronJob", "metadata": map[string]any{"name": "nightly", "namespace": "jobs"},
			"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"serviceAccountName": "default", "containers": toAnySlice([]map[string]any{{"name": "nightly", "image": "nightly:v1"}})}}}}}}},
		{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "debug", "namespace": "tools"},
			"spec": map[string]any{"serviceAccountName": "default", "containers": toAnySlice([]map[string]any{{"name": "debug", "image": "debug:v1"}})}}},
	}

	workloads, _ := Inventory(InventoryRequest{Manifests: manifests, Cluster: "eks-prod", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 5 {
		t.Fatalf("expected 5 workloads, got %d: %+v", len(workloads), workloads)
	}
	kinds := map[string]bool{}
	for _, w := range workloads {
		kinds[w.Kind] = true
	}
	for _, want := range []string{"StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"} {
		if !kinds[want] {
			t.Fatalf("expected a %s workload, got kinds %+v", want, kinds)
		}
	}
}

func TestInventoryEnvAndConfigCapture(t *testing.T) {
	cm := Manifest{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "app-config", "namespace": "payments"},
		"data":     map[string]any{"LOG_LEVEL": "info", "REGION": "us-east-1"},
	}}
	container := map[string]any{
		"name":  "app",
		"image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/payments:v1",
		"env": toAnySlice([]map[string]any{
			{"name": "STAGE", "value": "prod"},
			{"name": "LOG_LEVEL", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "app-config", "key": "LOG_LEVEL"}}},
			{"name": "DB_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "db-secret", "key": "password"}}},
			{"name": "MISSING", "valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "absent-config", "key": "x"}}},
		}),
		"envFrom": toAnySlice([]map[string]any{
			{"configMapRef": map[string]any{"name": "app-config"}, "prefix": "CFG_"},
		}),
	}
	dep := deploymentManifest("payments-api", "payments", "default", []map[string]any{container}, nil)

	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{cm, dep}, Cluster: "eks-prod", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(workloads))
	}
	config := workloads[0].Configuration
	if config["STAGE"] != "prod" {
		t.Fatalf("expected literal env captured, got %+v", config)
	}
	if config["LOG_LEVEL"] != "info" {
		t.Fatalf("expected configMap-resolved env captured, got %+v", config)
	}
	if _, ok := config["DB_PASSWORD"]; ok {
		t.Fatalf("secret-sourced env must never be captured, got %+v", config)
	}
	if config["CFG_REGION"] != "us-east-1" {
		t.Fatalf("expected envFrom configMap with prefix captured, got %+v", config)
	}
	foundGap := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unresolved_config" {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatalf("expected unresolved_config gap for missing configmap, got %+v", gaps)
	}
}

func TestInventoryUnresolvedNamespaceGap(t *testing.T) {
	dep := deploymentManifest("orphan", "", "default", []map[string]any{{"name": "app", "image": "img:v1"}}, nil)
	_, gaps := Inventory(InventoryRequest{Manifests: []Manifest{dep}, Cluster: "eks-prod", Provider: AWS, Account: "1"})
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.unresolved_namespace" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unresolved_namespace gap, got %+v", gaps)
	}
}

func TestInventoryMalformedPodSpecGap(t *testing.T) {
	malformed := Manifest{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "broken", "namespace": "ns"},
		"spec":     map[string]any{},
	}}
	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{malformed}, Cluster: "eks-prod", Provider: AWS})
	if len(workloads) != 0 {
		t.Fatalf("expected no workloads for malformed pod spec, got %+v", workloads)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.pod_spec_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pod_spec_missing gap, got %+v", gaps)
	}
}

func TestInventoryServiceAccountNotRenderedGap(t *testing.T) {
	dep := deploymentManifest("app", "ns", "custom-sa", []map[string]any{{"name": "app", "image": "img:v1"}}, nil)
	_, gaps := Inventory(InventoryRequest{Manifests: []Manifest{dep}, Cluster: "eks-prod", Provider: AWS, Account: "1"})
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.service_account_not_rendered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected service_account_not_rendered gap, got %+v", gaps)
	}
}

func TestInventoryWorkloadsAreSortedDeterministically(t *testing.T) {
	dep := deploymentManifest("app", "ns", "default", []map[string]any{
		{"name": "z", "image": "img:v1"},
		{"name": "a", "image": "img:v1"},
	}, nil)
	workloads, _ := Inventory(InventoryRequest{Manifests: []Manifest{dep}, Cluster: "eks-prod", Provider: AWS, Account: "1"})
	ids := make([]string, len(workloads))
	for i, w := range workloads {
		ids[i] = w.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("expected workload IDs sorted deterministically, got %v", ids)
	}
}

func TestInventoryRolloutInlineTemplateIsWorkload(t *testing.T) {
	sa := serviceAccountManifest("checkout-sa", "checkout", map[string]string{
		manifestInventoryAnnotationIRSARole: "arn:aws:iam::123456789012:role/checkout-role",
	})
	rollout := Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"name": "checkout-api", "namespace": "checkout"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"serviceAccountName": "checkout-sa",
			"containers": toAnySlice([]map[string]any{
				{"name": "app", "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v1"},
			}),
		}}},
	}}

	workloads, _ := Inventory(InventoryRequest{
		Manifests: []Manifest{sa, rollout},
		Cluster:   "cluster-aws", Provider: AWS, Account: "123456789012",
	})
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload for an inline-template Rollout, got %d: %+v", len(workloads), workloads)
	}
	w := workloads[0]
	if w.Kind != "Rollout" {
		t.Fatalf("expected Kind Rollout, got %q", w.Kind)
	}
	if w.ServiceAccount != "checkout-sa" {
		t.Fatalf("expected ServiceAccount checkout-sa, got %q", w.ServiceAccount)
	}
	if w.Image != "123456789012.dkr.ecr.us-east-1.amazonaws.com/checkout:v1" {
		t.Fatalf("expected the container image captured, got %q", w.Image)
	}
	if len(w.Principals) == 0 {
		t.Fatalf("expected the IRSA-annotated ServiceAccount to resolve a Principal, got %+v", w.Principals)
	}
}

func TestInventoryRolloutWorkloadRefSkippedWithoutGap(t *testing.T) {
	rollout := Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"name": "checkout-api", "namespace": "checkout"},
		"spec":       map[string]any{"workloadRef": map[string]any{"name": "checkout-api", "kind": "Deployment"}},
	}}

	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{rollout}, Cluster: "cluster-aws", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 0 {
		t.Fatalf("expected no workload from a workloadRef Rollout (its referenced Deployment is inventoried separately), got %+v", workloads)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap from a workloadRef Rollout, got %+v", gaps)
	}
}

func TestInventoryRolloutWithoutTemplateOrWorkloadRefGap(t *testing.T) {
	rollout := Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"name": "broken", "namespace": "checkout"},
		"spec":       map[string]any{},
	}}

	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{rollout}, Cluster: "cluster-aws", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 0 {
		t.Fatalf("expected no workloads for a Rollout with neither template nor workloadRef, got %+v", workloads)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.inventory.pod_spec_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pod_spec_missing gap, got %+v", gaps)
	}
}

func TestInventoryNonArgoRolloutKindIgnored(t *testing.T) {
	rollout := Manifest{Object: map[string]any{
		"apiVersion": "other.example.com/v1",
		"kind":       "Rollout",
		"metadata":   map[string]any{"name": "checkout-api", "namespace": "checkout"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"serviceAccountName": "default",
			"containers":         toAnySlice([]map[string]any{{"name": "app", "image": "img:v1"}}),
		}}},
	}}

	workloads, gaps := Inventory(InventoryRequest{Manifests: []Manifest{rollout}, Cluster: "cluster-aws", Provider: AWS, Account: "123456789012"})
	if len(workloads) != 0 {
		t.Fatalf("expected a Rollout from a non-argoproj.io group to be ignored entirely, got %+v", workloads)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gap for an ignored non-argoproj.io Rollout kind, got %+v", gaps)
	}
}

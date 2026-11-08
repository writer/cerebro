package cloudidentitysource

import (
	"errors"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func validationTestPlan() ci.ScanPlan {
	manifest := ci.ManifestInput{Source: ci.SourcePin{Repository: "example-org/gitops", Revision: "main"}, Chart: "charts/apps"}
	terraform := ci.TerraformRoot{Source: ci.SourcePin{Repository: "example-org/infra", Revision: "main"}, Root: "stacks/app", Region: "us-central1"}
	return ci.ScanPlan{
		Scope: "example",
		Targets: []ci.ScanTarget{
			{Name: "aws-east", Environment: "prod", Cluster: "cluster-east", Provider: ci.AWS, Account: "111111111111", Region: "us-east-1", Manifests: []ci.ManifestInput{manifest}},
			{Name: "gcp-central", Environment: "prod", Cluster: "cluster-central", Provider: ci.GCP, Project: "example-project", Region: "us-central1", Manifests: []ci.ManifestInput{manifest}, Terraform: []ci.TerraformRoot{terraform}},
		},
		Services: []ci.ServiceMapping{{Service: "app", ImagePrefixes: []string{"registry.example.com/app"}, Repository: "example-org/app"}},
	}
}

// validInputAssertion is a well-formed file_digest assertion, reused across
// every test that only needs ValidateInputAssertion to accept the shape.
func validInputAssertion(repository string) ci.InputAssertion {
	return ci.InputAssertion{
		Source: ci.SourcePin{Repository: repository, Revision: "main"},
		Path:   "README.md",
		Kind:   "file_digest",
		Digest: strings.Repeat("a", 64),
	}
}

// federatedGCPTestPlan returns a plan with one AWS target carrying a
// paired GCP project -- the same planHasFederatedGCPProject signal
// factory.go uses to provision a GCP CloudReader -- and nothing else
// private-inventory related.
func federatedGCPTestPlan() ci.ScanPlan {
	plan := validationTestPlan()
	plan.Targets[0].Project = "federated-project"
	return plan
}

// Workload IDs, service-account subjects and resolved cluster identifiers
// are keyed by cluster name, so two targets naming the same cluster in
// different accounts/regions must be rejected rather than mis-linked.
func TestValidateScanPlanRejectsAmbiguousClusterNames(t *testing.T) {
	plan := validationTestPlan()
	if err := validateScanPlan(plan); err != nil {
		t.Fatalf("distinct clusters: unexpected error %v", err)
	}
	west := plan.Targets[0]
	west.Name, west.Account, west.Region = "aws-west", "222222222222", "us-west-2"
	plan.Targets = append(plan.Targets, west)
	var ambiguousErr *ErrAmbiguousClusterName
	if err := validateScanPlan(plan); !errors.As(err, &ambiguousErr) {
		t.Fatalf("duplicate cluster name across accounts/regions: got %v, want *ErrAmbiguousClusterName", err)
	}
}

func TestValidateScanPlanMetadataBindings(t *testing.T) {
	cases := []struct {
		name     string
		bindings map[string]string
		project  string
		wantErr  bool
	}{
		{name: "bootstrap project facts", bindings: map[string]string{"data.terraform_remote_state.bootstrap.outputs.project_id": "project_id", "data.terraform_remote_state.bootstrap.outputs.project_number": "project_number"}, project: "example-project"},
		{name: "region fact", bindings: map[string]string{"data.terraform_remote_state.network.outputs.region": "region"}, project: "example-project"},
		{name: "unknown fact", bindings: map[string]string{"data.terraform_remote_state.bootstrap.outputs.secret": "password"}, project: "example-project", wantErr: true},
		{name: "not a data traversal", bindings: map[string]string{"var.project_id": "project_id"}, project: "example-project", wantErr: true},
		{name: "fact the target cannot supply", bindings: map[string]string{"data.terraform_remote_state.bootstrap.outputs.account": "account_id"}, project: "example-project", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := validationTestPlan()
			plan.Targets[1].Project = tc.project
			plan.Targets[1].Terraform[0].MetadataBindings = tc.bindings
			err := validateScanPlan(plan)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateScanPlan error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateEvidenceHandoffSettings(t *testing.T) {
	cases := []struct {
		name    string
		bucket  string
		stream  string
		wantErr bool
	}{
		{name: "both empty is disabled", bucket: "", stream: ""},
		{name: "bucket with valid stream", bucket: "vulnview-cloud-identity-intake-111111111111", stream: "security"},
		{name: "bucket with another valid stream", bucket: "vulnview-cloud-identity-intake-111111111111", stream: "production"},
		{name: "bucket without stream", bucket: "vulnview-cloud-identity-intake-111111111111", stream: "", wantErr: true},
		{name: "bucket with uppercase stream", bucket: "vulnview-cloud-identity-intake-111111111111", stream: "Security", wantErr: true},
		{name: "bucket with overlong stream", bucket: "vulnview-cloud-identity-intake-111111111111", stream: "this-stream-name-is-far-too-long-for-the-pattern", wantErr: true},
		{name: "stream without bucket", bucket: "", stream: "security", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEvidenceHandoffSettings(tc.bucket, tc.stream)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateEvidenceHandoffSettings(%q, %q) error = %v, wantErr %v", tc.bucket, tc.stream, err, tc.wantErr)
			}
		})
	}
}

// TestValidateScanPlanAcceptsAWSTargetWithGCPProjectWithoutPrivateInventory
// confirms an AWS target carrying a paired GCP project passes validation
// on its own, with no private-inventory field required to accompany it.
func TestValidateScanPlanAcceptsAWSTargetWithGCPProjectWithoutPrivateInventory(t *testing.T) {
	if err := validateScanPlan(federatedGCPTestPlan()); err != nil {
		t.Fatalf("unexpected error for an AWS target with a paired GCP project: %v", err)
	}
}

func TestValidateScanPlanTargetServices(t *testing.T) {
	cases := []struct {
		name    string
		service ci.ServiceMapping
		wantErr bool
	}{
		{name: "well-formed", service: ci.ServiceMapping{Service: "worker", Repository: "example-org/worker", ImagePrefixes: []string{"registry.example.com/worker"}}},
		{name: "missing service name", service: ci.ServiceMapping{Repository: "example-org/worker", ImagePrefixes: []string{"registry.example.com/worker"}}, wantErr: true},
		{name: "missing repository", service: ci.ServiceMapping{Service: "worker", ImagePrefixes: []string{"registry.example.com/worker"}}, wantErr: true},
		{name: "missing image prefixes", service: ci.ServiceMapping{Service: "worker", Repository: "example-org/worker"}, wantErr: true},
		{name: "blank workload name", service: ci.ServiceMapping{Service: "worker", Repository: "example-org/worker", ImagePrefixes: []string{"registry.example.com/worker"}, Workloads: []string{" "}}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := validationTestPlan()
			plan.Targets[0].Services = []ci.ServiceMapping{tc.service}
			err := validateScanPlan(plan)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateScanPlan error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateScanPlanRequiresServiceMappingAcrossPlanAndTargets covers the
// generalized "at least one service mapping" rule: it now sums plan-level
// and every target-level Services, so a plan with none at the plan level
// is still accepted when a target supplies its own.
func TestValidateScanPlanRequiresServiceMappingAcrossPlanAndTargets(t *testing.T) {
	plan := validationTestPlan()
	plan.Services = nil
	if err := validateScanPlan(plan); err == nil {
		t.Fatalf("expected an error when neither the plan nor any target supplies a service mapping")
	}
	plan.Targets[0].Services = []ci.ServiceMapping{{Service: "app", Repository: "example-org/app", ImagePrefixes: []string{"registry.example.com/app"}}}
	if err := validateScanPlan(plan); err != nil {
		t.Fatalf("unexpected error when a target supplies the only service mapping: %v", err)
	}
}

func TestValidateScanPlanInputAssertions(t *testing.T) {
	t.Run("valid target assertion accepted", func(t *testing.T) {
		plan := validationTestPlan()
		plan.Targets[0].InputAssertions = []ci.InputAssertion{validInputAssertion("example-org/infra")}
		if err := validateScanPlan(plan); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("malformed target assertion rejected", func(t *testing.T) {
		plan := validationTestPlan()
		bad := validInputAssertion("example-org/infra")
		bad.Digest = "not-hex"
		plan.Targets[0].InputAssertions = []ci.InputAssertion{bad}
		if err := validateScanPlan(plan); err == nil {
			t.Fatalf("expected an error for a malformed target input assertion digest")
		}
	})
	t.Run("valid root assertion accepted", func(t *testing.T) {
		plan := validationTestPlan()
		plan.Targets[1].Terraform[0].InputAssertions = []ci.InputAssertion{validInputAssertion("example-org/infra")}
		if err := validateScanPlan(plan); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("malformed root assertion rejected", func(t *testing.T) {
		plan := validationTestPlan()
		bad := validInputAssertion("example-org/infra")
		bad.Source.Repository = ""
		plan.Targets[1].Terraform[0].InputAssertions = []ci.InputAssertion{bad}
		if err := validateScanPlan(plan); err == nil {
			t.Fatalf("expected an error for a malformed root input assertion")
		}
	})
}

func TestValidateScanPlanKnownGaps(t *testing.T) {
	cases := []struct {
		name    string
		gap     ci.KnownGap
		wantErr bool
	}{
		{name: "well-formed", gap: ci.KnownGap{Code: "generator.partial_coverage", Message: "upstream input was incomplete"}},
		{name: "missing code", gap: ci.KnownGap{Message: "upstream input was incomplete"}, wantErr: true},
		{name: "missing message", gap: ci.KnownGap{Code: "generator.partial_coverage"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := validationTestPlan()
			plan.Targets[0].KnownGaps = []ci.KnownGap{tc.gap}
			err := validateScanPlan(plan)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateScanPlan error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateModuleSourceOverrides(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]string
		wantErr   bool
	}{
		{name: "empty", overrides: map[string]string{}},
		{name: "well-formed", overrides: map[string]string{"registry.example.com/acme/network/aws": "github.com/example-org/terraform-modules//network/aws?ref={version}"}},
		{name: "blank key", overrides: map[string]string{"": "github.com/example-org/terraform-modules//network/aws?ref={version}"}, wantErr: true},
		{name: "blank template", overrides: map[string]string{"registry.example.com/acme/network/aws": ""}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModuleSourceOverrides(tc.overrides)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateModuleSourceOverrides(%v) error = %v, wantErr %v", tc.overrides, err, tc.wantErr)
			}
		})
	}
}

func TestPlanRepositoriesIncludesAssertionAndTargetServiceRepositories(t *testing.T) {
	plan := validationTestPlan()
	plan.Targets[0].Services = []ci.ServiceMapping{{Service: "worker", Repository: "example-org/worker-repo", ImagePrefixes: []string{"registry.example.com/worker"}}}
	plan.Targets[0].InputAssertions = []ci.InputAssertion{validInputAssertion("example-org/target-assertion-repo")}
	plan.Targets[1].Terraform[0].InputAssertions = []ci.InputAssertion{validInputAssertion("example-org/root-assertion-repo")}
	repositories := planRepositories(plan)
	for _, want := range []string{"example-org/worker-repo", "example-org/target-assertion-repo", "example-org/root-assertion-repo"} {
		found := false
		for _, repository := range repositories {
			if repository == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("planRepositories() = %v, want to include %q", repositories, want)
		}
	}
}

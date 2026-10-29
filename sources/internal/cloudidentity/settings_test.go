package cloudidentitysource

import (
	"errors"
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

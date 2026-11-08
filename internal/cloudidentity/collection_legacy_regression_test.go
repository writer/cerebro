package cloudidentity_test

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"github.com/writer/cerebro/internal/cloudidentity/iac"
)

// legacyRegressionRepositoryReader hands back a fixed set of committed
// files keyed by pin.Repository: a federated-target repository (whose
// Terraform root carries a file a root input_assertion checks) and a
// legacy-infra repository, matching every pre-existing legacy
// target.
type legacyRegressionRepositoryReader struct {
	byRepository map[string][]ci.SourceFile
}

func (r legacyRegressionRepositoryReader) ReadRepository(_ context.Context, pin ci.SourcePin) (ci.Repository, error) {
	return ci.Repository{Pin: pin, Files: r.byRepository[pin.Repository]}, nil
}

type legacyRegressionManifestRenderer struct {
	byRelease map[string][]ci.Manifest
}

func (r legacyRegressionManifestRenderer) Render(_ context.Context, req ci.ManifestRequest) ([]ci.Manifest, []ci.Gap, error) {
	return r.byRelease[req.Release], nil, nil
}

func (legacyRegressionManifestRenderer) Compose(_ context.Context, _ ci.ComposeRequest) ([]ci.Manifest, []ci.Gap, error) {
	return nil, nil, nil
}

type legacyRegressionRegistryReader struct{}

func (legacyRegressionRegistryReader) ReadImage(_ context.Context, image string) (ci.ImageProvenance, error) {
	return ci.ImageProvenance{
		Image:            image,
		Digest:           "sha256:" + image,
		DeploymentPinned: true,
		Source:           ci.SourcePin{Repository: "github.com/example/app", Revision: "abc123", Exact: true},
	}, nil
}

type legacyRegressionCloudReader struct{}

func (legacyRegressionCloudReader) Observe(_ context.Context, _ ci.CloudRequest) (ci.Observation, error) {
	return ci.Observation{Policy: ci.PolicyState{Complete: true, Grants: []ci.Grant{}}}, nil
}

func (legacyRegressionCloudReader) Define(_ context.Context, _ ci.DefinitionRequest) (ci.Definitions, error) {
	return ci.Definitions{Complete: true}, nil
}

type legacyRegressionInvestigator struct{}

func (legacyRegressionInvestigator) Investigate(_ context.Context, req ci.InvestigationRequest) (ci.Investigation, error) {
	return ci.Investigation{ConsumerID: req.Workload.ID, Source: req.Workload.Source, Validation: ci.Validation{ScopeComplete: true}}, nil
}

const legacyRegressionRoleFixture = `
variable "role_name" {}

resource "aws_iam_role" "x" {
  name               = var.role_name
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"eks.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
}
`

func legacyRegressionServiceAccountManifest(name, namespace, roleARN string) ci.Manifest {
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata": map[string]any{
			"name":        name,
			"namespace":   namespace,
			"annotations": map[string]any{"eks.amazonaws.com/role-arn": roleARN},
		},
	}}
}

func legacyRegressionDeploymentManifest(name, namespace, saName, image string) ci.Manifest {
	return ci.Manifest{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": name, "namespace": namespace},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"serviceAccountName": saName,
				"containers":         []any{map[string]any{"name": "app", "image": image}},
			}}},
		},
		Reference: ci.Reference{Repository: "github.com/example/gitops", Revision: "abc123", Path: "deploy/" + name + ".yaml"},
	}
}

func legacyRegressionFindEvidence(t *testing.T, result ci.Collection, principalID string) ci.Evidence {
	t.Helper()
	for _, e := range result.Evidence {
		if e.Principal.ID == principalID {
			return e
		}
	}
	t.Fatalf("no evidence cohort found for principal %q among %d cohorts", principalID, len(result.Evidence))
	return ci.Evidence{}
}

const (
	legacyRegressionLegacyRoleARN      = "arn:aws:iam::222222222222:role/legacy-role"
	legacyRegressionFederatedRoleARN   = "arn:aws:iam::111111111111:role/federated-role"
	legacyRegressionAssertedFileDigest = "a8e04d0148585749489382feed3e6eea5007156517abb837f4b2ac24c10ec44e"
	// legacyRegressionUnresolvedKey is an intentional legacy-target-only
	// Terraform-contract value the fixture declares unresolved
	// (ManifestInput.UnresolvedValues). The fake renderer never binds it
	// into any rendered object, so it produces no
	// cloud_identity.manifest.unresolved_value_in_object gap here -- this
	// proves an unresolved value with no identity-bearing object it
	// reaches (review finding #4) never demotes anything, blanket or
	// otherwise.
	legacyRegressionUnresolvedKey = "legacy.ack.permissionsBoundaryArn"
	// legacyRegressionLegacyOnlyGapScope is cloud_identity.inventory.unmapped_service's
	// own Scope for the legacy target's rendered container (no
	// ServiceMapping configured for its image): a real, deterministic,
	// legacy-target-only gap that proves a gap scoped to the legacy
	// target's own collection survives, unchanged, the addition of an
	// unrelated federated target.
	legacyRegressionLegacyOnlyGapScope = "payments/legacy-api/app"
	legacyRegressionFederatedCluster   = "example-federated-cluster"
	legacyRegressionLegacyCluster      = "legacy-cluster"
)

// legacyRegressionLegacyTarget is a legacy-infra-style legacy target (no
// input assertions, app-of-apps-rendered manifests, its own AWS account):
// used byte-for-byte identical across every plan in this file so any
// observed difference can only come from the OTHER targets sharing the plan.
func legacyRegressionLegacyTarget() ci.ScanTarget {
	return ci.ScanTarget{
		Name:        "legacy-devops",
		Environment: "prod",
		Cluster:     legacyRegressionLegacyCluster,
		Provider:    ci.AWS,
		Account:     "222222222222",
		Region:      "us-east-1",
		Manifests: []ci.ManifestInput{{
			Source:           ci.SourcePin{Repository: "github.com/example/gitops", Revision: "abc123"},
			Release:          "legacy-release",
			UnresolvedValues: []string{legacyRegressionUnresolvedKey},
		}},
		Terraform: []ci.TerraformRoot{{
			Source:   ci.SourcePin{Repository: "test-org/legacy-infra", Revision: "main"},
			Root:     "modules/legacy-root",
			VarFiles: []string{"variables/legacy.tfvars"},
		}},
	}
}

// legacyRegressionFederatedTarget is an AWS target with a paired GCP
// project (triggering collectTarget's extra GCP-provider Inventory pass)
// whose Terraform root carries one root-level input_assertion checking a
// committed file's digest. assertedDigest lets each case choose whether
// that digest agrees with the fixture's actual committed file.
func legacyRegressionFederatedTarget(assertedDigest string) ci.ScanTarget {
	return ci.ScanTarget{
		Name:        "federated-example",
		Environment: "prod",
		Cluster:     legacyRegressionFederatedCluster,
		Provider:    ci.AWS,
		Account:     "111111111111",
		Project:     "federated-project-123",
		Region:      "eu-west-1",
		Manifests: []ci.ManifestInput{{
			Source:  ci.SourcePin{Repository: "github.com/example/gitops", Revision: "abc123"},
			Release: "federated-release",
		}},
		Terraform: []ci.TerraformRoot{{
			Source: ci.SourcePin{Repository: "test-org/federated-infra", Revision: "main"},
			Root:   "stacks/federated/example/cluster/iam",
			InputAssertions: []ci.InputAssertion{{
				Source: ci.SourcePin{Repository: "test-org/federated-infra", Revision: "main"},
				Path:   "stacks/federated/example/cluster/iam/README.md",
				Kind:   "file_digest",
				Digest: assertedDigest,
			}},
		}},
	}
}

// legacyRegressionRepositories covers both the legacy-infra root
// and the federated-target root, the latter carrying the committed
// README.md its own root input_assertion checks.
func legacyRegressionRepositories() legacyRegressionRepositoryReader {
	return legacyRegressionRepositoryReader{byRepository: map[string][]ci.SourceFile{
		"test-org/legacy-infra": {
			{Path: "modules/legacy-root/main.tf", Content: []byte(legacyRegressionRoleFixture)},
			{Path: "variables/legacy.tfvars", Content: []byte(`role_name = "legacy-role"`)},
		},
		"test-org/federated-infra": {
			{Path: "stacks/federated/example/cluster/iam/main.tf", Content: []byte(legacyRegressionRoleFixture)},
			{Path: "stacks/federated/example/cluster/iam/README.md", Content: []byte("federated identity root readme\n")},
		},
	}}
}

// legacyRegressionManifests renders the legacy target's ServiceAccount/
// Deployment pair regardless of which plan requests "legacy-release", so
// the legacy target's own rendered output never depends on whether a
// federated target is also present in the plan; "federated-release" is
// only rendered when a plan's federated target actually asks for it.
func legacyRegressionManifests() legacyRegressionManifestRenderer {
	return legacyRegressionManifestRenderer{byRelease: map[string][]ci.Manifest{
		"legacy-release": {
			legacyRegressionServiceAccountManifest("legacy-sa", "payments", legacyRegressionLegacyRoleARN),
			legacyRegressionDeploymentManifest("legacy-api", "payments", "legacy-sa", "222222222222.dkr.ecr.us-east-1.amazonaws.com/legacy-api:v1"),
		},
		"federated-release": {
			legacyRegressionServiceAccountManifest("federated-sa", "federated-payments", legacyRegressionFederatedRoleARN),
			legacyRegressionDeploymentManifest("federated-api", "federated-payments", "federated-sa", "111111111111.dkr.ecr.eu-west-1.amazonaws.com/federated-api:v1"),
		},
	}}
}

// legacyRegressionPorts builds one CollectionPorts shared by every plan in
// this file: identical repository/manifest/registry/cloud/investigator
// fixtures regardless of which targets a given plan actually lists, so the
// only input that ever varies between runs is the plan itself.
func legacyRegressionPorts() ci.CollectionPorts {
	return ci.CollectionPorts{
		Repositories: legacyRegressionRepositories(),
		Registry:     legacyRegressionRegistryReader{},
		Manifests:    legacyRegressionManifests(),
		Declarations: iac.NewDeclarationReader(nil),
		Clouds:       map[ci.Provider]ci.CloudReader{ci.AWS: legacyRegressionCloudReader{}, ci.GCP: legacyRegressionCloudReader{}},
		Investigator: legacyRegressionInvestigator{},
	}
}

var legacyRegressionNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// legacyRegressionPlanLegacyOnly is the baseline every case below compares
// against: the legacy target, collected entirely alone.
func legacyRegressionPlanLegacyOnly() ci.ScanPlan {
	return ci.ScanPlan{Scope: "test", Targets: []ci.ScanTarget{legacyRegressionLegacyTarget()}}
}

// legacyRegressionCohortsForCluster returns every Evidence cohort in result
// with at least one Consumer collected from cluster, keyed by principal ID
// -- the general form of "every evidence cohort whose principal belongs to
// the legacy target", not assuming there is exactly one such cohort.
func legacyRegressionCohortsForCluster(result ci.Collection, cluster string) map[string]ci.Evidence {
	cohorts := make(map[string]ci.Evidence)
	for _, e := range result.Evidence {
		for _, consumer := range e.Consumers {
			if consumer.Cluster == cluster {
				cohorts[e.Principal.ID] = e
				break
			}
		}
	}
	return cohorts
}

// legacyRegressionNormalize zeroes the one field this comparison must
// ignore (collection timestamps); every other field -- principal,
// consumers, declared/observed policy state, definitions, investigations,
// consumer-inventory completeness, gaps -- is compared exactly as
// collected.
func legacyRegressionNormalize(e ci.Evidence) ci.Evidence {
	e.CollectedAt = time.Time{}
	return e
}

func legacyRegressionGapsWithScope(gaps []ci.Gap, scope string) []ci.Gap {
	var out []ci.Gap
	for _, g := range gaps {
		if g.Scope == scope {
			out = append(out, g)
		}
	}
	return out
}

func legacyRegressionGapCodes(gaps []ci.Gap) []string {
	codes := make([]string, 0, len(gaps))
	for _, g := range gaps {
		codes = append(codes, g.Code)
	}
	sort.Strings(codes)
	return codes
}

func legacyRegressionHasGapCode(gaps []ci.Gap, code string) bool {
	for _, g := range gaps {
		if g.Code == code {
			return true
		}
	}
	return false
}

// legacyRegressionAssertNoFederatedGapLeaked fails if
// ci.InputAssertionFailedGapCode (the only gap code the federated target's
// own addition can ever raise in this fixture) appears anywhere in gaps --
// the legacy cohort's own Declared/Observed/top-level Gaps must never
// carry a gap that only ever describes the federated target's own root.
func legacyRegressionAssertNoFederatedGapLeaked(t *testing.T, where string, gaps []ci.Gap) {
	t.Helper()
	for _, g := range gaps {
		if g.Code == ci.InputAssertionFailedGapCode {
			t.Fatalf("%s: unexpected input-assertion gap leaked onto the legacy cohort: %+v", where, g)
		}
	}
}

// legacyRegressionAssertLegacyCohortsIdentical runs both plans through the
// real Collect and asserts every legacy-target evidence cohort collected
// from legacy is byte-for-byte identical (after normalizing collection
// timestamps) between the two results, and that no federated-only gap ever
// attached to one. It returns the with-federated-target result for
// case-specific follow-up assertions.
func legacyRegressionAssertLegacyCohortsIdentical(t *testing.T, label string, legacyOnlyPlan, withFederatedPlan ci.ScanPlan) ci.Collection {
	t.Helper()

	baseline, err := ci.Collect(context.Background(), legacyOnlyPlan, legacyRegressionPorts(), legacyRegressionNow)
	if err != nil {
		t.Fatalf("%s: baseline Collect() error = %v", label, err)
	}
	withFederated, err := ci.Collect(context.Background(), withFederatedPlan, legacyRegressionPorts(), legacyRegressionNow)
	if err != nil {
		t.Fatalf("%s: with-federated-target Collect() error = %v", label, err)
	}

	baselineCohorts := legacyRegressionCohortsForCluster(baseline, legacyRegressionLegacyCluster)
	withFederatedCohorts := legacyRegressionCohortsForCluster(withFederated, legacyRegressionLegacyCluster)
	if len(baselineCohorts) == 0 {
		t.Fatalf("%s: baseline produced no legacy-target evidence cohort to compare", label)
	}
	if len(baselineCohorts) != len(withFederatedCohorts) {
		t.Fatalf("%s: legacy-target cohort count changed: baseline=%d with-federated=%d (keys baseline=%v with-federated=%v)",
			label, len(baselineCohorts), len(withFederatedCohorts), legacyRegressionSortedKeys(baselineCohorts), legacyRegressionSortedKeys(withFederatedCohorts))
	}
	for principalID, baselineCohort := range baselineCohorts {
		withFederatedCohort, ok := withFederatedCohorts[principalID]
		if !ok {
			t.Fatalf("%s: legacy principal %q present in baseline is missing once the federated target was added", label, principalID)
		}
		a := legacyRegressionNormalize(baselineCohort)
		b := legacyRegressionNormalize(withFederatedCohort)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%s: legacy cohort %q changed by adding the federated target:\nbaseline: %+v\nwith-federated: %+v", label, principalID, a, b)
		}
		legacyRegressionAssertNoFederatedGapLeaked(t, label+" Gaps", withFederatedCohort.Gaps)
		legacyRegressionAssertNoFederatedGapLeaked(t, label+" Declared.Gaps", withFederatedCohort.Declared.Gaps)
		legacyRegressionAssertNoFederatedGapLeaked(t, label+" Observed.Gaps", withFederatedCohort.Observed.Gaps)
	}

	baselineLegacyScoped := legacyRegressionGapsWithScope(baseline.Gaps, legacyRegressionLegacyOnlyGapScope)
	withFederatedLegacyScoped := legacyRegressionGapsWithScope(withFederated.Gaps, legacyRegressionLegacyOnlyGapScope)
	if !reflect.DeepEqual(baselineLegacyScoped, withFederatedLegacyScoped) {
		t.Fatalf("%s: top-level gaps scoped to the legacy target changed:\nbaseline: %+v\nwith-federated: %+v", label, baselineLegacyScoped, withFederatedLegacyScoped)
	}
	if len(baselineLegacyScoped) == 0 {
		t.Fatalf("%s: expected the legacy target's own intentional unmapped_service gap in the baseline, got none among %+v", label, baseline.Gaps)
	}

	return withFederated
}

func legacyRegressionSortedKeys(m map[string]ci.Evidence) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestCollectAddingFederatedGCPTargetLeavesLegacyTargetResultsUnchanged is
// the required collection-level proof that adding an AWS target with a
// paired GCP project (and its own root-level input_assertion) to a scan
// plan that already has a legacy-infra target never changes that
// legacy target's own collected evidence -- principal, consumers,
// declared/observed policy state, definitions, investigations,
// consumer-inventory completeness, and gaps -- nor lets a gap caused by
// the federated target's own root input_assertion attach to the legacy
// cohort, whether or not that assertion itself passes or fails.
func TestCollectAddingFederatedGCPTargetLeavesLegacyTargetResultsUnchanged(t *testing.T) {
	t.Run("clean_federated_addition", func(t *testing.T) {
		federatedTarget := legacyRegressionFederatedTarget(legacyRegressionAssertedFileDigest)
		plan := ci.ScanPlan{
			Scope:   "test",
			Targets: []ci.ScanTarget{legacyRegressionLegacyTarget(), federatedTarget},
		}

		result := legacyRegressionAssertLegacyCohortsIdentical(t, "clean_federated_addition", legacyRegressionPlanLegacyOnly(), plan)

		// The clean addition itself must really be clean: no input
		// assertion gap anywhere, confirming this case exercises a
		// genuinely unremarkable federated target, not an accidentally
		// broken one.
		if legacyRegressionHasGapCode(result.Gaps, ci.InputAssertionFailedGapCode) {
			t.Fatalf("clean_federated_addition: expected no input-assertion gap, got codes %v", legacyRegressionGapCodes(result.Gaps))
		}
	})

	t.Run("federated_root_assertion_failure", func(t *testing.T) {
		federatedTarget := legacyRegressionFederatedTarget("0000000000000000000000000000000000000000000000000000000000000000")
		plan := ci.ScanPlan{
			Scope:   "test",
			Targets: []ci.ScanTarget{legacyRegressionLegacyTarget(), federatedTarget},
		}

		result := legacyRegressionAssertLegacyCohortsIdentical(t, "federated_root_assertion_failure", legacyRegressionPlanLegacyOnly(), plan)

		// Confirm this case actually exercises the induced gap --
		// otherwise the "never leaks" assertions above would hold
		// vacuously.
		if !legacyRegressionHasGapCode(result.Gaps, ci.InputAssertionFailedGapCode) {
			t.Fatalf("federated_root_assertion_failure: expected an %s gap, got codes %v", ci.InputAssertionFailedGapCode, legacyRegressionGapCodes(result.Gaps))
		}

		// And the federated cohort itself (not the legacy one) must be
		// the one actually demoted by the failed assertion.
		federatedEvidence := legacyRegressionFindEvidence(t, result, legacyRegressionFederatedRoleARN)
		if federatedEvidence.Declared.Complete {
			t.Fatalf("federated_root_assertion_failure: expected the federated principal's Declared side to be demoted by the failed root input_assertion, got %+v", federatedEvidence.Declared)
		}
	})
}

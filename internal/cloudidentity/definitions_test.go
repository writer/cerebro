package cloudidentity

import (
	"testing"
	"time"
)

func TestMergeDefinitionsDedupesIdenticalBodiesAndMergesReferences(t *testing.T) {
	a := Definitions{
		Actions:  []ActionDefinition{{Name: "s3:GetObject", ResourceTypes: []string{"object"}, References: []Reference{{Digest: "d1"}}}},
		Roles:    []RoleDefinition{{Name: "roles/viewer", Permissions: []string{"storage.objects.get"}, References: []Reference{{Digest: "r1"}}}},
		Complete: true,
	}
	b := Definitions{
		Actions:  []ActionDefinition{{Name: "s3:GetObject", ResourceTypes: []string{"object"}, References: []Reference{{Digest: "d2"}}}},
		Roles:    []RoleDefinition{{Name: "roles/viewer", Permissions: []string{"storage.objects.get"}, References: []Reference{{Digest: "r2"}}}},
		Complete: true,
	}
	merged := MergeDefinitions(a, b)
	if !merged.Complete {
		t.Fatal("expected Complete=true when all inputs complete and bodies agree")
	}
	if len(merged.Actions) != 1 {
		t.Fatalf("expected 1 deduped action, got %d", len(merged.Actions))
	}
	if len(merged.Actions[0].References) != 2 {
		t.Errorf("expected references merged from both inputs, got %d", len(merged.Actions[0].References))
	}
	if hasGapCode(merged.Gaps, "cloudidentity.conflicting_definition") {
		t.Error("identical bodies should not produce a conflict gap")
	}
}

// TestMergeDefinitionsConflictingRoleRegression models a plausible real
// scenario: two separate CloudReader.Define calls for the same GCP role
// (e.g. one taken before and one after an out-of-band IAM role edit, or a
// paginated/retried read that landed on a different role version) return
// different permission sets. MergeDefinitions must never silently trust
// whichever response happened to arrive first.
func TestMergeDefinitionsConflictingRoleRegression(t *testing.T) {
	before := Definitions{
		Roles:    []RoleDefinition{{Name: "roles/custom.editor", Permissions: []string{"storage.objects.get", "storage.objects.list"}}},
		Complete: true,
	}
	after := Definitions{
		Roles:    []RoleDefinition{{Name: "roles/custom.editor", Permissions: []string{"storage.objects.get", "storage.objects.list", "storage.objects.delete"}}},
		Complete: true,
	}
	merged := MergeDefinitions(before, after)
	if merged.Complete {
		t.Fatal("expected Complete=false when a role definition conflicts across inputs")
	}
	if !hasGapCode(merged.Gaps, "cloudidentity.conflicting_definition") {
		t.Fatalf("expected conflicting_definition gap, got %+v", merged.Gaps)
	}
}

func TestMergeDefinitionsConflictingManagedPolicyRegression(t *testing.T) {
	a := Definitions{
		Policies: []ManagedPolicy{{ARN: "arn:aws:iam::aws:policy/ReadOnly", Grants: []Grant{{
			ID: "s1", Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"*"},
			References: []Reference{{Digest: "x1"}},
		}}}},
		Complete: true,
	}
	b := Definitions{
		Policies: []ManagedPolicy{{ARN: "arn:aws:iam::aws:policy/ReadOnly", Grants: []Grant{{
			ID: "s1", Effect: "Allow", Actions: []string{"s3:GetObject", "s3:PutObject"}, Resources: []string{"*"},
			References: []Reference{{Digest: "x2"}},
		}}}},
		Complete: true,
	}
	merged := MergeDefinitions(a, b)
	if merged.Complete {
		t.Fatal("expected Complete=false when a managed policy's grants conflict across inputs")
	}
	if !hasGapCode(merged.Gaps, "cloudidentity.conflicting_definition") {
		t.Fatalf("expected conflicting_definition gap, got %+v", merged.Gaps)
	}
}

func TestMergeDefinitionsIncompleteInputPropagates(t *testing.T) {
	merged := MergeDefinitions(Definitions{Complete: true}, Definitions{Complete: false})
	if merged.Complete {
		t.Fatal("expected Complete=false when any input is incomplete")
	}
}

func TestMergeDefinitionsEmptyInputIsIncomplete(t *testing.T) {
	if MergeDefinitions().Complete {
		t.Fatal("expected Complete=false for zero inputs")
	}
}

func TestMergeDefinitionsDigestDeterministic(t *testing.T) {
	a := Definitions{Actions: []ActionDefinition{{Name: "s3:GetObject"}}, Complete: true}
	b := Definitions{Actions: []ActionDefinition{{Name: "s3:PutObject"}}, Complete: true}
	m1 := MergeDefinitions(a, b)
	m2 := MergeDefinitions(b, a) // reversed input order
	if m1.Digest != m2.Digest {
		t.Errorf("Digest should be order-independent: %q != %q", m1.Digest, m2.Digest)
	}
}

func TestMergeDefinitionsUnencodableEvidenceIsUnknownNotConflicting(t *testing.T) {
	merged := MergeDefinitions(Definitions{
		Actions: []ActionDefinition{{
			Name:       "s3:GetObject",
			References: []Reference{{ObservedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}},
		}},
		Complete:                  true,
		AWSServiceCatalogComplete: true,
	})
	if merged.Complete || merged.AWSServiceCatalogComplete {
		t.Fatal("unencodable evidence cannot establish a complete definition catalog")
	}
	if !hasGapCode(merged.Gaps, "cloudidentity.definition_digest_unavailable") {
		t.Fatalf("expected an encoding gap, got %+v", merged.Gaps)
	}
	if hasGapCode(merged.Gaps, "cloudidentity.conflicting_definition") {
		t.Fatal("an encoding failure is not evidence of conflicting definitions")
	}
}

// TestMergeDefinitionsAWSServiceCatalogCompleteTrueWhenAssertedAndNoConflict
// is the R01 contract: a merge is only entitled to trust the full-catalog
// claim when some input actually asserted it AND the merge found no
// conflicting duplicate definitions anywhere in the merge.
func TestMergeDefinitionsAWSServiceCatalogCompleteTrueWhenAssertedAndNoConflict(t *testing.T) {
	full := Definitions{
		Actions:                   []ActionDefinition{{Name: "s3:GetObject"}, {Name: "ec2:DescribeInstances"}},
		Complete:                  true,
		AWSServiceCatalogComplete: true,
	}
	gcp := Definitions{
		Roles:    []RoleDefinition{{Name: "roles/viewer", Permissions: []string{"storage.objects.get"}}},
		Complete: true,
	}
	merged := MergeDefinitions(full, gcp)
	if !merged.AWSServiceCatalogComplete {
		t.Fatal("expected AWSServiceCatalogComplete=true: one input asserted it and the merge had no conflicts")
	}
}

func TestMergeDefinitionsAWSServiceCatalogCompleteFalseWhenNoInputAsserts(t *testing.T) {
	a := Definitions{Actions: []ActionDefinition{{Name: "s3:GetObject"}}, Complete: true}
	b := Definitions{Actions: []ActionDefinition{{Name: "ec2:DescribeInstances"}}, Complete: true}
	merged := MergeDefinitions(a, b)
	if merged.AWSServiceCatalogComplete {
		t.Fatal("expected AWSServiceCatalogComplete=false: no input asserted the full catalog was acquired")
	}
}

// TestMergeDefinitionsAWSServiceCatalogCompleteFalseOnConflict ensures a
// full-catalog claim is never trusted out of a merge that also contains an
// unrelated conflicting definition: a conflict means at least one input's
// data is untrustworthy, which could just as easily be the catalog claim.
func TestMergeDefinitionsAWSServiceCatalogCompleteFalseOnConflict(t *testing.T) {
	full := Definitions{
		Actions:                   []ActionDefinition{{Name: "s3:GetObject"}},
		Roles:                     []RoleDefinition{{Name: "roles/custom.editor", Permissions: []string{"storage.objects.get"}}},
		Complete:                  true,
		AWSServiceCatalogComplete: true,
	}
	conflicting := Definitions{
		Roles:    []RoleDefinition{{Name: "roles/custom.editor", Permissions: []string{"storage.objects.get", "storage.objects.delete"}}},
		Complete: true,
	}
	merged := MergeDefinitions(full, conflicting)
	if merged.AWSServiceCatalogComplete {
		t.Fatal("expected AWSServiceCatalogComplete=false when the merge contains a conflicting definition")
	}
}

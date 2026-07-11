package complianceimpact

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
)

type adapterReplayFixture struct {
	Mappings []CompatibilityMapping  `json:"mappings"`
	Expected []adapterExpectedTarget `json:"expected_targets"`
}

type adapterExpectedTarget struct {
	Kind      CompatibilityTargetKind `json:"kind"`
	ID        string                  `json:"id"`
	ActionIDs []string                `json:"action_ids"`
}

func TestCompatibilityAdapterFixtureStableReplayAndAllDestinationSlices(t *testing.T) {
	fixture := readAdapterReplayFixture(t)
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	program := adapterRevision(t, complianceintegration.FactProgram, "program-source", 2)
	objective := adapterRevision(t, complianceintegration.FactObjective, "objective-source", 3)
	impact := adapterImpact(t, root)
	impact.Programs = []AffectedFact{{Revision: program, Reasons: []ReasonCode{ReasonDependencyDeleted}, Relations: []string{"policy_scope"}, Distance: 1}}
	impact.Objectives = []AffectedFact{{Revision: objective, Reasons: []ReasonCode{ReasonDependencyDeleted}, Relations: []string{"program_objective"}, Distance: 2}}

	request := adapterRequest(impact, fixture.Mappings)
	first, err := AdaptCompatibility(request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Complete || len(first.Issues) != 0 {
		t.Fatalf("result complete=%v issues=%#v", first.Complete, first.Issues)
	}
	if first.ImpactSource.ContentDigest != root.Canonical().ContentDigest || first.ImpactSource.RevisionID != root.RevisionID() {
		t.Fatalf("impact source provenance changed: %#v", first.ImpactSource)
	}
	if first.MappingSet != request.MappingSet {
		t.Fatalf("mapping set provenance = %#v, want %#v", first.MappingSet, request.MappingSet)
	}

	gotTargets := make([]adapterExpectedTarget, 0, len(first.Targets))
	for _, target := range first.Targets {
		actions := make([]string, 0, len(target.Actions))
		for _, action := range target.Actions {
			actions = append(actions, action.ActionID)
		}
		gotTargets = append(gotTargets, adapterExpectedTarget{Kind: target.Kind, ID: target.ID, ActionIDs: actions})
		for _, source := range target.Sources {
			if source.Revision.ContentDigest != compliance.ContentDigest(adapterDigest("a")) {
				t.Fatalf("target %s source digest changed: %#v", target.ID, source.Revision)
			}
		}
	}
	if !reflect.DeepEqual(gotTargets, fixture.Expected) {
		t.Fatalf("targets = %#v, want %#v", gotTargets, fixture.Expected)
	}

	// Replay with duplicate/reordered mapping input and reordered impact output.
	replayedMappings := append([]CompatibilityMapping(nil), fixture.Mappings...)
	for left, right := 0, len(replayedMappings)-1; left < right; left, right = left+1, right-1 {
		replayedMappings[left], replayedMappings[right] = replayedMappings[right], replayedMappings[left]
	}
	replayedMappings = append(replayedMappings, replayedMappings[0])
	replayedImpact := impact
	replayedImpact.Programs[0].Reasons = []ReasonCode{ReasonDependencyDeleted, ReasonDependencyDeleted}
	replayedImpact.Programs[0].Relations = []string{"policy_scope", "policy_scope"}
	second, err := AdaptCompatibility(adapterRequest(replayedImpact, replayedMappings))
	if err != nil {
		t.Fatal(err)
	}
	left, err := CanonicalAdapterBytes(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalAdapterBytes(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("stable replay changed:\nfirst=%s\nsecond=%s", left, right)
	}
}

func TestCompatibilityAdapterDoesNotMapSimilarSubjectAtDifferentRevision(t *testing.T) {
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	mapping := adapterMapping(root, TargetPolicy, "policy-1", "review.complete")
	mapping.Source.ContentDigest = compliance.ContentDigest(adapterDigest("b"))

	result, err := AdaptCompatibility(adapterRequest(adapterImpact(t, root), []CompatibilityMapping{mapping}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Targets) != 0 || len(result.Issues) != 1 || result.Issues[0].Code != ReasonUnmappedTarget {
		t.Fatalf("different revision was mapped: %#v", result)
	}
	if result.Issues[0].Source.RevisionID != root.RevisionID() || result.Issues[0].Source.ContentDigest != root.Canonical().ContentDigest {
		t.Fatalf("unmapped issue lost exact source: %#v", result.Issues[0])
	}
}

func TestCompatibilityAdapterRejectsAmbiguousTargetsWithoutGuessing(t *testing.T) {
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	mappings := []CompatibilityMapping{
		adapterMapping(root, TargetPolicy, "policy-b", "review.complete"),
		adapterMapping(root, TargetPolicy, "policy-a", "review.complete"),
	}
	result, err := AdaptCompatibility(adapterRequest(adapterImpact(t, root), mappings))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 0 || len(result.Issues) != 1 || result.Issues[0].Code != ReasonAmbiguousTarget {
		t.Fatalf("ambiguous target was guessed: %#v", result)
	}
	if !reflect.DeepEqual(result.Issues[0].CandidateIDs, []string{"policy-a", "policy-b"}) {
		t.Fatalf("candidate ids = %v", result.Issues[0].CandidateIDs)
	}
}

func TestCompatibilityAdapterMergesActionsForOneExplicitTarget(t *testing.T) {
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	mappings := []CompatibilityMapping{
		adapterMapping(root, TargetPolicy, "policy-1", "review.complete"),
		adapterMapping(root, TargetPolicy, "policy-1", "exception.renew"),
	}
	result, err := AdaptCompatibility(adapterRequest(adapterImpact(t, root), mappings))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 1 || len(result.Targets[0].Actions) != 2 {
		t.Fatalf("target actions = %#v", result.Targets)
	}
	if got := []string{result.Targets[0].Actions[0].ActionID, result.Targets[0].Actions[1].ActionID}; !reflect.DeepEqual(got, []string{"exception.renew", "review.complete"}) {
		t.Fatalf("action ids = %v", got)
	}
}

func TestCompatibilityAdapterRejectsTenantBoundaryInvalidMappingsAndLimits(t *testing.T) {
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	impact := adapterImpact(t, root)
	mapping := adapterMapping(root, TargetPolicy, "policy-1", "review.complete")

	tenantRequest := adapterRequest(impact, []CompatibilityMapping{mapping})
	tenantRequest.Mappings[0].TenantID = "tenant-b"
	if _, err := AdaptCompatibility(tenantRequest); !errors.Is(err, ErrAdapterTenantBoundary) {
		t.Fatalf("tenant error = %v", err)
	}

	invalidRequest := adapterRequest(impact, []CompatibilityMapping{mapping})
	invalidRequest.Mappings[0].ActionIDs = []string{"Review Complete"}
	if _, err := AdaptCompatibility(invalidRequest); !errors.Is(err, ErrInvalidAdapterRequest) {
		t.Fatalf("invalid action error = %v", err)
	}

	limitedRequest := adapterRequest(impact, []CompatibilityMapping{mapping, mapping})
	limitedRequest.Limits.MaxMappings = 1
	if _, err := AdaptCompatibility(limitedRequest); !errors.Is(err, ErrAdapterLimit) {
		t.Fatalf("limit error = %v", err)
	}
}

func TestCompatibilityAdapterCarriesIncompleteImpactReason(t *testing.T) {
	root := adapterRevision(t, complianceintegration.FactPolicy, "policy-source", 1)
	impact := adapterImpact(t, root)
	impact.Complete = false
	impact.Issues = []Issue{{Code: ReasonDepthBudgetExceeded, Revision: root}}
	result, err := AdaptCompatibility(adapterRequest(impact, []CompatibilityMapping{adapterMapping(root, TargetPolicy, "policy-1", "review.complete")}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Issues) != 1 || result.Issues[0].Code != ReasonImpactIncomplete || result.Issues[0].ImpactReason != ReasonDepthBudgetExceeded {
		t.Fatalf("incomplete impact not preserved: %#v", result)
	}
}

func readAdapterReplayFixture(t *testing.T) adapterReplayFixture {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "compatibility_adapter_replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture adapterReplayFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func adapterImpact(t *testing.T, root complianceintegration.RevisionRef) Result {
	t.Helper()
	signal, err := complianceintegration.NewChangeSignal(complianceintegration.ChangeDeleted, root, nil, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	return Result{TenantID: "tenant-a", Signal: signal, Complete: true}
}

func adapterRequest(impact Result, mappings []CompatibilityMapping) AdapterRequest {
	return AdapterRequest{
		TenantID: "tenant-a", Impact: impact,
		MappingSet: MappingSetRevision{RevisionID: "compatibility-map-r1", ContentDigest: compliance.ContentDigest(adapterDigest("c"))},
		Mappings:   mappings, Limits: DefaultAdapterLimits(),
	}
}

func adapterMapping(source complianceintegration.RevisionRef, kind CompatibilityTargetKind, id string, actions ...string) CompatibilityMapping {
	return CompatibilityMapping{TenantID: "tenant-a", Source: provenance(source), TargetKind: kind, TargetID: id, ActionIDs: actions}
}

func adapterRevision(t *testing.T, kind complianceintegration.FactKind, id string, version uint64) complianceintegration.RevisionRef {
	t.Helper()
	ref, err := complianceintegration.AdaptRevisionRef("tenant-a", "test.domain", kind, compliance.RevisionRef{
		ID: id, RevisionID: id + "-r" + string(rune('0'+version)), Version: version,
		ContentDigest: compliance.ContentDigest(adapterDigest("a")), LastModified: time.Unix(int64(version), 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func adapterDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

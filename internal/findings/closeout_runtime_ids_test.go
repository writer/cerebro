package findings

// TestTombstoneFindingsBulk_RuntimeIDsSelector is a focused, fast unit test
// of CloseoutSelector.RuntimeIDs' matching semantics (the F14 legacy
// VulnView runtime closeout follow-up), independent of Postgres. See
// internal/findings/vulnview_legacy_finding_closeout_test.go for the
// Postgres-backed end-to-end proof of the same semantics against the real
// vulnview-actionable-external-finding/vulnview-external-asset-concentrated-signal
// rules.
//
// A candidate matches RuntimeIDs only when its (pinned, first-writer-wins)
// RuntimeID is in the set AND, when its source_runtime_id attribute is
// present (the runtime that most recently re-asserted it), that attribute
// is also in the set. A finding with no source_runtime_id attribute
// matches on RuntimeID alone.

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestTombstoneFindingsBulk_RuntimeIDsSelector(t *testing.T) {
	fx := newCloseoutFixture(t)
	const (
		legacyRuntime = "legacy-runtime-a"
		newRuntime    = "new-runtime-b"
	)
	// Every finding is old; RuntimeIDs must work without any OlderThan.
	oldObserved := fx.now.Add(-365 * 24 * time.Hour)

	fx.seedFinding("f-orphan-no-attr", "open", oldObserved, func(finding *ports.FindingRecord) {
		finding.RuntimeID = legacyRuntime
		finding.Attributes = nil
	})
	fx.seedFinding("f-orphan-legacy-attr", "open", oldObserved, func(finding *ports.FindingRecord) {
		finding.RuntimeID = legacyRuntime
		finding.Attributes = map[string]string{"source_runtime_id": legacyRuntime}
	})
	fx.seedFinding("f-converged", "open", oldObserved, func(finding *ports.FindingRecord) {
		finding.RuntimeID = legacyRuntime
		finding.Attributes = map[string]string{"source_runtime_id": newRuntime}
	})
	fx.seedFinding("f-new-runtime", "open", oldObserved, func(finding *ports.FindingRecord) {
		finding.RuntimeID = newRuntime
		finding.Attributes = map[string]string{"source_runtime_id": newRuntime}
	})

	req := fx.request("run-runtime-ids-selector", true)
	req.Selector.RuntimeIDs = []string{legacyRuntime}

	result, err := fx.service.TombstoneFindingsBulk(context.Background(), req)
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk() error = %v", err)
	}
	got := map[string]struct{}{}
	for _, finding := range result.Proposed {
		got[finding.ID] = struct{}{}
	}
	want := map[string]struct{}{"f-orphan-no-attr": {}, "f-orphan-legacy-attr": {}}
	if len(got) != len(want) {
		t.Fatalf("proposed = %v, want exactly %v", got, want)
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("proposed missing %q: got %v", id, got)
		}
	}
	if _, ok := got["f-converged"]; ok {
		t.Fatal("converged finding (new source_runtime_id) matched RuntimeIDs; it must not")
	}
	if _, ok := got["f-new-runtime"]; ok {
		t.Fatal("new-runtime finding matched RuntimeIDs; it must not")
	}
}

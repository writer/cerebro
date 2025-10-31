package runtime

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	"github.com/WriterInternal/cerebro/desktop-agent/internal/collector"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/config"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/pack"
	"github.com/WriterInternal/cerebro/desktop-agent/internal/types"
)

type stubSnapshotCollector struct {
	name string
}

var _ collector.SnapshotCollector = stubSnapshotCollector{}

func (s stubSnapshotCollector) Name() string { return s.name }

func (s stubSnapshotCollector) Collect(context.Context, config.Config, map[string]any) (*types.HostTelemetry, error) {
	return nil, nil
}

func TestScheduleKey(t *testing.T) {
	key := scheduleKey("remote", "baseline", "gather")
	if key != "remote:baseline:gather" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestBuildEventBatches(t *testing.T) {
	now := time.Now().UTC()
	events := []types.HostEvent{
		{HostID: "host-1", Hostname: "a", Timestamp: now},
		{HostID: "host-1", Hostname: "a", Timestamp: now.Add(time.Second)},
		{HostID: "host-1", Hostname: "a", Timestamp: now.Add(2 * time.Second)},
		{HostID: "host-2", Hostname: "b", Timestamp: now},
	}

	batches := buildEventBatches(events, "0.2.0", 2, "acme", "hq")
	if len(batches) != 3 {
		t.Fatalf("expected 3 batches, got %d", len(batches))
	}
	for _, batch := range batches {
		if batch.AgentVersion != "0.2.0" {
			t.Fatalf("expected agent version propagated, got %q", batch.AgentVersion)
		}
		if batch.Organization != "acme" || batch.Site != "hq" {
			t.Fatalf("expected metadata on batch")
		}
		if len(batch.Events) == 0 {
			t.Fatalf("batch should contain events")
		}
	}
}

func TestCloneTaskIsDeep(t *testing.T) {
	original := pack.Task{
		Name:            "collect",
		Tags:            map[string]string{"env": "prod"},
		Config:          map[string]any{"limit": 5},
		Parameters:      []types.ArtifactTaskParameter{{Name: "limit", Default: 10}},
		ParameterValues: map[string]any{"limit": 8},
		Resources:       &types.ArtifactTaskResources{TimeoutSeconds: 10},
		Tools:           []types.ArtifactTool{{Name: "helper"}},
	}

	clone := cloneTask(original)
	clone.Tags["env"] = "dev"
	clone.Config["limit"] = 1
	clone.ParameterValues["limit"] = 2
	clone.Tools[0].Name = "mutated"

	if original.Tags["env"] != "prod" {
		t.Fatalf("expected original tags untouched")
	}
	if original.Config["limit"].(int) != 5 {
		t.Fatalf("expected original config untouched")
	}
	if original.ParameterValues["limit"].(int) != 8 {
		t.Fatalf("expected parameter values untouched")
	}
	if original.Tools[0].Name != "helper" {
		t.Fatalf("expected tools slice cloned")
	}
}

func TestTaskEligibleDiscovery(t *testing.T) {
	cfg := config.Config{
		Tags:         map[string]string{"env": "prod", "role": "workstation"},
		Site:         "hq",
		Organization: "acme",
	}
	m := NewManager(cfg, nil, log.New(io.Discard, "", 0))
	m.RegisterSnapshot(stubSnapshotCollector{name: "snapshot.basic"})

	m.identityMu.Lock()
	m.hostname = "agent-01"
	m.identityMu.Unlock()

	task := pack.Task{
		Name:      "sample",
		Collector: "snapshot.basic",
		Discovery: []string{"tag:env=prod", "site:hq", "org:acme", "hostname~^agent", "collector:snapshot.basic"},
	}
	sched := scheduledTask{task: task}

	if !m.taskEligible(context.Background(), sched) {
		t.Fatalf("expected task to be eligible")
	}

	task.Discovery = append(task.Discovery, "!tag:role=server")
	sched = scheduledTask{task: task}
	if !m.taskEligible(context.Background(), sched) {
		t.Fatalf("expected negated clause to allow host")
	}

	task.Discovery = []string{"tag:env=dev"}
	if m.taskEligible(context.Background(), scheduledTask{task: task}) {
		t.Fatalf("expected task to be filtered out by discovery")
	}
}

func TestBuildTaskParametersPrecedence(t *testing.T) {
	task := pack.Task{
		Config:          map[string]any{"limit": 5},
		ParameterValues: map[string]any{"limit": 20},
		Parameters:      []types.ArtifactTaskParameter{{Name: "limit", Default: 100}, {Name: "format", Default: "json"}},
	}

	merged := buildTaskParameters(task)
	if merged["limit"].(int) != 20 {
		t.Fatalf("expected parameter values to override config")
	}
	if merged["format"].(string) != "json" {
		t.Fatalf("expected default parameter to be applied")
	}
}

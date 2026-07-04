package sourcecdk

import (
	"context"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/resourcescope"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFamilyEngineSkipsOutOfScopeFamilyBeforeRead(t *testing.T) {
	called := false
	engine, err := NewFamilyEngineWithSourceID("aws", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "s3_bucket",
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			called = true
			return Pull{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}
	rawPolicy, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedAssetClasses: []string{"aws.s3_bucket"}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	pull, err := engine.Read(context.Background(), NewConfig(map[string]string{
		"family":                "s3_bucket",
		resourcescope.ConfigKey: rawPolicy,
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if called {
		t.Fatal("family Read was called for out-of-scope family")
	}
	if len(pull.Events) != 0 {
		t.Fatalf("events len = %d, want 0", len(pull.Events))
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonScopeExcluded {
		t.Fatalf("ShortCircuitReason = %q, want scope_excluded", pull.ShortCircuitReason)
	}
}

func TestFamilyEngineFiltersOutOfScopeEvents(t *testing.T) {
	engine, err := NewFamilyEngineWithSourceID("aws", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "cloudtrail",
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			return Pull{Events: []*primitives.Event{
				{
					Id:         "keep",
					Kind:       "aws.cloudtrail",
					OccurredAt: timestamppb.New(time.Now().UTC()),
					Attributes: map[string]string{"resource_urn": "urn:cerebro:tenant:aws_s3_bucket:kept"},
				},
				{
					Id:         "drop",
					Kind:       "aws.cloudtrail",
					OccurredAt: timestamppb.New(time.Now().UTC()),
					Attributes: map[string]string{"resource_urn": "urn:cerebro:tenant:aws_s3_bucket:excluded"},
				},
			}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}
	rawPolicy, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedResourceURNs: []string{"urn:cerebro:tenant:aws_s3_bucket:excluded"}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	pull, err := engine.Read(context.Background(), NewConfig(map[string]string{
		"family":                "cloudtrail",
		resourcescope.ConfigKey: rawPolicy,
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].GetId() != "keep" {
		t.Fatalf("events = %#v, want only keep", pull.Events)
	}
}

func TestFamilyEngineMarksFullyFilteredEvents(t *testing.T) {
	engine, err := NewFamilyEngineWithSourceID("aws", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "cloudtrail",
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			return Pull{Events: []*primitives.Event{
				{
					Id:         "drop",
					Kind:       "aws.cloudtrail",
					OccurredAt: timestamppb.New(time.Now().UTC()),
					Attributes: map[string]string{"resource_urn": "urn:cerebro:tenant:aws_s3_bucket:excluded"},
				},
			}}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}
	rawPolicy, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedResourceURNs: []string{"urn:cerebro:tenant:aws_s3_bucket:excluded"}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}
	pull, err := engine.Read(context.Background(), NewConfig(map[string]string{
		"family":                "cloudtrail",
		resourcescope.ConfigKey: rawPolicy,
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("events = %#v, want none", pull.Events)
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonResourceScopeFiltered {
		t.Fatalf("ShortCircuitReason = %q, want resource_scope_filtered", pull.ShortCircuitReason)
	}
}

func TestFamilyEngineProbeShortCircuitsBeforeRead(t *testing.T) {
	readCalled := false
	readWithChangeCalled := false
	probeCheckpoint := &cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)),
	}
	engine, err := NewFamilyEngine(func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "pull_request",
		Probe: func(context.Context, string, *cerebrov1.SourceCheckpoint) (ChangeProbe, error) {
			return ChangeProbe{Unchanged: true, Checkpoint: probeCheckpoint}, nil
		},
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			readCalled = true
			return Pull{}, nil
		},
		ReadWithChange: func(context.Context, string, *cerebrov1.SourceCursor, *cerebrov1.SourceCheckpoint, ChangeProbe) (Pull, error) {
			readWithChangeCalled = true
			return Pull{}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngine() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "pull_request"}), nil, &cerebrov1.SourceCheckpoint{})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if readCalled {
		t.Fatal("family Read was called after unchanged probe")
	}
	if readWithChangeCalled {
		t.Fatal("family ReadWithChange was called after unchanged probe")
	}
	if pull.Checkpoint != probeCheckpoint {
		t.Fatal("probe checkpoint was not returned")
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
	}
}

func TestFamilyEnginePassesChangedProbeToReadWithChange(t *testing.T) {
	probeCheckpoint := &cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)),
	}
	cursor := &cerebrov1.SourceCursor{}
	var seenCheckpoint *cerebrov1.SourceCheckpoint
	var seenProbe ChangeProbe
	readCalled := false
	engine, err := NewFamilyEngine(func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "repository",
		Probe: func(context.Context, string, *cerebrov1.SourceCheckpoint) (ChangeProbe, error) {
			return ChangeProbe{
				Checkpoint:         probeCheckpoint,
				ChangedResourceIDs: []string{"repo-1", "repo-2"},
				ChangedURNs:        []URN{"urn:cerebro:writer:repo:writer/repo-1"},
			}, nil
		},
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			readCalled = true
			return Pull{}, nil
		},
		ReadWithChange: func(_ context.Context, _ string, gotCursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, probe ChangeProbe) (Pull, error) {
			if gotCursor != cursor {
				t.Fatalf("cursor = %p, want %p", gotCursor, cursor)
			}
			seenCheckpoint = checkpoint
			seenProbe = probe
			return Pull{Checkpoint: checkpoint}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngine() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "repository"}), cursor, &cerebrov1.SourceCheckpoint{})
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if readCalled {
		t.Fatal("fallback Read was called")
	}
	if seenCheckpoint != probeCheckpoint {
		t.Fatalf("checkpoint = %p, want probe checkpoint %p", seenCheckpoint, probeCheckpoint)
	}
	if len(seenProbe.ChangedResourceIDs) != 2 || seenProbe.ChangedResourceIDs[0] != "repo-1" || seenProbe.ChangedResourceIDs[1] != "repo-2" {
		t.Fatalf("ChangedResourceIDs = %#v, want repo-1/repo-2", seenProbe.ChangedResourceIDs)
	}
	if len(seenProbe.ChangedURNs) != 1 || seenProbe.ChangedURNs[0] != "urn:cerebro:writer:repo:writer/repo-1" {
		t.Fatalf("ChangedURNs = %#v, want repo urn", seenProbe.ChangedURNs)
	}
	if pull.Checkpoint != probeCheckpoint {
		t.Fatal("pull did not preserve probe checkpoint")
	}
}

func TestFamilyEngineSkipsProbeOnContinuationAndCarriesFreshness(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	checkpoint := IncrementalWatermarkCheckpoint("okta", "user", []*primitives.Event{
		{Id: "known", OccurredAt: timestamppb.New(watermark)},
	}, IncrementalWatermarkState{})
	probeTime := watermark.Add(time.Hour)
	probeCalls := 0
	readCalls := 0
	engine, err := NewFamilyEngineWithSourceID("okta", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name:                 "user",
		IncrementalWatermark: true,
		Probe: func(context.Context, string, *cerebrov1.SourceCheckpoint) (ChangeProbe, error) {
			probeCalls++
			return FamilyFreshnessChangeProbe("okta", "user", checkpoint, FamilyFreshnessProbe{
				Kind:       "latest_user",
				ResourceID: "00u1",
				ObservedAt: probeTime,
				UpdatedAt:  probeTime,
				Confidence: FamilyFreshnessConfidenceHeuristic,
			}), nil
		},
		Read: func(_ context.Context, _ string, cursor *cerebrov1.SourceCursor) (Pull, error) {
			readCalls++
			if readCalls == 1 {
				if CursorToken(cursor) != "" {
					t.Fatalf("first read cursor token = %q, want empty", CursorToken(cursor))
				}
				return Pull{
					Events: []*primitives.Event{
						{Id: "new-1", OccurredAt: timestamppb.New(watermark.Add(time.Minute))},
					},
					NextCursor: &cerebrov1.SourceCursor{Opaque: "page-2"},
				}, nil
			}
			if got := CursorToken(cursor); got != "page-2" {
				t.Fatalf("continuation cursor token = %q, want page-2", got)
			}
			return Pull{
				Events: []*primitives.Event{
					{Id: "new-2", OccurredAt: timestamppb.New(watermark.Add(2 * time.Minute))},
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}

	first, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "user"}), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(first) error = %v", err)
	}
	if probeCalls != 1 {
		t.Fatalf("probe calls after first read = %d, want 1", probeCalls)
	}
	if first.NextCursor == nil || CursorToken(first.NextCursor) != "page-2" {
		t.Fatalf("first.NextCursor = %#v, want page-2", first.NextCursor)
	}
	if _, ok := FamilyFreshnessProbeFromCheckpoint("okta", "user", &cerebrov1.SourceCheckpoint{CursorOpaque: first.NextCursor.GetOpaque()}); !ok {
		t.Fatalf("first next cursor %q missing freshness probe", first.NextCursor.GetOpaque())
	}
	if _, ok := FamilyFreshnessProbeFromCheckpoint("okta", "user", first.Checkpoint); !ok {
		t.Fatalf("first checkpoint %q missing freshness probe", first.Checkpoint.GetCursorOpaque())
	}

	second, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "user"}), first.NextCursor, first.Checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint(second) error = %v", err)
	}
	if probeCalls != 1 {
		t.Fatalf("probe calls after continuation = %d, want still 1", probeCalls)
	}
	if len(second.Events) != 1 || second.Events[0].GetId() != "new-2" {
		t.Fatalf("second events = %#v, want new-2", second.Events)
	}
	if _, ok := FamilyFreshnessProbeFromCheckpoint("okta", "user", second.Checkpoint); !ok {
		t.Fatalf("second checkpoint %q missing freshness probe", second.Checkpoint.GetCursorOpaque())
	}
}

func TestFamilyEngineUsesCheckpointAwareRead(t *testing.T) {
	checkpoint := &cerebrov1.SourceCheckpoint{
		Watermark: timestamppb.New(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)),
	}
	var seenCheckpoint *cerebrov1.SourceCheckpoint
	readCalled := false
	engine, err := NewFamilyEngine(func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "securityhub_finding",
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			readCalled = true
			return Pull{}, nil
		},
		ReadWithCheckpoint: func(_ context.Context, _ string, _ *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
			seenCheckpoint = checkpoint
			return Pull{ShortCircuitReason: PullShortCircuitReasonWatermarkReached}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngine() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "securityhub_finding"}), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if readCalled {
		t.Fatal("fallback Read was called")
	}
	if seenCheckpoint != checkpoint {
		t.Fatalf("checkpoint = %p, want %p", seenCheckpoint, checkpoint)
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonWatermarkReached {
		t.Fatalf("ShortCircuitReason = %q, want watermark_reached", pull.ShortCircuitReason)
	}
}

func TestFamilyEngineForcedFreshnessReconcilePassesProbeCheckpointToRead(t *testing.T) {
	now := time.Date(2026, 6, 16, 15, 30, 0, 0, time.UTC)
	hash := FamilyFreshnessHash("audit_log_latest_event", "latest_event", now.Format(time.RFC3339Nano))
	checkpoint := FamilyFreshnessCheckpoint("github", "audit", nil, FamilyFreshnessProbe{
		Kind:       "audit_log_latest_event",
		ResourceID: "latest_event",
		UpdatedAt:  now,
		Hash:       hash,
		Confidence: FamilyFreshnessConfidenceHeuristic,
		SkipCount:  1,
		FullReadAt: now.Add(-time.Minute),
	})
	var seenCheckpoint *cerebrov1.SourceCheckpoint
	engine, err := NewFamilyEngineWithSourceID("github", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name: "audit",
		Probe: func(context.Context, string, *cerebrov1.SourceCheckpoint) (ChangeProbe, error) {
			return FamilyFreshnessChangeProbe("github", "audit", checkpoint, FamilyFreshnessProbe{
				Kind:       "audit_log_latest_event",
				ResourceID: "latest_event",
				ObservedAt: now,
				UpdatedAt:  now,
				Hash:       hash,
				Confidence: FamilyFreshnessConfidenceHeuristic,
			}), nil
		},
		ProbeOptions: FamilyFreshnessReadOptions{
			MaxSkipCount: 1,
			Now:          func() time.Time { return now },
		},
		ReadWithCheckpoint: func(_ context.Context, _ string, _ *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (Pull, error) {
			seenCheckpoint = checkpoint
			return Pull{Checkpoint: checkpoint}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "audit"}), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if seenCheckpoint == nil {
		t.Fatal("ReadWithCheckpoint checkpoint = nil, want forced reconcile checkpoint")
	}
	probe, ok := FamilyFreshnessProbeFromCheckpoint("github", "audit", seenCheckpoint)
	if !ok {
		t.Fatalf("seen checkpoint %q missing freshness probe", seenCheckpoint.GetCursorOpaque())
	}
	if probe.Reason != FamilyFreshnessReasonMaxSkipCount {
		t.Fatalf("seen checkpoint reason = %q, want max_skip_count", probe.Reason)
	}
	if pull.Checkpoint != seenCheckpoint {
		t.Fatal("pull did not preserve forced reconcile checkpoint")
	}
}

func TestFamilyEngineAppliesIncrementalWatermarkFallback(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	checkpoint := IncrementalWatermarkCheckpoint("github", "pull_request", []*primitives.Event{
		{Id: "known", OccurredAt: timestamppb.New(watermark)},
	}, IncrementalWatermarkState{})
	engine, err := NewFamilyEngineWithSourceID("github", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name:                 "pull_request",
		IncrementalWatermark: true,
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			return Pull{
				Events: []*primitives.Event{
					{Id: "new", OccurredAt: timestamppb.New(watermark.Add(time.Minute))},
				},
				NextCursor: &cerebrov1.SourceCursor{Opaque: "2"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{"family": "pull_request"}), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].GetId() != "new" {
		t.Fatalf("events = %#v, want event newer than checkpoint", pull.Events)
	}
	if pull.NextCursor == nil || CursorToken(pull.NextCursor) != "2" {
		t.Fatalf("NextCursor = %#v, want provider token 2", pull.NextCursor)
	}
	if !ResumableCursorOpaque(pull.NextCursor.GetOpaque()) {
		t.Fatalf("NextCursor opaque = %q, want resumable envelope", pull.NextCursor.GetOpaque())
	}
}

func TestFamilyEngineCarriesResourceScopeThroughIncrementalWatermark(t *testing.T) {
	watermark := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	checkpoint := IncrementalWatermarkCheckpoint("aws", "cloudtrail", []*primitives.Event{
		{Id: "known", OccurredAt: timestamppb.New(watermark)},
	}, IncrementalWatermarkState{})
	engine, err := NewFamilyEngineWithSourceID("aws", func(cfg Config) (string, error) {
		family, _ := cfg.Lookup("family")
		return family, nil
	}, func(settings string) string { return settings }, Family[string]{
		Name:                 "cloudtrail",
		IncrementalWatermark: true,
		Read: func(context.Context, string, *cerebrov1.SourceCursor) (Pull, error) {
			return Pull{
				Events: []*primitives.Event{
					{
						Id:         "keep",
						Kind:       "aws.cloudtrail",
						OccurredAt: timestamppb.New(watermark.Add(time.Minute)),
						Attributes: map[string]string{"resource_urn": "urn:cerebro:tenant:aws_s3_bucket:kept"},
					},
					{
						Id:         "drop",
						Kind:       "aws.cloudtrail",
						OccurredAt: timestamppb.New(watermark.Add(2 * time.Minute)),
						Attributes: map[string]string{"resource_urn": "urn:cerebro:tenant:aws_s3_bucket:excluded"},
					},
				},
				NextCursor: &cerebrov1.SourceCursor{Opaque: "2"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewFamilyEngineWithSourceID() error = %v", err)
	}
	rawPolicy, err := resourcescope.ConfigValue(resourcescope.Policy{ExcludedResourceURNs: []string{"urn:cerebro:tenant:aws_s3_bucket:excluded"}})
	if err != nil {
		t.Fatalf("ConfigValue() error = %v", err)
	}

	pull, err := engine.ReadWithCheckpoint(context.Background(), NewConfig(map[string]string{
		"family":                "cloudtrail",
		resourcescope.ConfigKey: rawPolicy,
	}), nil, checkpoint)
	if err != nil {
		t.Fatalf("ReadWithCheckpoint() error = %v", err)
	}
	if len(pull.Events) != 1 || pull.Events[0].GetId() != "keep" {
		t.Fatalf("events = %#v, want resource-scope exclusion applied after incremental filtering", pull.Events)
	}
	if pull.NextCursor == nil || !ResumableCursorOpaque(pull.NextCursor.GetOpaque()) {
		t.Fatalf("NextCursor = %#v, want resumable incremental cursor", pull.NextCursor)
	}
}

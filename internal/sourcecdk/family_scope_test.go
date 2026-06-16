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
	if pull.Checkpoint != probeCheckpoint {
		t.Fatal("probe checkpoint was not returned")
	}
	if pull.ShortCircuitReason != PullShortCircuitReasonNotModified {
		t.Fatalf("ShortCircuitReason = %q, want not_modified", pull.ShortCircuitReason)
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

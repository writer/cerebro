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

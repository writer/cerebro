package transport

import (
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDecisionRequestPreservesLegacyZeroTimestampFallback(t *testing.T) {
	request := DecisionRequest(&cerebrov1.WriteDecisionRequest{
		ObservedAt: &timestamppb.Timestamp{},
		ValidFrom:  &timestamppb.Timestamp{},
		ValidTo:    &timestamppb.Timestamp{},
	}, nil)
	if !request.ObservedAt.IsZero() || !request.ValidFrom.IsZero() || !request.ValidTo.IsZero() {
		t.Fatalf("zero timestamps = (%v, %v, %v), want Go zero values", request.ObservedAt, request.ValidFrom, request.ValidTo)
	}
}

func TestTimestampValueNormalizesToUTC(t *testing.T) {
	value := timestamppb.New(time.Date(2026, 7, 15, 12, 0, 0, 0, time.FixedZone("test", -7*60*60)))
	got := timestampValue(value)
	if got.Location() != time.UTC {
		t.Fatalf("timestamp location = %v, want UTC", got.Location())
	}
}

package graphactionworkflow

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

type recordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *recordingAppendLog) Ping(context.Context) error { return nil }

func (l *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func TestRecordUsesCanonicalActionURNForProviderID(t *testing.T) {
	appendLog := &recordingAppendLog{}
	tenantID := "tenant:1/prod"
	externalID := "act:v2/oja?x=1#fragment"
	err := Record(context.Background(), appendLog, &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: tenantID,
		RuleID:   "rule-1",
		Attributes: map[string]string{
			"primary_resource_urn": "urn:cerebro:tenant-1:okta.user:00u123",
		},
	}, &graphactions.GraphAction{
		ID:             "local-action-1",
		ExternalID:     externalID,
		Action:         graphactions.ActionIdentityOktaSuspendUser,
		Provider:       graphactions.ProviderAccessApprovals,
		ExternalStatus: "queued",
		CreatedAtUnix:  1700000000,
	}, "00u123")
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("recorded events = %d, want 1", len(appendLog.events))
	}
	payload, err := workflowevents.DecodeActionRecorded(appendLog.events[0])
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	prefix := "urn:cerebro:tenant%3A1%2Fprod:graph_action:"
	if !strings.HasPrefix(payload.ActionID, prefix) {
		t.Fatalf("ActionID = %q, want %q prefix", payload.ActionID, prefix)
	}
	suffix := strings.TrimPrefix(payload.ActionID, prefix)
	if len(suffix) != 64 || strings.ContainsAny(suffix, ":/?#") || strings.Contains(payload.ActionID, externalID) {
		t.Fatalf("ActionID = %q, want hash-derived canonical URN", payload.ActionID)
	}
	if payload.SourceEventID != externalID {
		t.Fatalf("SourceEventID = %q, want provider external id", payload.SourceEventID)
	}
	if got, _ := payload.Metadata["external_id"].(string); got != externalID {
		t.Fatalf("metadata external_id = %q, want provider external id", got)
	}
	if got, _ := payload.Metadata["target_urn"].(string); got != "urn:cerebro:tenant-1:okta.user:00u123" {
		t.Fatalf("metadata target_urn = %q, want primary resource urn", got)
	}
	if got, _ := payload.Metadata["reconciliation_status"].(string); got != "queued" {
		t.Fatalf("metadata reconciliation_status = %q, want queued", got)
	}
	if got, _ := payload.Metadata["dry_run"].(bool); got {
		t.Fatalf("metadata dry_run = true, want false")
	}
}

func TestRecordEmitsGraphActionMetricAfterAppend(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	oldProvider := otel.GetMeterProvider()
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(oldProvider)
		_ = provider.Shutdown(context.Background())
	})

	appendLog := &recordingAppendLog{}
	err := Record(context.Background(), appendLog, &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-1",
		RuleID:   "rule-1",
	}, &graphactions.GraphAction{
		ID:             "local-action-1",
		Action:         graphactions.ActionIdentityOktaSuspendUser,
		Provider:       graphactions.ProviderAccessApprovals,
		ExternalStatus: "queued",
		Metadata: map[string]string{
			"dry_run": "false",
		},
	}, "00u123")
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("recorded events = %d, want 1", len(appendLog.events))
	}

	metrics := collectMetricNames(t, reader)
	if !metrics["cerebro.graph_action.recorded"] {
		t.Fatalf("cerebro.graph_action.recorded metric missing from %#v", metrics)
	}
}

func collectMetricNames(t *testing.T, reader *sdkmetric.ManualReader) map[string]bool {
	t.Helper()
	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	names := map[string]bool{}
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			names[metric.Name] = true
		}
	}
	return names
}

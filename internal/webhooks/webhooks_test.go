package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testPublicWebhookBaseURL = "https://93.184.216.34"

func TestServiceRegisterWebhook(t *testing.T) {
	svc := NewService()

	webhook, err := svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{EventFindingCreated}, "secret123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if webhook.ID == "" {
		t.Error("expected webhook ID to be set")
	}
	if webhook.URL != testPublicWebhookBaseURL+"/hook" {
		t.Errorf("expected URL %q, got %q", testPublicWebhookBaseURL+"/hook", webhook.URL)
	}
	if !webhook.Enabled {
		t.Error("expected webhook to be enabled")
	}
	if webhook.Secret != "secret123" {
		t.Error("expected secret to be set")
	}
}

func TestServiceRegisterWebhook_SSRFProtection(t *testing.T) {
	svc := NewService()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid HTTPS", testPublicWebhookBaseURL + "/hook", false},
		{"HTTP not allowed", "http://93.184.216.34/hook", true},
		{"localhost blocked", "https://localhost/hook", true},
		{"loopback blocked", "https://127.0.0.1/hook", true},
		{"metadata service blocked", "https://169.254.169.254/latest/meta-data/", true},
		{"private IP blocked", "https://10.0.0.1/hook", true},
		{"private IP blocked 172", "https://172.16.0.1/hook", true},
		{"private IP blocked 192", "https://192.168.1.1/hook", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.RegisterWebhook(tt.url, []EventType{EventFindingCreated}, "")
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterWebhook(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestServiceGetWebhook(t *testing.T) {
	svc := NewService()

	webhook, _ := svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{EventFindingCreated}, "")

	got, ok := svc.GetWebhook(webhook.ID)
	if !ok {
		t.Error("expected to find webhook")
	}
	if got.URL != webhook.URL {
		t.Errorf("expected URL '%s', got '%s'", webhook.URL, got.URL)
	}

	_, ok = svc.GetWebhook("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent webhook")
	}
}

func TestServiceListWebhooks(t *testing.T) {
	svc := NewService()

	_, _ = svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook1", []EventType{EventFindingCreated}, "")
	_, _ = svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook2", []EventType{EventScanCompleted}, "")

	webhooks := svc.ListWebhooks()
	if len(webhooks) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(webhooks))
	}
}

func TestServiceDisableWebhook(t *testing.T) {
	svc := NewService()

	webhook, _ := svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{EventFindingCreated}, "")

	if !svc.DisableWebhook(webhook.ID) {
		t.Error("expected DisableWebhook to return true")
	}

	got, _ := svc.GetWebhook(webhook.ID)
	if got.Enabled {
		t.Error("expected webhook to be disabled")
	}

	if svc.DisableWebhook("nonexistent") {
		t.Error("expected DisableWebhook to return false for nonexistent")
	}
}

func TestServiceDeleteWebhook(t *testing.T) {
	svc := NewService()

	webhook, _ := svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{EventFindingCreated}, "")

	if !svc.DeleteWebhook(webhook.ID) {
		t.Error("expected DeleteWebhook to return true")
	}

	if _, ok := svc.GetWebhook(webhook.ID); ok {
		t.Error("expected webhook to be deleted")
	}
}

func TestServiceEmit(t *testing.T) {
	var received int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)

		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type application/json")
		}
		if r.Header.Get("X-Cerebro-Event") != string(EventFindingCreated) {
			t.Error("expected X-Cerebro-Event header")
		}

		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Errorf("failed to decode event: %v", err)
		}

		if event.Type != EventFindingCreated {
			t.Errorf("expected event type %s, got %s", EventFindingCreated, event.Type)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	_, _ = svc.RegisterWebhook(server.URL, []EventType{EventFindingCreated}, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc.Emit(ctx, EventFindingCreated, map[string]interface{}{
		"finding_id": "test-123",
	})

	// Give time for async delivery
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected 1 webhook call, got %d", received)
	}
}

func TestServiceEmitWithSignature(t *testing.T) {
	var signature string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-Cerebro-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	_, _ = svc.RegisterWebhook(server.URL, []EventType{EventFindingCreated}, "mysecret")

	ctx := context.Background()
	svc.Emit(ctx, EventFindingCreated, map[string]interface{}{"test": true})

	time.Sleep(100 * time.Millisecond)

	if signature == "" {
		t.Error("expected signature header to be set")
	}
	if signature[:7] != "sha256=" {
		t.Error("expected signature to start with sha256=")
	}
}

func TestServiceEmitFiltersByEventType(t *testing.T) {
	var calls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	// Only subscribe to ScanCompleted, not FindingCreated
	_, _ = svc.RegisterWebhook(server.URL, []EventType{EventScanCompleted}, "")

	ctx := context.Background()
	svc.Emit(ctx, EventFindingCreated, map[string]interface{}{"test": true})

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&calls) != 0 {
		t.Errorf("expected 0 webhook calls for unsubscribed event, got %d", calls)
	}

	// Now emit subscribed event
	svc.Emit(ctx, EventScanCompleted, map[string]interface{}{"test": true})

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("expected 1 webhook call for subscribed event, got %d", calls)
	}
}

func TestServiceDeliveries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	webhook, _ := svc.RegisterWebhook(server.URL, []EventType{EventFindingCreated}, "")

	ctx := context.Background()
	svc.Emit(ctx, EventFindingCreated, map[string]interface{}{"test": true})

	time.Sleep(100 * time.Millisecond)

	deliveries := svc.GetDeliveries(webhook.ID, 10)
	if len(deliveries) != 1 {
		t.Errorf("expected 1 delivery, got %d", len(deliveries))
	}

	if deliveries[0].ResponseStatus != 200 {
		t.Errorf("expected status 200, got %d", deliveries[0].ResponseStatus)
	}
	if !deliveries[0].Success {
		t.Error("expected delivery to be successful")
	}
}

func TestServiceEmitBlocksSSRFOnDelivery(t *testing.T) {
	svc := NewService()

	var transportCalls int32
	svc.client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&transportCalls, 1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	webhook := &Webhook{
		ID:        "wh-internal",
		URL:       "https://127.0.0.1/internal",
		Events:    []EventType{EventFindingCreated},
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	svc.webhooks[webhook.ID] = webhook

	err := svc.EmitWithErrors(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"})
	if err == nil {
		t.Fatal("expected delivery to reject internal webhook URL")
	}
	if !errors.Is(err, ErrInvalidWebhookURL) {
		t.Fatalf("expected invalid webhook URL error, got %v", err)
	}
	if got := atomic.LoadInt32(&transportCalls); got != 0 {
		t.Fatalf("expected no HTTP delivery attempt, got %d transport calls", got)
	}

	deliveries := svc.GetDeliveries(webhook.ID, 10)
	if len(deliveries) != 1 {
		t.Fatalf("expected one failed delivery record, got %d", len(deliveries))
	}
	if deliveries[0].Success {
		t.Fatal("expected delivery record to be unsuccessful")
	}
	if deliveries[0].ResponseStatus != 0 {
		t.Fatalf("expected no HTTP status for blocked delivery, got %d", deliveries[0].ResponseStatus)
	}
}

func TestServiceEmitRetriesTransientHTTPFailuresWithBackoff(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&calls, 1)
		if attempt < 3 {
			http.Error(w, "retry later", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	svc.maxDeliveryAttempts = 3
	svc.baseRetryDelay = 10 * time.Millisecond
	var sleeps []time.Duration
	svc.sleep = func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	}

	webhook, _ := svc.RegisterWebhook(server.URL, []EventType{EventFindingCreated}, "")
	if err := svc.EmitWithErrors(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"}); err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 delivery attempts, got %d", got)
	}
	if !slices.Equal(sleeps, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}) {
		t.Fatalf("unexpected retry schedule: %v", sleeps)
	}

	deliveries := svc.GetDeliveries(webhook.ID, 10)
	if len(deliveries) != 3 {
		t.Fatalf("expected 3 delivery records, got %d", len(deliveries))
	}
	if !deliveries[0].Success {
		t.Fatal("expected final delivery to be successful")
	}
	if deliveries[1].Success || deliveries[2].Success {
		t.Fatal("expected earlier retry records to be failures")
	}
}

func TestServiceEmitRetriesTransportErrorsThenSucceeds(t *testing.T) {
	var calls int32
	svc := NewServiceForTesting()
	svc.maxDeliveryAttempts = 2
	svc.baseRetryDelay = 5 * time.Millisecond
	var sleeps []time.Duration
	svc.sleep = func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	}
	svc.client.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return nil, errors.New("connection reset by peer")
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	webhook, _ := svc.RegisterWebhook("https://93.184.216.34/hook", []EventType{EventFindingCreated}, "")
	if err := svc.EmitWithErrors(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"}); err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 delivery attempts, got %d", got)
	}
	if !slices.Equal(sleeps, []time.Duration{5 * time.Millisecond}) {
		t.Fatalf("unexpected retry schedule: %v", sleeps)
	}

	deliveries := svc.GetDeliveries(webhook.ID, 10)
	if len(deliveries) != 2 {
		t.Fatalf("expected 2 delivery records, got %d", len(deliveries))
	}
	if !deliveries[0].Success {
		t.Fatal("expected final retry to succeed")
	}
	if deliveries[1].ResponseStatus != 0 || deliveries[1].Success {
		t.Fatalf("expected first attempt to record transport failure, got %#v", deliveries[1])
	}
}

func TestServiceEmitDoesNotRetryClientErrors(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()

	svc := NewServiceForTesting()
	svc.maxDeliveryAttempts = 3
	svc.baseRetryDelay = 10 * time.Millisecond
	var sleeps []time.Duration
	svc.sleep = func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	}

	webhook, _ := svc.RegisterWebhook(server.URL, []EventType{EventFindingCreated}, "")
	err := svc.EmitWithErrors(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"})
	if err == nil {
		t.Fatal("expected delivery error")
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 delivery attempt, got %d", got)
	}
	if len(sleeps) != 0 {
		t.Fatalf("expected no retry sleeps, got %v", sleeps)
	}

	deliveries := svc.GetDeliveries(webhook.ID, 10)
	if len(deliveries) != 1 {
		t.Fatalf("expected 1 delivery record, got %d", len(deliveries))
	}
	if deliveries[0].ResponseStatus != http.StatusBadRequest {
		t.Fatalf("expected 400 delivery record, got %d", deliveries[0].ResponseStatus)
	}
}

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"type":"test"}`)
	secret := "mysecret"

	// Create valid signature
	svc := NewService()
	validSig := svc.sign(payload, secret)

	if !VerifySignature(payload, validSig, secret) {
		t.Error("expected valid signature to verify")
	}

	if VerifySignature(payload, "sha256=invalid", secret) {
		t.Error("expected invalid signature to fail")
	}

	if VerifySignature(payload, validSig, "wrongsecret") {
		t.Error("expected wrong secret to fail verification")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com/webhook", false},
		{"http not allowed", "http://example.com/webhook", true},
		{"empty url", "", true},
		{"localhost blocked", "http://localhost/webhook", true},
		{"127.0.0.1 blocked", "http://127.0.0.1/webhook", true},
		{"private 10.x blocked", "http://10.0.0.1/webhook", true},
		{"private 192.168.x blocked", "http://192.168.1.1/webhook", true},
		{"private 172.16.x blocked", "http://172.16.0.1/webhook", true},
		{"metadata endpoint blocked", "http://169.254.169.254/webhook", true},
		{"ftp scheme blocked", "ftp://example.com/webhook", true},
		{"invalid url", "not-a-url", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateWebhookURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWebhookURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestRegisterWebhookSSRFProtection(t *testing.T) {
	svc := NewService() // Use regular service (with validation)

	// Should reject localhost
	_, err := svc.RegisterWebhook("http://localhost/hook", []EventType{EventFindingCreated}, "")
	if err == nil {
		t.Error("expected error for localhost webhook")
	}

	// Should reject private IPs
	_, err = svc.RegisterWebhook("http://10.0.0.1/hook", []EventType{EventFindingCreated}, "")
	if err == nil {
		t.Error("expected error for private IP webhook")
	}

	// Should reject invalid events
	_, err = svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{"invalid.event"}, "")
	if err == nil {
		t.Error("expected error for invalid event type")
	}

	// Should reject empty events
	_, err = svc.RegisterWebhook(testPublicWebhookBaseURL+"/hook", []EventType{}, "")
	if err == nil {
		t.Error("expected error for empty events")
	}
}

type mockEventPublisher struct {
	publishCalls int32
	closeCalls   int32
	publishErr   error
	readyErr     error
	status       map[string]interface{}
}

func (m *mockEventPublisher) Publish(ctx context.Context, event Event) error {
	atomic.AddInt32(&m.publishCalls, 1)
	return m.publishErr
}

func (m *mockEventPublisher) Close() error {
	atomic.AddInt32(&m.closeCalls, 1)
	return nil
}

func (m *mockEventPublisher) Ready(context.Context) error {
	return m.readyErr
}

func (m *mockEventPublisher) Status(context.Context) map[string]interface{} {
	return m.status
}

func TestServiceEmitPublishesToEventPublisher(t *testing.T) {
	svc := NewService()
	publisher := &mockEventPublisher{}
	svc.SetEventPublisher(publisher)

	svc.Emit(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"})

	if got := atomic.LoadInt32(&publisher.publishCalls); got != 1 {
		t.Fatalf("expected 1 publish call, got %d", got)
	}
}

func TestServiceEmitWithErrorsReturnsPublisherError(t *testing.T) {
	svc := NewService()
	publisher := &mockEventPublisher{publishErr: errors.New("publish failed")}
	svc.SetEventPublisher(publisher)

	err := svc.EmitWithErrors(context.Background(), EventFindingCreated, map[string]interface{}{"finding_id": "f-1"})
	if err == nil {
		t.Fatal("expected publisher error")
	}
}

func TestServiceCloseClosesEventPublisher(t *testing.T) {
	svc := NewService()
	publisher := &mockEventPublisher{}
	svc.SetEventPublisher(publisher)

	if err := svc.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	if got := atomic.LoadInt32(&publisher.closeCalls); got != 1 {
		t.Fatalf("expected 1 close call, got %d", got)
	}
}

func TestServiceEventPublisherReady(t *testing.T) {
	svc := NewService()
	if err := svc.EventPublisherReady(context.Background()); err == nil {
		t.Fatal("expected readiness error when publisher not configured")
	}

	publisher := &mockEventPublisher{}
	svc.SetEventPublisher(publisher)
	if err := svc.EventPublisherReady(context.Background()); err != nil {
		t.Fatalf("unexpected readiness error: %v", err)
	}

	publisher.readyErr = errors.New("not ready")
	if err := svc.EventPublisherReady(context.Background()); err == nil {
		t.Fatal("expected readiness error from publisher")
	}
}

func TestServiceEventPublisherReadyRequiresContext(t *testing.T) {
	svc := NewService()
	publisher := &mockEventPublisher{}
	svc.SetEventPublisher(publisher)

	if err := svc.EventPublisherReady(nilContext()); err == nil {
		t.Fatal("expected readiness error when context is nil")
	}
}

func TestServiceEventPublisherStatus(t *testing.T) {
	svc := NewService()
	status := svc.EventPublisherStatus(context.Background())
	if configured, ok := status["configured"].(bool); !ok || configured {
		t.Fatalf("expected configured=false, got %#v", status)
	}

	publisher := &mockEventPublisher{status: map[string]interface{}{"ready": true, "stream": "TEST"}}
	svc.SetEventPublisher(publisher)
	status = svc.EventPublisherStatus(context.Background())
	if configured, ok := status["configured"].(bool); !ok || !configured {
		t.Fatalf("expected configured=true, got %#v", status)
	}
	if status["stream"] != "TEST" {
		t.Fatalf("expected stream TEST, got %#v", status["stream"])
	}
}

func TestServiceEventPublisherStatusRequiresContext(t *testing.T) {
	svc := NewService()
	publisher := &mockEventPublisher{status: map[string]interface{}{"ready": true}}
	svc.SetEventPublisher(publisher)

	status := svc.EventPublisherStatus(nilContext())
	if ready, ok := status["ready"].(bool); !ok || ready {
		t.Fatalf("expected ready=false when context is nil, got %#v", status)
	}
	if status["error"] == nil {
		t.Fatalf("expected context error status, got %#v", status)
	}
}

func nilContext() context.Context {
	return nil
}

func TestNoopEmitter(t *testing.T) {
	emitter := NewNoopEmitter()

	// Should not panic
	emitter.Emit(context.Background(), EventFindingCreated, map[string]interface{}{"test": true})
}

func TestMustEmitter(t *testing.T) {
	svc := NewService()

	emitter := MustEmitter(svc)
	if _, ok := emitter.(*Service); !ok {
		t.Error("expected MustEmitter to return service when not nil")
	}

	emitter = MustEmitter(nil)
	if _, ok := emitter.(*NoopEmitter); !ok {
		t.Error("expected MustEmitter to return NoopEmitter when nil")
	}
}

func TestServiceSubscribeReceivesEmittedEvents(t *testing.T) {
	svc := NewServiceForTesting()
	received := false

	svc.Subscribe(func(_ context.Context, event Event) error {
		received = true
		if event.Type != EventSignalCreated {
			t.Fatalf("expected event type %q, got %q", EventSignalCreated, event.Type)
		}
		return nil
	})

	if err := svc.EmitWithErrors(context.Background(), EventSignalCreated, map[string]interface{}{"signal_type": "test"}); err != nil {
		t.Fatalf("emit with subscriber: %v", err)
	}
	if !received {
		t.Fatal("expected subscriber to receive emitted event")
	}
}

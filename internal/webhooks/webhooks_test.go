package webhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceRegisterWebhook(t *testing.T) {
	svc := NewService()

	webhook, err := svc.RegisterWebhook("https://example.com/hook", []EventType{EventFindingCreated}, "secret123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if webhook.ID == "" {
		t.Error("expected webhook ID to be set")
	}
	if webhook.URL != "https://example.com/hook" {
		t.Errorf("expected URL 'https://example.com/hook', got '%s'", webhook.URL)
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
		{"valid HTTPS", "https://example.com/hook", false},
		{"HTTP not allowed", "http://example.com/hook", true},
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

	webhook, _ := svc.RegisterWebhook("https://example.com/hook", []EventType{EventFindingCreated}, "")

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

	_, _ = svc.RegisterWebhook("https://example.com/hook1", []EventType{EventFindingCreated}, "")
	_, _ = svc.RegisterWebhook("https://example.com/hook2", []EventType{EventScanCompleted}, "")

	webhooks := svc.ListWebhooks()
	if len(webhooks) != 2 {
		t.Errorf("expected 2 webhooks, got %d", len(webhooks))
	}
}

func TestServiceDisableWebhook(t *testing.T) {
	svc := NewService()

	webhook, _ := svc.RegisterWebhook("https://example.com/hook", []EventType{EventFindingCreated}, "")

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

	webhook, _ := svc.RegisterWebhook("https://example.com/hook", []EventType{EventFindingCreated}, "")

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

	svc := NewService()
	svc.RegisterWebhookUnsafe(server.URL, []EventType{EventFindingCreated}, "")

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

	svc := NewService()
	svc.RegisterWebhookUnsafe(server.URL, []EventType{EventFindingCreated}, "mysecret")

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

	svc := NewService()
	// Only subscribe to ScanCompleted, not FindingCreated
	svc.RegisterWebhookUnsafe(server.URL, []EventType{EventScanCompleted}, "")

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

	svc := NewService()
	webhook := svc.RegisterWebhookUnsafe(server.URL, []EventType{EventFindingCreated}, "")

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

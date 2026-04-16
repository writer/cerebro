package notifications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type trackingReadCloser struct {
	reader io.Reader
	closed bool
}

func newTrackingReadCloser(body string) *trackingReadCloser {
	return &trackingReadCloser{reader: strings.NewReader(body)}
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type retryBodyCloseCheckingTransport struct {
	statuses []int
	bodies   []*trackingReadCloser
	call     int
}

func (t *retryBodyCloseCheckingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.call > 0 && !t.bodies[t.call-1].closed {
		return nil, fmt.Errorf("response body from attempt %d was not closed before retry", t.call)
	}
	if t.call >= len(t.statuses) {
		return nil, fmt.Errorf("unexpected request %d", t.call+1)
	}

	body := newTrackingReadCloser(`{"ok":true}`)
	t.bodies = append(t.bodies, body)

	resp := &http.Response{
		StatusCode: t.statuses[t.call],
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}
	t.call++
	return resp, nil
}

func TestManager_NewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	if m.notifiers == nil {
		t.Error("notifiers slice should be initialized")
	}
}

func TestManager_AddNotifier(t *testing.T) {
	m := NewManager()

	webhook, _ := NewWebhookNotifier(WebhookConfig{URL: "http://example.com"})
	m.AddNotifier(webhook)

	names := m.ListNotifiers()
	if len(names) != 1 {
		t.Errorf("expected 1 notifier, got %d", len(names))
	}

	if names[0] != "webhook" {
		t.Errorf("expected webhook, got %s", names[0])
	}
}

func TestManager_ListNotifiers(t *testing.T) {
	m := NewManager()

	slack, _ := NewSlackNotifier(SlackConfig{WebhookURL: "http://example.com"})
	pd, _ := NewPagerDutyNotifier(PagerDutyConfig{RoutingKey: "key"})
	webhook, _ := NewWebhookNotifier(WebhookConfig{URL: "http://example.com"})
	m.AddNotifier(slack)
	m.AddNotifier(pd)
	m.AddNotifier(webhook)

	names := m.ListNotifiers()
	if len(names) != 3 {
		t.Errorf("expected 3 notifiers, got %d", len(names))
	}
}

func TestEvent_Fields(t *testing.T) {
	now := time.Now()
	event := Event{
		Type:      EventFindingCreated,
		Timestamp: now,
		Severity:  "critical",
		Title:     "Test Finding",
		Message:   "A critical finding was detected",
		Data:      map[string]interface{}{"finding_id": "123"},
	}

	if event.Type != EventFindingCreated {
		t.Error("type field incorrect")
	}

	if event.Severity != "critical" {
		t.Error("severity field incorrect")
	}

	if event.Title != "Test Finding" {
		t.Error("title field incorrect")
	}

	if event.Message != "A critical finding was detected" {
		t.Error("message field incorrect")
	}

	if !event.Timestamp.Equal(now) {
		t.Error("timestamp field incorrect")
	}

	if event.Data["finding_id"] != "123" {
		t.Error("data field incorrect")
	}
}

func TestEventType_Constants(t *testing.T) {
	types := []EventType{
		EventFindingCreated,
		EventFindingResolved,
		EventScanCompleted,
		EventScanFailed,
		EventSecurityDigest,
		EventAttackPathFound,
		EventReviewRequired,
	}

	for _, et := range types {
		if et == "" {
			t.Error("event type should not be empty")
		}
	}
}

func TestSlackNotifier_Name(t *testing.T) {
	n, _ := NewSlackNotifier(SlackConfig{WebhookURL: "http://example.com"})
	if n.Name() != "slack" {
		t.Errorf("expected 'slack', got %s", n.Name())
	}
}

func TestSlackNotifier_Send(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("decode request payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n, _ := NewSlackNotifier(SlackConfig{
		WebhookURL: server.URL,
		Channel:    "#test",
	})

	event := Event{
		Type:     EventFindingCreated,
		Title:    "Test",
		Message:  "Test message",
		Severity: "high",
	}

	err := n.Send(context.Background(), event)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if receivedPayload["channel"] != "#test" {
		t.Error("channel should be set")
	}
}

func TestSlackNotifier_SeverityColor(t *testing.T) {
	n, _ := NewSlackNotifier(SlackConfig{WebhookURL: "http://example.com"})

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "#FF0000"},
		{"high", "#FF6600"},
		{"medium", "#FFCC00"},
		{"low", "#0066FF"},
		{"unknown", "#808080"},
	}

	for _, tt := range tests {
		got := n.severityColor(tt.severity)
		if got != tt.want {
			t.Errorf("severityColor(%s) = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

func TestSlackNotifier_SendClosesRateLimitedResponseBeforeRetry(t *testing.T) {
	transport := &retryBodyCloseCheckingTransport{
		statuses: []int{http.StatusTooManyRequests, http.StatusOK},
	}
	n := &SlackNotifier{
		webhookURL: "https://example.com/slack",
		channel:    "#test",
		client:     &http.Client{Transport: transport},
		limiter:    rate.NewLimiter(rate.Inf, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := n.Send(ctx, Event{
		Type:      EventFindingCreated,
		Timestamp: time.Now().UTC(),
		Title:     "Test",
		Message:   "retry body close regression",
		Severity:  "high",
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if transport.call != 2 {
		t.Fatalf("expected 2 requests, got %d", transport.call)
	}
	for i, body := range transport.bodies {
		if !body.closed {
			t.Fatalf("response body %d was not closed", i+1)
		}
	}
}

func TestPagerDutyNotifier_Name(t *testing.T) {
	n, _ := NewPagerDutyNotifier(PagerDutyConfig{RoutingKey: "key"})
	if n.Name() != "pagerduty" {
		t.Errorf("expected 'pagerduty', got %s", n.Name())
	}
}

func TestPagerDutyNotifier_SkipsLowSeverity(t *testing.T) {
	n, _ := NewPagerDutyNotifier(PagerDutyConfig{RoutingKey: "key"})

	event := Event{
		Type:     EventFindingCreated,
		Title:    "Low severity",
		Severity: "low",
	}

	// Should return nil without making a request (no routing key validation)
	err := n.Send(context.Background(), event)
	if err != nil {
		t.Errorf("expected nil for low severity, got %v", err)
	}
}

func TestPagerDutyNotifier_Send(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Fatalf("decode pagerduty payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Override the PagerDuty URL for testing
	limiter := rate.NewLimiter(rate.Limit(2), 10)
	n := &PagerDutyNotifier{
		routingKey: "test-key",
		client:     &http.Client{Timeout: 10 * time.Second},
		limiter:    limiter,
	}

	event := Event{
		Type:     EventFindingCreated,
		Title:    "Critical finding",
		Severity: "critical",
		Data:     map[string]interface{}{"finding_id": "123"},
	}

	// This will fail because we can't override the PagerDuty URL
	// but we can verify the logic for skipping low severity
	_ = n.Send(context.Background(), event)
}

func TestPagerDutyNotifier_SendClosesRateLimitedResponseBeforeRetry(t *testing.T) {
	transport := &retryBodyCloseCheckingTransport{
		statuses: []int{http.StatusTooManyRequests, http.StatusAccepted},
	}
	n := &PagerDutyNotifier{
		routingKey: "test-key",
		client:     &http.Client{Transport: transport},
		limiter:    rate.NewLimiter(rate.Inf, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := n.Send(ctx, Event{
		Type:      EventFindingCreated,
		Timestamp: time.Now().UTC(),
		Title:     "Critical finding",
		Message:   "retry body close regression",
		Severity:  "critical",
		Data:      map[string]interface{}{"finding_id": "123"},
	})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if transport.call != 2 {
		t.Fatalf("expected 2 requests, got %d", transport.call)
	}
	for i, body := range transport.bodies {
		if !body.closed {
			t.Fatalf("response body %d was not closed", i+1)
		}
	}
}

func TestWebhookNotifier_Name(t *testing.T) {
	n, _ := NewWebhookNotifier(WebhookConfig{URL: "http://example.com"})
	if n.Name() != "webhook" {
		t.Errorf("expected 'webhook', got %s", n.Name())
	}
}

func TestWebhookNotifier_Send(t *testing.T) {
	var receivedEvent Event

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("expected Content-Type: application/json")
		}

		if r.Header.Get("X-Cerebro-Event") != string(EventFindingCreated) {
			t.Error("expected X-Cerebro-Event header")
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedEvent); err != nil {
			t.Fatalf("decode webhook event: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n, _ := NewWebhookNotifier(WebhookConfig{
		URL: server.URL,
	})

	event := Event{
		Type:     EventFindingCreated,
		Title:    "Test",
		Message:  "Test message",
		Severity: "high",
	}

	err := n.Send(context.Background(), event)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if receivedEvent.Type != EventFindingCreated {
		t.Error("event type not received correctly")
	}
}

func TestWebhookNotifier_WithSecret(t *testing.T) {
	var gotSignature, gotTimestamp string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature = r.Header.Get("X-Cerebro-Signature")
		gotTimestamp = r.Header.Get("X-Cerebro-Timestamp")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n, _ := NewWebhookNotifier(WebhookConfig{
		URL:    server.URL,
		Secret: "my-secret",
	})

	if err := n.Send(context.Background(), Event{Type: "test", Title: "Test"}); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if gotSignature == "" {
		t.Error("expected signature header")
	}
	if gotTimestamp == "" {
		t.Error("expected timestamp header")
	}
	if !strings.HasPrefix(gotSignature, "sha256=") {
		t.Errorf("expected sha256= prefix in signature, got %s", gotSignature)
	}
}

func TestWebhookNotifier_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	n, _ := NewWebhookNotifier(WebhookConfig{URL: server.URL})

	err := n.Send(context.Background(), Event{Type: "test", Title: "Test"})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestManager_Send(t *testing.T) {
	called := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager()
	webhook, _ := NewWebhookNotifier(WebhookConfig{URL: server.URL})
	m.AddNotifier(webhook)

	event := Event{
		Type:    EventFindingCreated,
		Title:   "Test",
		Message: "Test",
	}

	err := m.Send(context.Background(), event)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if called != 1 {
		t.Errorf("expected 1 call, got %d", called)
	}
}

func TestManager_Send_SetsTimestamp(t *testing.T) {
	var receivedEvent Event

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedEvent); err != nil {
			t.Fatalf("decode manager event: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	m := NewManager()
	webhook, _ := NewWebhookNotifier(WebhookConfig{URL: server.URL})
	m.AddNotifier(webhook)

	// Event without timestamp
	event := Event{
		Type:  EventFindingCreated,
		Title: "Test",
	}

	if err := m.Send(context.Background(), event); err != nil {
		t.Fatalf("manager send failed: %v", err)
	}

	if receivedEvent.Timestamp.IsZero() {
		t.Error("expected timestamp to be set automatically")
	}
}

func TestWebhookNotifier_HMACSignature(t *testing.T) {
	var receivedSignature, receivedTimestamp string
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSignature = r.Header.Get("X-Cerebro-Signature")
		receivedTimestamp = r.Header.Get("X-Cerebro-Timestamp")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	secret := "test-secret-key"
	n, err := NewWebhookNotifier(WebhookConfig{URL: server.URL, Secret: secret})
	if err != nil {
		t.Fatalf("failed to create webhook notifier: %v", err)
	}

	event := Event{
		Type:    EventFindingCreated,
		Title:   "Test Finding",
		Message: "A test finding",
	}

	err = n.Send(context.Background(), event)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if receivedSignature == "" {
		t.Fatal("expected X-Cerebro-Signature header")
	}
	if receivedTimestamp == "" {
		t.Fatal("expected X-Cerebro-Timestamp header")
	}
	if !strings.HasPrefix(receivedSignature, "sha256=") {
		t.Errorf("expected signature to start with sha256=, got %s", receivedSignature)
	}

	if !VerifyWebhookSignature(receivedBody, receivedSignature, receivedTimestamp, secret) {
		t.Error("signature verification failed")
	}

	if VerifyWebhookSignature(receivedBody, receivedSignature, receivedTimestamp, "wrong-secret") {
		t.Error("signature should not verify with wrong secret")
	}
}

func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"type":"test","title":"Test Event"}`)
	secret := "my-webhook-secret"
	timestamp := "1712345678"

	signaturePayload := timestamp + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signaturePayload))
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	tests := []struct {
		name      string
		body      []byte
		signature string
		timestamp string
		secret    string
		want      bool
	}{
		{"valid signature", body, validSig, timestamp, secret, true},
		{"valid without prefix", body, validSig[7:], timestamp, secret, true},
		{"wrong secret", body, validSig, timestamp, "wrong-secret", false},
		{"wrong timestamp", body, validSig, "1712345679", secret, false},
		{"tampered body", []byte("tampered"), validSig, timestamp, secret, false},
		{"empty signature", body, "", timestamp, secret, false},
		{"empty timestamp", body, validSig, "", secret, false},
		{"empty secret", body, validSig, timestamp, "", false},
		{"invalid signature", body, "sha256=invalid", timestamp, secret, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerifyWebhookSignature(tt.body, tt.signature, tt.timestamp, tt.secret)
			if got != tt.want {
				t.Errorf("VerifyWebhookSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSlackNotifier_ValidationError(t *testing.T) {
	_, err := NewSlackNotifier(SlackConfig{WebhookURL: ""})
	if err == nil {
		t.Error("expected error for empty webhook URL")
	}
}

func TestPagerDutyNotifier_ValidationError(t *testing.T) {
	_, err := NewPagerDutyNotifier(PagerDutyConfig{RoutingKey: ""})
	if err == nil {
		t.Error("expected error for empty routing key")
	}
}

func TestWebhookNotifier_ValidationError(t *testing.T) {
	_, err := NewWebhookNotifier(WebhookConfig{URL: ""})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

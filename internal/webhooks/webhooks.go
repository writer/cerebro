package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventType represents webhook event types
type EventType string

const (
	EventFindingCreated    EventType = "finding.created"
	EventFindingResolved   EventType = "finding.resolved"
	EventFindingSuppressed EventType = "finding.suppressed"
	EventScanCompleted     EventType = "scan.completed"
	EventReviewStarted     EventType = "review.started"
	EventReviewCompleted   EventType = "review.completed"
	EventAttackPathFound   EventType = "attack_path.found"
	EventTicketCreated     EventType = "ticket.created"
	EventCloudQuerySynced  EventType = "cloudquery.synced"
	EventGraphRebuilt      EventType = "graph.rebuilt"
)

// Webhook represents a webhook configuration
type Webhook struct {
	ID        string      `json:"id"`
	URL       string      `json:"url"`
	Events    []EventType `json:"events"`
	Secret    string      `json:"secret,omitempty"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
}

// Event represents a webhook event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Delivery represents a webhook delivery attempt
type Delivery struct {
	ID             string    `json:"id"`
	WebhookID      string    `json:"webhook_id"`
	EventType      EventType `json:"event_type"`
	Payload        []byte    `json:"payload"`
	ResponseStatus int       `json:"response_status"`
	ResponseBody   string    `json:"response_body"`
	DeliveredAt    time.Time `json:"delivered_at"`
	DurationMs     int64     `json:"duration_ms"`
	Success        bool      `json:"success"`
}

// Service manages webhooks and event delivery
type Service struct {
	webhooks   map[string]*Webhook
	deliveries []Delivery
	client     *http.Client
	mu         sync.RWMutex
}

func NewService() *Service {
	return &Service{
		webhooks:   make(map[string]*Webhook),
		deliveries: make([]Delivery, 0),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RegisterWebhook registers a new webhook
func (s *Service) RegisterWebhook(url string, events []EventType, secret string) *Webhook {
	s.mu.Lock()
	defer s.mu.Unlock()

	webhook := &Webhook{
		ID:        uuid.New().String(),
		URL:       url,
		Events:    events,
		Secret:    secret,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	s.webhooks[webhook.ID] = webhook
	return webhook
}

// GetWebhook retrieves a webhook by ID
func (s *Service) GetWebhook(id string) (*Webhook, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.webhooks[id]
	return w, ok
}

// ListWebhooks returns all registered webhooks
func (s *Service) ListWebhooks() []*Webhook {
	s.mu.RLock()
	defer s.mu.RUnlock()

	webhooks := make([]*Webhook, 0, len(s.webhooks))
	for _, w := range s.webhooks {
		webhooks = append(webhooks, w)
	}
	return webhooks
}

// DisableWebhook disables a webhook
func (s *Service) DisableWebhook(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if w, ok := s.webhooks[id]; ok {
		w.Enabled = false
		return true
	}
	return false
}

// DeleteWebhook removes a webhook
func (s *Service) DeleteWebhook(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.webhooks[id]; ok {
		delete(s.webhooks, id)
		return true
	}
	return false
}

// Emit sends an event to all subscribed webhooks
func (s *Service) Emit(ctx context.Context, eventType EventType, data map[string]interface{}) {
	event := Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	s.mu.RLock()
	webhooks := make([]*Webhook, 0)
	for _, w := range s.webhooks {
		if w.Enabled && s.isSubscribed(w, eventType) {
			webhooks = append(webhooks, w)
		}
	}
	s.mu.RUnlock()

	// Deliver to all subscribed webhooks in parallel
	var wg sync.WaitGroup
	for _, webhook := range webhooks {
		wg.Add(1)
		go func(w *Webhook) {
			defer wg.Done()
			s.deliver(ctx, w, event)
		}(webhook)
	}
	wg.Wait()
}

func (s *Service) isSubscribed(webhook *Webhook, eventType EventType) bool {
	for _, e := range webhook.Events {
		if e == eventType || e == "*" {
			return true
		}
	}
	return false
}

func (s *Service) deliver(ctx context.Context, webhook *Webhook, event Event) {
	start := time.Now()

	payload, err := json.Marshal(event)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerebro-Event", string(event.Type))
	req.Header.Set("X-Cerebro-Delivery", event.ID)

	// Sign payload if secret is configured
	if webhook.Secret != "" {
		signature := s.sign(payload, webhook.Secret)
		req.Header.Set("X-Cerebro-Signature", signature)
	}

	resp, err := s.client.Do(req)

	delivery := Delivery{
		ID:          uuid.New().String(),
		WebhookID:   webhook.ID,
		EventType:   event.Type,
		Payload:     payload,
		DeliveredAt: time.Now(),
		DurationMs:  time.Since(start).Milliseconds(),
	}

	if err != nil {
		delivery.ResponseStatus = 0
		delivery.ResponseBody = err.Error()
		delivery.Success = false
	} else {
		defer func() { _ = resp.Body.Close() }()
		delivery.ResponseStatus = resp.StatusCode
		delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	}

	s.mu.Lock()
	s.deliveries = append(s.deliveries, delivery)
	// Keep only last 1000 deliveries
	if len(s.deliveries) > 1000 {
		s.deliveries = s.deliveries[len(s.deliveries)-1000:]
	}
	s.mu.Unlock()
}

func (s *Service) sign(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// GetDeliveries returns recent deliveries for a webhook
func (s *Service) GetDeliveries(webhookID string, limit int) []Delivery {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit == 0 {
		limit = 100
	}

	var result []Delivery
	for i := len(s.deliveries) - 1; i >= 0 && len(result) < limit; i-- {
		if webhookID == "" || s.deliveries[i].WebhookID == webhookID {
			result = append(result, s.deliveries[i])
		}
	}
	return result
}

// Helper functions to emit common events

func (s *Service) EmitFindingCreated(ctx context.Context, findingID, policyID, severity string, resource map[string]interface{}) {
	s.Emit(ctx, EventFindingCreated, map[string]interface{}{
		"finding_id": findingID,
		"policy_id":  policyID,
		"severity":   severity,
		"resource":   resource,
	})
}

func (s *Service) EmitFindingResolved(ctx context.Context, findingID string) {
	s.Emit(ctx, EventFindingResolved, map[string]interface{}{
		"finding_id": findingID,
	})
}

func (s *Service) EmitScanCompleted(ctx context.Context, scanned, violations int64, duration time.Duration) {
	s.Emit(ctx, EventScanCompleted, map[string]interface{}{
		"scanned":     scanned,
		"violations":  violations,
		"duration_ms": duration.Milliseconds(),
	})
}

func (s *Service) EmitAttackPathFound(ctx context.Context, pathID, severity string, steps int) {
	s.Emit(ctx, EventAttackPathFound, map[string]interface{}{
		"path_id":  pathID,
		"severity": severity,
		"steps":    steps,
	})
}

// VerifySignature verifies a webhook signature (for incoming webhooks)
func VerifySignature(payload []byte, signature, secret string) bool {
	expected := "sha256=" + hex.EncodeToString(func() []byte {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write(payload)
		return h.Sum(nil)
	}())
	return hmac.Equal([]byte(signature), []byte(expected))
}

// WebhookHandler creates an HTTP handler for webhook management
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		webhooks := s.ListWebhooks()
		// Redact secrets
		for _, wh := range webhooks {
			if wh.Secret != "" {
				wh.Secret = "***"
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"webhooks": webhooks})
	})

	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL    string      `json:"url"`
			Events []EventType `json:"events"`
			Secret string      `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhook := s.RegisterWebhook(req.URL, req.Events, req.Secret)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(webhook)
	})

	mux.HandleFunc("DELETE /{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if s.DeleteWebhook(id) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	mux.HandleFunc("GET /{id}/deliveries", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		deliveries := s.GetDeliveries(id, 100)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"deliveries": deliveries})
	})

	mux.HandleFunc("POST /test", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Send test event
		testEvent := Event{
			ID:        uuid.New().String(),
			Type:      "test",
			Timestamp: time.Now().UTC(),
			Data:      map[string]interface{}{"message": "Test webhook from Cerebro"},
		}

		payload, _ := json.Marshal(testEvent)
		httpReq, _ := http.NewRequestWithContext(r.Context(), "POST", req.URL, bytes.NewReader(payload))
		httpReq.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(httpReq)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
			return
		}
		defer func() { _ = resp.Body.Close() }()

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": resp.StatusCode >= 200 && resp.StatusCode < 300,
			"status":  resp.StatusCode,
		})
	})

	return mux
}

// EventEmitter interface for services that emit webhook events
type EventEmitter interface {
	Emit(ctx context.Context, eventType EventType, data map[string]interface{})
}

// Ensure Service implements EventEmitter
var _ EventEmitter = (*Service)(nil)

// NoopEmitter is a no-op implementation for when webhooks are disabled
type NoopEmitter struct{}

func (n *NoopEmitter) Emit(ctx context.Context, eventType EventType, data map[string]interface{}) {}

var _ EventEmitter = (*NoopEmitter)(nil)

// NewNoopEmitter creates a no-op emitter
func NewNoopEmitter() *NoopEmitter {
	return &NoopEmitter{}
}

// MustEmitter returns the service if not nil, otherwise returns a no-op emitter
func MustEmitter(s *Service) EventEmitter {
	if s == nil {
		return NewNoopEmitter()
	}
	return s
}

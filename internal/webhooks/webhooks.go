package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
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

const defaultDeliveryConcurrency = 5

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
	webhooks            map[string]*Webhook
	deliveries          []Delivery
	client              *http.Client
	deliveryConcurrency int
	mu                  sync.RWMutex
}

func NewService() *Service {
	return &Service{
		webhooks:   make(map[string]*Webhook),
		deliveries: make([]Delivery, 0),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		deliveryConcurrency: defaultDeliveryConcurrency,
	}
}

func (s *Service) SetDeliveryConcurrency(n int) {
	if n > 0 {
		s.deliveryConcurrency = n
	}
}

// RegisterWebhook registers a new webhook with SSRF validation
func (s *Service) RegisterWebhook(webhookURL string, events []EventType, secret string) (*Webhook, error) {
	// Validate URL to prevent SSRF attacks
	if err := validateWebhookURL(webhookURL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	webhook := &Webhook{
		ID:        uuid.New().String(),
		URL:       webhookURL,
		Events:    events,
		Secret:    secret,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	s.webhooks[webhook.ID] = webhook
	return webhook, nil
}

// validateWebhookURL validates that a webhook URL is safe (prevents SSRF)
func validateWebhookURL(webhookURL string) error {
	parsed, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Require HTTPS for security
	if parsed.Scheme != "https" {
		return fmt.Errorf("HTTPS is required for webhook URLs")
	}

	// Get hostname without port
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	// Block localhost and loopback
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return fmt.Errorf("localhost URLs are not allowed")
	}

	// Block link-local addresses (metadata services like 169.254.169.254)
	if strings.HasPrefix(hostname, "169.254.") {
		return fmt.Errorf("link-local addresses are not allowed")
	}

	// Resolve hostname to check for internal IPs
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return fmt.Errorf("unable to resolve hostname: %w", err)
	}

	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("webhook URL resolves to private/internal IP address")
		}
	}

	return nil
}

// RegisterWebhookUnsafe registers a webhook without URL validation.
// This is exported for testing but should NOT be used in production code.
func (s *Service) RegisterWebhookUnsafe(webhookURL string, events []EventType, secret string) *Webhook {
	s.mu.Lock()
	defer s.mu.Unlock()

	webhook := &Webhook{
		ID:        uuid.New().String(),
		URL:       webhookURL,
		Events:    events,
		Secret:    secret,
		Enabled:   true,
		CreatedAt: time.Now(),
	}

	s.webhooks[webhook.ID] = webhook
	return webhook
}

// isPublicIP checks if an IP address is publicly routable
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// Additional check for IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return false
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return false
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return false
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
	}

	return true
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
	_ = s.EmitWithErrors(ctx, eventType, data)
}

func (s *Service) EmitWithErrors(ctx context.Context, eventType EventType, data map[string]interface{}) error {
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

	var group errgroup.Group
	if s.deliveryConcurrency > 0 {
		group.SetLimit(s.deliveryConcurrency)
	}
	var mu sync.Mutex
	var errs []error

	for _, webhook := range webhooks {
		w := webhook
		group.Go(func() error {
			if err := s.deliver(ctx, w, event); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
			return nil
		})
	}

	_ = group.Wait()
	return errors.Join(errs...)
}

func (s *Service) isSubscribed(webhook *Webhook, eventType EventType) bool {
	for _, e := range webhook.Events {
		if e == eventType || e == "*" {
			return true
		}
	}
	return false
}

func (s *Service) deliver(ctx context.Context, webhook *Webhook, event Event) error {
	start := time.Now()

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhook.URL, bytes.NewReader(payload))
	if err != nil {
		return err
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

	var deliveryErr error
	if err != nil {
		delivery.ResponseStatus = 0
		delivery.ResponseBody = err.Error()
		delivery.Success = false
		deliveryErr = err
	} else {
		defer func() { _ = resp.Body.Close() }()
		delivery.ResponseStatus = resp.StatusCode
		delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
		if !delivery.Success {
			deliveryErr = fmt.Errorf("webhook %s returned status %d", webhook.ID, resp.StatusCode)
		}
	}

	s.mu.Lock()
	s.deliveries = append(s.deliveries, delivery)
	// Keep only last 1000 deliveries
	if len(s.deliveries) > 1000 {
		s.deliveries = s.deliveries[len(s.deliveries)-1000:]
	}
	s.mu.Unlock()

	return deliveryErr
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

func (s *Service) EmitFindingCreated(ctx context.Context, findingID, policyID, severity string, resource map[string]interface{}) error {
	return s.EmitWithErrors(ctx, EventFindingCreated, map[string]interface{}{
		"finding_id": findingID,
		"policy_id":  policyID,
		"severity":   severity,
		"resource":   resource,
	})
}

func (s *Service) EmitFindingResolved(ctx context.Context, findingID string) error {
	return s.EmitWithErrors(ctx, EventFindingResolved, map[string]interface{}{
		"finding_id": findingID,
	})
}

func (s *Service) EmitScanCompleted(ctx context.Context, scanned, violations int64, duration time.Duration) error {
	return s.EmitWithErrors(ctx, EventScanCompleted, map[string]interface{}{
		"scanned":     scanned,
		"violations":  violations,
		"duration_ms": duration.Milliseconds(),
	})
}

func (s *Service) EmitAttackPathFound(ctx context.Context, pathID, severity string, steps int) error {
	return s.EmitWithErrors(ctx, EventAttackPathFound, map[string]interface{}{
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
		webhook, err := s.RegisterWebhook(req.URL, req.Events, req.Secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
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

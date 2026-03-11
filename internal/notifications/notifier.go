package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Event represents a notification event
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity,omitempty"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

type EventType string

const (
	EventFindingCreated  EventType = "finding.created"
	EventFindingResolved EventType = "finding.resolved"
	EventScanCompleted   EventType = "scan.completed"
	EventScanFailed      EventType = "scan.failed"
	EventSecurityDigest  EventType = "security.digest"
	EventAttackPathFound EventType = "attack_path.found"
	EventReviewRequired  EventType = "review.required"
)

// Notifier sends notifications
type Notifier interface {
	Send(ctx context.Context, event Event) error
	Name() string
	Test(ctx context.Context) error
}

// Manager coordinates multiple notifiers with thread-safe access
type Manager struct {
	notifiers []Notifier
	client    *http.Client
	mu        sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		notifiers: make([]Notifier, 0),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (m *Manager) AddNotifier(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers = append(m.notifiers, n)
}

func (m *Manager) Send(ctx context.Context, event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Take a snapshot of notifiers to avoid holding lock during sends
	m.mu.RLock()
	notifiers := make([]Notifier, len(m.notifiers))
	copy(notifiers, m.notifiers)
	m.mu.RUnlock()

	var errs []error
	for _, n := range notifiers {
		if err := n.Send(ctx, event); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name(), err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *Manager) ListNotifiers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, len(m.notifiers))
	for i, n := range m.notifiers {
		names[i] = n.Name()
	}
	return names
}

// SlackNotifier sends notifications to Slack
type SlackNotifier struct {
	webhookURL string
	channel    string
	client     *http.Client
	limiter    *rate.Limiter
}

type SlackConfig struct {
	WebhookURL string
	Channel    string
}

// NewSlackNotifier creates a Slack notifier with the given config.
// Returns an error if the webhook URL is empty.
func NewSlackNotifier(cfg SlackConfig) (*SlackNotifier, error) {
	if cfg.WebhookURL == "" {
		return nil, errors.New("slack webhook URL is required")
	}
	return &SlackNotifier{
		webhookURL: cfg.WebhookURL,
		channel:    cfg.Channel,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		// Limit to 1 request per second with burst of 5
		limiter: rate.NewLimiter(rate.Limit(1), 5),
	}, nil
}

func (s *SlackNotifier) Name() string { return "slack" }

func (s *SlackNotifier) Send(ctx context.Context, event Event) error {
	if err := s.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}

	color := s.severityColor(event.Severity)

	fields := []map[string]interface{}{
		{"title": "Type", "value": string(event.Type), "short": true},
		{"title": "Severity", "value": event.Severity, "short": true},
	}

	// Add finding ID if available
	if findingID, ok := event.Data["finding_id"].(string); ok && findingID != "" {
		fields = append(fields, map[string]interface{}{
			"title": "Finding ID",
			"value": findingID,
			"short": true,
		})
	}

	// Add resource info if available
	if resourceID, ok := event.Data["resource_id"].(string); ok && resourceID != "" {
		fields = append(fields, map[string]interface{}{
			"title": "Resource",
			"value": resourceID,
			"short": true,
		})
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  event.Title,
				"text":   event.Message,
				"footer": "Cerebro Security",
				"ts":     event.Timestamp.Unix(),
				"fields": fields,
			},
		},
	}

	if s.channel != "" {
		payload["channel"] = s.channel
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		// Retry with exponential backoff
		for attempt := 1; attempt <= 3; attempt++ {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			req, err = http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err = s.client.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusTooManyRequests {
				break
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("slack rate limited after retries: %d", resp.StatusCode)
		}
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}
	return nil
}

func (s *SlackNotifier) Test(ctx context.Context) error {
	return s.Send(ctx, Event{
		Type:     "test",
		Title:    "Cerebro Test Notification",
		Message:  "This is a test notification from Cerebro.",
		Severity: "info",
	})
}

func (s *SlackNotifier) severityColor(severity string) string {
	switch severity {
	case "critical":
		return "#FF0000"
	case "high":
		return "#FF6600"
	case "medium":
		return "#FFCC00"
	case "low":
		return "#0066FF"
	default:
		return "#808080"
	}
}

// PagerDutyNotifier sends alerts to PagerDuty
type PagerDutyNotifier struct {
	routingKey string
	client     *http.Client
	limiter    *rate.Limiter
}

type PagerDutyConfig struct {
	RoutingKey string // Integration key from PagerDuty
}

// NewPagerDutyNotifier creates a PagerDuty notifier with the given config.
// Returns an error if the routing key is empty.
func NewPagerDutyNotifier(cfg PagerDutyConfig) (*PagerDutyNotifier, error) {
	if cfg.RoutingKey == "" {
		return nil, errors.New("pagerduty routing key is required")
	}
	return &PagerDutyNotifier{
		routingKey: cfg.RoutingKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		limiter: rate.NewLimiter(rate.Limit(2), 10),
	}, nil
}

func (p *PagerDutyNotifier) Name() string { return "pagerduty" }

func (p *PagerDutyNotifier) Send(ctx context.Context, event Event) error {
	// Only send to PagerDuty for high/critical severity
	if event.Severity != "critical" && event.Severity != "high" {
		return nil
	}

	if err := p.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit: %w", err)
	}

	severity := "warning"
	if event.Severity == "critical" {
		severity = "critical"
	}

	payload := map[string]interface{}{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("cerebro-%s-%v", event.Type, event.Data["finding_id"]),
		"payload": map[string]interface{}{
			"summary":   event.Title,
			"severity":  severity,
			"source":    "cerebro",
			"timestamp": event.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"type":    event.Type,
				"message": event.Message,
				"data":    event.Data,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal pagerduty payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		// Retry with exponential backoff
		for attempt := 1; attempt <= 3; attempt++ {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			req, err = http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err = p.client.Do(req)
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusTooManyRequests {
				break
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("pagerduty rate limited after retries: %d", resp.StatusCode)
		}
	}

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pagerduty returned status %d", resp.StatusCode)
	}
	return nil
}

func (p *PagerDutyNotifier) Test(ctx context.Context) error {
	return p.Send(ctx, Event{
		Type:     "test",
		Title:    "Cerebro Test Alert",
		Message:  "This is a test alert from Cerebro.",
		Severity: "high",
		Data:     map[string]interface{}{"finding_id": "test-123"},
	})
}

// WebhookNotifier sends to a generic webhook URL
type WebhookNotifier struct {
	url    string
	secret string
	client *http.Client
}

type WebhookConfig struct {
	URL    string
	Secret string
}

// NewWebhookNotifier creates a webhook notifier with the given config.
// Returns an error if the URL is empty.
func NewWebhookNotifier(cfg WebhookConfig) (*WebhookNotifier, error) {
	if cfg.URL == "" {
		return nil, errors.New("webhook URL is required")
	}
	return &WebhookNotifier{
		url:    cfg.URL,
		secret: cfg.Secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (w *WebhookNotifier) Name() string { return "webhook" }

func (w *WebhookNotifier) Send(ctx context.Context, event Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerebro-Event", string(event.Type))

	// Add HMAC signature for webhook authentication
	if w.secret != "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		signaturePayload := timestamp + "." + string(body)
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write([]byte(signaturePayload))
		signature := hex.EncodeToString(mac.Sum(nil))

		req.Header.Set("X-Cerebro-Timestamp", timestamp)
		req.Header.Set("X-Cerebro-Signature", "sha256="+signature)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func (w *WebhookNotifier) Test(ctx context.Context) error {
	return w.Send(ctx, Event{
		Type:     "test",
		Title:    "Cerebro Test Webhook",
		Message:  "This is a test webhook from Cerebro.",
		Severity: "info",
	})
}

// VerifyWebhookSignature verifies an HMAC-SHA256 signature from X-Cerebro-Signature header.
// The signature payload is "<timestamp>.<body>".
func VerifyWebhookSignature(body []byte, signature, timestamp, secret string) bool {
	if signature == "" || timestamp == "" || secret == "" {
		return false
	}

	// Remove "sha256=" prefix if present
	if len(signature) > 7 && signature[:7] == "sha256=" {
		signature = signature[7:]
	}

	signaturePayload := timestamp + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signaturePayload))
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(signature), []byte(expected))
}

// Ensure implementations satisfy interface
var _ Notifier = (*SlackNotifier)(nil)
var _ Notifier = (*PagerDutyNotifier)(nil)
var _ Notifier = (*WebhookNotifier)(nil)

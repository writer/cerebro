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
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// ErrInvalidWebhookURL is returned when a webhook URL fails validation
var ErrInvalidWebhookURL = errors.New("invalid webhook URL")

// ValidateWebhookURL checks if a URL is safe for webhook delivery.
// It prevents SSRF by blocking:
// - Non-HTTPS URLs (except localhost in development)
// - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
// - Loopback addresses (127.x, ::1)
// - Link-local addresses (169.254.x)
// - Cloud metadata endpoints (169.254.169.254)
func ValidateWebhookURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("%w: empty URL", ErrInvalidWebhookURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidWebhookURL, err)
	}

	// Require HTTPS for production webhooks
	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: HTTPS is required for webhook URLs", ErrInvalidWebhookURL)
	}

	// Get the hostname (without port)
	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("%w: missing hostname", ErrInvalidWebhookURL)
	}

	// Check for localhost/loopback (block these in production)
	lowHost := strings.ToLower(hostname)
	if lowHost == "localhost" || lowHost == "127.0.0.1" || lowHost == "::1" {
		return fmt.Errorf("%w: localhost not allowed", ErrInvalidWebhookURL)
	}

	// Resolve the hostname to check for private IPs
	dnsCtx, cancel := context.WithTimeout(context.Background(), webhookDNSLookupTimeout)
	defer cancel()
	addrRecords, err := net.DefaultResolver.LookupIPAddr(dnsCtx, hostname)
	ips := make([]net.IP, 0, len(addrRecords))
	for _, record := range addrRecords {
		ips = append(ips, record.IP)
	}
	if err != nil {
		// If DNS fails, check if it's an IP literal
		ip := net.ParseIP(hostname)
		if ip != nil {
			ips = []net.IP{ip}
		} else {
			return fmt.Errorf("%w: cannot resolve hostname", ErrInvalidWebhookURL)
		}
	}

	for _, ip := range ips {
		if isPrivateOrReservedIP(ip) {
			return fmt.Errorf("%w: private or reserved IP not allowed", ErrInvalidWebhookURL)
		}
	}

	return nil
}

// isPrivateOrReservedIP checks if an IP is private, loopback, or reserved
func isPrivateOrReservedIP(ip net.IP) bool {
	// Check for loopback (127.x.x.x or ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for private networks
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local (169.254.x.x or fe80::/10)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for cloud metadata endpoint (169.254.169.254)
	metadataIP := net.ParseIP("169.254.169.254")
	if ip.Equal(metadataIP) {
		return true
	}

	// Check for unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	return false
}

// EventType represents webhook event types
type EventType string

const (
	EventFindingCreated             EventType = "finding.created"
	EventFindingResolved            EventType = "finding.resolved"
	EventFindingSuppressed          EventType = "finding.suppressed"
	EventScanCompleted              EventType = "scan.completed"
	EventSchedulerJobRun            EventType = "scheduler.job.run"
	EventReviewStarted              EventType = "review.started"
	EventReviewCompleted            EventType = "review.completed"
	EventAttackPathFound            EventType = "attack_path.found"
	EventTicketCreated              EventType = "ticket.created"
	EventGraphRebuilt               EventType = "graph.rebuilt"
	EventGraphMutated               EventType = "graph.mutated"
	EventThreatIntelSynced          EventType = "threatintel.feed.synced"
	EventRuntimeIngested            EventType = "runtime.ingested"
	EventRbacUserCreated            EventType = "rbac.user.created"
	EventRbacRoleAssigned           EventType = "rbac.role.assigned"
	EventRbacTenantCreated          EventType = "rbac.tenant.created"
	EventWebhookCreated             EventType = "webhook.created"
	EventRemediationRule            EventType = "remediation.rule.created"
	EventRemediationActionCompleted EventType = "remediation.action.completed"
	EventRemediationActionFailed    EventType = "remediation.action.failed"
	EventSignalCreated              EventType = "signal.created"
	EventSignalResolved             EventType = "signal.resolved"
	EventSignalEscalated            EventType = "signal.escalated"

	EventRiskScoreChanged                   EventType = "risk_score.changed"
	EventToxicCombinationDetected           EventType = "toxic_combination.detected"
	EventToxicCombinationResolved           EventType = "toxic_combination.resolved"
	EventApprovalRequested                  EventType = "approval.requested"
	EventCohortOutlierDetected              EventType = "cohort.outlier_detected"
	EventComplianceScoreChanged             EventType = "compliance.score_changed"
	EventPlatformClaimWritten               EventType = "platform.claim.written"
	EventPlatformClaimAdjudicated           EventType = "platform.claim.adjudicated"
	EventPlatformDecisionRecorded           EventType = "platform.decision.recorded"
	EventPlatformOutcomeRecorded            EventType = "platform.outcome.recorded"
	EventPlatformActionRecorded             EventType = "platform.action.recorded"
	EventPlatformReportRunQueued            EventType = "platform.report_run.queued"
	EventPlatformReportRunStarted           EventType = "platform.report_run.started"
	EventPlatformReportRunCompleted         EventType = "platform.report_run.completed"
	EventPlatformReportRunFailed            EventType = "platform.report_run.failed"
	EventPlatformReportRunCanceled          EventType = "platform.report_run.canceled"
	EventPlatformReportSectionEmitted       EventType = "platform.report_run.section_emitted"
	EventPlatformReportSnapshotMaterialized EventType = "platform.report_snapshot.materialized"
	EventPlatformGraphChangelogComputed     EventType = "platform.graph_changelog.computed"
	EventSecurityWorkloadScanStarted        EventType = "security.workload_scan.started"
	EventSecurityWorkloadScanCompleted      EventType = "security.workload_scan.completed"
	EventSecurityWorkloadScanFailed         EventType = "security.workload_scan.failed"
	EventSecurityWorkloadScanReconciled     EventType = "security.workload_scan.reconciled"
	EventSecurityImageScanStarted           EventType = "security.image_scan.started"
	EventSecurityImageScanCompleted         EventType = "security.image_scan.completed"
	EventSecurityImageScanFailed            EventType = "security.image_scan.failed"
	EventSecurityFunctionScanStarted        EventType = "security.function_scan.started"
	EventSecurityFunctionScanCompleted      EventType = "security.function_scan.completed"
	EventSecurityFunctionScanFailed         EventType = "security.function_scan.failed"
)

var defaultEventTypes = []EventType{
	EventFindingCreated,
	EventFindingResolved,
	EventFindingSuppressed,
	EventScanCompleted,
	EventSchedulerJobRun,
	EventReviewStarted,
	EventReviewCompleted,
	EventAttackPathFound,
	EventTicketCreated,
	EventGraphRebuilt,
	EventGraphMutated,
	EventThreatIntelSynced,
	EventRuntimeIngested,
	EventRbacUserCreated,
	EventRbacRoleAssigned,
	EventRbacTenantCreated,
	EventWebhookCreated,
	EventRemediationRule,
	EventRemediationActionCompleted,
	EventRemediationActionFailed,
	EventSignalCreated,
	EventSignalResolved,
	EventSignalEscalated,
	EventRiskScoreChanged,
	EventToxicCombinationDetected,
	EventToxicCombinationResolved,
	EventApprovalRequested,
	EventCohortOutlierDetected,
	EventComplianceScoreChanged,
	EventPlatformClaimWritten,
	EventPlatformClaimAdjudicated,
	EventPlatformDecisionRecorded,
	EventPlatformOutcomeRecorded,
	EventPlatformActionRecorded,
	EventPlatformReportRunQueued,
	EventPlatformReportRunStarted,
	EventPlatformReportRunCompleted,
	EventPlatformReportRunFailed,
	EventPlatformReportRunCanceled,
	EventPlatformReportSectionEmitted,
	EventPlatformReportSnapshotMaterialized,
	EventPlatformGraphChangelogComputed,
	EventSecurityWorkloadScanStarted,
	EventSecurityWorkloadScanCompleted,
	EventSecurityWorkloadScanFailed,
	EventSecurityWorkloadScanReconciled,
	EventSecurityImageScanStarted,
	EventSecurityImageScanCompleted,
	EventSecurityImageScanFailed,
	EventSecurityFunctionScanStarted,
	EventSecurityFunctionScanCompleted,
	EventSecurityFunctionScanFailed,
}

// DefaultEventTypes returns the list of webhook event types registered by default.
func DefaultEventTypes() []EventType {
	return append([]EventType(nil), defaultEventTypes...)
}

const (
	defaultDeliveryConcurrency = 5
	webhookDNSLookupTimeout    = 5 * time.Second
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

// EventSubscriber handles in-process webhook events.
type EventSubscriber func(ctx context.Context, event Event) error

// EventPublisher can publish webhook events to external systems (for example JetStream).
type EventPublisher interface {
	Publish(ctx context.Context, event Event) error
	Close() error
}

// EventPublisherReadiness can be implemented by publishers that expose readiness checks.
type EventPublisherReadiness interface {
	Ready(ctx context.Context) error
}

// EventPublisherStatusReporter can be implemented by publishers that expose runtime status.
type EventPublisherStatusReporter interface {
	Status(ctx context.Context) map[string]interface{}
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
	eventPublisher      EventPublisher
	subscribers         []EventSubscriber
	mu                  sync.RWMutex
	skipValidation      bool // For testing only - allows localhost URLs
}

func NewService() *Service {
	return &Service{
		webhooks:    make(map[string]*Webhook),
		deliveries:  make([]Delivery, 0),
		subscribers: make([]EventSubscriber, 0),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		deliveryConcurrency: defaultDeliveryConcurrency,
	}
}

// SetEventPublisher sets an optional publisher used for all emitted events.
func (s *Service) SetEventPublisher(publisher EventPublisher) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.eventPublisher != nil {
		_ = s.eventPublisher.Close()
	}
	s.eventPublisher = publisher
}

// EventPublisherReady checks publisher readiness when supported.
func (s *Service) EventPublisherReady(ctx context.Context) error {
	s.mu.RLock()
	publisher := s.eventPublisher
	s.mu.RUnlock()

	if publisher == nil {
		return errors.New("event publisher is not configured")
	}

	readiness, ok := publisher.(EventPublisherReadiness)
	if !ok {
		return nil
	}

	if ctx == nil {
		return errors.New("context is required")
	}

	return readiness.Ready(ctx)
}

// EventPublisherStatus returns publisher runtime status when supported.
func (s *Service) EventPublisherStatus(ctx context.Context) map[string]interface{} {
	s.mu.RLock()
	publisher := s.eventPublisher
	s.mu.RUnlock()

	if publisher == nil {
		return map[string]interface{}{"configured": false, "ready": false}
	}

	statusReporter, ok := publisher.(EventPublisherStatusReporter)
	if !ok {
		return map[string]interface{}{"configured": true, "ready": true}
	}

	if ctx == nil {
		return map[string]interface{}{
			"configured": true,
			"ready":      false,
			"error":      "context is required",
		}
	}
	status := statusReporter.Status(ctx)
	if status == nil {
		status = map[string]interface{}{}
	}
	status["configured"] = true
	return status
}

// Subscribe registers an in-process subscriber for all emitted events.
func (s *Service) Subscribe(subscriber EventSubscriber) {
	if subscriber == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscribers = append(s.subscribers, subscriber)
}

// Close releases service resources.
func (s *Service) Close() error {
	s.mu.Lock()
	publisher := s.eventPublisher
	s.eventPublisher = nil
	s.mu.Unlock()

	if publisher == nil {
		return nil
	}
	return publisher.Close()
}

func (s *Service) SetDeliveryConcurrency(n int) {
	if n > 0 {
		s.deliveryConcurrency = n
	}
}

// NewServiceForTesting creates a service that skips URL validation (for testing only)
func NewServiceForTesting() *Service {
	s := NewService()
	s.skipValidation = true
	return s
}

// RegisterWebhook registers a new webhook with URL validation to prevent SSRF
func (s *Service) RegisterWebhook(webhookURL string, events []EventType, secret string) (*Webhook, error) {
	// Validate URL to prevent SSRF attacks (skip in test mode)
	if !s.skipValidation {
		if err := ValidateWebhookURL(webhookURL); err != nil {
			return nil, err
		}
	}

	// Validate events
	if len(events) == 0 {
		return nil, errors.New("at least one event type is required")
	}
	for _, e := range events {
		if !isValidEventType(e) {
			return nil, fmt.Errorf("invalid event type: %s", e)
		}
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

// isValidEventType checks if an event type is valid
func isValidEventType(e EventType) bool {
	switch e {
	case EventFindingCreated, EventFindingResolved, EventFindingSuppressed,
		EventScanCompleted, EventSchedulerJobRun, EventReviewStarted, EventReviewCompleted,
		EventAttackPathFound, EventTicketCreated, EventGraphRebuilt, EventGraphMutated,
		EventThreatIntelSynced, EventRuntimeIngested, EventRbacUserCreated,
		EventRbacRoleAssigned, EventRbacTenantCreated, EventWebhookCreated,
		EventRemediationRule, EventRemediationActionCompleted, EventRemediationActionFailed,
		EventSignalCreated, EventSignalResolved, EventSignalEscalated,
		EventRiskScoreChanged, EventToxicCombinationDetected, EventToxicCombinationResolved,
		EventApprovalRequested, EventCohortOutlierDetected, EventComplianceScoreChanged,
		EventPlatformClaimWritten, EventPlatformClaimAdjudicated, EventPlatformDecisionRecorded,
		EventPlatformOutcomeRecorded, EventPlatformActionRecorded, EventPlatformReportRunQueued,
		EventPlatformReportRunStarted, EventPlatformReportRunCompleted, EventPlatformReportRunFailed,
		EventPlatformReportRunCanceled, EventPlatformReportSectionEmitted,
		EventPlatformReportSnapshotMaterialized, EventPlatformGraphChangelogComputed,
		EventSecurityWorkloadScanStarted, EventSecurityWorkloadScanCompleted,
		EventSecurityWorkloadScanFailed, EventSecurityWorkloadScanReconciled,
		EventSecurityImageScanStarted, EventSecurityImageScanCompleted,
		EventSecurityImageScanFailed, EventSecurityFunctionScanStarted,
		EventSecurityFunctionScanCompleted, EventSecurityFunctionScanFailed:
		return true
	default:
		return false
	}
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

// Emit sends an event to all subscribed webhooks. Errors are logged but not returned.
func (s *Service) Emit(ctx context.Context, eventType EventType, data map[string]interface{}) {
	if err := s.EmitWithErrors(ctx, eventType, data); err != nil {
		slog.Warn("webhook delivery errors", "event_type", string(eventType), "error", err.Error())
	}
}

func (s *Service) EmitWithErrors(ctx context.Context, eventType EventType, data map[string]interface{}) error {
	event := Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	s.mu.RLock()
	publisher := s.eventPublisher
	subscribers := append([]EventSubscriber(nil), s.subscribers...)
	webhooks := make([]*Webhook, 0)
	for _, w := range s.webhooks {
		if w.Enabled && s.isSubscribed(w, eventType) {
			webhooks = append(webhooks, w)
		}
	}
	s.mu.RUnlock()

	var errs []error
	if publisher != nil {
		if err := publisher.Publish(ctx, event); err != nil {
			errs = append(errs, fmt.Errorf("event publisher: %w", err))
		}
	}
	for _, subscriber := range subscribers {
		if err := subscriber(ctx, event); err != nil {
			errs = append(errs, fmt.Errorf("event subscriber: %w", err))
		}
	}

	var group errgroup.Group
	if s.deliveryConcurrency > 0 {
		group.SetLimit(s.deliveryConcurrency)
	}
	var mu sync.Mutex

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
			Secret string      `json:"secret"` // #nosec G117 -- explicit webhook signing secret field
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
		_ = json.NewEncoder(w).Encode(webhook) // #nosec G117 -- webhook secret is intentionally returned on creation for client use
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

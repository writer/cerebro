package events

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
)

//go:embed routes.yaml
var defaultAlertRoutesYAML []byte

const (
	defaultAlertNotifySubjectPrefix = "ensemble.notify"
	defaultAlertEscalationReason    = "alert_unacknowledged"
)

func normalizeAlertSubjectPrefix(value string) string {
	return strings.Trim(strings.TrimSpace(value), ".")
}

type AlertRoutingConfig struct {
	Routes []AlertRoute `json:"routes" yaml:"routes"`
}

type AlertRoute struct {
	Name          string                 `json:"name,omitempty" yaml:"name"`
	Match         AlertRouteMatch        `json:"match" yaml:"match"`
	DeliverTo     []AlertRouteDelivery   `json:"deliver_to" yaml:"deliver_to"`
	GroupBy       string                 `json:"group_by,omitempty" yaml:"group_by"`
	Throttle      string                 `json:"throttle,omitempty" yaml:"throttle"`
	Digest        string                 `json:"digest,omitempty" yaml:"digest"`
	EscalateAfter string                 `json:"escalate_after,omitempty" yaml:"escalate_after"`
	Metadata      map[string]interface{} `json:"metadata,omitempty" yaml:"metadata"`
}

type AlertRouteMatch struct {
	EventType string   `json:"event_type" yaml:"event_type"`
	Severity  []string `json:"severity,omitempty" yaml:"severity"`
	Delta     string   `json:"delta,omitempty" yaml:"delta"`
}

type AlertRouteDelivery struct {
	Type    string `json:"type" yaml:"type"`
	Channel string `json:"channel,omitempty" yaml:"channel"`
}

type AlertRecipient struct {
	Type     string                 `json:"type"`
	ID       string                 `json:"id"`
	Channel  string                 `json:"channel,omitempty"`
	Label    string                 `json:"label,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type AlertSender interface {
	Send(ctx context.Context, subject string, payload []byte) error
	Close() error
}

type AlertRecipientResolver interface {
	ResolveEntityOwner(ctx context.Context, entityID string, event webhooks.Event) []AlertRecipient
	ResolveAccountTeam(ctx context.Context, entityID string, event webhooks.Event) []AlertRecipient
	ResolveManager(ctx context.Context, personID string) (AlertRecipient, bool)
}

type AlertRouterOptions struct {
	Config        AlertRoutingConfig
	Resolver      AlertRecipientResolver
	Sender        AlertSender
	StateStore    AlertRouterStateStore
	SubjectPrefix string
	Logger        *slog.Logger
	Now           func() time.Time
}

type AlertNotifierConfig struct {
	Stream         string
	SubjectPrefix  string
	URLs           []string
	ConnectTimeout time.Duration
	AuthMode       string
	Username       string
	Password       string
	NKeySeed       string
	UserJWT        string

	TLSEnabled            bool
	TLSCAFile             string
	TLSCertFile           string
	TLSKeyFile            string
	TLSServerName         string
	TLSInsecureSkipVerify bool
}

type NATSAlertNotifier struct {
	nc            *nats.Conn
	js            nats.JetStreamContext
	stream        string
	subjectPrefix string
	logger        *slog.Logger
}

type AlertRouter struct {
	logger        *slog.Logger
	routes        []compiledAlertRoute
	resolver      AlertRecipientResolver
	sender        AlertSender
	stateStore    AlertRouterStateStore
	subjectPrefix string
	now           func() time.Time

	mu             sync.Mutex
	stateRevision  uint64
	throttleUntil  map[string]time.Time
	digestBuckets  map[string]*digestBucket
	pendingAcks    map[string]pendingAck
	fallbackAlerts []outboundAlert
}

type compiledAlertRoute struct {
	id            string
	name          string
	match         AlertRouteMatch
	deliverTo     []AlertRouteDelivery
	groupBy       string
	throttle      time.Duration
	digestEvery   time.Duration
	escalateAfter time.Duration
	metadata      map[string]interface{}
	severitySet   map[string]struct{}
	deltaMatch    numericMatcher
}

type numericMatcher struct {
	operator string
	value    float64
	valid    bool
}

type digestBucket struct {
	key       string
	routeID   string
	recipient AlertRecipient
	groupKey  string
	firstSeen time.Time
	dueAt     time.Time
	events    []webhooks.Event
}

type pendingAck struct {
	key       string
	alertID   string
	routeID   string
	event     webhooks.Event
	entityID  string
	groupKey  string
	recipient AlertRecipient
	deadline  time.Time
}

type outboundAlert struct {
	subject string
	payload []byte
}

type GraphAlertResolver struct {
	graphFn func() *graph.Graph
}

func LoadAlertRoutingConfig(path string) (AlertRoutingConfig, error) {
	if strings.TrimSpace(path) == "" {
		return parseAlertRoutingConfig(defaultAlertRoutesYAML)
	}

	payload, err := os.ReadFile(path) // #nosec G304 -- operator-provided path intentionally allows explicit config file location
	if err != nil {
		return AlertRoutingConfig{}, fmt.Errorf("read alert routes config %s: %w", path, err)
	}
	return parseAlertRoutingConfig(payload)
}

func parseAlertRoutingConfig(payload []byte) (AlertRoutingConfig, error) {
	var config AlertRoutingConfig
	if err := yaml.Unmarshal(payload, &config); err != nil {
		return AlertRoutingConfig{}, fmt.Errorf("decode alert routing config: %w", err)
	}
	if len(config.Routes) == 0 {
		return AlertRoutingConfig{}, errors.New("alert routing config requires at least one route")
	}
	return config, nil
}

func NewAlertRouter(options AlertRouterOptions) (*AlertRouter, error) {
	if options.Sender == nil {
		return nil, errors.New("alert router sender is required")
	}
	if options.Resolver == nil {
		return nil, errors.New("alert router resolver is required")
	}
	if len(options.Config.Routes) == 0 {
		return nil, errors.New("alert router requires at least one route")
	}

	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}

	subjectPrefix := normalizeAlertSubjectPrefix(options.SubjectPrefix)
	if subjectPrefix == "" {
		subjectPrefix = defaultAlertNotifySubjectPrefix
	}

	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	compiled := make([]compiledAlertRoute, 0, len(options.Config.Routes))
	for idx, route := range options.Config.Routes {
		next, err := compileAlertRoute(route, idx)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, next)
	}

	router := &AlertRouter{
		logger:         logger,
		routes:         compiled,
		resolver:       options.Resolver,
		sender:         options.Sender,
		stateStore:     options.StateStore,
		subjectPrefix:  subjectPrefix,
		now:            now,
		throttleUntil:  make(map[string]time.Time),
		digestBuckets:  make(map[string]*digestBucket),
		pendingAcks:    make(map[string]pendingAck),
		fallbackAlerts: make([]outboundAlert, 0),
	}
	if options.StateStore != nil {
		snapshot, err := options.StateStore.Load(context.Background())
		if err != nil {
			logger.Warn("failed to load alert router state; continuing without persisted state", "error", err)
		} else {
			router.restoreState(snapshot, now().UTC())
		}
	}
	return router, nil
}

func compileAlertRoute(route AlertRoute, idx int) (compiledAlertRoute, error) {
	name := strings.TrimSpace(route.Name)
	if name == "" {
		name = fmt.Sprintf("route_%d", idx+1)
	}
	if strings.TrimSpace(route.Match.EventType) == "" {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q requires match.event_type", name)
	}
	if len(route.DeliverTo) == 0 {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q requires at least one delivery target", name)
	}

	throttle, err := parseOptionalDuration(route.Throttle)
	if err != nil {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q invalid throttle: %w", name, err)
	}
	digestEvery, err := parseOptionalDuration(route.Digest)
	if err != nil {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q invalid digest: %w", name, err)
	}
	escalateAfter, err := parseOptionalDuration(route.EscalateAfter)
	if err != nil {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q invalid escalate_after: %w", name, err)
	}
	deltaMatcher, err := parseNumericMatcher(route.Match.Delta)
	if err != nil {
		return compiledAlertRoute{}, fmt.Errorf("alert route %q invalid match.delta: %w", name, err)
	}

	severitySet := make(map[string]struct{}, len(route.Match.Severity))
	for _, severity := range route.Match.Severity {
		normalized := strings.ToLower(strings.TrimSpace(severity))
		if normalized == "" {
			continue
		}
		severitySet[normalized] = struct{}{}
	}

	return compiledAlertRoute{
		id:            normalizeRouteID(name),
		name:          name,
		match:         route.Match,
		deliverTo:     append([]AlertRouteDelivery(nil), route.DeliverTo...),
		groupBy:       strings.TrimSpace(route.GroupBy),
		throttle:      throttle,
		digestEvery:   digestEvery,
		escalateAfter: escalateAfter,
		metadata:      cloneMap(route.Metadata),
		severitySet:   severitySet,
		deltaMatch:    deltaMatcher,
	}, nil
}

func (r *AlertRouter) RouteCount() int {
	if r == nil {
		return 0
	}
	return len(r.routes)
}

func (r *AlertRouter) Route(ctx context.Context, event webhooks.Event) error {
	if r == nil {
		return errors.New("alert router not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := r.now().UTC()

	r.mu.Lock()
	previousSnapshot := r.snapshotStateLocked(now)
	outbound := r.planDueDigestMessagesLocked(now)
	outbound = append(outbound, r.planEscalationMessagesLocked(ctx, now)...)
	outbound = append(outbound, r.planRouteMessagesLocked(ctx, event, now)...)
	r.stateRevision++
	nextSnapshot := r.snapshotStateLocked(now)
	r.mu.Unlock()

	var errs []error
	for _, item := range outbound {
		if len(item.payload) == 0 || strings.TrimSpace(item.subject) == "" {
			continue
		}
		if err := r.sender.Send(ctx, item.subject, item.payload); err != nil {
			errs = append(errs, err)
		}
	}
	if sendErr := errors.Join(errs...); sendErr != nil {
		r.mu.Lock()
		if r.stateRevision == nextSnapshot.Revision {
			r.restoreStateLocked(previousSnapshot, now)
		}
		r.mu.Unlock()
		return sendErr
	}
	if err := r.persistSnapshot(ctx, nextSnapshot); err != nil {
		return err
	}
	return nil
}

func (r *AlertRouter) Acknowledge(alertID string, recipientID string) bool {
	if r == nil {
		return false
	}
	alertID = strings.TrimSpace(alertID)
	recipientID = strings.TrimSpace(recipientID)
	if alertID == "" && recipientID == "" {
		return false
	}

	r.mu.Lock()
	now := r.now().UTC()
	previousSnapshot := r.snapshotStateLocked(now)

	acknowledged := false
	for key, pending := range r.pendingAcks {
		if alertID != "" && pending.alertID != alertID {
			continue
		}
		if recipientID != "" && pending.recipient.ID != recipientID {
			continue
		}
		delete(r.pendingAcks, key)
		acknowledged = true
	}
	nextSnapshot := alertRouterStateSnapshot{}
	if acknowledged {
		r.stateRevision++
		nextSnapshot = r.snapshotStateLocked(now)
	}
	r.mu.Unlock()

	if acknowledged {
		if err := r.persistSnapshot(context.Background(), nextSnapshot); err != nil {
			r.mu.Lock()
			if r.stateRevision == nextSnapshot.Revision {
				r.restoreStateLocked(previousSnapshot, now)
			}
			r.mu.Unlock()
			r.logger.Warn("failed to persist alert router state after acknowledgement", "error", err)
			return false
		}
	}
	return acknowledged
}

func (r *AlertRouter) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	snapshot := r.snapshotStateLocked(r.now().UTC())
	r.mu.Unlock()

	var errs []error
	if err := r.persistSnapshot(context.Background(), snapshot); err != nil {
		errs = append(errs, err)
	}
	if r.sender != nil {
		if err := r.sender.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.stateStore != nil {
		if err := r.stateStore.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *AlertRouter) planRouteMessagesLocked(ctx context.Context, event webhooks.Event, now time.Time) []outboundAlert {
	if event.Timestamp.IsZero() {
		event.Timestamp = now
	}
	messages := make([]outboundAlert, 0)
	entityID := extractEntityID(event.Data)
	severity := extractSeverity(event.Data)
	deltaValue, deltaFound := extractDelta(event.Data)

	for _, route := range r.routes {
		if !route.matches(event, severity, deltaValue, deltaFound) {
			continue
		}

		recipients := r.resolveRecipientsLocked(ctx, route, entityID, event)
		if len(recipients) == 0 {
			continue
		}

		groupKey := route.resolveGroupKey(event, entityID)
		for _, recipient := range recipients {
			key := routeKey(route.id, groupKey, recipient)
			if route.throttle > 0 {
				until := r.throttleUntil[key]
				if until.After(now) {
					continue
				}
			}

			if route.digestEvery > 0 {
				bucket := r.digestBuckets[key]
				if bucket == nil {
					bucket = &digestBucket{
						key:       key,
						routeID:   route.id,
						recipient: recipient,
						groupKey:  groupKey,
						firstSeen: now,
						dueAt:     now.Add(route.digestEvery),
						events:    make([]webhooks.Event, 0, 1),
					}
					r.digestBuckets[key] = bucket
				}
				bucket.events = append(bucket.events, event)
				if now.Before(bucket.dueAt) {
					continue
				}
				out, err := r.digestAlertPayload(route, bucket, now)
				if err != nil {
					r.logger.Warn("failed to build digest alert payload", "route", route.name, "error", err)
					continue
				}
				messages = append(messages, out)
				delete(r.digestBuckets, key)
				if route.throttle > 0 {
					r.throttleUntil[key] = now.Add(route.throttle)
				}
				continue
			}

			out, alertID, err := r.immediateAlertPayload(route, recipient, event, entityID, groupKey, now)
			if err != nil {
				r.logger.Warn("failed to build immediate alert payload", "route", route.name, "error", err)
				continue
			}
			messages = append(messages, out)
			if route.throttle > 0 {
				r.throttleUntil[key] = now.Add(route.throttle)
			}
			if route.escalateAfter > 0 && strings.EqualFold(recipient.Type, "person") {
				pendingKey := pendingAckKey(route.id, alertID, recipient.ID)
				r.pendingAcks[pendingKey] = pendingAck{
					key:       pendingKey,
					alertID:   alertID,
					routeID:   route.id,
					event:     event,
					entityID:  entityID,
					groupKey:  groupKey,
					recipient: recipient,
					deadline:  now.Add(route.escalateAfter),
				}
			}
		}
	}

	return messages
}

func (r *AlertRouter) planDueDigestMessagesLocked(now time.Time) []outboundAlert {
	if len(r.digestBuckets) == 0 {
		return nil
	}

	keys := make([]string, 0, len(r.digestBuckets))
	for key := range r.digestBuckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	messages := make([]outboundAlert, 0)
	for _, key := range keys {
		bucket := r.digestBuckets[key]
		if bucket == nil || bucket.dueAt.After(now) {
			continue
		}
		route, ok := r.routeByID(bucket.routeID)
		if !ok {
			delete(r.digestBuckets, key)
			continue
		}
		out, err := r.digestAlertPayload(route, bucket, now)
		if err != nil {
			r.logger.Warn("failed to build scheduled digest payload", "route", route.name, "error", err)
			delete(r.digestBuckets, key)
			continue
		}
		messages = append(messages, out)
		delete(r.digestBuckets, key)
		if route.throttle > 0 {
			r.throttleUntil[key] = now.Add(route.throttle)
		}
	}
	return messages
}

func (r *AlertRouter) planEscalationMessagesLocked(ctx context.Context, now time.Time) []outboundAlert {
	if len(r.pendingAcks) == 0 {
		return nil
	}

	keys := make([]string, 0, len(r.pendingAcks))
	for key := range r.pendingAcks {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	messages := make([]outboundAlert, 0)
	for _, key := range keys {
		pending := r.pendingAcks[key]
		if pending.deadline.After(now) {
			continue
		}
		delete(r.pendingAcks, key)
		if r.resolver == nil {
			continue
		}
		manager, ok := r.resolver.ResolveManager(ctx, pending.recipient.ID)
		if !ok || strings.TrimSpace(manager.ID) == "" {
			continue
		}
		if strings.TrimSpace(manager.Channel) == "" {
			manager.Channel = "dm"
		}

		payload := map[string]interface{}{
			"alert_type":          "escalation",
			"reason":              defaultAlertEscalationReason,
			"route_id":            pending.routeID,
			"alert_id":            pending.alertID,
			"group_key":           pending.groupKey,
			"entity_id":           pending.entityID,
			"escalated_at":        now.UTC().Format(time.RFC3339),
			"escalated_recipient": manager,
			"original_recipient":  pending.recipient,
			"event":               pending.event,
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			r.logger.Warn("failed to encode escalation payload", "route", pending.routeID, "error", err)
			continue
		}
		messages = append(messages, outboundAlert{
			subject: r.subjectForRecipient(manager),
			payload: encoded,
		})
	}
	return messages
}

func (r *AlertRouter) resolveRecipientsLocked(ctx context.Context, route compiledAlertRoute, entityID string, event webhooks.Event) []AlertRecipient {
	recipients := make([]AlertRecipient, 0)
	for _, delivery := range route.deliverTo {
		deliveryType := strings.ToLower(strings.TrimSpace(delivery.Type))
		channelMode := strings.ToLower(strings.TrimSpace(delivery.Channel))
		switch deliveryType {
		case "channel":
			channel := strings.TrimSpace(delivery.Channel)
			if channel == "" {
				continue
			}
			recipients = append(recipients, AlertRecipient{
				Type:    "channel",
				ID:      channel,
				Channel: "channel",
				Label:   channel,
			})
		case "entity_owner":
			owners := r.resolver.ResolveEntityOwner(ctx, entityID, event)
			for _, owner := range owners {
				next := owner
				if channelMode != "" {
					next.Channel = channelMode
				}
				if strings.TrimSpace(next.Channel) == "" {
					next.Channel = "dm"
				}
				recipients = append(recipients, next)
			}
		case "account_team":
			team := r.resolver.ResolveAccountTeam(ctx, entityID, event)
			for _, member := range team {
				next := member
				if channelMode != "" {
					next.Channel = channelMode
				}
				if strings.TrimSpace(next.Channel) == "" {
					next.Channel = "thread"
				}
				recipients = append(recipients, next)
			}
		default:
			continue
		}
	}
	return dedupeRecipients(recipients)
}

func (r *AlertRouter) immediateAlertPayload(route compiledAlertRoute, recipient AlertRecipient, event webhooks.Event, entityID string, groupKey string, now time.Time) (outboundAlert, string, error) {
	alertID := strings.TrimSpace(event.ID)
	if alertID == "" {
		alertID = fmt.Sprintf("%s:%d", route.id, now.UnixNano())
	}

	payload := map[string]interface{}{
		"alert_type": "routed_event",
		"alert_id":   alertID,
		"route_id":   route.id,
		"route_name": route.name,
		"group_key":  groupKey,
		"entity_id":  entityID,
		"recipient":  recipient,
		"event":      event,
		"routed_at":  now.UTC().Format(time.RFC3339),
	}
	if len(route.metadata) > 0 {
		payload["metadata"] = route.metadata
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return outboundAlert{}, "", err
	}
	return outboundAlert{
		subject: r.subjectForRecipient(recipient),
		payload: encoded,
	}, alertID, nil
}

func (r *AlertRouter) digestAlertPayload(route compiledAlertRoute, bucket *digestBucket, now time.Time) (outboundAlert, error) {
	if bucket == nil {
		return outboundAlert{}, errors.New("digest bucket is nil")
	}
	summary := make([]map[string]interface{}, 0, len(bucket.events))
	for _, event := range bucket.events {
		summary = append(summary, map[string]interface{}{
			"id":         event.ID,
			"type":       event.Type,
			"severity":   extractSeverity(event.Data),
			"entity_id":  extractEntityID(event.Data),
			"timestamp":  event.Timestamp.UTC().Format(time.RFC3339),
			"data":       event.Data,
			"event_time": event.Timestamp.UTC().Format(time.RFC3339),
		})
	}
	payload := map[string]interface{}{
		"alert_type":   "digest",
		"route_id":     route.id,
		"route_name":   route.name,
		"group_key":    bucket.groupKey,
		"recipient":    bucket.recipient,
		"digest_count": len(bucket.events),
		"window_start": bucket.firstSeen.UTC().Format(time.RFC3339),
		"window_end":   now.UTC().Format(time.RFC3339),
		"events":       summary,
		"routed_at":    now.UTC().Format(time.RFC3339),
	}
	if len(route.metadata) > 0 {
		payload["metadata"] = route.metadata
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return outboundAlert{}, err
	}
	return outboundAlert{
		subject: r.subjectForRecipient(bucket.recipient),
		payload: encoded,
	}, nil
}

func (r *AlertRouter) routeByID(routeID string) (compiledAlertRoute, bool) {
	for _, route := range r.routes {
		if route.id == routeID {
			return route, true
		}
	}
	return compiledAlertRoute{}, false
}

func (r *AlertRouter) subjectForRecipient(recipient AlertRecipient) string {
	token := ""
	if strings.EqualFold(recipient.Type, "channel") {
		token = normalizeSubjectToken(recipient.ID)
		if token == "" {
			token = normalizeSubjectToken(recipient.Channel)
		}
	} else {
		token = normalizeSubjectToken(recipient.Channel)
		if token == "" {
			token = normalizeSubjectToken(recipient.ID)
		}
	}
	if token == "" {
		token = "alerts"
	}
	return r.subjectPrefix + "." + token
}

func (r *AlertRouter) persistSnapshot(ctx context.Context, snapshot alertRouterStateSnapshot) error {
	if r == nil || r.stateStore == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.stateStore.Save(ctx, snapshot); err != nil {
		return fmt.Errorf("persist alert router state: %w", err)
	}
	return nil
}

func (r *AlertRouter) snapshotStateLocked(now time.Time) alertRouterStateSnapshot {
	r.pruneStateLocked(now)
	snapshot := alertRouterStateSnapshot{
		Revision:      r.stateRevision,
		ThrottleUntil: make(map[string]time.Time, len(r.throttleUntil)),
		DigestBuckets: make(map[string]digestBucketState, len(r.digestBuckets)),
		PendingAcks:   make(map[string]pendingAckState, len(r.pendingAcks)),
	}
	for key, until := range r.throttleUntil {
		snapshot.ThrottleUntil[key] = until
	}
	for key, bucket := range r.digestBuckets {
		if bucket == nil {
			continue
		}
		snapshot.DigestBuckets[key] = digestBucketState{
			Key:       bucket.key,
			RouteID:   bucket.routeID,
			Recipient: bucket.recipient,
			GroupKey:  bucket.groupKey,
			FirstSeen: bucket.firstSeen,
			DueAt:     bucket.dueAt,
			Events:    append([]webhooks.Event(nil), bucket.events...),
		}
	}
	for key, pending := range r.pendingAcks {
		snapshot.PendingAcks[key] = pendingAckState{
			Key:       pending.key,
			AlertID:   pending.alertID,
			RouteID:   pending.routeID,
			Event:     pending.event,
			EntityID:  pending.entityID,
			GroupKey:  pending.groupKey,
			Recipient: pending.recipient,
			Deadline:  pending.deadline,
		}
	}
	return snapshot
}

func (r *AlertRouter) restoreState(snapshot alertRouterStateSnapshot, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restoreStateLocked(snapshot, now)
}

func (r *AlertRouter) restoreStateLocked(snapshot alertRouterStateSnapshot, now time.Time) {
	r.stateRevision = snapshot.Revision
	r.throttleUntil = make(map[string]time.Time, len(snapshot.ThrottleUntil))
	for key, until := range snapshot.ThrottleUntil {
		r.throttleUntil[key] = until
	}

	r.digestBuckets = make(map[string]*digestBucket, len(snapshot.DigestBuckets))
	for key, bucket := range snapshot.DigestBuckets {
		next := bucket
		r.digestBuckets[key] = &digestBucket{
			key:       next.Key,
			routeID:   next.RouteID,
			recipient: next.Recipient,
			groupKey:  next.GroupKey,
			firstSeen: next.FirstSeen,
			dueAt:     next.DueAt,
			events:    append([]webhooks.Event(nil), next.Events...),
		}
	}

	r.pendingAcks = make(map[string]pendingAck, len(snapshot.PendingAcks))
	for key, pending := range snapshot.PendingAcks {
		r.pendingAcks[key] = pendingAck{
			key:       pending.Key,
			alertID:   pending.AlertID,
			routeID:   pending.RouteID,
			event:     pending.Event,
			entityID:  pending.EntityID,
			groupKey:  pending.GroupKey,
			recipient: pending.Recipient,
			deadline:  pending.Deadline,
		}
	}
	r.pruneStateLocked(now)
}

func (r *AlertRouter) pruneStateLocked(now time.Time) {
	for key, until := range r.throttleUntil {
		if !until.After(now) {
			delete(r.throttleUntil, key)
		}
	}
	for key, bucket := range r.digestBuckets {
		if bucket == nil || strings.TrimSpace(bucket.routeID) == "" || len(bucket.events) == 0 {
			delete(r.digestBuckets, key)
			continue
		}
		if _, ok := r.routeByID(bucket.routeID); !ok {
			delete(r.digestBuckets, key)
		}
	}
	for key, pending := range r.pendingAcks {
		if strings.TrimSpace(pending.routeID) == "" || strings.TrimSpace(pending.recipient.ID) == "" {
			delete(r.pendingAcks, key)
			continue
		}
		if _, ok := r.routeByID(pending.routeID); !ok {
			delete(r.pendingAcks, key)
		}
	}
}

func (route compiledAlertRoute) matches(event webhooks.Event, severity string, delta float64, deltaFound bool) bool {
	if !strings.EqualFold(strings.TrimSpace(route.match.EventType), strings.TrimSpace(string(event.Type))) {
		return false
	}
	if len(route.severitySet) > 0 {
		normalized := strings.ToLower(strings.TrimSpace(severity))
		if normalized == "" {
			return false
		}
		if _, ok := route.severitySet[normalized]; !ok {
			return false
		}
	}
	if route.deltaMatch.valid {
		if !deltaFound {
			return false
		}
		if !route.deltaMatch.matches(delta) {
			return false
		}
	}
	return true
}

func (route compiledAlertRoute) resolveGroupKey(event webhooks.Event, entityID string) string {
	selector := strings.TrimSpace(route.groupBy)
	if selector == "" {
		return strings.TrimSpace(event.ID)
	}
	value := extractGroupValue(event.Data, selector)
	if value != "" {
		return value
	}
	if selector == "entity_id" && entityID != "" {
		return entityID
	}
	if entityID != "" {
		return entityID
	}
	if strings.TrimSpace(event.ID) != "" {
		return strings.TrimSpace(event.ID)
	}
	return route.id
}

func (matcher numericMatcher) matches(value float64) bool {
	if !matcher.valid {
		return true
	}
	switch matcher.operator {
	case ">":
		return value > matcher.value
	case ">=":
		return value >= matcher.value
	case "<":
		return value < matcher.value
	case "<=":
		return value <= matcher.value
	case "=", "==":
		return value == matcher.value
	default:
		return false
	}
}

func parseNumericMatcher(raw string) (numericMatcher, error) {
	expression := strings.TrimSpace(raw)
	if expression == "" {
		return numericMatcher{}, nil
	}
	for _, op := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(expression, op) {
			value, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(expression, op)), 64)
			if err != nil {
				return numericMatcher{}, err
			}
			return numericMatcher{operator: op, value: value, valid: true}, nil
		}
	}
	value, err := strconv.ParseFloat(expression, 64)
	if err != nil {
		return numericMatcher{}, err
	}
	return numericMatcher{operator: "=", value: value, valid: true}, nil
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}
	return time.ParseDuration(value)
}

func pendingAckKey(routeID, alertID, recipientID string) string {
	return strings.Join([]string{routeID, alertID, recipientID}, "|")
}

func routeKey(routeID, groupKey string, recipient AlertRecipient) string {
	return strings.Join([]string{routeID, strings.TrimSpace(groupKey), strings.TrimSpace(recipient.Type), strings.TrimSpace(recipient.ID), strings.TrimSpace(recipient.Channel)}, "|")
}

func normalizeRouteID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "route"
	}
	var b strings.Builder
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	normalized := strings.Trim(b.String(), "_")
	if normalized == "" {
		return "route"
	}
	return normalized
}

func normalizeSubjectToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.TrimPrefix(value, "#")
	value = strings.Trim(value, ".")
	var b strings.Builder
	for _, ch := range strings.ToLower(value) {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-', ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	normalized := strings.Trim(b.String(), "_")
	return normalized
}

func extractGroupValue(data map[string]interface{}, selector string) string {
	if len(data) == 0 {
		return ""
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return ""
	}
	if value, ok := data[selector]; ok {
		return strings.TrimSpace(stringValue(value))
	}
	parts := strings.Split(selector, ".")
	current := interface{}(data)
	for _, part := range parts {
		nextMap, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		value, ok := nextMap[part]
		if !ok {
			return ""
		}
		current = value
	}
	return strings.TrimSpace(stringValue(current))
}

func extractSeverity(data map[string]interface{}) string {
	for _, key := range []string{"severity", "risk_level", "level"} {
		if value, ok := data[key]; ok {
			normalized := strings.ToLower(strings.TrimSpace(stringValue(value)))
			if normalized != "" {
				return normalized
			}
		}
	}
	return ""
}

func extractEntityID(data map[string]interface{}) string {
	for _, key := range []string{"entity_id", "resource_id", "target", "customer_id", "principal_id", "node_id"} {
		if value, ok := data[key]; ok {
			entityID := strings.TrimSpace(stringValue(value))
			if entityID != "" {
				return entityID
			}
		}
	}
	resource, ok := data["resource"].(map[string]interface{})
	if ok {
		if value, ok := resource["id"]; ok {
			entityID := strings.TrimSpace(stringValue(value))
			if entityID != "" {
				return entityID
			}
		}
	}
	return ""
}

func extractDelta(data map[string]interface{}) (float64, bool) {
	for _, key := range []string{"delta", "risk_delta", "score_delta", "risk_score_delta"} {
		if value, ok := data[key]; ok {
			if parsed, ok := floatValue(value); ok {
				return parsed, true
			}
		}
	}
	return 0, false
}

func dedupeRecipients(values []AlertRecipient) []AlertRecipient {
	seen := make(map[string]struct{}, len(values))
	out := make([]AlertRecipient, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value.ID) == "" {
			continue
		}
		key := strings.Join([]string{strings.ToLower(strings.TrimSpace(value.Type)), strings.TrimSpace(value.ID), strings.ToLower(strings.TrimSpace(value.Channel))}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			if out[i].Channel == out[j].Channel {
				return out[i].ID < out[j].ID
			}
			return out[i].Channel < out[j].Channel
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func floatValue(value interface{}) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case json.Number:
		return typed.String()
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}

func cloneMap(value map[string]interface{}) map[string]interface{} {
	if len(value) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func NewNATSAlertNotifier(cfg AlertNotifierConfig, logger *slog.Logger) (*NATSAlertNotifier, error) {
	base := JetStreamConfig{
		Stream:                cfg.Stream,
		SubjectPrefix:         cfg.SubjectPrefix,
		URLs:                  cfg.URLs,
		ConnectTimeout:        cfg.ConnectTimeout,
		AuthMode:              cfg.AuthMode,
		Username:              cfg.Username,
		Password:              cfg.Password,
		NKeySeed:              cfg.NKeySeed,
		UserJWT:               cfg.UserJWT,
		TLSEnabled:            cfg.TLSEnabled,
		TLSCAFile:             cfg.TLSCAFile,
		TLSCertFile:           cfg.TLSCertFile,
		TLSKeyFile:            cfg.TLSKeyFile,
		TLSServerName:         cfg.TLSServerName,
		TLSInsecureSkipVerify: cfg.TLSInsecureSkipVerify,
	}.withDefaults()
	base.SubjectPrefix = normalizeAlertSubjectPrefix(base.SubjectPrefix)
	if base.SubjectPrefix == "" {
		base.SubjectPrefix = defaultAlertNotifySubjectPrefix
	}
	options, err := base.natsOptions()
	if err != nil {
		return nil, err
	}

	nc, err := nats.Connect(strings.Join(base.URLs, ","), options...)
	if err != nil {
		return nil, fmt.Errorf("connect alert notifier to nats: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("initialize alert notifier jetstream context: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	notifier := &NATSAlertNotifier{
		nc:            nc,
		js:            js,
		stream:        base.Stream,
		subjectPrefix: base.SubjectPrefix,
		logger:        logger,
	}
	if err := notifier.ensureStream(); err != nil {
		nc.Close()
		return nil, err
	}
	return notifier, nil
}

func (n *NATSAlertNotifier) Send(ctx context.Context, subject string, payload []byte) error {
	if n == nil || n.nc == nil || n.js == nil {
		return errors.New("alert notifier not initialized")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return errors.New("alert notifier subject is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	publish := func() error {
		_, err := n.js.Publish(subject, payload, nats.Context(ctx))
		return err
	}
	if err := publish(); err != nil {
		if shouldEnsureJetStreamStream(err) {
			if ensureErr := n.ensureStream(); ensureErr != nil {
				return errors.Join(err, ensureErr)
			}
			return publish()
		}
		return err
	}
	return nil
}

func (n *NATSAlertNotifier) Close() error {
	if n == nil || n.nc == nil {
		return nil
	}
	if err := n.nc.Drain(); err != nil {
		n.nc.Close()
		return err
	}
	n.nc.Close()
	return nil
}

func (n *NATSAlertNotifier) ensureStream() error {
	if n == nil || n.js == nil {
		return errors.New("alert notifier not initialized")
	}
	if strings.TrimSpace(n.stream) == "" {
		return errors.New("alert notifier stream is required")
	}
	if strings.TrimSpace(n.subjectPrefix) == "" {
		return errors.New("alert notifier subject prefix is required")
	}

	n.subjectPrefix = normalizeAlertSubjectPrefix(n.subjectPrefix)
	streamSubject := n.subjectPrefix + ".>"
	stream, err := n.js.StreamInfo(n.stream)
	if err == nil {
		if streamHasSubject(stream.Config.Subjects, streamSubject) {
			return nil
		}
		updated := stream.Config
		updated.Subjects = append(append([]string(nil), stream.Config.Subjects...), streamSubject)
		if _, err := n.js.UpdateStream(&updated); err != nil {
			return fmt.Errorf("update alert notifier stream %s subjects: %w", n.stream, err)
		}
		n.logger.Info("updated alert notifier stream subjects",
			"stream", n.stream,
			"stream_subjects", updated.Subjects,
			"added_subject", streamSubject,
		)
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return fmt.Errorf("lookup alert notifier stream %s: %w", n.stream, err)
	}

	_, err = n.js.AddStream(&nats.StreamConfig{
		Name:      n.stream,
		Subjects:  []string{streamSubject},
		Storage:   nats.FileStorage,
		Retention: nats.LimitsPolicy,
		Discard:   nats.DiscardOld,
	})
	if err != nil {
		return fmt.Errorf("create alert notifier stream %s: %w", n.stream, err)
	}
	n.logger.Info("created alert notifier stream", "stream", n.stream, "subject", streamSubject)
	return nil
}

func NewGraphAlertResolver(graphFn func() *graph.Graph) *GraphAlertResolver {
	return &GraphAlertResolver{graphFn: graphFn}
}

func (r *GraphAlertResolver) ResolveEntityOwner(_ context.Context, entityID string, event webhooks.Event) []AlertRecipient {
	g := r.currentGraph()
	if g == nil {
		return nil
	}
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		entityID = extractEntityID(event.Data)
	}
	if entityID == "" {
		return nil
	}

	candidates := make(map[string]AlertRecipient)
	appendPerson := func(personID string) {
		personID = normalizePersonID(strings.TrimSpace(personID))
		if personID == "" {
			return
		}
		if node, ok := g.GetNode(personID); ok && node != nil {
			candidates[node.ID] = recipientFromPersonNode(node)
			return
		}
		candidates[personID] = AlertRecipient{
			Type:    "person",
			ID:      personID,
			Channel: "dm",
			Label:   strings.TrimPrefix(personID, "person:"),
		}
	}

	if node, ok := g.GetNode(entityID); ok && node != nil {
		for _, key := range []string{"owner", "owner_id", "account_owner", "primary_contact", "account_manager"} {
			if value, ok := node.Properties[key]; ok {
				for _, item := range stringSliceFromAny(value) {
					appendPerson(item)
				}
			}
		}
	}

	for _, edge := range g.GetInEdges(entityID) {
		if edge == nil || !isOwnerEdgeKind(edge.Kind) {
			continue
		}
		source, ok := g.GetNode(edge.Source)
		if !ok || source == nil || !isPersonKind(source.Kind) {
			continue
		}
		candidates[source.ID] = recipientFromPersonNode(source)
	}
	for _, edge := range g.GetOutEdges(entityID) {
		if edge == nil || !isOwnerEdgeKind(edge.Kind) {
			continue
		}
		target, ok := g.GetNode(edge.Target)
		if !ok || target == nil || !isPersonKind(target.Kind) {
			continue
		}
		candidates[target.ID] = recipientFromPersonNode(target)
	}

	out := make([]AlertRecipient, 0, len(candidates))
	for _, recipient := range candidates {
		out = append(out, recipient)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func (r *GraphAlertResolver) ResolveAccountTeam(ctx context.Context, entityID string, event webhooks.Event) []AlertRecipient {
	g := r.currentGraph()
	if g == nil {
		return nil
	}
	owners := r.ResolveEntityOwner(ctx, entityID, event)
	if len(owners) == 0 {
		return nil
	}

	teamRecipients := make(map[string]AlertRecipient)
	personRecipients := make(map[string]AlertRecipient)
	for _, owner := range owners {
		personRecipients[owner.ID] = owner
		for _, edge := range g.GetOutEdges(owner.ID) {
			if edge == nil || edge.Kind != graph.EdgeKindMemberOf {
				continue
			}
			dept, ok := g.GetNode(edge.Target)
			if !ok || dept == nil || dept.Kind != graph.NodeKindDepartment {
				continue
			}
			channel := strings.TrimSpace(stringValue(firstPresentMap(dept.Properties, "slack_channel", "channel", "notify_channel")))
			if channel != "" {
				teamRecipients[channel] = AlertRecipient{
					Type:    "channel",
					ID:      channel,
					Channel: "thread",
					Label:   channel,
				}
			}
			for _, inEdge := range g.GetInEdges(dept.ID) {
				if inEdge == nil || inEdge.Kind != graph.EdgeKindMemberOf {
					continue
				}
				member, ok := g.GetNode(inEdge.Source)
				if !ok || member == nil || !isPersonKind(member.Kind) {
					continue
				}
				personRecipients[member.ID] = recipientFromPersonNode(member)
			}
		}
	}

	out := make([]AlertRecipient, 0, len(teamRecipients)+len(personRecipients))
	for _, recipient := range teamRecipients {
		out = append(out, recipient)
	}
	for _, recipient := range personRecipients {
		out = append(out, recipient)
	}
	out = dedupeRecipients(out)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func (r *GraphAlertResolver) ResolveManager(_ context.Context, personID string) (AlertRecipient, bool) {
	g := r.currentGraph()
	if g == nil {
		return AlertRecipient{}, false
	}
	personID = strings.TrimSpace(personID)
	if personID == "" {
		return AlertRecipient{}, false
	}

	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != graph.EdgeKindReportsTo {
			continue
		}
		manager, ok := g.GetNode(edge.Target)
		if !ok || manager == nil || !isPersonKind(manager.Kind) {
			continue
		}
		return recipientFromPersonNode(manager), true
	}

	person, ok := g.GetNode(personID)
	if !ok || person == nil {
		return AlertRecipient{}, false
	}
	for _, key := range []string{"manager", "manager_id"} {
		value := strings.TrimSpace(stringValue(person.Properties[key]))
		if value == "" {
			continue
		}
		managerID := normalizePersonID(value)
		manager, ok := g.GetNode(managerID)
		if !ok || manager == nil || !isPersonKind(manager.Kind) {
			continue
		}
		return recipientFromPersonNode(manager), true
	}
	return AlertRecipient{}, false
}

func (r *GraphAlertResolver) currentGraph() *graph.Graph {
	if r == nil || r.graphFn == nil {
		return nil
	}
	return r.graphFn()
}

func recipientFromPersonNode(node *graph.Node) AlertRecipient {
	if node == nil {
		return AlertRecipient{}
	}
	label := strings.TrimSpace(node.Name)
	if label == "" {
		label = strings.TrimPrefix(node.ID, "person:")
	}

	metadata := make(map[string]interface{})
	for _, key := range []string{"email", "slack_user_id", "department"} {
		if value := strings.TrimSpace(stringValue(node.Properties[key])); value != "" {
			metadata[key] = value
		}
	}

	return AlertRecipient{
		Type:     "person",
		ID:       node.ID,
		Channel:  "dm",
		Label:    label,
		Metadata: metadata,
	}
}

func normalizePersonID(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "@") && !strings.Contains(value, ":") {
		return "person:" + value
	}
	return value
}

func isPersonKind(kind graph.NodeKind) bool {
	return kind == graph.NodeKindPerson || kind == graph.NodeKindUser
}

func isOwnerEdgeKind(kind graph.EdgeKind) bool {
	switch kind {
	case graph.EdgeKindManagedBy, graph.EdgeKindOwns, graph.EdgeKindAssignedTo, graph.EdgeKindEscalatedTo:
		return true
	default:
		return false
	}
}

func stringSliceFromAny(value interface{}) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			next := strings.TrimSpace(stringValue(item))
			if next != "" {
				out = append(out, next)
			}
		}
		return out
	case string:
		next := strings.TrimSpace(typed)
		if next == "" {
			return nil
		}
		if strings.Contains(next, ",") {
			parts := strings.Split(next, ",")
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
			return out
		}
		return []string{next}
	default:
		return nil
	}
}

func firstPresentMap(snapshot map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := snapshot[key]; ok {
			return value
		}
	}
	return nil
}

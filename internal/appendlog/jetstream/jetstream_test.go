package jetstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	natsjetstream "github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
)

type fakePublisher struct {
	accountErr   error
	publishErr   error
	publishErrs  []error
	ack          *natsjetstream.PubAck
	published    *nats.Msg
	publishCalls int
}

func (f *fakePublisher) AccountInfo(context.Context) (*natsjetstream.AccountInfo, error) {
	return &natsjetstream.AccountInfo{}, f.accountErr
}

func (f *fakePublisher) PublishMsg(_ context.Context, msg *nats.Msg, _ ...natsjetstream.PublishOpt) (*natsjetstream.PubAck, error) {
	f.publishCalls++
	f.published = msg
	if len(f.publishErrs) > 0 {
		err := f.publishErrs[0]
		f.publishErrs = f.publishErrs[1:]
		return &natsjetstream.PubAck{}, err
	}
	if f.ack != nil {
		return f.ack, f.publishErr
	}
	return &natsjetstream.PubAck{}, f.publishErr
}

type fakeReplayManager struct {
	streams      []*natsjetstream.StreamInfo
	msgs         map[string]map[uint64]*natsjetstream.RawStreamMsg
	err          error
	getMsgErr    error
	msgFunc      func(stream string, seq uint64) *natsjetstream.RawStreamMsg
	streamCalls  int
	getMsgCalls  int
	nextForCalls int
}

func (f *fakeReplayManager) Streams(context.Context) ([]*natsjetstream.StreamInfo, error) {
	return f.streams, f.err
}

func (f *fakeReplayManager) Stream(_ context.Context, stream string) (replayStream, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.streamCalls++
	return &fakeReplayStream{manager: f, stream: stream, msgs: f.msgs[stream]}, nil
}

type fakeReplayStream struct {
	manager *fakeReplayManager
	stream  string
	msgs    map[uint64]*natsjetstream.RawStreamMsg
}

func (f *fakeReplayStream) GetMsg(_ context.Context, seq uint64) (*natsjetstream.RawStreamMsg, error) {
	if f.manager != nil {
		f.manager.getMsgCalls++
		if f.manager.getMsgErr != nil {
			return nil, f.manager.getMsgErr
		}
	}
	raw := f.msgs[seq]
	if raw == nil && f.manager != nil && f.manager.msgFunc != nil {
		raw = f.manager.msgFunc(f.stream, seq)
	}
	if raw == nil {
		return nil, natsjetstream.ErrMsgNotFound
	}
	cloned := *raw
	if cloned.Sequence == 0 {
		cloned.Sequence = seq
	}
	return &cloned, nil
}

func (f *fakeReplayStream) GetNextMsgForSubject(_ context.Context, seq uint64, subject string) (*natsjetstream.RawStreamMsg, error) {
	if f.manager != nil {
		f.manager.nextForCalls++
		if f.manager.getMsgErr != nil {
			return nil, f.manager.getMsgErr
		}
	}
	maxSeq := seq
	for current := range f.msgs {
		if current > maxSeq {
			maxSeq = current
		}
	}
	for current := seq; current <= maxSeq; current++ {
		raw := f.msgs[current]
		if raw == nil && f.manager != nil && f.manager.msgFunc != nil {
			raw = f.manager.msgFunc(f.stream, current)
		}
		if raw != nil && raw.Subject == subject {
			cloned := *raw
			if cloned.Sequence == 0 {
				cloned.Sequence = current
			}
			return &cloned, nil
		}
	}
	return nil, natsjetstream.ErrMsgNotFound
}

func captureJetstreamTelemetry(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stderr = writer
	defer func() {
		os.Stderr = oldStderr
		_ = writer.Close()
		_ = reader.Close()
	}()
	fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr pipe: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr pipe: %v", err)
	}
	return string(output)
}

func jetstreamTelemetryPayloads(t *testing.T, stderr string, kind string, name string) []map[string]any {
	t.Helper()
	var payloads []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			t.Fatalf("telemetry line is not JSON: %v\nline=%s\nstderr=%s", err, line, stderr)
		}
		if payload["kind"] == kind && payload["name"] == name {
			payloads = append(payloads, payload)
		}
	}
	return payloads
}

func skipPublishRetryWaits(t *testing.T) {
	t.Helper()
	original := waitBeforePublishRetryFunc
	waitBeforePublishRetryFunc = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t.Cleanup(func() {
		waitBeforePublishRetryFunc = original
	})
}

func TestPublishRetryConfigUsesAppendLogOverrides(t *testing.T) {
	retry := publishRetryConfigFromAppendLog(config.AppendLogConfig{
		JetStreamPublishRetryAttempts:       22,
		JetStreamPublishRetryInitialBackoff: 750 * time.Millisecond,
		JetStreamPublishRetryMaxBackoff:     9 * time.Second,
		JetStreamPublishClientRetryAttempts: 6,
		JetStreamPublishClientRetryWait:     800 * time.Millisecond,
		JetStreamPublishAttemptTimeout:      45 * time.Second,
		JetStreamPublishRetryMaxElapsed:     5 * time.Minute,
	})

	if retry.MaxAttempts != 22 {
		t.Fatalf("MaxAttempts = %d, want 22", retry.MaxAttempts)
	}
	if retry.InitialBackoff != 750*time.Millisecond {
		t.Fatalf("InitialBackoff = %v, want 750ms", retry.InitialBackoff)
	}
	if retry.MaxBackoff != 9*time.Second {
		t.Fatalf("MaxBackoff = %v, want 9s", retry.MaxBackoff)
	}
	if retry.ClientRetryAttempts != 6 {
		t.Fatalf("ClientRetryAttempts = %d, want 6", retry.ClientRetryAttempts)
	}
	if retry.ClientRetryWait != 800*time.Millisecond {
		t.Fatalf("ClientRetryWait = %v, want 800ms", retry.ClientRetryWait)
	}
	if retry.AttemptTimeout != 45*time.Second {
		t.Fatalf("AttemptTimeout = %v, want 45s", retry.AttemptTimeout)
	}
	if retry.MaxElapsed != 5*time.Minute {
		t.Fatalf("MaxElapsed = %v, want 5m", retry.MaxElapsed)
	}
}

func TestAppendPublishesEnvelope(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}

	event := &cerebrov1.EventEnvelope{
		Id:       "evt-1",
		TenantId: "tenant-1",
		SourceId: "source-1",
		Kind:     "entity.upsert",
	}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published == nil {
		t.Fatal("published message = nil")
	}
	if pub.published.Subject != "events.entity.upsert" {
		t.Fatalf("subject = %q, want %q", pub.published.Subject, "events.entity.upsert")
	}
	if got := pub.published.Header.Get(nats.MsgIdHdr); got != "evt-1" {
		t.Fatalf("msg id = %q, want %q", got, "evt-1")
	}
	var decoded cerebrov1.EventEnvelope
	if err := proto.Unmarshal(pub.published.Data, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if !proto.Equal(&decoded, event) {
		t.Fatalf("decoded envelope = %#v, want %#v", &decoded, event)
	}
}

func TestAppendRetriesTransientPublishErrorWhenMessageIDIsSet(t *testing.T) {
	skipPublishRetryWaits(t)
	pub := &fakePublisher{
		publishErrs: []error{
			errors.New("nats: no response from stream"),
			nil,
		},
	}
	log := &Log{js: pub, subjectPrefix: "events"}

	err := log.Append(context.Background(), &cerebrov1.EventEnvelope{
		Id:   "evt-1",
		Kind: "entity.upsert",
	})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.publishCalls != 2 {
		t.Fatalf("publish calls = %d, want 2", pub.publishCalls)
	}
}

func TestAppendEmitsPublishRetryTelemetry(t *testing.T) {
	skipPublishRetryWaits(t)
	pub := &fakePublisher{
		publishErrs: []error{
			errors.New("nats: no response from stream"),
			nil,
		},
	}
	log := &Log{js: pub, subjectPrefix: "events"}

	stderr := captureJetstreamTelemetry(t, func() {
		err := log.Append(context.Background(), &cerebrov1.EventEnvelope{
			Id:   "evt-retry-telemetry",
			Kind: "entity.upsert",
		})
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	})

	if strings.Contains(stderr, "evt-retry-telemetry") {
		t.Fatalf("raw message id leaked into telemetry: %s", stderr)
	}
	retryEvents := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.publish.retry")
	if len(retryEvents) != 1 {
		t.Fatalf("retry events = %d, want 1; stderr=%s", len(retryEvents), stderr)
	}
	retry := retryEvents[0]
	if retry["messaging.jetstream.subject"] != "events.entity.upsert" {
		t.Fatalf("retry subject = %v, want events.entity.upsert", retry["messaging.jetstream.subject"])
	}
	if retry["messaging.jetstream.publish.retry_count"] != float64(1) {
		t.Fatalf("retry count = %v, want 1", retry["messaging.jetstream.publish.retry_count"])
	}
	if retry["messaging.jetstream.publish.next_attempt"] != float64(2) {
		t.Fatalf("next attempt = %v, want 2", retry["messaging.jetstream.publish.next_attempt"])
	}
	if retry["messaging.jetstream.publish.retry_budget_ms"] != float64(publishRetryMaxElapsed.Milliseconds()) {
		t.Fatalf("retry budget = %v, want %d", retry["messaging.jetstream.publish.retry_budget_ms"], publishRetryMaxElapsed.Milliseconds())
	}
	if retry["messaging.jetstream.publish.attempt_timeout_ms"] != float64(publishAttemptTimeout.Milliseconds()) {
		t.Fatalf("attempt timeout = %v, want %d", retry["messaging.jetstream.publish.attempt_timeout_ms"], publishAttemptTimeout.Milliseconds())
	}
	if retry["messaging.jetstream.publish.max_backoff_ms"] != float64(publishRetryMaxBackoff.Milliseconds()) {
		t.Fatalf("max backoff = %v, want %d", retry["messaging.jetstream.publish.max_backoff_ms"], publishRetryMaxBackoff.Milliseconds())
	}
	if retry["messaging.jetstream.publish.client_retry_attempts"] != float64(publishClientRetryAttempts) {
		t.Fatalf("client retry attempts = %v, want %d", retry["messaging.jetstream.publish.client_retry_attempts"], publishClientRetryAttempts)
	}
	if retry["messaging.jetstream.publish.client_retry_wait_ms"] != float64(publishClientRetryWait.Milliseconds()) {
		t.Fatalf("client retry wait = %v, want %d", retry["messaging.jetstream.publish.client_retry_wait_ms"], publishClientRetryWait.Milliseconds())
	}

	recoveredEvents := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.publish.recovered")
	if len(recoveredEvents) != 1 {
		t.Fatalf("recovered events = %d, want 1; stderr=%s", len(recoveredEvents), stderr)
	}
	spanEnds := jetstreamTelemetryPayloads(t, stderr, "span_end", "jetstream.append")
	if len(spanEnds) != 1 {
		t.Fatalf("jetstream.append span_end events = %d, want 1; stderr=%s", len(spanEnds), stderr)
	}
	end := spanEnds[0]
	if end["messaging.message.id.present"] != true {
		t.Fatalf("message id present = %v, want true", end["messaging.message.id.present"])
	}
	if hash, ok := end["messaging.message.id_hash"].(string); !ok || hash == "" {
		t.Fatalf("message id hash = %v, want non-empty string", end["messaging.message.id_hash"])
	}
	if end["messaging.jetstream.publish.retry_count"] != float64(1) {
		t.Fatalf("span retry count = %v, want 1", end["messaging.jetstream.publish.retry_count"])
	}
}

func TestAppendRetryTelemetryUsesConfiguredPublishBudget(t *testing.T) {
	skipPublishRetryWaits(t)
	pub := &fakePublisher{
		publishErrs: []error{
			errors.New("nats: no response from stream"),
			nil,
		},
	}
	log := &Log{
		js:            pub,
		subjectPrefix: "events",
		publishRetry: publishRetryConfig{
			MaxAttempts:         7,
			InitialBackoff:      750 * time.Millisecond,
			MaxBackoff:          9 * time.Second,
			ClientRetryAttempts: 6,
			ClientRetryWait:     800 * time.Millisecond,
			AttemptTimeout:      45 * time.Second,
			MaxElapsed:          5 * time.Minute,
		},
	}

	stderr := captureJetstreamTelemetry(t, func() {
		err := log.Append(context.Background(), &cerebrov1.EventEnvelope{
			Id:   "evt-configured-retry-telemetry",
			Kind: "entity.upsert",
		})
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	})

	retryEvents := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.publish.retry")
	if len(retryEvents) != 1 {
		t.Fatalf("retry events = %d, want 1; stderr=%s", len(retryEvents), stderr)
	}
	retry := retryEvents[0]
	if retry["messaging.jetstream.publish.max_attempts"] != float64(7) {
		t.Fatalf("max attempts = %v, want 7", retry["messaging.jetstream.publish.max_attempts"])
	}
	if retry["messaging.jetstream.publish.retry_budget_ms"] != float64((5 * time.Minute).Milliseconds()) {
		t.Fatalf("retry budget = %v, want 5m", retry["messaging.jetstream.publish.retry_budget_ms"])
	}
	if retry["messaging.jetstream.publish.attempt_timeout_ms"] != float64((45 * time.Second).Milliseconds()) {
		t.Fatalf("attempt timeout = %v, want 45s", retry["messaging.jetstream.publish.attempt_timeout_ms"])
	}
	if retry["messaging.jetstream.publish.max_backoff_ms"] != float64((9 * time.Second).Milliseconds()) {
		t.Fatalf("max backoff = %v, want 9s", retry["messaging.jetstream.publish.max_backoff_ms"])
	}
	if retry["messaging.jetstream.publish.client_retry_attempts"] != float64(6) {
		t.Fatalf("client retry attempts = %v, want 6", retry["messaging.jetstream.publish.client_retry_attempts"])
	}
	if retry["messaging.jetstream.publish.client_retry_wait_ms"] != float64((800 * time.Millisecond).Milliseconds()) {
		t.Fatalf("client retry wait = %v, want 800ms", retry["messaging.jetstream.publish.client_retry_wait_ms"])
	}
	if retry["messaging.jetstream.publish.next_backoff_ms"] != float64((750 * time.Millisecond).Milliseconds()) {
		t.Fatalf("next backoff = %v, want 750ms", retry["messaging.jetstream.publish.next_backoff_ms"])
	}
}

func TestAppendEmitsPublishRetryExhaustedTelemetry(t *testing.T) {
	skipPublishRetryWaits(t)
	errs := make([]error, publishRetryAttempts)
	for i := range errs {
		errs[i] = errors.New("nats: no response from stream")
	}
	pub := &fakePublisher{
		publishErrs: errs,
	}
	log := &Log{js: pub, subjectPrefix: "events"}

	stderr := captureJetstreamTelemetry(t, func() {
		err := log.Append(context.Background(), &cerebrov1.EventEnvelope{
			Id:   "evt-exhausted-telemetry",
			Kind: "entity.upsert",
		})
		if err == nil {
			t.Fatal("Append() error = nil, want non-nil")
		}
	})

	if pub.publishCalls != publishRetryAttempts {
		t.Fatalf("publish calls = %d, want %d", pub.publishCalls, publishRetryAttempts)
	}
	if strings.Contains(stderr, "evt-exhausted-telemetry") {
		t.Fatalf("raw message id leaked into telemetry: %s", stderr)
	}
	exhaustedEvents := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.publish.retry_exhausted")
	if len(exhaustedEvents) != 1 {
		t.Fatalf("retry_exhausted events = %d, want 1; stderr=%s", len(exhaustedEvents), stderr)
	}
	exhausted := exhaustedEvents[0]
	if exhausted["messaging.jetstream.publish.retry_count"] != float64(publishRetryAttempts-1) {
		t.Fatalf("exhausted retry count = %v, want %d", exhausted["messaging.jetstream.publish.retry_count"], publishRetryAttempts-1)
	}
	if exhausted["messaging.jetstream.publish.max_attempts"] != float64(publishRetryAttempts) {
		t.Fatalf("exhausted max attempts = %v, want %d", exhausted["messaging.jetstream.publish.max_attempts"], publishRetryAttempts)
	}
	if exhausted["messaging.jetstream.publish.retry_budget_ms"] != float64(publishRetryMaxElapsed.Milliseconds()) {
		t.Fatalf("retry budget = %v, want %d", exhausted["messaging.jetstream.publish.retry_budget_ms"], publishRetryMaxElapsed.Milliseconds())
	}
	if exhausted["messaging.jetstream.publish.last_backoff_ms"] != float64(publishRetryMaxBackoff.Milliseconds()) {
		t.Fatalf("last backoff = %v, want capped %d", exhausted["messaging.jetstream.publish.last_backoff_ms"], publishRetryMaxBackoff.Milliseconds())
	}
	if exhausted["messaging.jetstream.publish.retry_exhausted"] != true {
		t.Fatalf("exhausted retry flag = %v, want true", exhausted["messaging.jetstream.publish.retry_exhausted"])
	}
	if exhausted["messaging.jetstream.publish.max_attempts_exhausted"] != true {
		t.Fatalf("max attempts exhausted = %v, want true", exhausted["messaging.jetstream.publish.max_attempts_exhausted"])
	}
	if exhausted["messaging.jetstream.error.category"] != "no_response" {
		t.Fatalf("exhausted error category = %v, want no_response", exhausted["messaging.jetstream.error.category"])
	}
	errorEvents := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.error")
	if len(errorEvents) != 1 {
		t.Fatalf("jetstream.error events = %d, want 1; stderr=%s", len(errorEvents), stderr)
	}
	if errorEvents[0]["messaging.jetstream.publish.retry_count"] != float64(publishRetryAttempts-1) {
		t.Fatalf("jetstream.error retry count = %v, want %d", errorEvents[0]["messaging.jetstream.publish.retry_count"], publishRetryAttempts-1)
	}
	if errorEvents[0]["messaging.jetstream.publish.max_attempts_exhausted"] != true {
		t.Fatalf("jetstream.error max attempts exhausted = %v, want true", errorEvents[0]["messaging.jetstream.publish.max_attempts_exhausted"])
	}
}

func TestAppendRetriesTransientPublishErrorWithDerivedMessageID(t *testing.T) {
	skipPublishRetryWaits(t)
	pub := &fakePublisher{
		publishErrs: []error{
			errors.New("nats: no response from stream"),
			nil,
		},
	}
	log := &Log{js: pub, subjectPrefix: "events"}

	event := &cerebrov1.EventEnvelope{Kind: "entity.upsert", TenantId: "tenant-1", SourceId: "source-1"}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.publishCalls != 2 {
		t.Fatalf("publish calls = %d, want 2", pub.publishCalls)
	}
	if event.Id != "" {
		t.Fatalf("event id mutated = %q, want empty", event.Id)
	}
	if got := pub.published.Header.Get(nats.MsgIdHdr); !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("derived msg id = %q, want sha256 fallback", got)
	}
}

func TestAppendEmitsPublishBulkheadTelemetry(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events", publishSlots: make(chan struct{}, 1)}

	stderr := captureJetstreamTelemetry(t, func() {
		err := log.Append(context.Background(), &cerebrov1.EventEnvelope{
			Id:   "evt-bulkhead-telemetry",
			Kind: "entity.upsert",
		})
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	})

	spanEnds := jetstreamTelemetryPayloads(t, stderr, "span_end", "jetstream.append")
	if len(spanEnds) != 1 {
		t.Fatalf("jetstream.append span_end events = %d, want 1; stderr=%s", len(spanEnds), stderr)
	}
	end := spanEnds[0]
	if end["messaging.jetstream.publish.bulkhead.enabled"] != true {
		t.Fatalf("bulkhead enabled = %v, want true", end["messaging.jetstream.publish.bulkhead.enabled"])
	}
	if end["messaging.jetstream.publish.bulkhead.max_in_flight"] != float64(1) {
		t.Fatalf("bulkhead max in flight = %v, want 1", end["messaging.jetstream.publish.bulkhead.max_in_flight"])
	}
}

func TestAcquirePublishSlotRespectsContextDeadline(t *testing.T) {
	log := &Log{publishSlots: make(chan struct{}, 1)}
	log.publishSlots <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	_, release, err := log.acquirePublishSlot(ctx)
	if err == nil {
		release()
		t.Fatal("acquirePublishSlot() error = nil, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquirePublishSlot() error = %v, want deadline exceeded", err)
	}
	if len(log.publishSlots) != 1 {
		t.Fatalf("publishSlots len = %d, want 1", len(log.publishSlots))
	}
}

func TestJetstreamErrorTelemetryAttrsIncludesAPIErrorDetails(t *testing.T) {
	attrs := jetstreamErrorTelemetryAttrs("append", &natsjetstream.APIError{
		Code:        503,
		ErrorCode:   natsjetstream.JSErrCodeStreamNotFound,
		Description: "stream not found",
	})
	values := map[string]string{}
	for _, attr := range attrs.OTELAttributes() {
		values[string(attr.Key)] = fmt.Sprint(attr.Value.AsInterface())
	}
	if values["nats.api.error.code"] != "503" {
		t.Fatalf("nats.api.error.code = %q, want 503", values["nats.api.error.code"])
	}
	if values["nats.jetstream.error_code"] != strconv.Itoa(int(natsjetstream.JSErrCodeStreamNotFound)) {
		t.Fatalf("nats.jetstream.error_code = %q, want %d", values["nats.jetstream.error_code"], natsjetstream.JSErrCodeStreamNotFound)
	}
	if values["nats.jetstream.error_description"] != "stream not found" {
		t.Fatalf("nats.jetstream.error_description = %q, want stream not found", values["nats.jetstream.error_description"])
	}
	if values["messaging.jetstream.publish.retryable"] != "true" {
		t.Fatalf("messaging.jetstream.publish.retryable = %q, want true", values["messaging.jetstream.publish.retryable"])
	}
}

func TestJetstreamErrorTelemetryAttrsScopesPublishRetryableToAppend(t *testing.T) {
	attrs := jetstreamErrorTelemetryAttrs("ping", errors.New("nats: no response from stream"))
	for _, attr := range attrs.OTELAttributes() {
		if string(attr.Key) == "messaging.jetstream.publish.retryable" {
			t.Fatalf("unexpected publish retryable attr on ping: %v", attr.Value.AsInterface())
		}
	}
}

func TestRedactNATSURLRemovesCredentials(t *testing.T) {
	if got := redactNATSURL("nats://user:secret@nats.example:4222"); got != "nats://nats.example:4222" {
		t.Fatalf("redactNATSURL() = %q, want credential-free URL", got)
	}
	if got := redactNATSURL("nats://token@nats.example:4222"); got != "nats://nats.example:4222" {
		t.Fatalf("redactNATSURL() token URL = %q, want credential-free URL", got)
	}
	if got := redactNATSURL("://user:secret@nats.example:4222"); got != "<redacted>" {
		t.Fatalf("redactNATSURL() malformed URL = %q, want <redacted>", got)
	}
}

func TestAppendPublishesCanonicalSecuritySubjectWithoutLegacyPrefix(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}

	event := &cerebrov1.EventEnvelope{
		Id:       "evt-1",
		TenantId: "tenant-1",
		Kind:     securityevents.FindingRecorded,
	}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published == nil {
		t.Fatal("published message = nil")
	}
	if pub.published.Subject != securityevents.FindingRecorded {
		t.Fatalf("subject = %q, want %q", pub.published.Subject, securityevents.FindingRecorded)
	}
	var decoded cerebrov1.EventEnvelope
	if err := proto.Unmarshal(pub.published.Data, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if got := decoded.GetKind(); got != securityevents.FindingRecorded {
		t.Fatalf("decoded kind = %q, want %q", got, securityevents.FindingRecorded)
	}
}

func TestAppendPublishesWorkflowEventAsSharedEnvelope(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}
	event, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:      "writer",
		DecisionID:    "urn:cerebro:writer:decision:decision-1",
		DecisionType:  "finding-triage",
		Status:        "approved",
		TargetIDs:     []string{"urn:cerebro:writer:resource:target-1"},
		SourceSystem:  "findings",
		SourceEventID: "finding-1",
		ObservedAt:    "2026-04-27T12:00:00Z",
		ValidFrom:     "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	if err := log.Append(context.Background(), event); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published == nil {
		t.Fatal("published message = nil")
	}
	if pub.published.Subject != "events.workflow.v1.knowledge.decision_recorded" {
		t.Fatalf("subject = %q, want workflow decision subject", pub.published.Subject)
	}
	if got := pub.published.Header.Get(nats.MsgIdHdr); got != event.GetId() {
		t.Fatalf("msg id = %q, want %q", got, event.GetId())
	}
	if got := pub.published.Header[workflowevents.EventAttributeTenantID]; len(got) != 1 || got[0] != "writer" {
		t.Fatalf("tenant header = %#v, want writer", got)
	}
	if got := pub.published.Header["event_type"]; len(got) != 1 || got[0] != workflowevents.EventKindKnowledgeDecisionRecorded {
		t.Fatalf("event_type header = %#v, want %q", got, workflowevents.EventKindKnowledgeDecisionRecorded)
	}
	replayed, err := workflowevents.DecodeSharedEnvelopeEvent(pub.published.Data, replayHeaderAttributes(pub.published.Header))
	if err != nil {
		t.Fatalf("DecodeSharedEnvelopeEvent() error = %v", err)
	}
	if replayed.GetKind() != event.GetKind() || replayed.GetId() != event.GetId() || replayed.GetTenantId() != event.GetTenantId() {
		t.Fatalf("replayed event = %#v, want kind/id/tenant from %#v", replayed, event)
	}
}

func TestAppendRejectsMissingKind(t *testing.T) {
	log := &Log{js: &fakePublisher{}, subjectPrefix: "events"}
	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Append() error = nil, want non-nil")
	}
}

func TestAppendPublishesTrimmedEnvelopeKind(t *testing.T) {
	pub := &fakePublisher{}
	log := &Log{js: pub, subjectPrefix: "events"}

	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{Id: "evt-1", Kind: " entity.upsert "}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if pub.published.Subject != "events.entity.upsert" {
		t.Fatalf("subject = %q, want events.entity.upsert", pub.published.Subject)
	}
	var decoded cerebrov1.EventEnvelope
	if err := proto.Unmarshal(pub.published.Data, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if got := decoded.GetKind(); got != "entity.upsert" {
		t.Fatalf("decoded kind = %q, want entity.upsert", got)
	}
}

func TestAppendRejectsInvalidKindSubjects(t *testing.T) {
	log := &Log{js: &fakePublisher{}, subjectPrefix: "events"}
	for _, kind := range []string{
		"entity update",
		"entity\tupdate",
		"entity..update",
		".entity",
		"entity.",
		"entity.*",
		"entity.>",
	} {
		t.Run(kind, func(t *testing.T) {
			if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{Kind: kind}); err == nil {
				t.Fatal("Append() error = nil, want non-nil")
			}
		})
	}
}

func TestAppendRejectsInvalidSubjectPrefix(t *testing.T) {
	log := &Log{js: &fakePublisher{}, subjectPrefix: "events.*"}
	if err := log.Append(context.Background(), &cerebrov1.EventEnvelope{Kind: "entity.update"}); err == nil {
		t.Fatal("Append() error = nil, want non-nil")
	}
}

func TestEventSubjectDefaultsAndValidatesPrefix(t *testing.T) {
	subject, err := eventSubject("", "entity.update")
	if err != nil {
		t.Fatalf("eventSubject() error = %v", err)
	}
	if subject != "events.entity.update" {
		t.Fatalf("eventSubject() = %q, want events.entity.update", subject)
	}
	if _, err := eventSubject("events.", "entity.update"); err == nil {
		t.Fatal("eventSubject(invalid prefix) error = nil, want non-nil")
	}
}

func TestEventSubjectKeepsCanonicalSecurityKindAbsolute(t *testing.T) {
	subject, err := eventSubject("events", securityevents.APIAccessAudit)
	if err != nil {
		t.Fatalf("eventSubject() error = %v", err)
	}
	if subject != securityevents.APIAccessAudit {
		t.Fatalf("eventSubject() = %q, want %q", subject, securityevents.APIAccessAudit)
	}
}

func TestPingSurfacesPublisherError(t *testing.T) {
	log := &Log{js: &fakePublisher{accountErr: errors.New("down")}, subjectPrefix: "events"}
	if err := log.Ping(context.Background()); err == nil {
		t.Fatal("Ping() error = nil, want non-nil")
	}
}

func TestPingRequiresMatchingStreamWhenReplayManagerIsConfigured(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{Config: natsjetstream.StreamConfig{Name: "OTHER", Subjects: []string{"other.>"}}},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}
	if err := log.Ping(context.Background()); err == nil {
		t.Fatal("Ping() error = nil, want non-nil")
	}
}

func TestPingAcceptsMatchingStream(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{Config: natsjetstream.StreamConfig{Name: "CEREBRO_EVENTS", Subjects: []string{"events.>"}}},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events", lastCanary: time.Now()}
	if err := log.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

func TestPingRunsPublishReplayCanary(t *testing.T) {
	pub := &fakePublisher{ack: &natsjetstream.PubAck{Stream: "CEREBRO_EVENTS", Sequence: 7}}
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{Name: "CEREBRO_EVENTS", Subjects: []string{"events.>"}},
				State:  natsjetstream.StreamState{FirstSeq: 1, LastSeq: 7, Msgs: 7, Bytes: 512, Consumers: 2, NumSubjects: 3},
			},
		},
		msgFunc: func(_ string, seq uint64) *natsjetstream.RawStreamMsg {
			if seq != 7 || pub.published == nil {
				return nil
			}
			return &natsjetstream.RawStreamMsg{
				Subject: pub.published.Subject,
				Header:  pub.published.Header,
				Data:    pub.published.Data,
			}
		},
	}
	log := &Log{js: pub, replay: replay, subjectPrefix: "events"}

	stderr := captureJetstreamTelemetry(t, func() {
		if err := log.Ping(context.Background()); err != nil {
			t.Fatalf("Ping() error = %v", err)
		}
	})

	if pub.publishCalls != 1 {
		t.Fatalf("publish calls = %d, want 1", pub.publishCalls)
	}
	if pub.published == nil || pub.published.Subject != "events."+jetstreamCanaryKind {
		t.Fatalf("canary subject = %#v, want events.%s", pub.published, jetstreamCanaryKind)
	}
	if got := pub.published.Header.Get(nats.MsgIdHdr); !strings.HasPrefix(got, "jetstream-canary-") {
		t.Fatalf("canary msg id = %q, want generated canary id", got)
	}
	events := jetstreamTelemetryPayloads(t, stderr, "event", "jetstream.canary.completed")
	if len(events) != 1 {
		t.Fatalf("canary completed events = %d, want 1; stderr=%s", len(events), stderr)
	}
	payload := events[0]
	for key, want := range map[string]any{
		"messaging.jetstream.canary.replayed":                   true,
		"messaging.jetstream.ack.stream":                        "CEREBRO_EVENTS",
		"messaging.jetstream.ack.sequence":                      float64(7),
		"messaging.jetstream.stream.state.messages":             float64(7),
		"messaging.jetstream.stream.state.consumer_count":       float64(2),
		"messaging.jetstream.stream.state.unique_subject_count": float64(3),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestReplayFiltersEventsByRuntime(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
				2: rawReplayMsg(t, "events.github.pull_request", replayEvent("evt-2", "github.pull_request", "other-runtime")),
				3: rawReplayMsg(t, "events.github.pull_request", replayEvent("evt-3", "github.pull_request", "writer-github")),
				4: rawReplayMsg(t, "events.ignored", replayEvent("evt-4", "ignored", "")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{
		RuntimeID: "writer-github",
		Limit:     2,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetId() != "evt-1" || events[1].GetId() != "evt-3" {
		t.Fatalf("replayed ids = [%q, %q], want [evt-1, evt-3]", events[0].GetId(), events[1].GetId())
	}
	if replay.streamCalls != 1 {
		t.Fatalf("streamCalls = %d, want 1", replay.streamCalls)
	}
}

func TestReplayExactKindFiltersUseSubjectIndex(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 5, Msgs: 5},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
				2: rawReplayMsg(t, "events.github.pull_request", replayEvent("evt-2", "github.pull_request", "writer-github")),
				3: rawReplayMsg(t, "events.github.audit", replayEvent("evt-3", "github.audit", "other-runtime")),
				4: rawReplayMsg(t, "events.github.audit", replayEvent("evt-4", "github.audit", "writer-github")),
				5: rawReplayMsg(t, "events.ignored", replayEvent("evt-5", "ignored", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	stderr := captureJetstreamTelemetry(t, func() {
		events, err := log.Replay(context.Background(), ports.ReplayRequest{
			RuntimeID:        "writer-github",
			KindPrefixes:     []string{"github.audit"},
			ExactKindFilters: true,
			Limit:            2,
		})
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("len(events) = %d, want 2", len(events))
		}
		if events[0].GetId() != "evt-1" || events[1].GetId() != "evt-4" {
			t.Fatalf("replayed ids = [%q, %q], want [evt-1, evt-4]", events[0].GetId(), events[1].GetId())
		}
	})

	if replay.getMsgCalls != 0 {
		t.Fatalf("legacy GetMsg calls = %d, want 0", replay.getMsgCalls)
	}
	if replay.nextForCalls == 0 {
		t.Fatal("NextFor subject calls = 0, want subject-index replay")
	}
	spanEnds := jetstreamTelemetryPayloads(t, stderr, "span_end", "jetstream.replay")
	if len(spanEnds) != 1 {
		t.Fatalf("jetstream.replay span_end events = %d, want 1; stderr=%s", len(spanEnds), stderr)
	}
	payload := spanEnds[0]
	for key, want := range map[string]any{
		"messaging.jetstream.replay.strategy":              replayStrategySubjectIndex,
		"messaging.jetstream.replay.subject_indexed":       true,
		"messaging.jetstream.replay.legacy_full_scan":      false,
		"messaging.jetstream.replay.subject_filter_count":  float64(1),
		"messaging.jetstream.replay.scanned_count":         float64(3),
		"messaging.jetstream.replay.subject_matched_count": float64(3),
		"messaging.jetstream.replay.decoded_count":         float64(3),
		"messaging.jetstream.replay.matched_count":         float64(2),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
}

func TestAppendNewestReplayCandidateKeepsNewestSequences(t *testing.T) {
	var candidates []replayCandidate
	for _, seq := range []uint64{100, 1, 2, 3, 101, 4} {
		candidates = appendNewestReplayCandidate(candidates, replayCandidate{seq: seq}, 3)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].seq < candidates[j].seq
	})
	got := []uint64{candidates[0].seq, candidates[1].seq, candidates[2].seq}
	want := []uint64{4, 100, 101}
	if !slices.Equal(got, want) {
		t.Fatalf("kept sequences = %#v, want %#v", got, want)
	}
}

func TestReplayEmitsScanTelemetry(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 3, Msgs: 3, Bytes: 256, Consumers: 1, NumSubjects: 2},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
				3: rawReplayMsg(t, "events.github.audit", replayEvent("evt-3", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	stderr := captureJetstreamTelemetry(t, func() {
		events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github", Limit: 2})
		if err != nil {
			t.Fatalf("Replay() error = %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("len(events) = %d, want 2", len(events))
		}
	})

	spanEnds := jetstreamTelemetryPayloads(t, stderr, "span_end", "jetstream.replay")
	if len(spanEnds) != 1 {
		t.Fatalf("jetstream.replay span_end events = %d, want 1; stderr=%s", len(spanEnds), stderr)
	}
	payload := spanEnds[0]
	for key, want := range map[string]any{
		"messaging.jetstream.stream":                       "CEREBRO_EVENTS",
		"messaging.jetstream.stream.state.messages":        float64(3),
		"messaging.jetstream.stream.state.bytes":           float64(256),
		"messaging.jetstream.replay.scanned_count":         float64(3),
		"messaging.jetstream.replay.missing_count":         float64(1),
		"messaging.jetstream.replay.subject_matched_count": float64(2),
		"messaging.jetstream.replay.decoded_count":         float64(2),
		"messaging.jetstream.replay.matched_count":         float64(2),
		"messaging.jetstream.replay.strategy":              replayStrategyLegacyReverseScan,
		"messaging.jetstream.replay.subject_indexed":       false,
		"messaging.jetstream.replay.legacy_full_scan":      true,
		"events_returned":                                  float64(2),
	} {
		if got := payload[key]; got != want {
			t.Fatalf("%s = %#v, want %#v; payload=%#v", key, got, want, payload)
		}
	}
	if _, ok := payload["messaging.jetstream.replay.duration_ms"].(float64); !ok {
		t.Fatalf("replay duration missing: %#v", payload)
	}
}

func TestReplayAppliesDefaultLimit(t *testing.T) {
	msgs := make(map[uint64]*natsjetstream.RawStreamMsg)
	for seq := uint64(1); seq <= defaultReplayLimit+5; seq++ {
		msgs[seq] = rawReplayMsg(t, "events.github.audit", replayEvent("evt-"+strconv.FormatUint(seq, 10), "github.audit", "writer-github"))
	}
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: defaultReplayLimit + 5},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{"CEREBRO_EVENTS": msgs},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != defaultReplayLimit {
		t.Fatalf("len(events) = %d, want %d", len(events), defaultReplayLimit)
	}
	if got := events[0].GetId(); got != "evt-6" {
		t.Fatalf("first replayed id = %q, want evt-6", got)
	}
	if got := events[len(events)-1].GetId(); got != "evt-105" {
		t.Fatalf("last replayed id = %q, want evt-105", got)
	}
}

func TestReplayFiltersWorkflowEventsByKindPrefixTenantAndAttribute(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.workflow.v1.knowledge.decision_recorded", workflowReplayEvent("evt-1", "workflow.v1.knowledge.decision_recorded", "writer", "knowledge_decision")),
				2: rawReplayMsg(t, "events.workflow.v1.knowledge.action_recorded", workflowReplayEvent("evt-2", "workflow.v1.knowledge.action_recorded", "writer", "knowledge_action")),
				3: rawReplayMsg(t, "events.workflow.v1.knowledge.decision_recorded", workflowReplayEvent("evt-3", "workflow.v1.knowledge.decision_recorded", "other", "knowledge_decision")),
				4: rawReplayMsg(t, "events.github.audit", replayEvent("evt-4", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{
		KindPrefix: "workflow.v1.",
		TenantID:   "writer",
		AttributeEquals: map[string]string{
			"workflow_kind": "knowledge_decision",
		},
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if got := events[0].GetId(); got != "evt-1" {
		t.Fatalf("replayed id = %q, want evt-1", got)
	}
}

func TestReplayFiltersCanonicalSecurityEventsByKindPrefix(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>", "sec.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 3},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, securityevents.FindingRecorded, replayEvent("evt-1", securityevents.FindingRecorded, "writer-github")),
				2: rawReplayMsg(t, securityevents.APIAccessAudit, replayEvent("evt-2", securityevents.APIAccessAudit, "")),
				3: rawReplayMsg(t, "events.github.audit", replayEvent("evt-3", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{KindPrefix: securityevents.FindingsV1Prefix})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if got := events[0].GetId(); got != "evt-1" {
		t.Fatalf("replayed id = %q, want evt-1", got)
	}
}

func TestReplayFiltersMultipleKindPrefixesInAppendOrder(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>", "sec.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, securityevents.FindingRecorded, workflowReplayEvent("evt-1", securityevents.FindingRecorded, "writer", "")),
				2: rawReplayMsg(t, "events.github.audit", replayEvent("evt-2", "github.audit", "writer-github")),
				3: rawReplayMsg(t, "events.workflow.v1.finding.tombstoned", workflowReplayEvent("evt-3", "workflow.v1.finding.tombstoned", "writer", "")),
				4: rawReplayMsg(t, securityevents.ToolRegistered, workflowReplayEvent("evt-4", securityevents.ToolRegistered, "writer", "")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{
		KindPrefixes: []string{"workflow.v1.", securityevents.FindingsV1Prefix + "."},
		TenantID:     "writer",
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetId() != "evt-1" || events[1].GetId() != "evt-3" {
		t.Fatalf("replayed ids = [%q, %q], want [evt-1, evt-3]", events[0].GetId(), events[1].GetId())
	}
}

func TestReplaySkipsDecodeForSubjectsOutsideKindPrefix(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 1},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: &natsjetstream.RawStreamMsg{Subject: "events.github.audit", Data: []byte("not protobuf")},
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{KindPrefix: "workflow.v1."})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("len(events) = %d, want 0", len(events))
	}
}

func TestReplayDecodesSharedWorkflowEnvelope(t *testing.T) {
	event, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:      "writer",
		DecisionID:    "urn:cerebro:writer:decision:decision-1",
		DecisionType:  "finding-triage",
		Status:        "approved",
		TargetIDs:     []string{"urn:cerebro:writer:resource:target-1"},
		SourceSystem:  "findings",
		SourceEventID: "finding-1",
		ObservedAt:    "2026-04-27T12:00:00Z",
		ValidFrom:     "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 1},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: &natsjetstream.RawStreamMsg{
					Subject: "events.workflow.v1.knowledge.decision_recorded",
					Header:  eventAttributesHeader(event.GetAttributes()),
					Data:    event.GetPayload(),
				},
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{
		KindPrefix: "workflow.v1.",
		TenantID:   "writer",
		AttributeEquals: map[string]string{
			workflowevents.EventAttributeWorkflowKind: "knowledge_decision",
		},
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
	if events[0].GetId() != event.GetId() {
		t.Fatalf("replayed id = %q, want %q", events[0].GetId(), event.GetId())
	}
	decoded, err := workflowevents.DecodeDecisionRecorded(events[0])
	if err != nil {
		t.Fatalf("DecodeDecisionRecorded() error = %v", err)
	}
	if decoded.DecisionID != "urn:cerebro:writer:decision:decision-1" {
		t.Fatalf("decoded decision id = %q", decoded.DecisionID)
	}
}

func TestReplayScansSparseStreamsUntilLimitOrStreamStart(t *testing.T) {
	const matchingSeq = uint64(10005)
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: matchingSeq},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				matchingSeq: rawReplayMsg(t, "events.github.audit", replayEvent("evt-sparse", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 1 || events[0].GetId() != "evt-sparse" {
		t.Fatalf("replayed events = %#v, want evt-sparse", events)
	}
	if replay.getMsgCalls != int(matchingSeq) {
		t.Fatalf("getMsgCalls = %d, want %d", replay.getMsgCalls, matchingSeq)
	}
}

func TestReplayReturnsLatestMatchesInAppendOrder(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
				2: rawReplayMsg(t, "events.github.audit", replayEvent("evt-2", "github.audit", "writer-github")),
				3: rawReplayMsg(t, "events.github.audit", replayEvent("evt-3", "github.audit", "other-runtime")),
				4: rawReplayMsg(t, "events.github.audit", replayEvent("evt-4", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github", Limit: 2})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetId() != "evt-2" || events[1].GetId() != "evt-4" {
		t.Fatalf("replayed ids = [%q, %q], want [evt-2, evt-4]", events[0].GetId(), events[1].GetId())
	}
}

func TestReplayReturnsNewestOccurredEventsWhenAppendedNewestFirst(t *testing.T) {
	base := time.Date(2026, 5, 13, 18, 0, 0, 0, time.UTC)
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 4},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEventAt("evt-newest", "github.audit", "writer-github", base.Add(4*time.Minute))),
				2: rawReplayMsg(t, "events.github.audit", replayEventAt("evt-newer", "github.audit", "writer-github", base.Add(3*time.Minute))),
				3: rawReplayMsg(t, "events.github.audit", replayEventAt("evt-older", "github.audit", "writer-github", base.Add(2*time.Minute))),
				4: rawReplayMsg(t, "events.github.audit", replayEventAt("evt-oldest", "github.audit", "writer-github", base.Add(time.Minute))),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github", Limit: 2})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if events[0].GetId() != "evt-newest" || events[1].GetId() != "evt-newer" {
		t.Fatalf("replayed ids = [%q, %q], want newest events [evt-newest, evt-newer]", events[0].GetId(), events[1].GetId())
	}
}

func TestReplayStopsAfterBoundedCandidateWindow(t *testing.T) {
	msgs := make(map[uint64]*natsjetstream.RawStreamMsg)
	for seq := uint64(1); seq <= 100; seq++ {
		msgs[seq] = rawReplayMsg(t, "events.github.audit", replayEvent("evt-"+strconv.FormatUint(seq, 10), "github.audit", "writer-github"))
	}
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.>"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 100},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{"CEREBRO_EVENTS": msgs},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github", Limit: 2})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("len(events) = %d, want 2", len(events))
	}
	if replay.getMsgCalls != 10 {
		t.Fatalf("getMsgCalls = %d, want bounded candidate window 10", replay.getMsgCalls)
	}
}

func TestSubjectMatchesRequiresTokenForFullWildcard(t *testing.T) {
	if subjectMatches("events.>", "events") {
		t.Fatal("subjectMatches(events.>, events) = true, want false")
	}
	if !subjectMatches("events.>", "events.github.audit") {
		t.Fatal("subjectMatches(events.>, events.github.audit) = false, want true")
	}
}

func TestReplayStreamMatchesMultiTokenSubjectPatterns(t *testing.T) {
	replay := &fakeReplayManager{
		streams: []*natsjetstream.StreamInfo{
			{
				Config: natsjetstream.StreamConfig{
					Name:     "CEREBRO_EVENTS",
					Subjects: []string{"events.*.*"},
				},
				State: natsjetstream.StreamState{FirstSeq: 1, LastSeq: 1},
			},
		},
		msgs: map[string]map[uint64]*natsjetstream.RawStreamMsg{
			"CEREBRO_EVENTS": {
				1: rawReplayMsg(t, "events.github.audit", replayEvent("evt-1", "github.audit", "writer-github")),
			},
		},
	}
	log := &Log{js: &fakePublisher{}, replay: replay, subjectPrefix: "events"}

	events, err := log.Replay(context.Background(), ports.ReplayRequest{RuntimeID: "writer-github"})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(events))
	}
}

func TestSubjectPatternOverlapsPrefix(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		prefix  string
		want    bool
	}{
		{pattern: "events.>", prefix: "events", want: true},
		{pattern: "events.*", prefix: "events", want: true},
		{pattern: "events.*.*", prefix: "events", want: true},
		{pattern: "events.github.>", prefix: "events", want: true},
		{pattern: "events", prefix: "events", want: false},
		{pattern: "other.>", prefix: "events", want: false},
	} {
		t.Run(tt.pattern, func(t *testing.T) {
			if got := subjectPatternOverlapsPrefix(tt.pattern, tt.prefix); got != tt.want {
				t.Fatalf("subjectPatternOverlapsPrefix(%q, %q) = %v, want %v", tt.pattern, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestReplayRejectsMissingFilter(t *testing.T) {
	log := &Log{replay: &fakeReplayManager{}, subjectPrefix: "events"}
	if _, err := log.Replay(context.Background(), ports.ReplayRequest{}); err == nil {
		t.Fatal("Replay() error = nil, want non-nil")
	}
}

func TestReplayStreamMatchesMultiTokenWildcardSubjects(t *testing.T) {
	log := &Log{
		replay: &fakeReplayManager{
			streams: []*natsjetstream.StreamInfo{
				{
					Config: natsjetstream.StreamConfig{
						Name:     "CEREBRO_EVENTS",
						Subjects: []string{"events.*.>"},
					},
				},
			},
		},
		subjectPrefix: "events",
	}

	stream, err := log.replayStream(context.Background())
	if err != nil {
		t.Fatalf("replayStream() error = %v", err)
	}
	if stream == nil {
		t.Fatal("replayStream() = nil, want non-nil")
	}
	if got := stream.Config.Name; got != "CEREBRO_EVENTS" {
		t.Fatalf("replayStream().Config.Name = %q, want CEREBRO_EVENTS", got)
	}
}

func TestSubjectMatchesRequiresRemainingTokensForWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		subject string
		want    bool
	}{
		{pattern: "events.*.>", subject: "events.replay", want: false},
		{pattern: "events.*.>", subject: "events.github.audit", want: true},
		{pattern: "events.>", subject: "events", want: false},
		{pattern: "events.>", subject: "events.github", want: true},
	}
	for _, tt := range tests {
		if got := subjectMatches(tt.pattern, tt.subject); got != tt.want {
			t.Fatalf("subjectMatches(%q, %q) = %v, want %v", tt.pattern, tt.subject, got, tt.want)
		}
	}
}

func workflowReplayEvent(id string, kind string, tenantID string, workflowKind string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       id,
		TenantId: tenantID,
		Kind:     kind,
		SourceId: "platform.knowledge",
		Attributes: map[string]string{
			"workflow_kind": workflowKind,
		},
	}
}

func replayEvent(id string, kind string, runtimeID string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:       id,
		Kind:     kind,
		SourceId: "github",
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: runtimeID,
		},
	}
}

//nolint:unparam // Helper preserves explicit event-kind argument for table readability.
func replayEventAt(id string, kind string, runtimeID string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	event := replayEvent(id, kind, runtimeID)
	event.OccurredAt = timestamppb.New(occurredAt)
	return event
}

func rawReplayMsg(t *testing.T, subject string, event *cerebrov1.EventEnvelope) *natsjetstream.RawStreamMsg {
	t.Helper()
	payload, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	return &natsjetstream.RawStreamMsg{Subject: subject, Data: payload}
}

package events

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/pipeline"
	"github.com/evalops/cerebro/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type consumerBatchDecodedMessage struct {
	message        consumerPipelineMessage
	ctx            context.Context
	event          CloudEvent
	decodeErr      error
	payloadPreview string
}

type consumerBatchPersistKind uint8

const (
	consumerBatchPersistProcessed consumerBatchPersistKind = iota
	consumerBatchPersistDuplicate
	consumerBatchPersistHashMismatch
	consumerBatchPersistHandlerFailure
	consumerBatchPersistMalformed
)

type consumerBatchPersistRecord struct {
	kind           consumerBatchPersistKind
	message        consumerPipelineMessage
	ctx            context.Context
	event          CloudEvent
	result         consumerMessageResult
	err            error
	payloadPreview string
	ingestSpan     trace.Span
}

type consumerBatchDeduper struct {
	mu   sync.Mutex
	seen map[string]string
}

func (c *Consumer) processBatchWithPipeline(ctx context.Context, messages []consumerPipelineMessage) bool {
	if len(messages) == 0 {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	batchInProgress := make([]func() error, len(messages))
	for i := range messages {
		batchInProgress[i] = messages[i].inProgress
	}
	deactivateBatchHeartbeat, stopBatchHeartbeat := c.startBatchInProgressHeartbeat(ctx, batchInProgress)
	defer stopBatchHeartbeat()

	intakeSignal := &pipeline.BackpressureSignal{}
	intake := pipeline.StreamSlice(ctx, messages, consumerPipelineStageBuffer(c.config, len(messages)), intakeSignal)

	batchDeduper := consumerBatchDeduper{seen: make(map[string]string, len(messages))}
	handlerWorkers := consumerHandlerWorkers(c.config)
	transformStage := pipeline.StartStage(ctx, intake, pipeline.StageConfig[consumerPipelineMessage, consumerBatchPersistRecord]{
		Workers: handlerWorkers,
		Buffer:  consumerHandlerQueueDepth(c.config, handlerWorkers),
		Key: func(message consumerPipelineMessage) string {
			return consumerOrderingKeyForMessage(message)
		},
		Transform: func(stageCtx context.Context, message consumerPipelineMessage) (consumerBatchPersistRecord, bool) {
			return c.transformBatchMessage(stageCtx, message, &batchDeduper), true
		},
	})

	persistSink := pipeline.StartBatchSink(ctx, transformStage.Output(), pipeline.BatchConfig[consumerBatchPersistRecord]{
		BatchSize: consumerPersistBatchSize(c.config),
		Flush: func(flushCtx context.Context, batch []consumerBatchPersistRecord) {
			c.persistBatchRecords(flushCtx, batch, deactivateBatchHeartbeat)
		},
	})

	persistSink.Wait()
	transformStage.Wait()

	return intakeSignal.Active() || transformStage.Backpressured()
}

func (c *Consumer) decodePipelineMessageForBatch(ctx context.Context, message consumerPipelineMessage) consumerBatchDecodedMessage {
	envelope := consumerTraceEnvelopeFromPayload(message.payload)
	traceCtx := consumerTraceContext(ctx, envelope.TraceParent)
	decodeCtx, decodeSpan := c.startTracingSpan(traceCtx, "cerebro.event.decode", c.consumerEnvelopeAttributes(message, envelope)...)
	defer decodeSpan.End()

	decoded := consumerBatchDecodedMessage{
		message: message,
		ctx:     decodeCtx,
	}
	if err := json.Unmarshal(message.payload, &decoded.event); err != nil {
		consumerRecordSpanError(decodeSpan, err)
		decoded.decodeErr = err
		decoded.payloadPreview = payloadPreview(message.payload, c.config.PayloadPreviewBytes)
		return decoded
	}
	decodeSpan.SetAttributes(c.consumerEventAttributes(message, decoded.event)...)
	return decoded
}

func (c *Consumer) transformBatchMessage(ctx context.Context, message consumerPipelineMessage, batchDeduper *consumerBatchDeduper) consumerBatchPersistRecord {
	decoded := c.decodePipelineMessageForBatch(ctx, message)
	return c.transformDecodedBatchMessage(decoded, batchDeduper)
}

func (c *Consumer) transformDecodedBatchMessage(decoded consumerBatchDecodedMessage, batchDeduper *consumerBatchDeduper) consumerBatchPersistRecord {
	if decoded.decodeErr != nil {
		return consumerBatchPersistRecord{
			kind:           consumerBatchPersistMalformed,
			message:        decoded.message,
			ctx:            decoded.ctx,
			err:            decoded.decodeErr,
			payloadPreview: decoded.payloadPreview,
		}
	}

	evt := decoded.event
	ingestCtx, ingestSpan := c.startTracingSpan(decoded.ctx, "cerebro.event.ingest", c.consumerEventAttributes(decoded.message, evt)...)
	dedupCtx, dedupSpan := c.startTracingSpan(ingestCtx, "cerebro.event.dedup", c.consumerEventAttributes(decoded.message, evt)...)
	if duplicate, hashMismatch := batchDeduper.observe(evt, decoded.message.payload); duplicate {
		if hashMismatch {
			dedupSpan.End()
			return consumerBatchPersistRecord{
				kind:       consumerBatchPersistHashMismatch,
				message:    decoded.message,
				ctx:        ingestCtx,
				event:      evt,
				err:        fmt.Errorf("duplicate event key matched different payload hash within batch"),
				ingestSpan: ingestSpan,
			}
		}
		dedupSpan.SetAttributes(attribute.Bool("cerebro.event.duplicate", true))
		dedupSpan.End()
		return consumerBatchPersistRecord{
			kind:       consumerBatchPersistDuplicate,
			message:    decoded.message,
			ctx:        ingestCtx,
			event:      evt,
			ingestSpan: ingestSpan,
		}
	}
	if c.deduper != nil {
		record, hashMismatch, err := c.deduper.Lookup(dedupCtx, evt, decoded.message.payload, time.Now().UTC())
		if err != nil {
			consumerRecordSpanError(dedupSpan, err)
			c.logger.Warn("tap consumer dedupe lookup failed; continuing without duplicate suppression",
				"error", err,
				"event_id", evt.ID,
				"event_type", evt.Type,
			)
		} else if record != nil {
			if hashMismatch {
				dedupSpan.End()
				return consumerBatchPersistRecord{
					kind:       consumerBatchPersistHashMismatch,
					message:    decoded.message,
					ctx:        ingestCtx,
					event:      evt,
					err:        fmt.Errorf("duplicate event key matched different payload hash: processed_at=%s", record.ProcessedAt.UTC().Format(time.RFC3339Nano)),
					ingestSpan: ingestSpan,
				}
			}
			dedupSpan.SetAttributes(attribute.Bool("cerebro.event.duplicate", true))
			dedupSpan.End()
			return consumerBatchPersistRecord{
				kind:       consumerBatchPersistDuplicate,
				message:    decoded.message,
				ctx:        ingestCtx,
				event:      evt,
				ingestSpan: ingestSpan,
			}
		}
	}
	dedupSpan.End()

	handlerCtx, handlerSpan := c.startTracingSpan(ingestCtx, "cerebro.event.handle", c.consumerEventAttributes(decoded.message, evt)...)
	handlerCtx = telemetry.ContextWithAttributes(handlerCtx, c.consumerEventAttributes(decoded.message, evt)...)
	if err := c.handler(handlerCtx, evt); err != nil {
		consumerRecordSpanError(handlerSpan, err)
		handlerSpan.End()
		return consumerBatchPersistRecord{
			kind:       consumerBatchPersistHandlerFailure,
			message:    decoded.message,
			ctx:        ingestCtx,
			event:      evt,
			err:        err,
			ingestSpan: ingestSpan,
		}
	}
	handlerSpan.End()

	return consumerBatchPersistRecord{
		kind:    consumerBatchPersistProcessed,
		message: decoded.message,
		ctx:     ingestCtx,
		event:   evt,
		result: consumerMessageResult{
			Processed: true,
			EventTime: evt.Time.UTC(),
		},
		ingestSpan: ingestSpan,
	}
}

func (c *Consumer) persistBatchRecords(ctx context.Context, batch []consumerBatchPersistRecord, deactivate func(int)) {
	for _, record := range batch {
		result := c.persistBatchRecord(ctx, record)
		if deactivate != nil {
			deactivate(record.message.index)
		}
		if result.Processed {
			c.recordProcessed(result.ProcessedAt, result.EventTime)
		}
	}
}

func (c *Consumer) persistBatchRecord(ctx context.Context, record consumerBatchPersistRecord) consumerMessageResult {
	defer func() {
		if record.ingestSpan != nil {
			record.ingestSpan.End()
		}
	}()

	switch record.kind {
	case consumerBatchPersistMalformed:
		if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
			RecordedAt: time.Now().UTC(),
			Stream:     c.config.Stream,
			Durable:    c.config.Durable,
			Subject:    record.message.subject,
			Reason:     "malformed",
			Error:      record.err.Error(),
			Payload:    string(record.message.payload),
		}); dlqErr != nil {
			c.logger.Error("tap consumer failed to dead-letter malformed cloud event; message requeued",
				"error", dlqErr,
				"subject", record.message.subject,
				"stream", c.config.Stream,
				"durable", c.config.Durable,
				"payload_preview", record.payloadPreview,
			)
			if nakErr := record.message.nak(); nakErr != nil {
				c.logger.Warn("tap consumer nak failed after dead-letter error", "error", nakErr, "subject", record.message.subject)
			}
			return consumerMessageResult{}
		}
		c.logger.Error("tap consumer dead-lettered malformed cloud event",
			"error", record.err,
			"subject", record.message.subject,
			"stream", c.config.Stream,
			"durable", c.config.Durable,
			"payload_preview", record.payloadPreview,
		)
		c.recordDropped("malformed", time.Now().UTC())
		if err := record.message.ack(); err != nil {
			c.logger.Warn("tap consumer ack failed after dead-lettering malformed event", "error", err, "subject", record.message.subject)
		}
		return consumerMessageResult{}

	case consumerBatchPersistDuplicate:
		if c.deduper != nil {
			if err := c.deduper.ObserveDuplicate(ctx, record.event, time.Now().UTC()); err != nil {
				c.logger.Warn("tap consumer failed to refresh duplicate dedupe state",
					"error", err,
					"event_id", record.event.ID,
					"event_type", record.event.Type,
				)
			}
		}
		metrics.RecordNATSConsumerDeduplicated(c.config.Stream, c.config.Durable)
		if err := c.consumerAckWithTracing(record.ctx, record.message, record.event, "ack", record.message.ack); err != nil {
			c.logger.Warn("tap consumer ack failed after duplicate suppression", "error", err, "event_type", record.event.Type)
		}
		return consumerMessageResult{}

	case consumerBatchPersistHashMismatch:
		if c.deduper != nil {
			if err := c.deduper.Forget(ctx, record.event); err != nil {
				c.logger.Error("tap consumer failed to clear conflicting dedupe state; message requeued",
					"error", err,
					"event_id", record.event.ID,
					"event_type", record.event.Type,
				)
				if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak", record.message.nak); nakErr != nil {
					c.logger.Warn("tap consumer nak failed after dedupe hash mismatch state clear failure", "error", nakErr, "event_type", record.event.Type)
				}
				return consumerMessageResult{}
			}
		}
		if dlqErr := c.dlq.Write(consumerDeadLetterRecord{
			RecordedAt: time.Now().UTC(),
			Stream:     c.config.Stream,
			Durable:    c.config.Durable,
			Subject:    record.message.subject,
			Reason:     "dedupe_hash_mismatch",
			Error:      record.err.Error(),
			Payload:    string(record.message.payload),
		}); dlqErr != nil {
			c.logger.Error("tap consumer failed to dead-letter duplicate hash mismatch; message requeued",
				"error", dlqErr,
				"event_id", record.event.ID,
				"event_type", record.event.Type,
				"source", record.event.Source,
			)
			if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak", record.message.nak); nakErr != nil {
				c.logger.Warn("tap consumer nak failed after dedupe hash mismatch dead-letter error", "error", nakErr, "event_type", record.event.Type)
			}
			return consumerMessageResult{}
		}
		c.logger.Error("tap consumer dead-lettered duplicate event key with different payload hash",
			"event_id", record.event.ID,
			"event_type", record.event.Type,
			"source", record.event.Source,
		)
		if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak", record.message.nak); nakErr != nil {
			c.logger.Warn("tap consumer nak failed after clearing dedupe hash mismatch state", "error", nakErr, "event_type", record.event.Type)
		}
		return consumerMessageResult{}

	case consumerBatchPersistHandlerFailure:
		if delay, ok := retryDelay(record.err); ok && record.message.nakWithDelay != nil {
			c.logger.Info("tap consumer handler deferred; message requeued with delay",
				"error", record.err,
				"event_type", record.event.Type,
				"delay", delay,
			)
			if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak_with_delay", func() error {
				return record.message.nakWithDelay(delay)
			}); nakErr != nil {
				c.logger.Warn("tap consumer delayed nak failed", "error", nakErr, "event_type", record.event.Type, "delay", delay)
			}
			return consumerMessageResult{}
		}
		c.logger.Warn("tap consumer handler failed; message requeued", "error", record.err, "event_type", record.event.Type)
		if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak", record.message.nak); nakErr != nil {
			c.logger.Warn("tap consumer nak failed", "error", nakErr, "event_type", record.event.Type)
		}
		return consumerMessageResult{}

	case consumerBatchPersistProcessed:
		processedAt := time.Now().UTC()
		metrics.RecordNATSConsumerProcessed(c.config.Stream, c.config.Durable)
		if c.deduper != nil {
			if err := c.deduper.Remember(ctx, record.event, record.message.payload, processedAt); err != nil {
				c.logger.Warn("tap consumer failed to persist processed event dedupe state",
					"error", err,
					"event_id", record.event.ID,
					"event_type", record.event.Type,
				)
			}
		}
		if err := c.consumerAckWithTracing(record.ctx, record.message, record.event, "ack", record.message.ack); err != nil {
			c.logger.Warn("tap consumer ack failed", "error", err, "event_type", record.event.Type)
		}
		record.result.ProcessedAt = processedAt
		return record.result

	default:
		c.logger.Error("tap consumer encountered unknown persist record kind; message requeued",
			"kind", record.kind,
			"subject", record.message.subject,
		)
		if nakErr := c.consumerAckWithTracing(record.ctx, record.message, record.event, "nak", record.message.nak); nakErr != nil {
			c.logger.Warn("tap consumer nak failed for unknown persist record kind",
				"error", nakErr,
				"kind", record.kind,
				"subject", record.message.subject,
			)
		}
		return consumerMessageResult{}
	}
}

func consumerPipelineStageBuffer(cfg ConsumerConfig, count int) int {
	if count <= 0 {
		return 1
	}
	if cfg.BatchSize > 0 && cfg.BatchSize < count {
		return cfg.BatchSize
	}
	return count
}

func consumerPersistBatchSize(cfg ConsumerConfig) int {
	workers := consumerHandlerWorkers(cfg)
	size := workers * 2
	if size < 1 {
		size = 1
	}
	if cfg.BatchSize > 0 && size > cfg.BatchSize {
		size = cfg.BatchSize
	}
	return size
}

func consumerOrderingKeyForMessage(message consumerPipelineMessage) string {
	var envelope struct {
		ID       string          `json:"id"`
		Source   string          `json:"source"`
		Type     string          `json:"type"`
		Subject  string          `json:"subject,omitempty"`
		TenantID string          `json:"tenant_id"`
		Data     json.RawMessage `json:"data,omitempty"`
	}
	if err := json.Unmarshal(message.payload, &envelope); err != nil {
		return strings.TrimSpace(message.subject)
	}

	tenantID := strings.TrimSpace(envelope.TenantID)
	if entityID := consumerOrderingEntityID(envelope.Data); entityID != "" {
		return tenantID + "|" + entityID
	}
	if key, ok := consumerProcessedEventKey(CloudEvent{
		ID:       envelope.ID,
		Source:   envelope.Source,
		Type:     envelope.Type,
		Subject:  envelope.Subject,
		TenantID: envelope.TenantID,
	}); ok {
		return key
	}
	if subject := strings.TrimSpace(envelope.Subject); subject != "" {
		return tenantID + "|" + subject
	}
	if eventID := strings.TrimSpace(envelope.ID); eventID != "" {
		return tenantID + "|" + eventID
	}
	return strings.TrimSpace(envelope.Type)
}

func consumerOrderingEntityID(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}

	var envelope struct {
		EntityID    interface{} `json:"entity_id"`
		ResourceID  interface{} `json:"resource_id"`
		Target      interface{} `json:"target"`
		CustomerID  interface{} `json:"customer_id"`
		PrincipalID interface{} `json:"principal_id"`
		NodeID      interface{} `json:"node_id"`
		Resource    struct {
			ID interface{} `json:"id"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return ""
	}

	for _, value := range []interface{}{
		envelope.EntityID,
		envelope.ResourceID,
		envelope.Target,
		envelope.CustomerID,
		envelope.PrincipalID,
		envelope.NodeID,
		envelope.Resource.ID,
	} {
		if entityID := strings.TrimSpace(stringValue(value)); entityID != "" {
			return entityID
		}
	}
	return ""
}

func (d *consumerBatchDeduper) observe(evt CloudEvent, payload []byte) (bool, bool) {
	if d == nil {
		return false, false
	}
	key, ok := consumerProcessedEventKey(evt)
	if !ok {
		return false, false
	}
	hash := consumerProcessedEventPayloadHash(payload)
	d.mu.Lock()
	defer d.mu.Unlock()
	previous, seen := d.seen[key]
	if !seen {
		d.seen[key] = hash
		return false, false
	}
	return true, previous != hash
}

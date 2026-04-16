package stream

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/events"
)

func CloudEventType(evt events.CloudEvent) string {
	eventType := strings.TrimSpace(evt.Type)
	if eventType != "" {
		return eventType
	}
	return strings.TrimSpace(evt.Subject)
}

func (r *Runtime) HandleGraphCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	eventType := CloudEventType(evt)
	switch {
	case strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap."):
		return r.HandleTapCloudEvent(ctx, evt)
	case isAuditMutationEventType(eventType):
		return r.handleAuditMutationCloudEvent(ctx, evt)
	default:
		return nil
	}
}

func (r *Runtime) HandleTapCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	if ctx == nil {
		ctx = context.Background()
	}
	eventType := CloudEventType(evt)
	if !strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap.") {
		return nil
	}
	if err := r.waitForSecurityGraphReady(ctx); err != nil {
		return err
	}
	if IsTapSchemaEventType(eventType) {
		return r.handleTapSchemaEvent(eventType, evt)
	}
	if IsTapInteractionType(eventType) {
		return r.handleTapInteractionEvent(ctx, eventType, evt)
	}
	if mapped, err := r.applyTapDeclarativeMappings(ctx, evt); err != nil {
		return err
	} else if mapped {
		return nil
	}

	system, entityType, _ := ParseTapType(eventType)
	if system == "" {
		return nil
	}
	if IsTapActivityType(eventType) {
		return r.handleTapActivityEvent(ctx, system, entityType, evt)
	}
	return r.handleTapBusinessEvent(ctx, eventType, evt)
}

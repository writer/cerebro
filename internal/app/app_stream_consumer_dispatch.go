package app

import (
	"context"
	"strings"

	"github.com/writer/cerebro/internal/events"
)

func (a *App) handleGraphCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	eventType := cloudEventType(evt)
	switch {
	case strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap."):
		return a.handleTapCloudEvent(ctx, evt)
	case isAuditMutationEventType(eventType):
		return a.handleAuditMutationCloudEvent(ctx, evt)
	default:
		return nil
	}
}

func cloudEventType(evt events.CloudEvent) string {
	eventType := strings.TrimSpace(evt.Type)
	if eventType != "" {
		return eventType
	}
	return strings.TrimSpace(evt.Subject)
}

func (a *App) handleTapCloudEvent(ctx context.Context, evt events.CloudEvent) error {
	eventType := cloudEventType(evt)
	if !strings.HasPrefix(strings.ToLower(eventType), "ensemble.tap.") {
		return nil
	}
	if isTapSchemaEventType(eventType) {
		return a.handleTapSchemaEvent(eventType, evt)
	}
	if err := a.waitForSecurityGraphReady(ctx); err != nil {
		return err
	}
	if isTapInteractionType(eventType) {
		return a.handleTapInteractionEvent(ctx, eventType, evt)
	}
	if mapped, err := a.applyTapDeclarativeMappings(ctx, evt); err != nil {
		return err
	} else if mapped {
		return nil
	}

	system, entityType, _ := parseTapType(eventType)
	if system == "" {
		return nil
	}
	if isTapActivityType(eventType) {
		return a.handleTapActivityEvent(ctx, system, entityType, evt)
	}
	return a.handleTapBusinessEvent(ctx, eventType, evt)
}

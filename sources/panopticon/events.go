package panopticon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func buildEvent(rec panopticonRecord, kind, schemaRef string) (*primitives.Event, error) {
	if strings.TrimSpace(rec.ID) == "" {
		return nil, errors.New("id is required")
	}
	if rec.OccurredAt.IsZero() {
		return nil, errors.New("occurred_at is required")
	}
	if strings.TrimSpace(rec.SourceID) != sourceID {
		return nil, fmt.Errorf("source_id %q does not match %q", rec.SourceID, sourceID)
	}
	if strings.TrimSpace(rec.Kind) != kind {
		return nil, fmt.Errorf("kind %q does not match configured family kind %q", rec.Kind, kind)
	}
	if strings.TrimSpace(rec.SchemaRef) != schemaRef {
		return nil, fmt.Errorf("schema_ref %q does not match configured family schema_ref %q", rec.SchemaRef, schemaRef)
	}
	if rec.Payload == nil {
		return nil, errors.New("payload is required")
	}
	if err := validateRawFamilyContract(kind, rec.Attributes, rec.Payload); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(rec.Payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	tenantID := strings.TrimSpace(rec.TenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	attributes := make(map[string]string, len(rec.Attributes))
	for k, v := range rec.Attributes {
		attributes[k] = v
	}
	promotePayloadAttributes(kind, attributes, rec.Payload)
	return &primitives.Event{
		Id:         rec.ID,
		TenantId:   tenantID,
		SourceId:   rec.SourceID,
		Kind:       rec.Kind,
		SchemaRef:  rec.SchemaRef,
		OccurredAt: timestamppb.New(rec.OccurredAt.UTC()),
		Payload:    payload,
		Attributes: attributes,
	}, nil
}

func sourcecdkEventContracts() []sourcecdk.EventContract {
	return []sourcecdk.EventContract{
		{Kind: kindAlert, SchemaRef: schemaRefAlert, RequiredAttributes: []string{"alert_id", "severity", "status"}, RequiredPayloadFields: []string{"alert_id", "severity", "status", "title"}},
		{Kind: kindCase, SchemaRef: schemaRefCase, RequiredAttributes: []string{"case_id", "status"}, RequiredPayloadFields: []string{"case_id", "status", "title"}},
		{Kind: kindIOC, SchemaRef: schemaRefIOC, RequiredAttributes: []string{"ioc_id", "ioc_type", "value"}, RequiredPayloadFields: []string{"ioc_id", "ioc_type", "value"}},
	}
}

func validateRawFamilyContract(kind string, attributes map[string]string, payload map[string]interface{}) error {
	required, err := requiredAttributeKeys(kind)
	if err != nil {
		return err
	}
	for _, key := range required {
		attribute, ok := attributes[key]
		if !ok || strings.TrimSpace(attribute) == "" {
			return fmt.Errorf("kind %q missing required attribute %q", kind, key)
		}
		payloadValue := (sourcecdk.JSONScalar{Value: payload[key]}).String()
		if payloadValue == "" {
			return fmt.Errorf("kind %q missing required payload field %q", kind, key)
		}
		if payloadValue != strings.TrimSpace(attribute) {
			return fmt.Errorf("kind %q attribute %q does not match payload", kind, key)
		}
	}
	if kind == kindAlert || kind == kindCase {
		if (sourcecdk.JSONScalar{Value: payload["title"]}).String() == "" {
			return fmt.Errorf("kind %q missing required payload field %q", kind, "title")
		}
	}
	return nil
}

func validateFamilyContract(event *primitives.Event) error {
	payload := map[string]interface{}{}
	if err := json.Unmarshal(event.GetPayload(), &payload); err != nil {
		return fmt.Errorf("decode payload object: %w", err)
	}
	required, err := requiredAttributeKeys(event.GetKind())
	if err != nil {
		return err
	}
	for _, key := range required {
		attribute := strings.TrimSpace(event.GetAttributes()[key])
		payloadValue := (sourcecdk.JSONScalar{Value: payload[key]}).String()
		if attribute == "" {
			return fmt.Errorf("kind %q missing required attribute %q", event.GetKind(), key)
		}
		if payloadValue == "" {
			return fmt.Errorf("kind %q missing required payload field %q", event.GetKind(), key)
		}
		if payloadValue != attribute {
			return fmt.Errorf("kind %q attribute %q does not match payload", event.GetKind(), key)
		}
	}
	if event.GetKind() == kindAlert || event.GetKind() == kindCase {
		if (sourcecdk.JSONScalar{Value: payload["title"]}).String() == "" {
			return fmt.Errorf("kind %q missing required payload field %q", event.GetKind(), "title")
		}
	}
	return nil
}

func requiredAttributeKeys(kind string) ([]string, error) {
	switch kind {
	case kindAlert:
		return []string{"alert_id", "severity", "status"}, nil
	case kindCase:
		return []string{"case_id", "status"}, nil
	case kindIOC:
		return []string{"ioc_id", "ioc_type", "value"}, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
}

func promotePayloadAttributes(kind string, attributes map[string]string, payload map[string]interface{}) {
	if len(payload) == 0 {
		return
	}
	for _, key := range payloadPromotedAttributeKeys(kind) {
		if _, ok := attributes[key]; ok {
			continue
		}
		if value := (sourcecdk.JSONScalar{Value: payload[key]}).String(); value != "" {
			attributes[key] = value
		}
	}
}

func payloadPromotedAttributeKeys(kind string) []string {
	switch kind {
	case kindAlert:
		return []string{"alert_id", "severity", "status", "title", "case_id", "case_title", "case_status", "created_at", "updated_at", "observed_at", "closed_at", "resolved_at", "alert_creation_time", "alert_source_event_time", "alert_closed_time", "alert_resolved_time", "close_date", "resolved_date"}
	case kindCase:
		return []string{"case_id", "status", "title", "created_at", "updated_at", "observed_at", "closed_at", "resolved_at", "initial_date", "open_date", "close_date", "resolved_date"}
	case kindIOC:
		return []string{"ioc_id", "ioc_type", "value"}
	default:
		return nil
	}
}

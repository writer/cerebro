package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func kandjiDeviceEvent(id string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "kandji",
		Kind:       "kandji.device",
		Attributes: attrs,
	}
}

func TestProjectKandjiDevicePostureEnrichment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := kandjiDeviceEvent("kandji-device-posture", map[string]string{
		"device_id":         "device-1",
		"device_name":       "mba-1",
		"serial_number":     "SERIAL1",
		"blueprint_id":      "blueprint-1",
		"blueprint_name":    "Engineering Macs",
		"mdm_enabled":       "true",
		"filevault_enabled": "false",
		"is_missing":        "false",
		"owner_email":       "alice@writer.com",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kandji_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	blueprintURN := "urn:cerebro:writer:kandji_blueprint:blueprint-1"

	device := state.entities[deviceURN]
	if device == nil || device.EntityType != "kandji.device" {
		t.Fatalf("kandji.device entity missing or wrong: %#v", device)
	}
	for key, want := range map[string]string{
		"mdm_enabled":       "true",
		"filevault_enabled": "false",
		"is_missing":        "false",
	} {
		if got := device.Attributes[key]; got != want {
			t.Fatalf("device posture attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, deviceURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, deviceURN, relationBelongsTo, blueprintURN)
}

func TestRegistryRoutesKandjiCoreKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"kandji.device", map[string]string{"device_id": "device-1", "filevault_enabled": "false"}, "kandji.device"},
		{"kandji.application", map[string]string{"device_id": "device-1", "application_name": "Safari", "installed_version": "18.0"}, "kandji.device"},
		{"kandji.vulnerability", map[string]string{"device_id": "device-1", "application_name": "Safari", "cve_id": "CVE-2026-0001", "severity": "high"}, "vulnerability"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:         "kandji-" + tc.kind,
				TenantId:   "writer",
				SourceId:   "kandji",
				Kind:       tc.kind,
				Attributes: tc.attrs,
			}
			entities, _, err := BuiltinRegistry().Project(event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to dedicated projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}

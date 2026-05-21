package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectKolideDeviceLinksOwnerIdentity(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-device-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.device",
		Attributes: map[string]string{
			"device_id":         "device-1",
			"device_name":       "mba-1",
			"hostname":          "mba-1.writer.test",
			"serial_number":     "SERIAL1",
			"compliance_status": "passing",
			"owner_email":       "alice@writer.com",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	if entity := state.entities[deviceURN]; entity == nil || entity.EntityType != "kolide.device" {
		t.Fatalf("device entity missing: %#v", entity)
	}
	assertProjectedLink(t, state, deviceURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, deviceURN, relationOwnedBy, identityURN)
}

func TestProjectKolideSoftwareLinksDevicePackageAndCanonicalPackage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-software-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.software",
		Attributes: map[string]string{
			"device_id":         "device-1",
			"device_name":       "mba-1",
			"application_name":  "openssl",
			"installed_version": "3.0.0",
			"ecosystem":         "macos",
			"purl":              "pkg:generic/openssl@3.0.0",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	packageURN := "urn:cerebro:writer:package:macos:openssl"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:generic/openssl"
	assertProjectedLink(t, state, deviceURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
}

func TestProjectKolideSoftwareDoesNotUseSoftwareExternalIDAsDevice(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-software-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.software",
		Attributes: map[string]string{
			"external_id":       "software-row-1",
			"application_name":  "openssl",
			"installed_version": "3.0.0",
			"ecosystem":         "macos",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	if entity := state.entities["urn:cerebro:writer:kolide_device:software-row-1"]; entity != nil {
		t.Fatalf("unexpected software external_id projected as device entity: %#v", entity)
	}
	if entity := state.entities["urn:cerebro:writer:package:macos:openssl"]; entity == nil {
		t.Fatal("expected package entity without endpoint correlation")
	}
}

func TestProjectKolideSoftwareSparseEndpointOmitsEmptyDeviceAttributes(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-software-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.software",
		Attributes: map[string]string{
			"device_id":         "device-1",
			"application_name":  "openssl",
			"installed_version": "3.0.0",
			"ecosystem":         "macos",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	entity := state.entities[deviceURN]
	if entity == nil {
		t.Fatalf("device entity %q missing", deviceURN)
	}
	for _, key := range []string{"hostname", "serial_number", "platform", "os_version", "status", "compliance_status"} {
		if value, ok := entity.Attributes[key]; ok {
			t.Fatalf("sparse endpoint attribute %q = %q, want omitted so existing metadata is preserved", key, value)
		}
	}
	if entity.Attributes["device_id"] != "device-1" || entity.Attributes["source_product"] != "kolide" {
		t.Fatalf("device attributes = %#v, want stable id/source metadata", entity.Attributes)
	}
}

func TestProjectKolideCheckLinksComplianceEvidenceToDevice(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-check-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.check",
		Attributes: map[string]string{
			"check_id":    "disk-encryption",
			"name":        "Disk encryption enabled",
			"status":      "failing",
			"device_id":   "device-1",
			"device_name": "mba-1",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	checkURN := "urn:cerebro:writer:kolide_check:disk-encryption"
	assertProjectedLink(t, state, deviceURN, relationHasEvidence, checkURN)
	assertProjectedLink(t, state, checkURN, relationObservedOn, deviceURN)
}

func TestProjectKandjiDeviceAndApplication(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	events := []*cerebrov1.EventEnvelope{
		{
			Id:       "kandji-device-1",
			TenantId: "writer",
			SourceId: "kandji",
			Kind:     "kandji.device",
			Attributes: map[string]string{
				"device_id":         "device-1",
				"device_name":       "mba-1",
				"serial_number":     "SERIAL1",
				"filevault_enabled": "true",
				"user_email":        "alice@writer.com",
			},
		},
		{
			Id:       "kandji-app-1",
			TenantId: "writer",
			SourceId: "kandji",
			Kind:     "kandji.application",
			Attributes: map[string]string{
				"device_id":         "device-1",
				"device_name":       "mba-1",
				"application_name":  "Safari",
				"installed_version": "18.0",
			},
		},
	}
	for _, event := range events {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}

	deviceURN := "urn:cerebro:writer:kandji_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	packageURN := "urn:cerebro:writer:package:macos:Safari"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:generic/Safari"
	assertProjectedLink(t, state, deviceURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, deviceURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
}

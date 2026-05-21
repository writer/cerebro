package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestProjectKolideDeviceLinksOwnerAndIdentifiers(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-device-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.device",
		Attributes: map[string]string{
			"device_id":     "device-1",
			"hostname":      "macbook-1",
			"serial_number": "SERIAL1",
			"user_email":    "alice@example.com",
			"os":            "darwin",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected < 3 {
		t.Fatalf("EntitiesProjected = %d, want endpoint and identity/identifier entities", result.EntitiesProjected)
	}
	endpointURN := "urn:cerebro:writer:kolide_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	if entity := state.entities[endpointURN]; entity == nil || entity.EntityType != "kolide.device" {
		t.Fatalf("endpoint entity = %#v, want kolide.device", entity)
	}
	assertProjectedLink(t, state, endpointURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, endpointURN, relationHasIdentifier, "urn:cerebro:writer:identifier:email:alice@example.com")
	assertProjectedLink(t, state, endpointURN, relationHasIdentifier, "urn:cerebro:writer:endpoint_identifier:serial_number:serial1")
	assertProjectedLinkMissing(t, state, endpointURN, relationRepresentsIdentity, "urn:cerebro:writer:identity:login:serial1")
}

func TestProjectKolideCheckWithoutDeviceIDDoesNotCreateEndpointFromRecordID(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-check-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.check",
		Attributes: map[string]string{
			"external_id": "check-1",
			"check_id":    "check-1",
			"title":       "Disk encryption enabled",
			"status":      "failing",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected == 0 {
		t.Fatal("EntitiesProjected = 0, want check projection")
	}
	if entity := state.entities["urn:cerebro:writer:kolide_check:check-1"]; entity == nil {
		t.Fatal("expected check entity")
	}
	if entity := state.entities["urn:cerebro:writer:kolide_device:check-1"]; entity != nil {
		t.Fatalf("synthetic endpoint entity = %#v, want none from check external_id", entity)
	}
}

func TestProjectKolideSoftwareUsesCanonicalPackage(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-software-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.software",
		Attributes: map[string]string{
			"device_id":         "device-1",
			"package_name":      "openssl",
			"installed_version": "3.0.1",
			"purl":              "pkg:generic/openssl@3.0.1",
			"user_email":        "alice@example.com",
			"source_provider":   "kolide",
			"source_product":    "osquery",
			"package_ecosystem": "homebrew",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.EntitiesProjected < 3 {
		t.Fatalf("EntitiesProjected = %d, want endpoint/package/canonical package", result.EntitiesProjected)
	}
	endpointURN := "urn:cerebro:writer:kolide_device:device-1"
	packageURN := "urn:cerebro:writer:package:homebrew:openssl"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:generic/openssl"
	assertProjectedLink(t, state, endpointURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
}

func TestProjectKandjiDeviceAndApplicationCorrelateByDevice(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	for _, event := range []*cerebrov1.EventEnvelope{
		{
			Id:       "kandji-device-1",
			TenantId: "writer",
			SourceId: "kandji",
			Kind:     "kandji.device",
			Attributes: map[string]string{
				"device_id":     "device-1",
				"device_name":   "MacBook Pro",
				"serial_number": "SERIAL1",
				"user_email":    "alice@example.com",
				"platform":      "macOS",
			},
		},
		{
			Id:       "kandji-app-1",
			TenantId: "writer",
			SourceId: "kandji",
			Kind:     "kandji.application",
			Attributes: map[string]string{
				"device_id":         "device-1",
				"application_name":  "Safari",
				"installed_version": "17.0",
				"bundle_id":         "com.apple.Safari",
			},
		},
	} {
		if _, err := service.Project(context.Background(), event); err != nil {
			t.Fatalf("Project(%s) error = %v", event.GetKind(), err)
		}
	}
	deviceURN := "urn:cerebro:writer:kandji_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@example.com"
	packageURN := "urn:cerebro:writer:package:macos:Safari"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:generic/Safari"
	assertProjectedLink(t, state, deviceURN, relationOwnedBy, identityURN)
	assertProjectedLink(t, state, deviceURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
}

func TestProjectKolideVulnerabilityUsesCanonicalEndpointPackageAndCVE(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	result, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-vuln-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.vulnerability",
		Attributes: map[string]string{
			"device_id":         "device-1",
			"package_name":      "openssl",
			"installed_version": "3.0.1",
			"cve_id":            "CVE-2026-0001",
			"severity":          "high",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if result.LinksProjected != 5 {
		t.Fatalf("LinksProjected = %d, want 5", result.LinksProjected)
	}
	endpointURN := "urn:cerebro:writer:kolide_device:device-1"
	packageURN := "urn:cerebro:writer:package:osquery:openssl"
	canonicalPackageURN := "urn:cerebro:writer:package:canonical:pkg:generic/openssl"
	vulnerabilityURN := "urn:cerebro:writer:vulnerability:cve-2026-0001"
	assertProjectedLink(t, state, endpointURN, relationAffectedBy, vulnerabilityURN)
	assertProjectedLink(t, state, endpointURN, relationContains, packageURN)
	assertProjectedLink(t, state, packageURN, relationRepresents, canonicalPackageURN)
}

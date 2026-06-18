package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func kolideDeviceEvent(id string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "kolide",
		Kind:       "kolide.device",
		Attributes: attrs,
	}
}

func TestProjectKolideDevicePostureEnrichment(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := kolideDeviceEvent("kolide-device-posture", map[string]string{
		"device_id":     "device-1",
		"device_name":   "mba-1",
		"serial_number": "SERIAL1",
		"failure_count": "3",
		"registered":    "true",
		"resolved_at":   "",
		"owner_email":   "alice@writer.com",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"

	device := state.entities[deviceURN]
	if device == nil || device.EntityType != "kolide.device" {
		t.Fatalf("kolide.device entity missing or wrong: %#v", device)
	}
	for key, want := range map[string]string{
		"failure_count": "3",
		"registered":    "true",
	} {
		if got := device.Attributes[key]; got != want {
			t.Fatalf("device posture attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, deviceURN, relationOwnedBy, identityURN)
}

func TestRegistryRoutesKolideCoreKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"kolide.device", map[string]string{"device_id": "device-1", "failure_count": "2"}, "kolide.device"},
		{"kolide.user_device", map[string]string{"device_id": "device-1", "user_email": "alice@writer.com"}, "kolide.device"},
		{"kolide.check", map[string]string{"check_id": "check-1", "device_id": "device-1", "status": "failing"}, "kolide.check"},
		{"kolide.issue", map[string]string{"issue_id": "issue-1", "check_id": "check-1", "device_id": "device-1", "title": "Disk encryption disabled"}, "kolide.issue"},
		{"kolide.software", map[string]string{"device_id": "device-1", "package_name": "openssl", "installed_version": "3.0.1"}, "kolide.device"},
		{"kolide.vulnerability", map[string]string{"device_id": "device-1", "package_name": "openssl", "cve_id": "CVE-2026-0001", "severity": "high"}, "vulnerability"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:         "kolide-" + tc.kind,
				TenantId:   "writer",
				SourceId:   "kolide",
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
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}

func TestProjectKolideIssueLinksDeviceCheckAndIssue(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	_, err := service.Project(context.Background(), &cerebrov1.EventEnvelope{
		Id:       "kolide-issue-1",
		TenantId: "writer",
		SourceId: "kolide",
		Kind:     "kolide.issue",
		Attributes: map[string]string{
			"issue_id":    "issue-1",
			"check_id":    "disk-encryption",
			"title":       "Disk encryption disabled",
			"device_id":   "device-1",
			"device_name": "mba-1",
			"exempted":    "false",
		},
	})
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	deviceURN := "urn:cerebro:writer:kolide_device:device-1"
	checkURN := "urn:cerebro:writer:kolide_check:disk-encryption"
	issueURN := "urn:cerebro:writer:kolide_issue:issue-1"
	if issue := state.entities[issueURN]; issue == nil || issue.EntityType != "kolide.issue" {
		t.Fatalf("issue entity = %#v, want kolide.issue", issue)
	}
	assertProjectedLink(t, state, deviceURN, relationHasEvidence, checkURN)
	assertProjectedLink(t, state, deviceURN, relationHasEvidence, issueURN)
	assertProjectedLink(t, state, issueURN, relationObservedOn, deviceURN)
	assertProjectedLink(t, state, checkURN, relationHasEvidence, issueURN)
}

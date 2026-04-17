package agents

import (
	"context"
	"testing"
)

func TestParseAWSArn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		value            string
		wantService      string
		wantResourceType string
		wantResourceID   string
		wantErr          bool
	}{
		{
			name:             "slash resource",
			value:            "arn:aws:ecs:us-east-1:123456789012:service/cluster-a/service-a",
			wantService:      "ecs",
			wantResourceType: "service",
			wantResourceID:   "cluster-a/service-a",
		},
		{
			name:             "colon resource",
			value:            "arn:aws:lambda:us-east-1:123456789012:function:handler",
			wantService:      "lambda",
			wantResourceType: "function",
			wantResourceID:   "handler",
		},
		{
			name:    "invalid arn",
			value:   "not-an-arn",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseAWSArn(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseAWSArn() error = nil, want error")
					return
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAWSArn() error = %v", err)
			}
			if got.Service != tt.wantService {
				t.Fatalf("service = %q, want %q", got.Service, tt.wantService)
			}
			if got.ResourceType != tt.wantResourceType {
				t.Fatalf("resource type = %q, want %q", got.ResourceType, tt.wantResourceType)
			}
			if got.ResourceID != tt.wantResourceID {
				t.Fatalf("resource id = %q, want %q", got.ResourceID, tt.wantResourceID)
			}
		})
	}
}

func TestParseCloudResourceHelpers(t *testing.T) {
	t.Parallel()

	if got, ok := parseS3URI("s3://bucket-a/path/to/object"); !ok || got != "bucket-a" {
		t.Fatalf("parseS3URI() = (%q, %v), want (%q, true)", got, ok, "bucket-a")
	}
	if got, ok := parseGCSURI("gs://bucket-b/path/to/object"); !ok || got != "bucket-b" {
		t.Fatalf("parseGCSURI() = (%q, %v), want (%q, true)", got, ok, "bucket-b")
	}
	if got, ok := parseGCSURL("https://storage.googleapis.com/bucket-c/folder/object"); !ok || got != "bucket-c" {
		t.Fatalf("parseGCSURL() = (%q, %v), want (%q, true)", got, ok, "bucket-c")
	}
	if got, ok := parseGCPProjectPath(`//cloudresourcemanager.googleapis.com/projects/project-123`); !ok || got != "project-123" {
		t.Fatalf("parseGCPProjectPath() = (%q, %v), want (%q, true)", got, ok, "project-123")
	}
	cluster, service := parseECSServiceResource("service/prod-cluster/payments")
	if cluster != "prod-cluster" || service != "payments" {
		t.Fatalf("parseECSServiceResource() = (%q, %q), want (%q, %q)", cluster, service, "prod-cluster", "payments")
	}
}

func TestIncidentResponseCreateIncidentStartsInvestigation(t *testing.T) {
	t.Parallel()

	registry := NewAgentRegistry()
	registry.RegisterAgent(&Agent{ID: "security-investigator", Name: "Security Investigator"})

	ir := NewIncidentResponse(registry)
	incident, err := ir.CreateIncident(context.Background(), CreateIncidentRequest{
		Title:      "Public S3 Bucket",
		AssetID:    "bucket-1",
		AssetType:  "aws:s3:bucket",
		Severity:   "high",
		FindingIDs: []string{"finding-1", "finding-2", "finding-3", "finding-4", "finding-5", "finding-6"},
	})
	if err != nil {
		t.Fatalf("CreateIncident() error = %v", err)
	}
	if incident.SessionID == "" {
		t.Fatal("expected session id to be populated")
	}
	if incident.Status != "investigating" {
		t.Fatalf("status = %q, want %q", incident.Status, "investigating")
	}
	if incident.BlastRadius == nil {
		t.Fatal("expected blast radius to be calculated")
		return
	}
	if incident.BlastRadius.DataExposure != "significant" {
		t.Fatalf("data exposure = %q, want %q", incident.BlastRadius.DataExposure, "significant")
	}
	if incident.BlastRadius.RiskScore != 70 {
		t.Fatalf("risk score = %d, want %d", incident.BlastRadius.RiskScore, 70)
	}
	if len(incident.Timeline) < 2 {
		t.Fatalf("timeline length = %d, want at least 2", len(incident.Timeline))
	}

	session, ok := registry.GetSession(incident.SessionID)
	if !ok {
		t.Fatal("expected created session to be retrievable")
	}
	if session.Context.Playbook == nil || session.Context.Playbook.ID != "s3-exposure" {
		t.Fatalf("playbook = %#v, want s3-exposure", session.Context.Playbook)
	}
}

func TestIncidentResponseHelpers(t *testing.T) {
	t.Parallel()

	ir := NewIncidentResponse(NewAgentRegistry())

	if got := ir.determineIncidentType(CreateIncidentRequest{
		Title:     "Code execution path",
		AssetType: "lambda:function",
	}); got != "code-to-cloud" {
		t.Fatalf("determineIncidentType() = %q, want %q", got, "code-to-cloud")
	}

	playbook := ir.GetPlaybook("missing")
	if playbook.ID != "default" {
		t.Fatalf("GetPlaybook() fallback id = %q, want %q", playbook.ID, "default")
	}
	if got := len(ir.ListPlaybooks()); got != 4 {
		t.Fatalf("ListPlaybooks() = %d, want 4", got)
	}
	if !contains("Public S3 Bucket", "S3") {
		t.Fatal("contains() should find embedded substring")
	}
	if containsAt("incident", "dentx") {
		t.Fatal("containsAt() should reject missing substring")
	}
}

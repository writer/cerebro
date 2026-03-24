package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/forensics"
	"github.com/writer/cerebro/internal/workloadscan"
)

type stubForensicsService struct {
	captureRecord   *forensics.CaptureRecord
	evidenceRecord  *forensics.RemediationEvidenceRecord
	pkg             *forensics.EvidencePackage
	err             error
	lastCaptureReq  forensicsCaptureRequest
	lastEvidenceReq forensicsRemediationEvidenceRequest
}

func (s *stubForensicsService) CreateCapture(_ context.Context, req forensicsCaptureRequest) (*forensics.CaptureRecord, error) {
	s.lastCaptureReq = req
	return s.captureRecord, s.err
}

func (s *stubForensicsService) ListCaptures(context.Context, forensics.CaptureListOptions) ([]forensics.CaptureRecord, error) {
	if s.captureRecord == nil {
		return nil, s.err
	}
	return []forensics.CaptureRecord{*s.captureRecord}, s.err
}

func (s *stubForensicsService) GetCapture(context.Context, string) (*forensics.CaptureRecord, bool, error) {
	return s.captureRecord, s.captureRecord != nil, s.err
}

func (s *stubForensicsService) RecordRemediationEvidence(_ context.Context, req forensicsRemediationEvidenceRequest) (*forensics.RemediationEvidenceRecord, error) {
	s.lastEvidenceReq = req
	return s.evidenceRecord, s.err
}

func (s *stubForensicsService) GetRemediationEvidence(context.Context, string) (*forensics.RemediationEvidenceRecord, bool, error) {
	return s.evidenceRecord, s.evidenceRecord != nil, s.err
}

func (s *stubForensicsService) ExportEvidencePackage(context.Context, string) (*forensics.EvidencePackage, error) {
	return s.pkg, s.err
}

func TestForensicsHandlersUseServiceInterface(t *testing.T) {
	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })

	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	svc := &stubForensicsService{
		captureRecord: &forensics.CaptureRecord{
			ID:          "forensic_capture:1",
			Status:      forensics.CaptureStatusCaptured,
			SubmittedAt: now,
			Target: workloadscan.VMTarget{
				Provider:   workloadscan.ProviderAWS,
				Region:     "us-east-1",
				InstanceID: "i-123",
			},
		},
		evidenceRecord: &forensics.RemediationEvidenceRecord{
			ID:        "remediation_evidence:1",
			Status:    forensics.EvidenceStatusRecorded,
			CreatedAt: now,
		},
		pkg: &forensics.EvidencePackage{
			ID:          "evidence_package:1",
			GeneratedAt: now,
		},
	}
	server.forensics = svc

	resp := do(t, server, http.MethodPost, "/api/v1/forensics/capture", map[string]any{
		"incident_id": "incident:sev1",
		"reason":      "capture state",
		"target": map[string]any{
			"provider":    "aws",
			"region":      "us-east-1",
			"instance_id": "i-123",
		},
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected capture 201, got %d: %s", resp.Code, resp.Body.String())
	}
	if svc.lastCaptureReq.Target.InstanceID != "i-123" {
		t.Fatalf("expected handler to bind target into service request, got %#v", svc.lastCaptureReq)
	}

	listResp := do(t, server, http.MethodGet, "/api/v1/forensics/captures?limit=10", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected captures 200, got %d: %s", listResp.Code, listResp.Body.String())
	}

	exportResp := do(t, server, http.MethodGet, "/api/v1/forensics/evidence/remediation_evidence:1/export", nil)
	if exportResp.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d: %s", exportResp.Code, exportResp.Body.String())
	}
}

func TestForensicsHandlersValidateRequestsAndUseUserFallbacks(t *testing.T) {
	server := NewServerWithDependencies(serverDependencies{Config: &app.Config{}})
	t.Cleanup(func() { server.Close() })

	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	svc := &stubForensicsService{
		captureRecord: &forensics.CaptureRecord{
			ID:          "forensic_capture:1",
			Status:      forensics.CaptureStatusCaptured,
			SubmittedAt: now,
			Target: workloadscan.VMTarget{
				Provider:   workloadscan.ProviderAWS,
				Region:     "us-east-1",
				InstanceID: "i-123",
			},
		},
		evidenceRecord: &forensics.RemediationEvidenceRecord{
			ID:        "remediation_evidence:1",
			Status:    forensics.EvidenceStatusRecorded,
			CreatedAt: now,
		},
	}
	server.forensics = svc

	captureResp := doAsUser(t, server, "analyst:alice", http.MethodPost, "/api/v1/forensics/capture", map[string]any{
		"reason": "capture state",
		"target": map[string]any{
			"provider":    "aws",
			"region":      "us-east-1",
			"instance_id": "i-123",
		},
	})
	if captureResp.Code != http.StatusCreated {
		t.Fatalf("expected capture 201, got %d: %s", captureResp.Code, captureResp.Body.String())
	}
	if svc.lastCaptureReq.RequestedBy != "analyst:alice" {
		t.Fatalf("RequestedBy = %q, want analyst:alice", svc.lastCaptureReq.RequestedBy)
	}

	evidenceResp := doAsUser(t, server, "operator:bob", http.MethodPost, "/api/v1/forensics/evidence", map[string]any{
		"before_capture_id": "forensic_capture:1",
	})
	if evidenceResp.Code != http.StatusCreated {
		t.Fatalf("expected evidence 201, got %d: %s", evidenceResp.Code, evidenceResp.Body.String())
	}
	if svc.lastEvidenceReq.Actor != "operator:bob" {
		t.Fatalf("Actor = %q, want operator:bob", svc.lastEvidenceReq.Actor)
	}

	invalidStatus := do(t, server, http.MethodGet, "/api/v1/forensics/captures?status=bogus", nil)
	if invalidStatus.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid status 400, got %d: %s", invalidStatus.Code, invalidStatus.Body.String())
	}

	invalidCapture := do(t, server, http.MethodPost, "/api/v1/forensics/capture", map[string]any{
		"target": map[string]any{
			"provider": "aws",
		},
	})
	if invalidCapture.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid capture 400, got %d: %s", invalidCapture.Code, invalidCapture.Body.String())
	}

	invalidEvidence := do(t, server, http.MethodPost, "/api/v1/forensics/evidence", map[string]any{
		"notes": "missing evidence linkage",
	})
	if invalidEvidence.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid evidence 400, got %d: %s", invalidEvidence.Code, invalidEvidence.Body.String())
	}
}

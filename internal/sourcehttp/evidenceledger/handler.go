package evidenceledgerhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/evidenceledger"
	"github.com/writer/cerebro/internal/ports"
)

const defaultMaxBodyBytes = int64(1 << 20)

type TenantResolver func(context.Context, string) (string, error)
type ActorResolver func(context.Context) string
type ForbiddenClassifier func(error) bool
type SensitivityResolver func(context.Context) string

var ErrServiceUnavailable = errors.New("evidence ledger service unavailable")

type Handler struct {
	service        *evidenceledger.Service
	resolveTenant  TenantResolver
	actorID        ActorResolver
	isForbidden    ForbiddenClassifier
	maxSensitivity SensitivityResolver
	maxBodyBytes   int64
}

func (h *Handler) WithMaximumSensitivity(resolver SensitivityResolver) *Handler {
	if h != nil {
		h.maxSensitivity = resolver
	}
	return h
}

func NewHandler(service *evidenceledger.Service, resolveTenant TenantResolver, actorID ActorResolver, isForbidden ForbiddenClassifier, maxBodyBytes int64) *Handler {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	return &Handler{service: service, resolveTenant: resolveTenant, actorID: actorID, isForbidden: isForbidden, maxBodyBytes: maxBodyBytes}
}

type registerEvidenceVersionRequest struct {
	Artifact ports.EvidenceArtifact `json:"artifact"`
	Version  ports.EvidenceVersion  `json:"version"`
}

type evidenceVersionResponse struct {
	Version ports.EvidenceVersion `json:"version"`
}

type evidenceVersionRegisterResponse struct {
	Artifact ports.EvidenceArtifact `json:"artifact"`
	Version  ports.EvidenceVersion  `json:"version"`
}

type evidenceClaimResponse struct {
	Claim ports.EvidenceClaim `json:"claim"`
}

type createEvidenceClaimRequest struct {
	Claim ports.EvidenceClaim `json:"claim"`
}

type reviewEvidenceClaimRequest struct {
	TenantID        string `json:"tenant_id"`
	ExpectedVersion uint64 `json:"expected_version"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
}

type invalidateEvidenceClaimRequest struct {
	TenantID        string `json:"tenant_id"`
	ExpectedVersion uint64 `json:"expected_version"`
	Reason          string `json:"reason"`
}

type validateEvidenceClaimRequest struct {
	TenantID    string                     `json:"tenant_id"`
	Subjects    []ports.EvidenceSubjectRef `json:"subjects"`
	PeriodStart time.Time                  `json:"period_start"`
	PeriodEnd   time.Time                  `json:"period_end"`
	At          time.Time                  `json:"at,omitempty"`
}

type validateEvidenceClaimResponse struct {
	ClaimID    string                        `json:"claim_id"`
	Validation ports.EvidenceClaimValidation `json:"validation"`
}

type reuseEvidenceClaimRequest struct {
	TenantID string              `json:"tenant_id"`
	Claim    ports.EvidenceClaim `json:"claim"`
}

type evidenceClaimCompatibilityRequest struct {
	TenantID string                     `json:"tenant_id"`
	ClaimID  string                     `json:"claim_id"`
	Source   compliance.ProofObligation `json:"source"`
	Target   compliance.ProofObligation `json:"target"`
	At       time.Time                  `json:"at,omitempty"`
}

type evidenceClaimCompatibilityResponse struct {
	Decision evidenceledger.CompatibilityDecision `json:"decision"`
}

func (h *Handler) RegisterVersion(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request registerEvidenceVersionRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.Artifact.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	request.Artifact.TenantID = tenantID
	request.Artifact.ID = strings.TrimSpace(r.PathValue("artifactID"))
	request.Version.TenantID = tenantID
	request.Version.ArtifactID = request.Artifact.ID
	version, err := h.service.RegisterVersion(r.Context(), evidenceledger.RegisterVersionRequest{
		Artifact: request.Artifact,
		Version:  request.Version,
		ActorID:  h.actorID(r.Context()),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	artifact, err := h.service.ReadArtifact(r.Context(), tenantID, request.Artifact.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, evidenceVersionRegisterResponse{Artifact: artifact, Version: version})
}

func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	maximumSensitivity := ports.EvidenceSensitivityPublic
	if h.maxSensitivity != nil {
		maximumSensitivity = h.maxSensitivity(r.Context())
	}
	version, err := h.service.ReadVersion(r.Context(), ports.EvidenceAccessRequest{
		TenantID: tenantID, Purpose: r.URL.Query().Get("purpose"),
		MaximumSensitivity: maximumSensitivity, ActorID: h.actorID(r.Context()),
	}, r.PathValue("versionID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidenceVersionResponse{Version: version})
}

func (h *Handler) CreateClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request createEvidenceClaimRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.Claim.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	request.Claim.ID = ""
	request.Claim.TenantID = tenantID
	request.Claim.Version = 0
	request.Claim.Decision = ports.EvidenceClaimDecision{}
	request.Claim.CreatedAt = time.Time{}
	request.Claim.CreatedBy = ""
	claim, err := h.service.CreateClaim(r.Context(), evidenceledger.CreateClaimRequest{Claim: request.Claim, ActorID: h.actorID(r.Context())})
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, evidenceClaimResponse{Claim: claim})
}

func (h *Handler) GetClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	claim, err := h.service.ReadClaim(r.Context(), tenantID, r.PathValue("claimID"))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidenceClaimResponse{Claim: claim})
}

func (h *Handler) ReviewClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request reviewEvidenceClaimRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	claim, err := h.service.ReviewClaim(r.Context(), tenantID, r.PathValue("claimID"), h.actorID(r.Context()), request.State, request.Reason, request.ExpectedVersion)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidenceClaimResponse{Claim: claim})
}

func (h *Handler) InvalidateClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request invalidateEvidenceClaimRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	claim, err := h.service.InvalidateClaim(r.Context(), tenantID, r.PathValue("claimID"), h.actorID(r.Context()), request.Reason, request.ExpectedVersion)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidenceClaimResponse{Claim: claim})
}

func (h *Handler) ValidateClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request validateEvidenceClaimRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	claimID := r.PathValue("claimID")
	validation, err := h.service.ValidateClaim(r.Context(), evidenceledger.ValidateClaimRequest{
		TenantID: tenantID, ClaimID: claimID, Subjects: request.Subjects,
		PeriodStart: request.PeriodStart, PeriodEnd: request.PeriodEnd, At: request.At,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, validateEvidenceClaimResponse{ClaimID: claimID, Validation: validation})
}

func (h *Handler) ReuseClaim(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request reuseEvidenceClaimRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	request.Claim.CreatedAt = time.Time{}
	request.Claim.CreatedBy = ""
	claim, err := h.service.ReuseClaim(r.Context(), tenantID, r.PathValue("claimID"), h.actorID(r.Context()), request.Claim)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, evidenceClaimResponse{Claim: claim})
}

func (h *Handler) EvaluateCompatibility(w http.ResponseWriter, r *http.Request) {
	if !h.available(w) {
		return
	}
	var request evidenceClaimCompatibilityRequest
	if err := h.decodeJSON(w, r, &request); err != nil {
		h.writeError(w, err)
		return
	}
	tenantID, err := h.resolveTenant(r.Context(), request.TenantID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	decision, err := h.service.EvaluateCompatibility(r.Context(), evidenceledger.CompatibilityRequest{
		TenantID: tenantID, ClaimID: request.ClaimID, Source: request.Source, Target: request.Target, At: request.At,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, evidenceClaimCompatibilityResponse{Decision: decision})
}

func (h *Handler) available(w http.ResponseWriter) bool {
	if h == nil || h.service == nil {
		h.writeError(w, ErrServiceUnavailable)
		return false
	}
	return true
}

func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode evidence request: %w", evidenceledger.ErrInvalidEvidence, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: evidence request must contain one JSON object", evidenceledger.ErrInvalidEvidence)
	}
	return nil
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case h != nil && h.isForbidden != nil && h.isForbidden(err), errors.Is(err, ports.ErrEvidenceAccessDenied):
		status = http.StatusForbidden
	case errors.Is(err, ErrServiceUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, ports.ErrEvidenceArtifactNotFound), errors.Is(err, ports.ErrEvidenceVersionNotFound), errors.Is(err, ports.ErrEvidenceClaimNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ports.ErrEvidenceLedgerConflict):
		status = http.StatusConflict
	case errors.Is(err, evidenceledger.ErrInvalidEvidence):
		status = http.StatusBadRequest
	case errors.Is(err, compliance.ErrInvalidProofObligation), errors.Is(err, compliance.ErrInvalidIdentifier), errors.Is(err, compliance.ErrInvalidRevision):
		status = http.StatusBadRequest
	}
	message := err.Error()
	if status >= http.StatusInternalServerError {
		message = strings.ToLower(http.StatusText(status))
	}
	http.Error(w, message, status)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

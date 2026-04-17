package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/writer/cerebro/internal/deviceauth"
)

// ---------- request / response types ----------

type deviceEnrollRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	HardwareUUID   string `json:"hardware_uuid"`
	SerialNumber   string `json:"serial_number"`
	Hostname       string `json:"hostname"`
	OSType         string `json:"os_type"`
	AgentVersion   string `json:"agent_version"`
}

type deviceTokenRequest struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
	DeviceID     string `json:"device_id"`
}

type deviceTokenResponse struct {
	DeviceID     string `json:"device_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type adminCreateBootstrapTokenRequest struct {
	HardwareUUID string            `json:"hardware_uuid"`
	OrgID        string            `json:"org_id,omitempty"`
	ExpiresInH   int               `json:"expires_in_hours,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type adminCreateBootstrapTokenResponse struct {
	TokenID  string `json:"token_id"`
	Token    string `json:"token"`
	ExpireAt string `json:"expires_at"`
}

type adminDeviceResponse struct {
	DeviceID     string            `json:"device_id"`
	HardwareUUID string           `json:"hardware_uuid"`
	SerialNumber string            `json:"serial_number"`
	Hostname     string            `json:"hostname"`
	OrgID        string            `json:"org_id"`
	OSType       string            `json:"os_type"`
	AgentVersion string            `json:"agent_version"`
	Status       string            `json:"status"`
	EnrolledAt   time.Time         `json:"enrolled_at"`
	LastSeen     time.Time         `json:"last_seen"`
	RevokedAt    *time.Time        `json:"revoked_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type adminDeviceCollection struct {
	Count   int                   `json:"count"`
	Devices []adminDeviceResponse `json:"devices"`
}

type adminRevokeDeviceRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ---------- public enrollment endpoint ----------

const deviceAuthMaxBodyBytes = 4096

func (s *Server) deviceEnroll(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil || s.deviceJWT == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, deviceAuthMaxBodyBytes)

	var req deviceEnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.BootstrapToken) == "" {
		s.error(w, http.StatusBadRequest, "bootstrap_token is required")
		return
	}
	if strings.TrimSpace(req.HardwareUUID) == "" {
		s.error(w, http.StatusBadRequest, "hardware_uuid is required")
		return
	}

	bt, err := s.deviceAuth.ConsumeBootstrapToken(req.BootstrapToken, req.HardwareUUID)
	if err != nil {
		s.error(w, http.StatusUnauthorized, "enrollment failed: invalid or expired bootstrap token")
		return
	}

	existing, found := s.deviceAuth.GetDeviceByHardwareUUID(req.HardwareUUID)
	if found && existing.Status == "active" {
		s.error(w, http.StatusConflict, "device already enrolled")
		return
	}

	device, err := s.deviceAuth.RegisterDevice(deviceauth.DeviceSpec{
		HardwareUUID: req.HardwareUUID,
		SerialNumber: req.SerialNumber,
		Hostname:     req.Hostname,
		OrgID:        bt.OrgID,
		OSType:       req.OSType,
		AgentVersion: req.AgentVersion,
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to register device")
		return
	}

	_ = s.deviceAuth.MarkBootstrapTokenConsumedBy(bt.TokenID, device.DeviceID)

	defaultScopes := []string{"security.findings.read", "security.runtime.write"}
	scopes := bt.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	accessToken, err := s.deviceJWT.IssueAccessToken(device, scopes)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to issue access token")
		return
	}

	refreshRaw, refreshRecord, err := s.deviceJWT.IssueRefreshToken(device, "")
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to issue refresh token")
		return
	}
	if err := s.deviceAuth.StoreRefreshToken(refreshRecord); err != nil {
		s.error(w, http.StatusInternalServerError, "failed to store refresh token")
		return
	}

	s.json(w, http.StatusOK, deviceTokenResponse{
		DeviceID:     device.DeviceID,
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		ExpiresIn:    300,
		TokenType:    "Bearer",
	})
}

// ---------- public token exchange endpoint ----------

func (s *Server) deviceToken(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil || s.deviceJWT == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, deviceAuthMaxBodyBytes)

	var req deviceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.GrantType != "refresh_token" {
		s.error(w, http.StatusBadRequest, "grant_type must be refresh_token")
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		s.error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	consumed, err := s.deviceAuth.ConsumeRefreshToken(req.RefreshToken)
	if err != nil {
		s.error(w, http.StatusUnauthorized, "token exchange failed: invalid or expired refresh token")
		return
	}

	if strings.TrimSpace(req.DeviceID) != "" && req.DeviceID != consumed.DeviceID {
		s.error(w, http.StatusUnauthorized, "device_id mismatch")
		return
	}

	device, ok := s.deviceAuth.GetDevice(consumed.DeviceID)
	if !ok || device.Status != "active" {
		s.error(w, http.StatusForbidden, "device not active")
		return
	}

	_ = s.deviceAuth.UpdateDeviceLastSeen(device.DeviceID, "")

	defaultScopes := []string{"security.findings.read", "security.runtime.write"}
	accessToken, err := s.deviceJWT.IssueAccessToken(device, defaultScopes)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to issue access token")
		return
	}

	refreshRaw, refreshRecord, err := s.deviceJWT.IssueRefreshToken(device, consumed.FamilyID)
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to issue refresh token")
		return
	}
	refreshRecord.Generation = consumed.Generation + 1
	if err := s.deviceAuth.StoreRefreshToken(refreshRecord); err != nil {
		s.error(w, http.StatusInternalServerError, "failed to store refresh token")
		return
	}

	s.json(w, http.StatusOK, deviceTokenResponse{
		DeviceID:     device.DeviceID,
		AccessToken:  accessToken,
		RefreshToken: refreshRaw,
		ExpiresIn:    300,
		TokenType:    "Bearer",
	})
}

// ---------- admin: bootstrap tokens ----------

func (s *Server) createBootstrapToken(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}

	var req adminCreateBootstrapTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.HardwareUUID) == "" {
		s.error(w, http.StatusBadRequest, "hardware_uuid is required")
		return
	}

	expiresInHours := req.ExpiresInH
	if expiresInHours <= 0 {
		expiresInHours = 72
	}
	if expiresInHours > 168 {
		s.error(w, http.StatusBadRequest, "expires_in_hours must be <= 168 (7 days)")
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(expiresInHours) * time.Hour)

	bt, rawToken, err := s.deviceAuth.CreateBootstrapToken(deviceauth.BootstrapTokenSpec{
		HardwareUUID: req.HardwareUUID,
		OrgID:        req.OrgID,
		ExpiresAt:    expiresAt,
		Scopes:       req.Scopes,
		Metadata:     req.Metadata,
	})
	if err != nil {
		s.error(w, http.StatusInternalServerError, "failed to create bootstrap token: "+err.Error())
		return
	}

	s.json(w, http.StatusCreated, adminCreateBootstrapTokenResponse{
		TokenID:  bt.TokenID,
		Token:    rawToken,
		ExpireAt: bt.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) revokeBootstrapToken(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}
	tokenID := strings.TrimSpace(chi.URLParam(r, "token_id"))
	if tokenID == "" {
		s.error(w, http.StatusBadRequest, "token_id is required")
		return
	}
	if err := s.deviceAuth.RevokeBootstrapToken(tokenID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.error(w, http.StatusNotFound, err.Error())
			return
		}
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ---------- admin: device management ----------

func (s *Server) listAdminDevices(w http.ResponseWriter, _ *http.Request) {
	if s.deviceAuth == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}
	devices := s.deviceAuth.ListDevices()
	resp := adminDeviceCollection{
		Count:   len(devices),
		Devices: make([]adminDeviceResponse, len(devices)),
	}
	for i, d := range devices {
		resp.Devices[i] = adminDeviceFromRecord(d)
	}
	s.json(w, http.StatusOK, resp)
}

func (s *Server) getAdminDevice(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}
	deviceID := strings.TrimSpace(chi.URLParam(r, "device_id"))
	if deviceID == "" {
		s.error(w, http.StatusBadRequest, "device_id is required")
		return
	}
	device, ok := s.deviceAuth.GetDevice(deviceID)
	if !ok {
		s.error(w, http.StatusNotFound, "device not found")
		return
	}
	s.json(w, http.StatusOK, adminDeviceFromRecord(device))
}

func (s *Server) revokeAdminDevice(w http.ResponseWriter, r *http.Request) {
	if s.deviceAuth == nil {
		s.error(w, http.StatusServiceUnavailable, "device auth not configured")
		return
	}
	deviceID := strings.TrimSpace(chi.URLParam(r, "device_id"))
	if deviceID == "" {
		s.error(w, http.StatusBadRequest, "device_id is required")
		return
	}
	var req adminRevokeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req = adminRevokeDeviceRequest{}
	}
	if err := s.deviceAuth.RevokeDevice(deviceID, req.Reason); err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.error(w, http.StatusNotFound, err.Error())
			return
		}
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func adminDeviceFromRecord(d deviceauth.DeviceRecord) adminDeviceResponse {
	return adminDeviceResponse{
		DeviceID:     d.DeviceID,
		HardwareUUID: d.HardwareUUID,
		SerialNumber: d.SerialNumber,
		Hostname:     d.Hostname,
		OrgID:        d.OrgID,
		OSType:       d.OSType,
		AgentVersion: d.AgentVersion,
		Status:       d.Status,
		EnrolledAt:   d.EnrolledAt,
		LastSeen:     d.LastSeen,
		RevokedAt:    d.RevokedAt,
		Metadata:     d.Metadata,
	}
}

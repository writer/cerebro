package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/evalops/cerebro/internal/apiauth"
)

type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
	AgentSDKEndpoint       string   `json:"agent_sdk_endpoint,omitempty"`
	MCPEndpoint            string   `json:"mcp_endpoint,omitempty"`
	MCPProtocolVersion     string   `json:"mcp_protocol_version,omitempty"`
}

type adminAgentSDKCredentialResponse struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	UserID           string            `json:"user_id,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	Surface          string            `json:"surface,omitempty"`
	ClientID         string            `json:"client_id,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	RateLimitBucket  string            `json:"rate_limit_bucket,omitempty"`
	TenantID         string            `json:"tenant_id,omitempty"`
	Enabled          bool              `json:"enabled"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	Managed          bool              `json:"managed"`
	Mutable          bool              `json:"mutable"`
	CreatedAt        *time.Time        `json:"created_at,omitempty"`
	RotatedAt        *time.Time        `json:"rotated_at,omitempty"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	RevocationReason string            `json:"revocation_reason,omitempty"`
	SecretPreview    string            `json:"secret_preview,omitempty"`
}

type adminAgentSDKCredentialCollection struct {
	Count       int                               `json:"count"`
	Credentials []adminAgentSDKCredentialResponse `json:"credentials"`
}

type adminCreateAgentSDKCredentialRequest struct {
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name,omitempty"`
	UserID          string            `json:"user_id,omitempty"`
	Kind            string            `json:"kind,omitempty"`
	Surface         string            `json:"surface,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	Scopes          []string          `json:"scopes,omitempty"`
	RateLimitBucket string            `json:"rate_limit_bucket,omitempty"`
	TenantID        string            `json:"tenant_id,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type adminRotateAgentSDKCredentialRequest struct {
	Reason string `json:"reason,omitempty"`
}

type adminRevokeAgentSDKCredentialRequest struct {
	Reason string `json:"reason,omitempty"`
}

type adminAgentSDKCredentialSecretResponse struct {
	Credential adminAgentSDKCredentialResponse `json:"credential"`
	APIKey     string                          `json:"api_key"`
}

func (s *Server) agentSDKProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	baseURL := requestBaseURL(r)
	metadata := protectedResourceMetadata{
		Resource:               baseURL,
		AuthorizationServers:   s.agentSDKAdmin.AuthorizationServers(),
		ScopesSupported:        s.agentSDKAdmin.SupportedScopes(),
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  baseURL + "/docs",
		AgentSDKEndpoint:       baseURL + "/api/v1/agent-sdk",
		MCPEndpoint:            baseURL + "/api/v1/mcp",
		MCPProtocolVersion:     agentSDKMCPProtocolVersion,
	}
	s.json(w, http.StatusOK, metadata)
}

func (s *Server) listAdminAgentSDKCredentials(w http.ResponseWriter, _ *http.Request) {
	credentials := s.agentSDKAdmin.ListCredentials()
	s.json(w, http.StatusOK, adminAgentSDKCredentialCollection{
		Count:       len(credentials),
		Credentials: credentials,
	})
}

func (s *Server) getAdminAgentSDKCredential(w http.ResponseWriter, r *http.Request) {
	credentialID := strings.TrimSpace(chi.URLParam(r, "credential_id"))
	if credentialID == "" {
		s.error(w, http.StatusBadRequest, "credential id required")
		return
	}
	credential, ok := s.agentSDKAdmin.GetCredential(credentialID)
	if !ok {
		s.error(w, http.StatusNotFound, "credential not found")
		return
	}
	s.json(w, http.StatusOK, credential)
}

func (s *Server) createAdminAgentSDKCredential(w http.ResponseWriter, r *http.Request) {
	var req adminCreateAgentSDKCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	scopes, err := validateManagedAgentSDKScopes(s.agentSDKAdmin.SupportedScopes(), req.Scopes)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	record, secret, err := s.agentSDKAdmin.CreateCredential(apiauth.ManagedCredentialSpec{
		ID:              req.ID,
		Name:            req.Name,
		UserID:          req.UserID,
		Kind:            req.Kind,
		Surface:         req.Surface,
		ClientID:        req.ClientID,
		Scopes:          scopes,
		RateLimitBucket: req.RateLimitBucket,
		TenantID:        req.TenantID,
		ExpiresAt:       req.ExpiresAt,
		Metadata:        req.Metadata,
	}, time.Now().UTC())
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusCreated, adminAgentSDKCredentialSecretResponse{
		Credential: record,
		APIKey:     secret,
	})
}

func (s *Server) rotateAdminAgentSDKCredential(w http.ResponseWriter, r *http.Request) {
	credentialID := strings.TrimSpace(chi.URLParam(r, "credential_id"))
	if credentialID == "" {
		s.error(w, http.StatusBadRequest, "credential id required")
		return
	}
	var req adminRotateAgentSDKCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	record, secret, err := s.agentSDKAdmin.RotateCredential(credentialID, time.Now().UTC())
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.error(w, http.StatusNotFound, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, adminAgentSDKCredentialSecretResponse{
		Credential: record,
		APIKey:     secret,
	})
}

func (s *Server) revokeAdminAgentSDKCredential(w http.ResponseWriter, r *http.Request) {
	credentialID := strings.TrimSpace(chi.URLParam(r, "credential_id"))
	if credentialID == "" {
		s.error(w, http.StatusBadRequest, "credential id required")
		return
	}
	var req adminRevokeAgentSDKCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	record, err := s.agentSDKAdmin.RevokeCredential(credentialID, req.Reason, time.Now().UTC())
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.error(w, http.StatusNotFound, err.Error())
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.json(w, http.StatusOK, record)
}

func adminAgentSDKCredentialFromManaged(record apiauth.ManagedCredentialRecord) adminAgentSDKCredentialResponse {
	response := adminAgentSDKCredentialResponse{
		ID:               record.Credential.ID,
		Name:             record.Credential.Name,
		UserID:           record.Credential.UserID,
		Kind:             record.Credential.Kind,
		Surface:          record.Credential.Surface,
		ClientID:         record.Credential.ClientID,
		Scopes:           append([]string(nil), record.Credential.Scopes...),
		RateLimitBucket:  record.Credential.RateLimitBucket,
		TenantID:         record.Credential.TenantID,
		Enabled:          record.Credential.Enabled,
		Metadata:         cloneStringStringMap(record.Credential.Metadata),
		Managed:          true,
		Mutable:          true,
		CreatedAt:        cloneTimeValue(record.CreatedAt),
		RotatedAt:        cloneTimeValuePtr(record.RotatedAt),
		RevokedAt:        cloneTimeValuePtr(record.RevokedAt),
		ExpiresAt:        cloneTimeValuePtr(record.ExpiresAt),
		RevocationReason: record.RevocationReason,
		SecretPreview:    record.SecretPrefix,
	}
	return response
}

func validateManagedAgentSDKScopes(supported, requested []string) ([]string, error) {
	allowed := make(map[string]struct{}, len(supported))
	for _, value := range supported {
		allowed[strings.TrimSpace(value)] = struct{}{}
	}
	normalized := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if !strings.HasPrefix(scope, "sdk.") {
			return nil, fmt.Errorf("managed sdk credential scopes must use the sdk.* namespace")
		}
		if _, ok := allowed[scope]; !ok {
			return nil, fmt.Errorf("unsupported sdk scope %q", scope)
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one sdk scope is required")
	}
	sort.Strings(normalized)
	return normalized, nil
}

func requestBaseURL(r *http.Request) string {
	scheme := "http"
	if r != nil {
		if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			scheme = "https"
		}
		if host := strings.TrimSpace(r.Host); host != "" {
			return scheme + "://" + host
		}
	}
	return scheme + "://localhost"
}

func cloneStringStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneTimeValue(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func cloneTimeValuePtr(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

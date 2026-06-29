package identitydirectory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

const defaultDirectoryLimit uint32 = 100
const maxDirectoryLimit uint32 = 500

type TenantResolver func(context.Context, string) (string, error)
type TenantAuthorizer func(context.Context, string) error

type Handler struct {
	store            ports.IdentityDirectoryStore
	cfg              config.AuthConfig
	tenantResolver   TenantResolver
	tenantAuthorizer TenantAuthorizer
}

type organizationResponse struct {
	OrgID        string `json:"org_id"`
	TenantID     string `json:"tenant_id"`
	Name         string `json:"name"`
	Slug         string `json:"slug,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Source       string `json:"source"`
	ExternalID   string `json:"external_id,omitempty"`
	UserCount    int    `json:"user_count"`
	LastSyncedAt string `json:"last_synced_at,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type userResponse struct {
	UserID       string   `json:"user_id"`
	TenantID     string   `json:"tenant_id"`
	OrgID        string   `json:"org_id,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	Email        string   `json:"email,omitempty"`
	DisplayName  string   `json:"display_name"`
	Status       string   `json:"status"`
	Provider     string   `json:"provider,omitempty"`
	Source       string   `json:"source"`
	Roles        []string `json:"roles,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
	LastSyncedAt string   `json:"last_synced_at,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
}

type listOrganizationsResponse struct {
	TenantID      string                 `json:"tenant_id,omitempty"`
	Organizations []organizationResponse `json:"organizations"`
	Meta          listMeta               `json:"meta"`
}

type listUsersResponse struct {
	TenantID string         `json:"tenant_id,omitempty"`
	OrgID    string         `json:"org_id,omitempty"`
	Users    []userResponse `json:"users"`
	Meta     listMeta       `json:"meta"`
}

type listMeta struct {
	Limit      uint32 `json:"limit"`
	Loaded     int    `json:"loaded"`
	Configured int    `json:"configured"`
	Persisted  int    `json:"persisted"`
}

func NewHandler(store ports.StateStore, cfg config.AuthConfig, tenantResolver TenantResolver, tenantAuthorizer TenantAuthorizer) Handler {
	directoryStore, _ := store.(ports.IdentityDirectoryStore)
	if isNil(directoryStore) {
		directoryStore = nil
	}
	return Handler{store: directoryStore, cfg: cfg, tenantResolver: tenantResolver, tenantAuthorizer: tenantAuthorizer}
}

func (h Handler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenantForRequest(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, statusForTenantError(err), err.Error())
		return
	}
	orgID := strings.TrimSpace(r.URL.Query().Get("org_id"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := directoryLimit(r.URL.Query().Get("limit"))
	configured := configuredOrganizations(h.cfg, tenantID)
	persisted, err := h.persistedOrganizations(r.Context(), ports.IdentityOrganizationFilter{TenantID: tenantID, OrgID: orgID, Query: query, Limit: limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "identity organizations unavailable")
		return
	}
	organizations := mergeOrganizations(configured, persisted, tenantID, orgID, query, limit)
	writeJSON(w, http.StatusOK, listOrganizationsResponse{
		TenantID:      tenantID,
		Organizations: organizationResponses(organizations),
		Meta:          listMeta{Limit: limit, Loaded: len(organizations), Configured: len(configured), Persisted: len(persisted)},
	})
}

func (h Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenantForRequest(r, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeError(w, statusForTenantError(err), err.Error())
		return
	}
	orgID := strings.TrimSpace(r.URL.Query().Get("org_id"))
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := directoryLimit(r.URL.Query().Get("limit"))
	configured := configuredUsers(h.cfg, tenantID, orgID)
	persisted, err := h.persistedUsers(r.Context(), ports.IdentityUserFilter{TenantID: tenantID, OrgID: orgID, Query: query, Limit: limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "identity users unavailable")
		return
	}
	users := mergeUsers(configured, persisted, tenantID, orgID, query, limit)
	writeJSON(w, http.StatusOK, listUsersResponse{
		TenantID: tenantID,
		OrgID:    orgID,
		Users:    userResponses(users),
		Meta:     listMeta{Limit: limit, Loaded: len(users), Configured: len(configured), Persisted: len(persisted)},
	})
}

func (h Handler) tenantForRequest(r *http.Request, requestedTenantID string) (string, error) {
	if h.tenantResolver != nil {
		return h.tenantResolver(r.Context(), requestedTenantID)
	}
	tenantID := strings.TrimSpace(requestedTenantID)
	if h.tenantAuthorizer != nil {
		if err := h.tenantAuthorizer(r.Context(), tenantID); err != nil {
			return "", err
		}
	}
	return tenantID, nil
}

func (h Handler) persistedOrganizations(ctx context.Context, filter ports.IdentityOrganizationFilter) ([]*ports.IdentityOrganization, error) {
	if h.store == nil {
		return nil, nil
	}
	return h.store.ListIdentityOrganizations(ctx, filter)
}

func (h Handler) persistedUsers(ctx context.Context, filter ports.IdentityUserFilter) ([]*ports.IdentityUser, error) {
	if h.store == nil {
		return nil, nil
	}
	return h.store.ListIdentityUsers(ctx, filter)
}

func configuredOrganizations(cfg config.AuthConfig, tenantID string) []*ports.IdentityOrganization {
	organizations := map[string]*ports.IdentityOrganization{}
	add := func(tenantID string, source string, provider string, externalID string) {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			return
		}
		key := tenantID + "\x00" + tenantID
		if existing := organizations[key]; existing != nil {
			if provider != "" {
				existing.Source = source
				existing.Provider = provider
			} else if existing.Source == "auth_config" && source != "" {
				existing.Source = source
			}
			if existing.ExternalID == "" {
				existing.ExternalID = externalID
			}
			return
		}
		organizations[key] = &ports.IdentityOrganization{
			OrgID:      tenantID,
			TenantID:   tenantID,
			Name:       tenantName(tenantID),
			Slug:       tenantSlug(tenantID),
			Provider:   provider,
			Source:     firstNonEmpty(source, "auth_config"),
			ExternalID: externalID,
		}
	}
	for _, tenant := range cfg.AllowedTenants {
		add(tenant, "auth_config", "", "")
	}
	for _, key := range cfg.APIKeys {
		add(key.TenantID, "api_key", "", "")
	}
	for _, credential := range cfg.APICredentials {
		add(credential.TenantID, "api_credential", "", "")
		for _, tenant := range credential.AllowedTenants {
			add(tenant, "api_credential", "", "")
		}
	}
	oauthProvider := oauthProvider(cfg.MCPOAuth.Upstream.Issuer)
	oauthExternalID := strings.TrimSpace(cfg.MCPOAuth.Upstream.Issuer)
	add(cfg.MCPOAuth.TenantID, "mcp_oauth", oauthProvider, oauthExternalID)
	for _, tenant := range cfg.MCPOAuth.AllowedTenants {
		add(tenant, "mcp_oauth", oauthProvider, oauthExternalID)
	}
	for _, client := range cfg.MCPOAuth.Clients {
		add(client.TenantID, "mcp_oauth_client", oauthProvider, oauthExternalID)
		for _, tenant := range client.AllowedTenants {
			add(tenant, "mcp_oauth_client", oauthProvider, oauthExternalID)
		}
	}
	for _, entitlement := range cfg.MCPOAuth.Entitlements {
		add(entitlement.TenantID, "mcp_oauth", oauthProvider, oauthExternalID)
		for _, tenant := range entitlement.AllowedTenants {
			add(tenant, "mcp_oauth", oauthProvider, oauthExternalID)
		}
	}
	var out []*ports.IdentityOrganization
	for _, org := range organizations {
		if tenantID != "" && org.TenantID != tenantID {
			continue
		}
		out = append(out, org)
	}
	return out
}

func configuredUsers(cfg config.AuthConfig, tenantID string, orgID string) []*ports.IdentityUser {
	var users []*ports.IdentityUser
	add := func(user ports.IdentityUser) {
		user.TenantID = strings.TrimSpace(user.TenantID)
		user.OrgID = firstNonEmpty(user.OrgID, user.TenantID)
		user.UserID = firstNonEmpty(user.UserID, user.Subject, user.Email, user.DisplayName)
		user.DisplayName = firstNonEmpty(user.DisplayName, user.Email, user.Subject, user.UserID)
		user.Status = firstNonEmpty(user.Status, "active")
		if user.TenantID == "" || user.UserID == "" || user.DisplayName == "" {
			return
		}
		if tenantID != "" && user.TenantID != tenantID {
			return
		}
		if orgID != "" && user.OrgID != orgID {
			return
		}
		users = append(users, &user)
	}
	for index, key := range cfg.APIKeys {
		userID := firstNonEmpty(key.Principal, fmt.Sprintf("api-key:%d", index+1))
		add(ports.IdentityUser{
			TenantID:    key.TenantID,
			UserID:      userID,
			DisplayName: userID,
			Source:      "api_key",
		})
	}
	for _, credential := range cfg.APICredentials {
		userID := firstNonEmpty(credential.Principal, credential.Name, credential.ClientID, credential.ID)
		add(ports.IdentityUser{
			TenantID:    credential.TenantID,
			UserID:      userID,
			DisplayName: userID,
			Source:      "api_credential",
			Roles:       credential.Roles,
			Groups:      nil,
		})
		for _, allowedTenant := range credential.AllowedTenants {
			add(ports.IdentityUser{
				TenantID:    allowedTenant,
				UserID:      userID,
				DisplayName: userID,
				Source:      "api_credential",
				Roles:       credential.Roles,
			})
		}
	}
	oauthProvider := oauthProvider(cfg.MCPOAuth.Upstream.Issuer)
	for _, client := range cfg.MCPOAuth.Clients {
		if !contains(client.GrantTypes, "client_credentials") {
			continue
		}
		userID := "service:" + strings.TrimSpace(client.ClientID)
		add(ports.IdentityUser{
			TenantID:    client.TenantID,
			UserID:      userID,
			DisplayName: firstNonEmpty(client.Name, client.ClientID),
			Status:      "active",
			Provider:    oauthProvider,
			Source:      "mcp_oauth_client",
			Roles:       client.Roles,
			Groups:      client.Groups,
		})
		for _, allowedTenant := range client.AllowedTenants {
			add(ports.IdentityUser{
				TenantID:    allowedTenant,
				UserID:      userID,
				DisplayName: firstNonEmpty(client.Name, client.ClientID),
				Status:      "active",
				Provider:    oauthProvider,
				Source:      "mcp_oauth_client",
				Roles:       client.Roles,
				Groups:      client.Groups,
			})
		}
	}
	for _, entitlement := range cfg.MCPOAuth.Entitlements {
		userID := firstNonEmpty(entitlement.Subject, entitlement.Email)
		if userID == "" {
			continue
		}
		add(ports.IdentityUser{
			TenantID:    entitlement.TenantID,
			UserID:      userID,
			Subject:     entitlement.Subject,
			Email:       strings.ToLower(strings.TrimSpace(entitlement.Email)),
			DisplayName: userID,
			Status:      "active",
			Provider:    oauthProvider,
			Source:      "mcp_oauth_entitlement",
			Roles:       entitlement.Roles,
			Groups:      entitlement.Groups,
		})
		for _, allowedTenant := range entitlement.AllowedTenants {
			add(ports.IdentityUser{
				TenantID:    allowedTenant,
				UserID:      userID,
				Subject:     entitlement.Subject,
				Email:       strings.ToLower(strings.TrimSpace(entitlement.Email)),
				DisplayName: userID,
				Status:      "active",
				Provider:    oauthProvider,
				Source:      "mcp_oauth_entitlement",
				Roles:       entitlement.Roles,
				Groups:      entitlement.Groups,
			})
		}
	}
	return users
}

func mergeOrganizations(configured []*ports.IdentityOrganization, persisted []*ports.IdentityOrganization, tenantID string, orgID string, query string, limit uint32) []*ports.IdentityOrganization {
	byKey := map[string]*ports.IdentityOrganization{}
	for _, org := range configured {
		if organizationVisible(org, tenantID, orgID, query) {
			byKey[identityOrgKey(org)] = cloneOrganization(org)
		}
	}
	for _, org := range persisted {
		if !organizationVisible(org, tenantID, orgID, query) {
			continue
		}
		key := identityOrgKey(org)
		if existing := byKey[key]; existing != nil {
			if existing.UserCount == 0 {
				existing.UserCount = org.UserCount
			}
			if existing.LastSyncedAt.IsZero() {
				existing.LastSyncedAt = org.LastSyncedAt
			}
			if existing.CreatedAt.IsZero() {
				existing.CreatedAt = org.CreatedAt
			}
			if org.UpdatedAt.After(existing.UpdatedAt) {
				existing.UpdatedAt = org.UpdatedAt
			}
			continue
		}
		byKey[key] = cloneOrganization(org)
	}
	out := make([]*ports.IdentityOrganization, 0, len(byKey))
	for _, org := range byKey {
		out = append(out, org)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].OrgID < out[j].OrgID
	})
	return capOrganizations(out, limit)
}

func mergeUsers(configured []*ports.IdentityUser, persisted []*ports.IdentityUser, tenantID string, orgID string, query string, limit uint32) []*ports.IdentityUser {
	byKey := map[string]*ports.IdentityUser{}
	configuredKeys := map[string]bool{}
	for _, user := range configured {
		if userVisible(user, tenantID, orgID, query) {
			key := identityUserKey(user)
			byKey[key] = cloneUser(user)
			configuredKeys[key] = true
		}
	}
	for _, user := range persisted {
		if !userVisible(user, tenantID, orgID, query) {
			continue
		}
		byKey[identityUserKey(user)] = cloneUser(user)
	}
	out := make([]*ports.IdentityUser, 0, len(byKey))
	for _, user := range byKey {
		out = append(out, user)
	}
	sort.Slice(out, func(i, j int) bool {
		leftConfigured := configuredKeys[identityUserKey(out[i])]
		rightConfigured := configuredKeys[identityUserKey(out[j])]
		if leftConfigured != rightConfigured {
			return leftConfigured
		}
		if !out[i].LastSeenAt.Equal(out[j].LastSeenAt) {
			return out[i].LastSeenAt.After(out[j].LastSeenAt)
		}
		if out[i].DisplayName != out[j].DisplayName {
			return out[i].DisplayName < out[j].DisplayName
		}
		return out[i].UserID < out[j].UserID
	})
	return capUsers(out, limit)
}

func organizationResponses(orgs []*ports.IdentityOrganization) []organizationResponse {
	responses := make([]organizationResponse, 0, len(orgs))
	for _, org := range orgs {
		responses = append(responses, organizationResponse{
			OrgID:        strings.TrimSpace(org.OrgID),
			TenantID:     strings.TrimSpace(org.TenantID),
			Name:         strings.TrimSpace(org.Name),
			Slug:         strings.TrimSpace(org.Slug),
			Domain:       strings.TrimSpace(org.Domain),
			Provider:     strings.TrimSpace(org.Provider),
			Source:       firstNonEmpty(org.Source, "identity_directory"),
			ExternalID:   strings.TrimSpace(org.ExternalID),
			UserCount:    org.UserCount,
			LastSyncedAt: timeString(org.LastSyncedAt),
			CreatedAt:    timeString(org.CreatedAt),
			UpdatedAt:    timeString(org.UpdatedAt),
		})
	}
	return responses
}

func userResponses(users []*ports.IdentityUser) []userResponse {
	responses := make([]userResponse, 0, len(users))
	for _, user := range users {
		responses = append(responses, userResponse{
			UserID:       strings.TrimSpace(user.UserID),
			TenantID:     strings.TrimSpace(user.TenantID),
			OrgID:        strings.TrimSpace(user.OrgID),
			Subject:      strings.TrimSpace(user.Subject),
			Email:        strings.TrimSpace(user.Email),
			DisplayName:  strings.TrimSpace(user.DisplayName),
			Status:       firstNonEmpty(user.Status, "active"),
			Provider:     strings.TrimSpace(user.Provider),
			Source:       firstNonEmpty(user.Source, "identity_directory"),
			Roles:        normalized(user.Roles),
			Groups:       normalized(user.Groups),
			LastSeenAt:   timeString(user.LastSeenAt),
			LastSyncedAt: timeString(user.LastSyncedAt),
			CreatedAt:    timeString(user.CreatedAt),
			UpdatedAt:    timeString(user.UpdatedAt),
		})
	}
	return responses
}

func organizationVisible(org *ports.IdentityOrganization, tenantID string, orgID string, query string) bool {
	if org == nil {
		return false
	}
	if tenantID != "" && org.TenantID != tenantID {
		return false
	}
	if orgID != "" && org.OrgID != orgID {
		return false
	}
	return matchesQuery(query, org.OrgID, org.Name, org.Domain, org.Provider, org.Source)
}

func userVisible(user *ports.IdentityUser, tenantID string, orgID string, query string) bool {
	if user == nil {
		return false
	}
	if tenantID != "" && user.TenantID != tenantID {
		return false
	}
	if orgID != "" && user.OrgID != orgID {
		return false
	}
	return matchesQuery(query, user.UserID, user.Email, user.DisplayName, user.Subject, user.Provider, user.Source)
}

func matchesQuery(query string, values ...string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), query) {
			return true
		}
	}
	return false
}

func cloneOrganization(org *ports.IdentityOrganization) *ports.IdentityOrganization {
	if org == nil {
		return nil
	}
	copied := *org
	return &copied
}

func cloneUser(user *ports.IdentityUser) *ports.IdentityUser {
	if user == nil {
		return nil
	}
	copied := *user
	copied.Roles = normalized(user.Roles)
	copied.Groups = normalized(user.Groups)
	return &copied
}

func capOrganizations(orgs []*ports.IdentityOrganization, limit uint32) []*ports.IdentityOrganization {
	remaining := limit
	for index := range orgs {
		if remaining == 0 {
			return orgs[:index]
		}
		remaining--
	}
	return orgs
}

func capUsers(users []*ports.IdentityUser, limit uint32) []*ports.IdentityUser {
	remaining := limit
	for index := range users {
		if remaining == 0 {
			return users[:index]
		}
		remaining--
	}
	return users
}

func directoryLimit(raw string) uint32 {
	parsed, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32)
	if err != nil || parsed == 0 {
		return defaultDirectoryLimit
	}
	if parsed > uint64(maxDirectoryLimit) {
		return maxDirectoryLimit
	}
	return uint32(parsed)
}

func statusForTenantError(error) int {
	return http.StatusForbidden
}

func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	http.Error(w, message, statusCode)
}

func tenantName(tenantID string) string {
	return strings.TrimSpace(tenantID)
}

func tenantSlug(tenantID string) string {
	slug := strings.ToLower(strings.TrimSpace(tenantID))
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		default:
			return '-'
		}
	}, slug)
	return strings.Trim(slug, "-")
}

func oauthProvider(issuer string) string {
	issuer = strings.ToLower(strings.TrimSpace(issuer))
	switch {
	case strings.Contains(issuer, "okta"):
		return "okta"
	case issuer != "":
		return "oidc"
	default:
		return ""
	}
}

func identityOrgKey(org *ports.IdentityOrganization) string {
	return strings.TrimSpace(org.TenantID) + "\x00" + strings.TrimSpace(org.OrgID)
}

func identityUserKey(user *ports.IdentityUser) string {
	return strings.TrimSpace(user.TenantID) + "\x00" + strings.TrimSpace(user.UserID)
}

func normalized(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func contains(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func timeString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.TypeOf(value).Kind()
	switch kind {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

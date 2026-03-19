package api

import (
	"sort"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/apiauth"
)

type agentSDKAdminService interface {
	AuthorizationServers() []string
	SupportedScopes() []string
	ListCredentials() []adminAgentSDKCredentialResponse
	GetCredential(id string) (adminAgentSDKCredentialResponse, bool)
	CreateCredential(spec apiauth.ManagedCredentialSpec, now time.Time) (adminAgentSDKCredentialResponse, string, error)
	RotateCredential(id string, now time.Time) (adminAgentSDKCredentialResponse, string, error)
	RevokeCredential(id, reason string, now time.Time) (adminAgentSDKCredentialResponse, error)
}

type serverAgentSDKAdminService struct {
	deps *serverDependencies
}

func newAgentSDKAdminService(deps *serverDependencies) agentSDKAdminService {
	return serverAgentSDKAdminService{deps: deps}
}

func (s serverAgentSDKAdminService) AuthorizationServers() []string {
	if s.deps == nil || s.deps.Config == nil {
		return nil
	}
	return append([]string(nil), s.deps.Config.APIAuthorizationServers...)
}

func (s serverAgentSDKAdminService) SupportedScopes() []string {
	if s.deps != nil && s.deps.RBAC != nil {
		values := s.deps.RBAC.ListPermissionIDs()
		scopes := make([]string, 0, len(values))
		for _, value := range values {
			if strings.HasPrefix(value, "sdk.") {
				scopes = append(scopes, value)
			}
		}
		if len(scopes) > 0 {
			sort.Strings(scopes)
			return scopes
		}
	}
	return []string{
		"sdk.admin",
		"sdk.context.read",
		"sdk.enforcement.run",
		"sdk.invoke",
		"sdk.schema.read",
		"sdk.worldmodel.write",
	}
}

func (s serverAgentSDKAdminService) ListCredentials() []adminAgentSDKCredentialResponse {
	if s.deps == nil {
		return nil
	}
	staticCredentials := s.deps.APICredentialsSnapshot()
	managedCredentials := s.deps.ManagedAPICredentials()

	credentials := make([]adminAgentSDKCredentialResponse, 0, len(staticCredentials)+len(managedCredentials))
	for _, key := range apiauth.SortedKeys(staticCredentials) {
		credentials = append(credentials, adminAgentSDKCredentialResponse{
			ID:              staticCredentials[key].ID,
			Name:            staticCredentials[key].Name,
			UserID:          staticCredentials[key].UserID,
			Kind:            staticCredentials[key].Kind,
			Surface:         staticCredentials[key].Surface,
			ClientID:        staticCredentials[key].ClientID,
			Scopes:          append([]string(nil), staticCredentials[key].Scopes...),
			RateLimitBucket: staticCredentials[key].RateLimitBucket,
			TenantID:        staticCredentials[key].TenantID,
			Enabled:         staticCredentials[key].Enabled,
			Metadata:        cloneStringStringMap(staticCredentials[key].Metadata),
			Managed:         false,
			Mutable:         false,
		})
	}
	for _, record := range managedCredentials {
		credentials = append(credentials, adminAgentSDKCredentialFromManaged(record))
	}
	sort.Slice(credentials, func(i, j int) bool {
		return credentials[i].ID < credentials[j].ID
	})
	return credentials
}

func (s serverAgentSDKAdminService) GetCredential(id string) (adminAgentSDKCredentialResponse, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return adminAgentSDKCredentialResponse{}, false
	}
	for _, credential := range s.ListCredentials() {
		if credential.ID == id {
			return credential, true
		}
	}
	return adminAgentSDKCredentialResponse{}, false
}

func (s serverAgentSDKAdminService) CreateCredential(spec apiauth.ManagedCredentialSpec, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
	if s.deps == nil {
		return adminAgentSDKCredentialResponse{}, "", errManagedAPICredentialsUnavailable
	}
	record, secret, err := s.deps.CreateManagedAPICredential(spec, now)
	if err != nil {
		return adminAgentSDKCredentialResponse{}, "", err
	}
	return adminAgentSDKCredentialFromManaged(record), secret, nil
}

func (s serverAgentSDKAdminService) RotateCredential(id string, now time.Time) (adminAgentSDKCredentialResponse, string, error) {
	if s.deps == nil {
		return adminAgentSDKCredentialResponse{}, "", errManagedAPICredentialsUnavailable
	}
	record, secret, err := s.deps.RotateManagedAPICredential(id, now)
	if err != nil {
		return adminAgentSDKCredentialResponse{}, "", err
	}
	return adminAgentSDKCredentialFromManaged(record), secret, nil
}

func (s serverAgentSDKAdminService) RevokeCredential(id, reason string, now time.Time) (adminAgentSDKCredentialResponse, error) {
	if s.deps == nil {
		return adminAgentSDKCredentialResponse{}, errManagedAPICredentialsUnavailable
	}
	record, err := s.deps.RevokeManagedAPICredential(id, reason, now)
	if err != nil {
		return adminAgentSDKCredentialResponse{}, err
	}
	return adminAgentSDKCredentialFromManaged(record), nil
}

var _ agentSDKAdminService = serverAgentSDKAdminService{}

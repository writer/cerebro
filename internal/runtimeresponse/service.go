package runtimeresponse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var (
	ErrInvalidRequest     = errors.New("invalid runtime response request")
	ErrUnsupportedAction  = errors.New("unsupported runtime response action")
	ErrRuntimeUnavailable = errors.New("runtime response store is unavailable")
)

const (
	ActionBlockIP                         = "block_ip"
	ActionBlockDomain                     = "block_domain"
	ActionGoogleWorkspaceRevokeOAuthGrant = "google_workspace.revoke_oauth_grant"
	ActionSlackRevokeAppInstall           = "slack.revoke_app_install"
	ActionGitHubRevokeOAuthApp            = "github.revoke_oauth_app"
	ActionOktaSuspendUser                 = "okta.suspend_user"
	ActionMicrosoft365RevokeSessions      = "microsoft_365.revoke_sessions"
	ActionAtlassianRevokeUserAccess       = "atlassian.revoke_user_access"
	ActionSalesforceRemoveAdminRole       = "salesforce.remove_admin_role"
)

type Capability struct {
	Action              string   `json:"action"`
	Mode                string   `json:"mode"`
	Supported           bool     `json:"supported"`
	RequiresScope       bool     `json:"requires_trusted_scope"`
	Provider            string   `json:"provider,omitempty"`
	ExternalOwner       string   `json:"external_owner,omitempty"`
	TargetTypes         []string `json:"target_types,omitempty"`
	RequiredContextKeys []string `json:"required_context_keys,omitempty"`
	DryRun              bool     `json:"dry_run"`
	ApprovalRequired    bool     `json:"approval_required"`
}

type ExecuteRequest struct {
	TenantID     string            `json:"tenant_id"`
	Action       string            `json:"action"`
	Target       string            `json:"target"`
	Reason       string            `json:"reason,omitempty"`
	Source       string            `json:"source,omitempty"`
	SourceJobID  string            `json:"source_job_id,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at,omitempty"`
	TrustedScope bool              `json:"trusted_scope,omitempty"`
}

type Service struct {
	store ports.RuntimeBlocklistStore
	now   func() time.Time
}

func New(store ports.RuntimeBlocklistStore) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Capabilities() []Capability {
	capabilities := []Capability{
		{Action: ActionBlockIP, Mode: "local_blocklist", Supported: s != nil && s.store != nil, RequiresScope: true},
		{Action: ActionBlockDomain, Mode: "local_blocklist", Supported: s != nil && s.store != nil, RequiresScope: true},
		{Action: "scale_down", Mode: "remote_or_provider", Supported: false, RequiresScope: true},
		{Action: "kill_process", Mode: "remote_tool", Supported: false, RequiresScope: true},
		{Action: "isolate_container", Mode: "remote_tool", Supported: false, RequiresScope: true},
		{Action: "isolate_host", Mode: "remote_tool", Supported: false, RequiresScope: true},
		{Action: "quarantine_file", Mode: "remote_tool", Supported: false, RequiresScope: true},
		{Action: "revoke_credentials", Mode: "remote_tool", Supported: false, RequiresScope: true},
	}
	return append(capabilities, aperioExternalWorkflowCapabilities()...)
}

func aperioExternalWorkflowCapabilities() []Capability {
	return []Capability{
		{
			Action:              ActionGoogleWorkspaceRevokeOAuthGrant,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "GOOGLE_WORKSPACE",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"oauth_grant", "oauth_app"},
			RequiredContextKeys: []string{"oauth_grant_id", "oauth_app_id", "oauth_user_email"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionSlackRevokeAppInstall,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "SLACK",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"oauth_app", "slack_app"},
			RequiredContextKeys: []string{"oauth_app_id", "slack_app_id", "workspace_id"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionGitHubRevokeOAuthApp,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "GITHUB",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"oauth_app", "github_oauth_app"},
			RequiredContextKeys: []string{"oauth_app_id", "github_org", "github_user"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionOktaSuspendUser,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "OKTA",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"user", "identity"},
			RequiredContextKeys: []string{"okta_user_id", "user_email"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionMicrosoft365RevokeSessions,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "MICROSOFT_365",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"user", "identity"},
			RequiredContextKeys: []string{"user_id", "user_principal_name"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionAtlassianRevokeUserAccess,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "ATLASSIAN",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"user", "group", "project"},
			RequiredContextKeys: []string{"atlassian_account_id", "resource_id"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
		{
			Action:              ActionSalesforceRemoveAdminRole,
			Mode:                "external_aperio_workflow",
			Supported:           false,
			RequiresScope:       true,
			Provider:            "SALESFORCE",
			ExternalOwner:       "aperio",
			TargetTypes:         []string{"user", "permission_set", "profile"},
			RequiredContextKeys: []string{"salesforce_user_id", "permission_set_id"},
			DryRun:              true,
			ApprovalRequired:    true,
		},
	}
}

func (s *Service) Execute(ctx context.Context, request ExecuteRequest) (*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	request.Action = strings.TrimSpace(request.Action)
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Target = strings.TrimSpace(request.Target)
	if request.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if request.Target == "" {
		return nil, fmt.Errorf("%w: target is required", ErrInvalidRequest)
	}
	if !request.TrustedScope {
		return nil, fmt.Errorf("%w: trusted_scope is required for %s", ErrInvalidRequest, request.Action)
	}
	entryType := ""
	value := request.Target
	switch request.Action {
	case ActionBlockIP:
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("%w: target must be an IP address", ErrInvalidRequest)
		}
		value = ip.String()
		entryType = "ip"
	case ActionBlockDomain:
		domain := normalizeDomain(value)
		if domain == "" {
			return nil, fmt.Errorf("%w: target must be a domain", ErrInvalidRequest)
		}
		value = domain
		entryType = "domain"
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAction, request.Action)
	}
	return s.store.PutRuntimeBlocklistEntry(ctx, ports.RuntimeBlocklistEntry{
		ID:          newID(),
		TenantID:    request.TenantID,
		Type:        entryType,
		Value:       value,
		Reason:      strings.TrimSpace(request.Reason),
		Source:      strings.TrimSpace(request.Source),
		SourceJobID: strings.TrimSpace(request.SourceJobID),
		Attributes:  request.Attributes,
		ExpiresAt:   request.ExpiresAt,
	})
}

func (s *Service) List(ctx context.Context, filter ports.RuntimeBlocklistFilter) ([]*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.ListRuntimeBlocklistEntries(ctx, filter)
}

func (s *Service) Revoke(ctx context.Context, tenantID string, id string) (*ports.RuntimeBlocklistEntry, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	return s.store.RevokeRuntimeBlocklistEntry(ctx, tenantID, id)
}

func normalizeDomain(value string) string {
	value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || strings.ContainsAny(value, "/:@") || strings.Contains(value, "..") {
		return ""
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, label := range labels {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return ""
			}
		}
	}
	return value
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("rr-%d", time.Now().UnixNano())
	}
	return "rr-" + hex.EncodeToString(b[:])
}

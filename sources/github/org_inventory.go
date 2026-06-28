package github

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/githubapi"
	"github.com/writer/cerebro/sources/internal/githubapp"
	"github.com/writer/cerebro/sources/internal/githubcanary"
)

const familyOrgInventory = "org_inventory"

type orgMemberPayload struct {
	Login     string `json:"login"`
	ID        int64  `json:"id"`
	Role      string `json:"role,omitempty"`
	Org       string `json:"org"`
	AvatarURL string `json:"avatar_url,omitempty"`
	URL       string `json:"html_url,omitempty"`
}

type orgInstallationPayload struct {
	ID                  int64    `json:"id"`
	AppSlug             string   `json:"app_slug"`
	Org                 string   `json:"org"`
	TargetType          string   `json:"target_type,omitempty"`
	RepositorySelection string   `json:"repository_selection,omitempty"`
	Permissions         []string `json:"permissions,omitempty"`
	Events              []string `json:"events,omitempty"`
	CreatedAt           string   `json:"created_at,omitempty"`
	UpdatedAt           string   `json:"updated_at,omitempty"`
}

func (s *Source) checkOrgInventory(ctx context.Context, client *gogithub.Client, settings settings) error {
	_, _, err := client.Organizations.ListMembers(ctx, settings.owner, &gogithub.ListMembersOptions{
		ListOptions: gogithub.ListOptions{PerPage: 1},
	})
	return githubapi.ProviderUnavailableLookupError(fmt.Sprintf("github org members for %s", settings.owner), err, settings.hasAuth())
}

func (s *Source) discoverOrgInventory(ctx context.Context, client *gogithub.Client, settings settings) ([]sourcecdk.URN, error) {
	if err := s.checkOrgInventory(ctx, client, settings); err != nil {
		return nil, err
	}
	return []sourcecdk.URN{sourcecdk.URN(fmt.Sprintf("urn:cerebro:%s:github_org_inventory:%s", settings.owner, settings.owner))}, nil
}

func (s *Source) readOrgInventory(ctx context.Context, client *gogithub.Client, settings settings, checkpoint *cerebrov1.SourceCheckpoint, configHash string) (sourcecdk.Pull, error) {
	now := time.Now().UTC()
	var canary *githubcanary.Result
	var err error
	if settings.auditLogCanary {
		canary, err = githubcanary.ProbeAuditLog(ctx, client, settings.owner, checkpoint, configHash, now)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		if pull, ok := canary.ShortCircuitPull(); ok {
			return pull, nil
		}
	}
	var events []*primitives.Event

	// Members
	members, _, err := client.Organizations.ListMembers(ctx, settings.owner, &gogithub.ListMembersOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	})
	if err != nil {
		if settings.hasAuth() && githubapi.ProviderUnavailable(err) {
			pull := githubapi.ProviderUnavailablePull(checkpoint)
			return canary.Apply(pull, "github", familyOrgInventory), nil
		}
		return sourcecdk.Pull{}, githubapi.LookupError(fmt.Sprintf("github org members for %s", settings.owner), err)
	}
	for _, member := range members {
		event, err := orgMemberEvent(settings, member, "member", now)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}

	// Outside collaborators
	collabs, _, err := client.Organizations.ListOutsideCollaborators(ctx, settings.owner, &gogithub.ListOutsideCollaboratorsOptions{
		ListOptions: gogithub.ListOptions{PerPage: 100},
	})
	if err == nil {
		for _, collab := range collabs {
			event, err := orgMemberEvent(settings, collab, "outside_collaborator", now)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
	}

	// Installations
	installs, _, err := client.Organizations.ListInstallations(ctx, settings.owner, &gogithub.ListOptions{PerPage: 100})
	if err == nil && installs != nil {
		for _, install := range installs.Installations {
			event, err := orgInstallationEvent(settings, install, now)
			if err != nil {
				return sourcecdk.Pull{}, err
			}
			events = append(events, event)
		}
	}

	if len(events) == 0 {
		return canary.Apply(sourcecdk.Pull{}, "github", familyOrgInventory), nil
	}
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark: timestamppb.New(now),
		},
	}
	return canary.Apply(pull, "github", familyOrgInventory), nil
}

func orgMemberEvent(settings settings, user *gogithub.User, role string, now time.Time) (*primitives.Event, error) {
	if user == nil {
		return nil, fmt.Errorf("org member is required")
	}
	payload := orgMemberPayload{
		Login:     user.GetLogin(),
		ID:        user.GetID(),
		Role:      role,
		Org:       settings.owner,
		AvatarURL: user.GetAvatarURL(),
		URL:       user.GetHTMLURL(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal github org member payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("github-org-member-%s-%s-%d", settings.owner, user.GetLogin(), now.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.org_member",
		OccurredAt: timestamppb.New(now),
		SchemaRef:  "github/org_member/v1",
		Payload:    payloadBytes,
		Attributes: map[string]string{
			"family":  familyOrgInventory,
			"login":   user.GetLogin(),
			"owner":   settings.owner,
			"role":    role,
			"user_id": strconv.FormatInt(user.GetID(), 10),
		},
	}, nil
}

func orgInstallationEvent(settings settings, install *gogithub.Installation, now time.Time) (*primitives.Event, error) {
	if install == nil {
		return nil, fmt.Errorf("org installation is required")
	}
	permissions := githubapp.InstallationPermissionPairs(install.GetPermissions())
	payload := orgInstallationPayload{
		ID:                  install.GetID(),
		AppSlug:             install.GetAppSlug(),
		Org:                 settings.owner,
		TargetType:          install.GetTargetType(),
		RepositorySelection: install.GetRepositorySelection(),
		Permissions:         permissions,
		Events:              install.Events,
	}
	if install.CreatedAt != nil {
		payload.CreatedAt = install.CreatedAt.UTC().Format(time.RFC3339)
	}
	if install.UpdatedAt != nil {
		payload.UpdatedAt = install.UpdatedAt.UTC().Format(time.RFC3339)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal github org installation payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("github-org-installation-%s-%d-%d", settings.owner, install.GetID(), now.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.org_installation",
		OccurredAt: timestamppb.New(now),
		SchemaRef:  "github/org_installation/v1",
		Payload:    payloadBytes,
		Attributes: map[string]string{
			"app_slug":             install.GetAppSlug(),
			"events":               strings.Join(install.Events, ","),
			"family":               familyOrgInventory,
			"installation_id":      strconv.FormatInt(install.GetID(), 10),
			"owner":                settings.owner,
			"permissions":          strings.Join(permissions, ","),
			"repository_selection": install.GetRepositorySelection(),
			"target_type":          install.GetTargetType(),
			"created_at":           payload.CreatedAt,
			"updated_at":           payload.UpdatedAt,
		},
	}, nil
}

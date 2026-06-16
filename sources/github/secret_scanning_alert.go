package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const familySecretScanning = "secret_scanning_alert"

type secretScanningAlertPayload struct {
	Number                     int        `json:"number"`
	Repository                 string     `json:"repository"`
	State                      string     `json:"state"`
	SecretType                 string     `json:"secret_type,omitempty"`
	SecretTypeDisplayName      string     `json:"secret_type_display_name,omitempty"`
	Resolution                 string     `json:"resolution,omitempty"`
	ResolutionComment          string     `json:"resolution_comment,omitempty"`
	ResolvedBy                 string     `json:"resolved_by,omitempty"`
	ResolvedByID               int64      `json:"resolved_by_id,omitempty"`
	PushProtectionBypassed     bool       `json:"push_protection_bypassed"`
	PushProtectionBypassedBy   string     `json:"push_protection_bypassed_by,omitempty"`
	PushProtectionBypassedByID int64      `json:"push_protection_bypassed_by_id,omitempty"`
	URL                        string     `json:"url,omitempty"`
	HTMLURL                    string     `json:"html_url,omitempty"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
	ResolvedAt                 *time.Time `json:"resolved_at,omitempty"`
	PushProtectionBypassedAt   *time.Time `json:"push_protection_bypassed_at,omitempty"`
}

func (s *Source) checkSecretScanningAlerts(ctx context.Context, client *gogithub.Client, settings settings) error {
	_, _, err := listSecretScanningAlertsForOrg(ctx, client, settings, nil, 1)
	if err != nil {
		return wrapLookupError(fmt.Sprintf("github secret scanning alerts for org %s", settings.owner), err)
	}
	return nil
}

func (s *Source) discoverSecretScanningAlerts(ctx context.Context, client *gogithub.Client, settings settings) ([]sourcecdk.URN, error) {
	if err := s.checkSecretScanningAlerts(ctx, client, settings); err != nil {
		return nil, err
	}
	return []sourcecdk.URN{sourcecdk.URN(fmt.Sprintf("urn:cerebro:%s:secret_scanning", settings.owner))}, nil
}

func (s *Source) readSecretScanningAlerts(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	alerts, resp, err := listSecretScanningAlertsForOrg(ctx, client, settings, cursor, settings.perPage)
	if err != nil {
		return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("github secret scanning alerts for org %s", settings.owner), err)
	}
	if len(alerts) == 0 {
		return sourcecdk.EmptyIncrementalWatermarkPull("github", familySecretScanning, checkpoint), nil
	}
	events := make([]*primitives.Event, 0, len(alerts))
	for _, alert := range alerts {
		event, err := secretScanningAlertEvent(settings, alert)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	nextCursor := ""
	if resp != nil {
		nextCursor = sourcecdk.NextAfterOrPageCursor(resp.After, resp.NextPageToken, resp.NextPage)
	}
	return sourcecdk.IncrementalWatermarkPull("github", familySecretScanning, events, checkpoint, nextCursor), nil
}

func listSecretScanningAlertsForOrg(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor, perPage int) ([]*gogithub.SecretScanningAlert, *gogithub.Response, error) {
	after, page, err := sourcecdk.CursorAfterOrPage(cursor)
	if err != nil {
		return nil, nil, err
	}
	query := url.Values{
		"after":     {after},
		"direction": {"desc"},
		"per_page":  {strconv.Itoa(perPage)},
		"sort":      {"updated"},
		"state":     {settings.state},
	}
	if page != "" {
		query.Del("after")
		query.Set("page", page)
	}
	path := fmt.Sprintf("orgs/%s/secret-scanning/alerts?%s", url.PathEscape(settings.owner), query.Encode())
	req, err := client.NewRequest("GET", path, nil)
	if err != nil {
		return nil, nil, err
	}
	var alerts []*gogithub.SecretScanningAlert
	resp, err := client.Do(ctx, req, &alerts)
	return alerts, resp, err
}

func secretScanningAlertEvent(settings settings, alert *gogithub.SecretScanningAlert) (*primitives.Event, error) {
	if alert == nil {
		return nil, fmt.Errorf("secret scanning alert is required")
	}
	occurredAt := alert.GetUpdatedAt().Time
	if occurredAt.IsZero() {
		occurredAt = alert.GetCreatedAt().Time
	}
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github secret scanning alert %d missing timestamps", alert.GetNumber())
	}
	createdAt := alert.GetCreatedAt().Time
	if createdAt.IsZero() {
		createdAt = occurredAt
	}
	repoName := ""
	if repo := alert.GetRepository(); repo != nil {
		repoName = repo.GetFullName()
	}
	payload := secretScanningAlertPayload{
		Number:                     alert.GetNumber(),
		Repository:                 repoName,
		State:                      alert.GetState(),
		SecretType:                 alert.GetSecretType(),
		SecretTypeDisplayName:      alert.GetSecretTypeDisplayName(),
		Resolution:                 alert.GetResolution(),
		ResolutionComment:          alert.GetResolutionComment(),
		ResolvedBy:                 githubUserLogin(alert.ResolvedBy),
		ResolvedByID:               githubUserID(alert.ResolvedBy),
		PushProtectionBypassed:     alert.GetPushProtectionBypassed(),
		PushProtectionBypassedBy:   githubUserLogin(alert.PushProtectionBypassedBy),
		PushProtectionBypassedByID: githubUserID(alert.PushProtectionBypassedBy),
		URL:                        alert.GetURL(),
		HTMLURL:                    alert.GetHTMLURL(),
		CreatedAt:                  createdAt,
		UpdatedAt:                  occurredAt,
		ResolvedAt:                 secretScanningTimestamp(alert.ResolvedAt),
		PushProtectionBypassedAt:   secretScanningTimestamp(alert.PushProtectionBypassedAt),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal github secret scanning alert payload: %w", err)
	}
	repo := repoName
	if repo == "" {
		repo = settings.owner
	}
	attributes := map[string]string{
		"alert_number": strconv.Itoa(alert.GetNumber()),
		"family":       familySecretScanning,
		"owner":        settings.owner,
		"state":        alert.GetState(),
	}
	addAttribute(attributes, "html_url", payload.HTMLURL)
	addAttribute(attributes, "repository", repoName)
	addAttribute(attributes, "resolution", payload.Resolution)
	addAttribute(attributes, "resolved_by", payload.ResolvedBy)
	if payload.ResolvedByID != 0 {
		addAttribute(attributes, "resolved_by_id", strconv.FormatInt(payload.ResolvedByID, 10))
	}
	addAttribute(attributes, "secret_type", payload.SecretType)
	addAttribute(attributes, "secret_type_display_name", payload.SecretTypeDisplayName)
	addAttribute(attributes, "push_protection_bypassed", strconv.FormatBool(payload.PushProtectionBypassed))
	addAttribute(attributes, "push_protection_bypassed_by", payload.PushProtectionBypassedBy)
	if payload.PushProtectionBypassedByID != 0 {
		addAttribute(attributes, "push_protection_bypassed_by_id", strconv.FormatInt(payload.PushProtectionBypassedByID, 10))
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("github-secret-scanning-%s-%d-%d", normalizeRepositoryEventID(repo), alert.GetNumber(), occurredAt.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.secret_scanning_alert",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "github/secret_scanning_alert/v1",
		Payload:    payloadBytes,
		Attributes: attributes,
	}, nil
}

func secretScanningTimestamp(value *gogithub.Timestamp) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

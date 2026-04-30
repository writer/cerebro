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
)

type dependabotAlertPayload struct {
	Number                 int        `json:"number"`
	Repository             string     `json:"repository"`
	State                  string     `json:"state"`
	URL                    string     `json:"url,omitempty"`
	HTMLURL                string     `json:"html_url,omitempty"`
	GHSAID                 string     `json:"ghsa_id,omitempty"`
	CVEID                  string     `json:"cve_id,omitempty"`
	AdvisorySummary        string     `json:"advisory_summary,omitempty"`
	AdvisorySeverity       string     `json:"advisory_severity,omitempty"`
	VulnerabilitySeverity  string     `json:"vulnerability_severity,omitempty"`
	Ecosystem              string     `json:"ecosystem,omitempty"`
	PackageName            string     `json:"package_name,omitempty"`
	ManifestPath           string     `json:"manifest_path,omitempty"`
	DependencyScope        string     `json:"dependency_scope,omitempty"`
	VulnerableVersionRange string     `json:"vulnerable_version_range,omitempty"`
	FirstPatchedVersion    string     `json:"first_patched_version,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	DismissedAt            *time.Time `json:"dismissed_at,omitempty"`
	FixedAt                *time.Time `json:"fixed_at,omitempty"`
}

func (s *Source) checkDependabotAlerts(ctx context.Context, client *gogithub.Client, settings settings) error {
	_, _, err := client.Dependabot.ListRepoAlerts(ctx, settings.owner, settings.repo, dependabotAlertOptions(settings, "", 1))
	if err != nil {
		return wrapLookupError(fmt.Sprintf("github dependabot alerts for repo %s/%s", settings.owner, settings.repo), err)
	}
	return nil
}

func (s *Source) discoverDependabotAlerts(ctx context.Context, client *gogithub.Client, settings settings) ([]sourcecdk.URN, error) {
	if err := s.checkDependabotAlerts(ctx, client, settings); err != nil {
		return nil, err
	}
	repo, err := getRepo(ctx, client, settings.owner, settings.repo)
	if err != nil {
		return nil, err
	}
	urn, err := repoURN(settings.owner, repo)
	if err != nil {
		return nil, err
	}
	return []sourcecdk.URN{urn}, nil
}

func (s *Source) readDependabotAlerts(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	after := readDependabotCursor(cursor)
	alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, settings.owner, settings.repo, dependabotAlertOptions(settings, after, settings.perPage))
	if err != nil {
		return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("github dependabot alerts for repo %s/%s", settings.owner, settings.repo), err)
	}
	if len(alerts) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(alerts))
	for _, alert := range alerts {
		event, err := dependabotAlertEvent(settings, alert)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	nextCursor := nextAuditCursor(resp)
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: checkpointDependabotCursor(alerts, nextCursor),
		},
	}
	if nextCursor != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: nextCursor}
	}
	return pull, nil
}

func dependabotAlertOptions(settings settings, after string, perPage int) *gogithub.ListAlertsOptions {
	return &gogithub.ListAlertsOptions{
		State:     gogithub.String(settings.state),
		Sort:      gogithub.String("updated"),
		Direction: gogithub.String("desc"),
		ListCursorOptions: gogithub.ListCursorOptions{
			After:   after,
			PerPage: perPage,
		},
	}
}

func readDependabotCursor(cursor *cerebrov1.SourceCursor) string {
	if cursor == nil {
		return ""
	}
	return strings.TrimSpace(cursor.GetOpaque())
}

func checkpointDependabotCursor(alerts []*gogithub.DependabotAlert, cursor string) string {
	if cursor != "" {
		return cursor
	}
	if len(alerts) == 0 {
		return ""
	}
	return strconv.Itoa(alerts[len(alerts)-1].GetNumber())
}

func dependabotAlertEvent(settings settings, alert *gogithub.DependabotAlert) (*primitives.Event, error) {
	if alert == nil {
		return nil, fmt.Errorf("dependabot alert is required")
	}
	occurredAt := alert.GetUpdatedAt().Time
	if occurredAt.IsZero() {
		occurredAt = alert.GetCreatedAt().Time
	}
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github dependabot alert %d missing timestamps", alert.GetNumber())
	}
	createdAt := alert.GetCreatedAt().Time
	if createdAt.IsZero() {
		createdAt = occurredAt
	}
	payload := dependabotAlertPayload{
		Number:                 alert.GetNumber(),
		Repository:             settings.owner + "/" + settings.repo,
		State:                  alert.GetState(),
		URL:                    alert.GetURL(),
		HTMLURL:                alert.GetHTMLURL(),
		GHSAID:                 dependabotAlertGHSAID(alert),
		CVEID:                  dependabotAlertCVEID(alert),
		AdvisorySummary:        dependabotAlertSummary(alert),
		AdvisorySeverity:       dependabotAlertAdvisorySeverity(alert),
		VulnerabilitySeverity:  dependabotAlertVulnerabilitySeverity(alert),
		Ecosystem:              dependabotAlertEcosystem(alert),
		PackageName:            dependabotAlertPackage(alert),
		ManifestPath:           dependabotAlertManifestPath(alert),
		DependencyScope:        dependabotAlertDependencyScope(alert),
		VulnerableVersionRange: dependabotAlertVulnerableVersionRange(alert),
		FirstPatchedVersion:    dependabotAlertFirstPatchedVersion(alert),
		CreatedAt:              createdAt,
		UpdatedAt:              occurredAt,
		DismissedAt:            timestamp(alert.DismissedAt),
		FixedAt:                timestamp(alert.FixedAt),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal github dependabot alert payload: %w", err)
	}
	attributes := map[string]string{
		"alert_number":             strconv.Itoa(alert.GetNumber()),
		"family":                   familyDependabot,
		"owner":                    settings.owner,
		"repo":                     settings.repo,
		"repository":               settings.owner + "/" + settings.repo,
		"severity":                 firstNonEmptyString(payload.AdvisorySeverity, payload.VulnerabilitySeverity),
		"state":                    alert.GetState(),
		"vulnerable_version_range": payload.VulnerableVersionRange,
	}
	addAttribute(attributes, "advisory_cve_id", payload.CVEID)
	addAttribute(attributes, "advisory_ghsa_id", payload.GHSAID)
	addAttribute(attributes, "advisory_severity", payload.AdvisorySeverity)
	addAttribute(attributes, "dependency_scope", payload.DependencyScope)
	addAttribute(attributes, "ecosystem", payload.Ecosystem)
	addAttribute(attributes, "first_patched_version", payload.FirstPatchedVersion)
	addAttribute(attributes, "html_url", payload.HTMLURL)
	addAttribute(attributes, "manifest_path", payload.ManifestPath)
	addAttribute(attributes, "package", payload.PackageName)
	addAttribute(attributes, "vulnerability_severity", payload.VulnerabilitySeverity)
	return &primitives.Event{
		Id:         fmt.Sprintf("github-dependabot-alert-%s-%s-%d-%d", settings.owner, settings.repo, alert.GetNumber(), occurredAt.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.dependabot_alert",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "github/dependabot_alert/v1",
		Payload:    payloadBytes,
		Attributes: attributes,
	}, nil
}

func dependabotAlertGHSAID(alert *gogithub.DependabotAlert) string {
	if advisory := alert.GetSecurityAdvisory(); advisory != nil {
		return advisory.GetGHSAID()
	}
	return ""
}

func dependabotAlertCVEID(alert *gogithub.DependabotAlert) string {
	if advisory := alert.GetSecurityAdvisory(); advisory != nil {
		return advisory.GetCVEID()
	}
	return ""
}

func dependabotAlertSummary(alert *gogithub.DependabotAlert) string {
	if advisory := alert.GetSecurityAdvisory(); advisory != nil {
		return advisory.GetSummary()
	}
	return ""
}

func dependabotAlertAdvisorySeverity(alert *gogithub.DependabotAlert) string {
	if advisory := alert.GetSecurityAdvisory(); advisory != nil {
		return advisory.GetSeverity()
	}
	return ""
}

func dependabotAlertVulnerabilitySeverity(alert *gogithub.DependabotAlert) string {
	if vulnerability := alert.GetSecurityVulnerability(); vulnerability != nil {
		return vulnerability.GetSeverity()
	}
	return ""
}

func dependabotAlertEcosystem(alert *gogithub.DependabotAlert) string {
	if dependency := alert.GetDependency(); dependency != nil {
		if pkg := dependency.GetPackage(); pkg != nil && strings.TrimSpace(pkg.GetEcosystem()) != "" {
			return pkg.GetEcosystem()
		}
	}
	if vulnerability := alert.GetSecurityVulnerability(); vulnerability != nil {
		if pkg := vulnerability.GetPackage(); pkg != nil {
			return pkg.GetEcosystem()
		}
	}
	return ""
}

func dependabotAlertPackage(alert *gogithub.DependabotAlert) string {
	if dependency := alert.GetDependency(); dependency != nil {
		if pkg := dependency.GetPackage(); pkg != nil && strings.TrimSpace(pkg.GetName()) != "" {
			return pkg.GetName()
		}
	}
	if vulnerability := alert.GetSecurityVulnerability(); vulnerability != nil {
		if pkg := vulnerability.GetPackage(); pkg != nil {
			return pkg.GetName()
		}
	}
	return ""
}

func dependabotAlertManifestPath(alert *gogithub.DependabotAlert) string {
	if dependency := alert.GetDependency(); dependency != nil {
		return dependency.GetManifestPath()
	}
	return ""
}

func dependabotAlertDependencyScope(alert *gogithub.DependabotAlert) string {
	if dependency := alert.GetDependency(); dependency != nil {
		return dependency.GetScope()
	}
	return ""
}

func dependabotAlertVulnerableVersionRange(alert *gogithub.DependabotAlert) string {
	if vulnerability := alert.GetSecurityVulnerability(); vulnerability != nil {
		return vulnerability.GetVulnerableVersionRange()
	}
	return ""
}

func dependabotAlertFirstPatchedVersion(alert *gogithub.DependabotAlert) string {
	if vulnerability := alert.GetSecurityVulnerability(); vulnerability != nil {
		if version := vulnerability.GetFirstPatchedVersion(); version != nil {
			return version.GetIdentifier()
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

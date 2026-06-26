package github

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/githubapi"
	"github.com/writer/cerebro/sources/internal/githubcanary"
)

//go:embed catalog.yaml
var catalogFS embed.FS

const (
	defaultPageSize     = 10
	maxPageSize         = 100
	sourceHTTPTimeout   = 30 * time.Second
	defaultState        = "open"
	defaultFamily       = familyPullRequest
	defaultAuditInclude = "all"
	defaultAuditOrder   = "asc"
	familyAudit         = "audit"
	familyRepository    = "repository"
	familyDependabot    = "dependabot_alert"
	familyPullRequest   = "pull_request"
)

// Source is the live GitHub source preview used by the builtin registry.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	allowLoopbackBaseURL bool
	lookupIPAddrs        func(context.Context, string) ([]net.IPAddr, error)
}

type pullRequestPayload struct {
	Number     int        `json:"number"`
	Repository string     `json:"repository"`
	Title      string     `json:"title"`
	State      string     `json:"state"`
	URL        string     `json:"url"`
	Author     string     `json:"author"`
	Draft      bool       `json:"draft"`
	Head       string     `json:"head"`
	Base       string     `json:"base"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	MergedAt   *time.Time `json:"merged_at,omitempty"`
}

type repositoryPayload struct {
	ID                               int64      `json:"id,omitempty"`
	OwnerLogin                       string     `json:"owner_login"`
	Name                             string     `json:"name"`
	FullName                         string     `json:"full_name"`
	URL                              string     `json:"url,omitempty"`
	Visibility                       string     `json:"visibility,omitempty"`
	Private                          bool       `json:"private"`
	Archived                         bool       `json:"archived"`
	Fork                             bool       `json:"fork"`
	DefaultBranch                    string     `json:"default_branch,omitempty"`
	CreatedAt                        time.Time  `json:"created_at"`
	UpdatedAt                        time.Time  `json:"updated_at"`
	PushedAt                         *time.Time `json:"pushed_at,omitempty"`
	SecretScanningEnabled            string     `json:"secret_scanning_enabled,omitempty"`
	SecretScanningPushProtection     string     `json:"secret_scanning_push_protection,omitempty"`
	DependabotSecurityUpdatesEnabled string     `json:"dependabot_security_updates_enabled,omitempty"`
}

// New constructs the live GitHub source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{
		spec:          spec,
		lookupIPAddrs: net.DefaultResolver.LookupIPAddr,
	}, nil
}

func (s *Source) Spec() *cerebrov1.SourceSpec {
	return s.spec
}

// Check validates that a GitHub owner or repository is reachable.
func (s *Source) Check(ctx context.Context, cfg sourcecdk.Config) error {
	client, settings, err := s.newClient(cfg, false)
	if err != nil {
		return err
	}
	if settings.family == familyAudit {
		return s.checkAudit(ctx, client, settings)
	}
	if settings.family == familyDependabot {
		return s.checkDependabotAlerts(ctx, client, settings)
	}
	if settings.family == familySecretScanning {
		return s.checkSecretScanningAlerts(ctx, client, settings)
	}
	if settings.family == familyOrgInventory {
		return s.checkOrgInventory(ctx, client, settings)
	}
	if settings.family == familyRepository {
		if settings.repo != "" {
			_, err := getRepo(ctx, client, settings.owner, settings.repo)
			return githubapi.ProviderUnavailableOrError(err, settings.hasAuth())
		}
		_, err := listRepos(ctx, client, settings.owner, settings.perPage)
		return githubapi.ProviderUnavailableOrError(err, settings.hasAuth())
	}
	if settings.repo != "" {
		_, err := getRepo(ctx, client, settings.owner, settings.repo)
		return err
	}
	_, err = listRepos(ctx, client, settings.owner, settings.perPage)
	return err
}

// Discover returns live GitHub URNs for the selected family.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	client, settings, err := s.newClient(cfg, false)
	if err != nil {
		return nil, err
	}
	if settings.family == familyAudit {
		return s.discoverAudit(ctx, client, settings)
	}
	if settings.family == familyDependabot {
		return s.discoverDependabotAlerts(ctx, client, settings)
	}
	if settings.family == familySecretScanning {
		return s.discoverSecretScanningAlerts(ctx, client, settings)
	}
	if settings.family == familyOrgInventory {
		return s.discoverOrgInventory(ctx, client, settings)
	}
	if settings.repo != "" {
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
	repos, err := listRepos(ctx, client, settings.owner, settings.perPage)
	if err != nil {
		return nil, err
	}
	urns := make([]sourcecdk.URN, 0, len(repos))
	for _, repo := range repos {
		urn, err := repoURN(settings.owner, repo)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

// Read pages through the configured live GitHub event family.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	return s.ReadWithCheckpoint(ctx, cfg, cursor, nil)
}

// ReadWithCheckpoint uses durable checkpoint watermarks to avoid re-emitting
// unchanged descending GitHub inventory pages.
func (s *Source) ReadWithCheckpoint(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	client, settings, err := s.newClient(cfg, true)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if settings.family == familyAudit {
		return s.readAudit(ctx, client, settings, cursor, checkpoint)
	}
	if settings.family == familyDependabot {
		return s.readDependabotAlerts(ctx, client, settings, cursor, checkpoint)
	}
	if settings.family == familySecretScanning {
		return s.readSecretScanningAlerts(ctx, client, settings, cursor, checkpoint)
	}
	if settings.family == familyOrgInventory {
		return s.readOrgInventory(ctx, client, settings, checkpoint, sourcecdk.ConfigHash(cfg.Values()))
	}
	if settings.family == familyRepository {
		return s.readRepositories(ctx, client, settings, cursor, checkpoint, sourcecdk.ConfigHash(cfg.Values()))
	}
	return s.readPullRequests(ctx, client, settings, cursor, checkpoint)
}

func (s *Source) readPullRequests(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint) (sourcecdk.Pull, error) {
	readCheckpoint := sourcecdk.IncrementalCheckpointForCursor("github", familyPullRequest, cursor, checkpoint)
	page, err := sourcecdk.CursorPage(cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	pulls, resp, err := client.PullRequests.List(ctx, settings.owner, settings.repo, &gogithub.PullRequestListOptions{
		State:     settings.state,
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    page,
			PerPage: settings.perPage,
		},
	})
	if err != nil {
		return sourcecdk.Pull{}, githubapi.LookupError(fmt.Sprintf("github repo %s/%s", settings.owner, settings.repo), err)
	}
	nextCursor := ""
	if resp != nil && resp.NextPage > 0 {
		nextCursor = strconv.Itoa(resp.NextPage)
	}
	return sourcecdk.IncrementalPullFromRecords("github", familyPullRequest, pulls, nextCursor, readCheckpoint, func(pullRequest *gogithub.PullRequest) (*primitives.Event, error) {
		return pullRequestEvent(settings, pullRequest)
	})
}

func (s *Source) readRepositories(ctx context.Context, client *gogithub.Client, settings settings, cursor *cerebrov1.SourceCursor, checkpoint *cerebrov1.SourceCheckpoint, configHash string) (sourcecdk.Pull, error) {
	options := githubcanary.RepositoryReadOptions{Owner: settings.owner, Repo: settings.repo, PerPage: settings.perPage, ConfigHash: configHash, Cursor: cursor, Checkpoint: checkpoint, AllowProviderUnavailable: settings.hasAuth()}
	options.Build = func(repo *gogithub.Repository) (*primitives.Event, error) { return repositoryEvent(settings, repo) }
	return githubcanary.ReadRepositories(ctx, client, options)
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	return sourcecdk.LoadSpecFromFS(catalogFS, "catalog.yaml")
}

func repoURN(owner string, repo *gogithub.Repository) (sourcecdk.URN, error) {
	if repo == nil {
		return "", errors.New("repository is required")
	}
	fullName := strings.TrimSpace(repo.GetFullName())
	if fullName == "" {
		name := strings.TrimSpace(repo.GetName())
		if name == "" {
			return "", errors.New("repository name is required")
		}
		fullName = owner + "/" + name
	}
	return sourcecdk.ParseURN(fmt.Sprintf("urn:cerebro:%s:repo:%s", owner, fullName))
}

func pullRequestEvent(settings settings, pullRequest *gogithub.PullRequest) (*primitives.Event, error) {
	if pullRequest == nil {
		return nil, errors.New("pull request is required")
	}
	occurredAt := pullRequest.GetUpdatedAt().Time
	if occurredAt.IsZero() {
		occurredAt = pullRequest.GetCreatedAt().Time
	}
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github pull request %d missing timestamps", pullRequest.GetNumber())
	}
	createdAt := pullRequest.GetCreatedAt().Time
	if createdAt.IsZero() {
		createdAt = occurredAt
	}
	payloadBytes, err := json.Marshal(pullRequestPayload{
		Number:     pullRequest.GetNumber(),
		Repository: settings.owner + "/" + settings.repo,
		Title:      pullRequest.GetTitle(),
		State:      pullRequest.GetState(),
		URL:        pullRequest.GetHTMLURL(),
		Author:     userLogin(pullRequest.User),
		Draft:      pullRequest.GetDraft(),
		Head:       branchLabel(pullRequest.Head),
		Base:       branchLabel(pullRequest.Base),
		CreatedAt:  createdAt,
		UpdatedAt:  occurredAt,
		ClosedAt:   timestamp(pullRequest.ClosedAt),
		MergedAt:   timestamp(pullRequest.MergedAt),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal github pull request payload: %w", err)
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("github-pr-%s-%s-%d-%d", settings.owner, settings.repo, pullRequest.GetNumber(), occurredAt.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.pull_request",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "github/pull_request/v1",
		Payload:    payloadBytes,
		Attributes: map[string]string{
			"author":      userLogin(pullRequest.User),
			"base":        branchLabel(pullRequest.Base),
			"head":        branchLabel(pullRequest.Head),
			"html_url":    pullRequest.GetHTMLURL(),
			"owner":       settings.owner,
			"pull_number": strconv.Itoa(pullRequest.GetNumber()),
			"repo":        settings.repo,
			"repository":  settings.owner + "/" + settings.repo,
			"state":       pullRequest.GetState(),
		},
	}, nil
}

func repositoryEvent(settings settings, repo *gogithub.Repository) (*primitives.Event, error) {
	if repo == nil {
		return nil, errors.New("repository is required")
	}
	occurredAt := repo.GetUpdatedAt().Time
	if occurredAt.IsZero() {
		occurredAt = repo.GetPushedAt().Time
	}
	if occurredAt.IsZero() {
		occurredAt = repo.GetCreatedAt().Time
	}
	if occurredAt.IsZero() {
		return nil, errors.New("github repository missing timestamps")
	}
	createdAt := repo.GetCreatedAt().Time
	if createdAt.IsZero() {
		createdAt = occurredAt
	}
	ownerLogin := repositoryOwnerLogin(settings.owner, repo)
	fullName := repositoryFullName(settings.owner, repo)
	if fullName == "" {
		return nil, errors.New("repository full_name is required")
	}
	repoID := ""
	if repo.GetID() != 0 {
		repoID = strconv.FormatInt(repo.GetID(), 10)
	}
	secretScanning, pushProtection, dependabotUpdates := repoSecurityAnalysis(repo)
	payloadBytes, err := json.Marshal(repositoryPayload{
		ID:                               repo.GetID(),
		OwnerLogin:                       ownerLogin,
		Name:                             repo.GetName(),
		FullName:                         fullName,
		URL:                              repo.GetHTMLURL(),
		Visibility:                       repo.GetVisibility(),
		Private:                          repo.GetPrivate(),
		Archived:                         repo.GetArchived(),
		Fork:                             repo.GetFork(),
		DefaultBranch:                    repo.GetDefaultBranch(),
		CreatedAt:                        createdAt,
		UpdatedAt:                        occurredAt,
		PushedAt:                         timestamp(repo.PushedAt),
		SecretScanningEnabled:            secretScanning,
		SecretScanningPushProtection:     pushProtection,
		DependabotSecurityUpdatesEnabled: dependabotUpdates,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal github repository payload: %w", err)
	}
	resourceID := firstNonEmptyString(repoID, fullName)
	attrs := map[string]string{
		"archived":       strconv.FormatBool(repo.GetArchived()),
		"default_branch": repo.GetDefaultBranch(),
		"fork":           strconv.FormatBool(repo.GetFork()),
		"full_name":      fullName,
		"html_url":       repo.GetHTMLURL(),
		"name":           repo.GetName(),
		"owner":          settings.owner,
		"owner_login":    ownerLogin,
		"private":        strconv.FormatBool(repo.GetPrivate()),
		"repo":           repo.GetName(),
		"repo_id":        repoID,
		"repository":     fullName,
		"resource_id":    resourceID,
		"resource_name":  fullName,
		"resource_type":  "code_repository",
		"visibility":     repo.GetVisibility(),
	}
	if secretScanning != "" {
		attrs["secret_scanning"] = secretScanning
	}
	if pushProtection != "" {
		attrs["secret_scanning_push_protection"] = pushProtection
	}
	if dependabotUpdates != "" {
		attrs["dependabot_security_updates"] = dependabotUpdates
	}
	return &primitives.Event{
		Id:         fmt.Sprintf("github-code-repository-%s-%d", normalizeRepositoryEventID(resourceID), occurredAt.Unix()),
		TenantId:   settings.owner,
		SourceId:   "github",
		Kind:       "github.code.repository",
		OccurredAt: timestamppb.New(occurredAt.UTC()),
		SchemaRef:  "github/code_repository/v1",
		Payload:    payloadBytes,
		Attributes: attrs,
	}, nil
}

func repoSecurityAnalysis(repo *gogithub.Repository) (secretScanning, pushProtection, dependabotUpdates string) {
	if repo == nil {
		return "", "", ""
	}
	sa := repo.GetSecurityAndAnalysis()
	if sa == nil {
		return "", "", ""
	}
	if ss := sa.GetSecretScanning(); ss != nil {
		secretScanning = ss.GetStatus()
	}
	if pp := sa.GetSecretScanningPushProtection(); pp != nil {
		pushProtection = pp.GetStatus()
	}
	if du := sa.GetDependabotSecurityUpdates(); du != nil {
		dependabotUpdates = du.GetStatus()
	}
	return secretScanning, pushProtection, dependabotUpdates
}

func repositoryOwnerLogin(fallback string, repo *gogithub.Repository) string {
	if repo == nil {
		return strings.TrimSpace(fallback)
	}
	if owner := strings.TrimSpace(repo.GetOwner().GetLogin()); owner != "" {
		return owner
	}
	if fullName := strings.TrimSpace(repo.GetFullName()); fullName != "" {
		if owner, _, ok := strings.Cut(fullName, "/"); ok {
			return strings.TrimSpace(owner)
		}
	}
	return strings.TrimSpace(fallback)
}

func repositoryFullName(owner string, repo *gogithub.Repository) string {
	if repo == nil {
		return ""
	}
	if fullName := strings.TrimSpace(repo.GetFullName()); fullName != "" {
		return fullName
	}
	name := strings.TrimSpace(repo.GetName())
	if name == "" {
		return ""
	}
	return strings.TrimSpace(owner) + "/" + name
}

func normalizeRepositoryEventID(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "/", "-")
	value = strings.ReplaceAll(value, ":", "-")
	if value == "" {
		return "unknown"
	}
	return value
}

func branchLabel(branch *gogithub.PullRequestBranch) string {
	if branch == nil {
		return ""
	}
	return branch.GetLabel()
}

func userLogin(user *gogithub.User) string {
	if user == nil {
		return ""
	}
	return user.GetLogin()
}

func timestamp(value *gogithub.Timestamp) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

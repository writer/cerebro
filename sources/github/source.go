package github

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gogithub "github.com/google/go-github/v66/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
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
	defaultAuditOrder   = "desc"
	familyAudit         = "audit"
	familyDependabot    = "dependabot_alert"
	familyPullRequest   = "pull_request"
)

// Source is the live GitHub source preview used by the builtin registry.
type Source struct {
	spec                 *cerebrov1.SourceSpec
	client               *http.Client
	allowLoopbackBaseURL bool
}

type settings struct {
	family       string
	owner        string
	repo         string
	token        string
	baseURL      string
	state        string
	auditInclude string
	auditPhrase  string
	auditOrder   string
	perPage      int
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

// New constructs the live GitHub source.
func New() (*Source, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, err
	}
	return &Source{spec: spec}, nil
}

// Spec returns static metadata for the GitHub source.
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
	client, settings, err := s.newClient(cfg, true)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	if settings.family == familyAudit {
		return s.readAudit(ctx, client, settings, cursor)
	}
	if settings.family == familyDependabot {
		return s.readDependabotAlerts(ctx, client, settings, cursor)
	}
	page, err := readPage(cursor)
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
		return sourcecdk.Pull{}, wrapLookupError(fmt.Sprintf("github repo %s/%s", settings.owner, settings.repo), err)
	}
	if len(pulls) == 0 {
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(pulls))
	for _, pullRequest := range pulls {
		event, err := pullRequestEvent(settings, pullRequest)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	nextPage := page + 1
	pull := sourcecdk.Pull{
		Events: events,
		Checkpoint: &cerebrov1.SourceCheckpoint{
			Watermark:    events[len(events)-1].OccurredAt,
			CursorOpaque: strconv.Itoa(nextPage),
		},
	}
	if resp != nil && resp.NextPage > 0 {
		nextPage = resp.NextPage
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: strconv.Itoa(resp.NextPage)}
		pull.Checkpoint.CursorOpaque = strconv.Itoa(nextPage)
	}
	return pull, nil
}

func loadSpec() (*cerebrov1.SourceSpec, error) {
	specBytes, err := catalogFS.ReadFile("catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	spec, err := sourcecdk.LoadCatalog(specBytes)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}
	return spec, nil
}

func (s *Source) newClient(cfg sourcecdk.Config, requireRepo bool) (*gogithub.Client, settings, error) {
	settings, err := parseSettings(cfg, requireRepo, s != nil && s.allowLoopbackBaseURL)
	if err != nil {
		return nil, settings, err
	}
	httpClient := (*http.Client)(nil)
	if s != nil {
		httpClient = s.client
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: sourceHTTPTimeout}
	}
	client := gogithub.NewClient(httpClient)
	if settings.token != "" {
		client = client.WithAuthToken(settings.token)
	}
	if settings.baseURL != "" {
		enterpriseClient, err := client.WithEnterpriseURLs(settings.baseURL, settings.baseURL)
		if err != nil {
			return nil, settings, fmt.Errorf("parse github base_url: %w", err)
		}
		client = enterpriseClient
	}
	return client, settings, nil
}

func parseSettings(cfg sourcecdk.Config, requireRepo bool, allowLoopbackBaseURL bool) (settings, error) {
	settings := settings{
		family:       configValue(cfg, "family"),
		owner:        configValue(cfg, "owner"),
		repo:         configValue(cfg, "repo"),
		token:        configValue(cfg, "token"),
		baseURL:      configValue(cfg, "base_url"),
		state:        configValue(cfg, "state"),
		auditInclude: configValue(cfg, "include"),
		auditPhrase:  configValue(cfg, "phrase"),
		auditOrder:   configValue(cfg, "order"),
		perPage:      defaultPageSize,
	}
	if settings.baseURL != "" {
		baseURL, err := normalizeBaseURL(settings.baseURL, allowLoopbackBaseURL)
		if err != nil {
			return settings, err
		}
		settings.baseURL = baseURL
	}
	if settings.owner == "" {
		return settings, fmt.Errorf("github owner is required")
	}
	if settings.family == "" {
		settings.family = defaultFamily
	}
	switch settings.family {
	case familyAudit, familyDependabot, familyPullRequest:
	default:
		return settings, fmt.Errorf("github family must be one of %s, %s, or %s", familyPullRequest, familyAudit, familyDependabot)
	}
	if rawPerPage, ok := cfg.Lookup("per_page"); ok && strings.TrimSpace(rawPerPage) != "" {
		perPage, err := strconv.Atoi(strings.TrimSpace(rawPerPage))
		if err != nil {
			return settings, fmt.Errorf("parse github per_page: %w", err)
		}
		if perPage < 1 || perPage > maxPageSize {
			return settings, fmt.Errorf("github per_page must be between 1 and %d", maxPageSize)
		}
		settings.perPage = perPage
	}
	switch settings.family {
	case familyPullRequest:
		if requireRepo && settings.repo == "" {
			return settings, fmt.Errorf("github repo is required")
		}
		if settings.state == "" {
			settings.state = defaultState
		}
		switch settings.state {
		case "all", "closed", "open":
		default:
			return settings, fmt.Errorf("github state must be one of open, closed, or all")
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyDependabot:
		if settings.token == "" {
			return settings, fmt.Errorf("github token is required when family=%q", familyDependabot)
		}
		if settings.repo == "" {
			return settings, fmt.Errorf("github repo is required when family=%q", familyDependabot)
		}
		if settings.state == "" {
			settings.state = defaultState
		}
		switch settings.state {
		case "auto_dismissed", "dismissed", "fixed", "open":
		default:
			return settings, fmt.Errorf("github state must be one of auto_dismissed, dismissed, fixed, or open when family=%q", familyDependabot)
		}
		if settings.auditInclude != "" || settings.auditOrder != "" || settings.auditPhrase != "" {
			return settings, fmt.Errorf("github include, order, and phrase are only supported when family=%q", familyAudit)
		}
	case familyAudit:
		if settings.token == "" {
			return settings, fmt.Errorf("github token is required when family=%q", familyAudit)
		}
		if settings.repo != "" {
			return settings, fmt.Errorf("github repo is not supported when family=%q", familyAudit)
		}
		if settings.state != "" {
			return settings, fmt.Errorf("github state is only supported when family=%q", familyPullRequest)
		}
		if settings.auditInclude == "" {
			settings.auditInclude = defaultAuditInclude
		}
		switch settings.auditInclude {
		case "all", "git", "web":
		default:
			return settings, fmt.Errorf("github include must be one of all, git, or web")
		}
		if settings.auditOrder == "" {
			settings.auditOrder = defaultAuditOrder
		}
		switch settings.auditOrder {
		case "asc", "desc":
		default:
			return settings, fmt.Errorf("github order must be one of asc or desc")
		}
	}
	return settings, nil
}

func normalizeBaseURL(raw string, allowLoopback bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse github base_url: %w", err)
	}
	allowInsecureLoopback := allowLoopback && parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())
	if parsed.Scheme != "https" && !allowInsecureLoopback {
		return "", fmt.Errorf("github base_url must use https")
	}
	if strings.TrimSpace(parsed.Hostname()) == "" {
		return "", fmt.Errorf("github base_url must include a host")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("github base_url must not include user info, query, or fragment")
	}
	path := strings.TrimRight(parsed.EscapedPath(), "/")
	if (path != "" && path != "/api/v3") || parsed.RawPath != "" {
		return "", fmt.Errorf("github base_url must be an origin URL")
	}
	if !allowLoopback && isLoopbackHost(parsed.Hostname()) {
		return "", fmt.Errorf("github base_url must not target loopback hosts")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	value := strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
	value = strings.Trim(value, "[]")
	if value == "" || value == "localhost" || strings.HasSuffix(value, ".localhost") {
		return true
	}
	if address, _, ok := strings.Cut(value, "%"); ok {
		value = address
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func getRepo(ctx context.Context, client *gogithub.Client, owner string, repo string) (*gogithub.Repository, error) {
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, wrapLookupError(fmt.Sprintf("github repo %s/%s", owner, repo), err)
	}
	return repository, nil
}

func listRepos(ctx context.Context, client *gogithub.Client, owner string, perPage int) ([]*gogithub.Repository, error) {
	repos, _, err := client.Repositories.ListByOrg(ctx, owner, &gogithub.RepositoryListByOrgOptions{
		Type:      "all",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    1,
			PerPage: perPage,
		},
	})
	if err == nil {
		return repos, nil
	}
	if !isNotFound(err) {
		return nil, fmt.Errorf("list github org repos for %s: %w", owner, err)
	}
	repos, _, err = client.Repositories.ListByUser(ctx, owner, &gogithub.RepositoryListByUserOptions{
		Type:      "owner",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    1,
			PerPage: perPage,
		},
	})
	if err != nil {
		return nil, wrapLookupError(fmt.Sprintf("github owner %s", owner), err)
	}
	return repos, nil
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

func readPage(cursor *cerebrov1.SourceCursor) (int, error) {
	if cursor == nil || strings.TrimSpace(cursor.Opaque) == "" {
		return 1, nil
	}
	page, err := strconv.Atoi(strings.TrimSpace(cursor.Opaque))
	if err != nil {
		return 0, fmt.Errorf("parse cursor: %w", err)
	}
	if page < 1 {
		return 0, fmt.Errorf("cursor page must be greater than zero")
	}
	return page, nil
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

func configValue(cfg sourcecdk.Config, key string) string {
	value, _ := cfg.Lookup(key)
	return strings.TrimSpace(value)
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

func isNotFound(err error) bool {
	var apiErr *gogithub.ErrorResponse
	return errors.As(err, &apiErr) && apiErr.Response != nil && apiErr.Response.StatusCode == 404
}

func wrapLookupError(subject string, err error) error {
	if isNotFound(err) {
		return fmt.Errorf("%s not found", subject)
	}
	return fmt.Errorf("%s: %w", subject, err)
}

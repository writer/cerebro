package github

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	defaultPageSize = 10
	maxPageSize     = 100
	defaultState    = "open"
	defaultTimeout  = 15 * time.Second
)

// Source is the live GitHub source preview used by the builtin registry.
type Source struct {
	spec *cerebrov1.SourceSpec
}

type settings struct {
	owner   string
	repo    string
	token   string
	baseURL string
	state   string
	perPage int
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
	client, settings, err := newClient(cfg, false)
	if err != nil {
		return err
	}
	if settings.repo != "" {
		_, err := getRepo(ctx, client, settings.owner, settings.repo)
		return err
	}
	_, err = listRepos(ctx, client, settings.owner, settings.perPage)
	return err
}

// Discover returns live GitHub repository URNs.
func (s *Source) Discover(ctx context.Context, cfg sourcecdk.Config) ([]sourcecdk.URN, error) {
	client, settings, err := newClient(cfg, false)
	if err != nil {
		return nil, err
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

// Read pages through live GitHub pull requests for a configured repository.
func (s *Source) Read(ctx context.Context, cfg sourcecdk.Config, cursor *cerebrov1.SourceCursor) (sourcecdk.Pull, error) {
	client, settings, err := newClient(cfg, true)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	page, err := readPage(cursor)
	if err != nil {
		return sourcecdk.Pull{}, err
	}
	pulls, resp, err := client.PullRequests.List(ctx, settings.owner, settings.repo, &gogithub.PullRequestListOptions{
		State:     settings.state,
		Sort:      "created",
		Direction: "asc",
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

func newClient(cfg sourcecdk.Config, requireRepo bool) (*gogithub.Client, settings, error) {
	settings, err := parseSettings(cfg, requireRepo)
	if err != nil {
		return nil, settings, err
	}
	client := gogithub.NewClient(&http.Client{Timeout: defaultTimeout})
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

func parseSettings(cfg sourcecdk.Config, requireRepo bool) (settings, error) {
	settings := settings{
		owner:   configValue(cfg, "owner"),
		repo:    configValue(cfg, "repo"),
		token:   configValue(cfg, "token"),
		baseURL: configValue(cfg, "base_url"),
		state:   configValue(cfg, "state"),
		perPage: defaultPageSize,
	}
	if settings.owner == "" {
		return settings, fmt.Errorf("github owner is required")
	}
	if requireRepo && settings.repo == "" {
		return settings, fmt.Errorf("github repo is required")
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
	if settings.state == "" {
		settings.state = defaultState
	}
	switch settings.state {
	case "all", "closed", "open":
	default:
		return settings, fmt.Errorf("github state must be one of open, closed, or all")
	}
	return settings, nil
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
	occurredAt := pullRequest.GetCreatedAt().Time
	if occurredAt.IsZero() {
		occurredAt = pullRequest.GetUpdatedAt().Time
	}
	if occurredAt.IsZero() {
		return nil, fmt.Errorf("github pull request %d missing timestamps", pullRequest.GetNumber())
	}
	createdAt := pullRequest.GetCreatedAt().Time
	if createdAt.IsZero() {
		createdAt = occurredAt
	}
	updatedAt := pullRequest.GetUpdatedAt().Time
	if updatedAt.IsZero() {
		updatedAt = occurredAt
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
		UpdatedAt:  updatedAt,
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

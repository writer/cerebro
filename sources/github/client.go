package github

import (
	"context"
	"fmt"
	"net"
	"net/http"

	gogithub "github.com/google/go-github/v66/github"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcehttp"
	"github.com/writer/cerebro/sources/internal/githubapi"
)

func (s *Source) newClient(cfg sourcecdk.Config, requireRepo bool) (*gogithub.Client, settings, error) {
	allowLoopbackBaseURL := s != nil && s.allowLoopbackBaseURL
	lookupIPAddrs := net.DefaultResolver.LookupIPAddr
	if s != nil && s.lookupIPAddrs != nil {
		lookupIPAddrs = s.lookupIPAddrs
	}
	settings, err := parseSettings(cfg, requireRepo, allowLoopbackBaseURL)
	if err != nil {
		return nil, settings, err
	}
	httpClient := (*http.Client)(nil)
	if s != nil {
		httpClient = s.client
	}
	httpClient = sourceHTTPClientNoRedirect(httpClient, allowLoopbackBaseURL, lookupIPAddrs)
	if settings.usesGitHubAppAuth() {
		httpClient, err = sourcehttp.WithGitHubAppAuth(httpClient, settings.githubAppAuthConfig())
		if err != nil {
			return nil, settings, fmt.Errorf("%w: %w", sourcecdk.ErrInvalidConfig, err)
		}
	}
	client := gogithub.NewClient(httpClient)
	if settings.token != "" && !settings.usesGitHubAppAuth() {
		client = client.WithAuthToken(settings.token)
	}
	if settings.baseURL != "" {
		enterpriseClient, err := client.WithEnterpriseURLs(settings.baseURL, settings.baseURL)
		if err != nil {
			return nil, settings, fmt.Errorf("%w: parse github base_url: %w", sourcecdk.ErrInvalidConfig, err)
		}
		client = enterpriseClient
	}
	return client, settings, nil
}

func sourceHTTPClientNoRedirect(client *http.Client, allowLoopback bool, lookupIPAddrs func(context.Context, string) ([]net.IPAddr, error)) *http.Client {
	return sourcehttp.HardenSourceClient(client, "github", sourceHTTPTimeout, allowLoopback, lookupIPAddrs)
}

func getRepo(ctx context.Context, client *gogithub.Client, owner string, repo string) (*gogithub.Repository, error) {
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, githubapi.LookupError(fmt.Sprintf("github repo %s/%s", owner, repo), err)
	}
	return repository, nil
}

func listRepos(ctx context.Context, client *gogithub.Client, owner string, perPage int) ([]*gogithub.Repository, error) {
	repos, _, err := listReposPage(ctx, client, owner, 1, perPage)
	return repos, err
}

func listReposPage(ctx context.Context, client *gogithub.Client, owner string, page int, perPage int) ([]*gogithub.Repository, *gogithub.Response, error) {
	repos, resp, err := client.Repositories.ListByOrg(ctx, owner, &gogithub.RepositoryListByOrgOptions{
		Type:      "all",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	})
	if err == nil {
		return repos, resp, nil
	}
	if !githubapi.NotFound(err) {
		return nil, nil, fmt.Errorf("list github org repos for %s: %w", owner, err)
	}
	repos, resp, err = client.Repositories.ListByUser(ctx, owner, &gogithub.RepositoryListByUserOptions{
		Type:      "owner",
		Sort:      "updated",
		Direction: "desc",
		ListOptions: gogithub.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	})
	if err != nil {
		return nil, nil, githubapi.LookupError(fmt.Sprintf("github owner %s", owner), err)
	}
	return repos, resp, nil
}

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type DockerHubClient struct {
	namespaces      []string
	apiBaseURL      string
	registryBaseURL string
	authBaseURL     string
	client          *http.Client
}

func NewDockerHubClient(namespaces ...string) *DockerHubClient {
	return &DockerHubClient{
		namespaces:      normalizeDockerHubNamespaces(namespaces),
		apiBaseURL:      "https://hub.docker.com",
		registryBaseURL: "https://registry-1.docker.io",
		authBaseURL:     "https://auth.docker.io/token",
		client:          &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *DockerHubClient) Name() string { return "dockerhub" }

func (c *DockerHubClient) RegistryHost() string { return "docker.io" }

func (c *DockerHubClient) QualifyImageRef(repo, tag string) string {
	return fmt.Sprintf("%s/%s:%s", c.RegistryHost(), normalizeDockerHubRepository(repo), strings.TrimSpace(tag))
}

func (c *DockerHubClient) ListRepositories(ctx context.Context) ([]Repository, error) {
	repos := make([]Repository, 0)
	for _, namespace := range c.namespaces {
		path := fmt.Sprintf("%s/v2/namespaces/%s/repositories", strings.TrimRight(c.apiBaseURL, "/"), namespace)
		for path != "" {
			body, next, err := c.doJSONRequest(ctx, path)
			if err != nil {
				return nil, err
			}
			var payload struct {
				Results []struct {
					Name string `json:"name"`
				} `json:"results"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}
			for _, repo := range payload.Results {
				name := strings.TrimSpace(repo.Name)
				if name == "" {
					continue
				}
				repos = append(repos, Repository{
					Name:     namespace + "/" + name,
					Registry: "dockerhub",
					URI:      "docker.io/" + namespace + "/" + name,
				})
			}
			path = next
		}
	}
	return repos, nil
}

func (c *DockerHubClient) ListTags(ctx context.Context, repo string) ([]ImageTag, error) {
	namespace, name := splitDockerHubRepository(repo)
	path := fmt.Sprintf("%s/v2/namespaces/%s/repositories/%s/tags", strings.TrimRight(c.apiBaseURL, "/"), namespace, name)
	tags := make([]ImageTag, 0)
	for path != "" {
		body, next, err := c.doJSONRequest(ctx, path)
		if err != nil {
			return nil, err
		}
		var payload struct {
			Results []struct {
				Name        string `json:"name"`
				LastUpdated string `json:"last_updated"`
				FullSize    int64  `json:"full_size"`
				Images      []struct {
					Digest string `json:"digest"`
				} `json:"images"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, err
		}
		for _, tag := range payload.Results {
			imageTag := ImageTag{
				Name:      strings.TrimSpace(tag.Name),
				SizeBytes: tag.FullSize,
			}
			if len(tag.Images) > 0 {
				imageTag.Digest = strings.TrimSpace(tag.Images[0].Digest)
			}
			if strings.TrimSpace(tag.LastUpdated) != "" {
				if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(tag.LastUpdated)); err == nil {
					imageTag.PushedAt = ts.UTC()
				}
			}
			tags = append(tags, imageTag)
		}
		path = next
	}
	return tags, nil
}

func (c *DockerHubClient) GetManifest(ctx context.Context, repo, tag string) (*ImageManifest, error) {
	repository := normalizeDockerHubRepository(repo)
	return resolveRegistryManifest(ctx, tag, func(ctx context.Context, reference string) ([]byte, http.Header, error) {
		return c.doRegistryRequest(ctx, repository, reference)
	}, func(ctx context.Context, digest string) ([]byte, error) {
		return downloadBlobBytes(ctx, c, repository, digest)
	})
}

func (c *DockerHubClient) DownloadBlob(ctx context.Context, repo, digest string) (io.ReadCloser, error) {
	repository := normalizeDockerHubRepository(repo)
	token, err := c.fetchToken(ctx, repository)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimRight(c.registryBaseURL, "/"), repository, strings.TrimSpace(digest)), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, sanitizeTransportError(err)
	}
	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry API error %d: %s", resp.StatusCode, string(body))
	}
	return resp.Body, nil
}

func (c *DockerHubClient) GetVulnerabilities(context.Context, string, string) ([]ImageVulnerability, error) {
	return nil, fmt.Errorf("registry does not provide vulnerability scanning")
}

func (c *DockerHubClient) SetAPIBaseURL(raw string) {
	if strings.TrimSpace(raw) != "" {
		c.apiBaseURL = strings.TrimRight(strings.TrimSpace(raw), "/")
	}
}

func (c *DockerHubClient) SetRegistryBaseURL(raw string) {
	if strings.TrimSpace(raw) != "" {
		c.registryBaseURL = strings.TrimRight(strings.TrimSpace(raw), "/")
	}
}

func (c *DockerHubClient) SetAuthBaseURL(raw string) {
	if strings.TrimSpace(raw) != "" {
		c.authBaseURL = strings.TrimRight(strings.TrimSpace(raw), "/")
	}
}

func (c *DockerHubClient) doJSONRequest(ctx context.Context, path string) ([]byte, string, error) {
	reqURL := path
	if !strings.Contains(reqURL, "?") {
		reqURL += "?page_size=100"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", sanitizeTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("docker hub API error %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Next string `json:"next"`
	}
	_ = json.Unmarshal(body, &payload)
	return body, strings.TrimSpace(payload.Next), nil
}

func (c *DockerHubClient) doRegistryRequest(ctx context.Context, repository, reference string) ([]byte, http.Header, error) {
	token, err := c.fetchToken(ctx, repository)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimRight(c.registryBaseURL, "/"), repository, strings.TrimSpace(reference)), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", manifestAcceptHeader())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, sanitizeTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, resp.Header, fmt.Errorf("registry API error %d: %s", resp.StatusCode, string(body))
	}
	return body, resp.Header, nil
}

func (c *DockerHubClient) fetchToken(ctx context.Context, repository string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?service=registry.docker.io&scope=repository:%s:pull", c.authBaseURL, repository), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", sanitizeTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("docker hub auth error %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	token := firstNonEmptyString(payload.Token, payload.AccessToken)
	if token == "" {
		return "", fmt.Errorf("docker hub auth response missing token")
	}
	return token, nil
}

func normalizeDockerHubNamespaces(values []string) []string {
	return normalizeStringList(lowerStringList(values))
}

func normalizeDockerHubRepository(repo string) string {
	repo = strings.ToLower(strings.TrimSpace(repo))
	if repo == "" {
		return ""
	}
	if !strings.Contains(repo, "/") {
		return "library/" + repo
	}
	return repo
}

func splitDockerHubRepository(repo string) (string, string) {
	repo = normalizeDockerHubRepository(repo)
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return "library", repo
	}
	return parts[0], parts[1]
}

func lowerStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

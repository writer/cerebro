package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"google.golang.org/protobuf/proto"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const githubSourceID = "github"

type githubLocalCLI interface {
	AuthToken(context.Context) (string, error)
	Repo(context.Context) (githubLocalRepo, error)
}

type execGitHubLocalCLI struct{}

type githubLocalRepo struct {
	Name  string               `json:"name"`
	Owner githubLocalRepoOwner `json:"owner"`
}

type githubLocalRepoOwner struct {
	Login string `json:"login"`
}

func (execGitHubLocalCLI) AuthToken(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {
		return "", fmt.Errorf("resolve github token from gh cli: %w", err)
	}
	token := strings.TrimSpace(string(output))
	if token == "" {
		return "", fmt.Errorf("resolve github token from gh cli: empty token")
	}
	return token, nil
}

func (execGitHubLocalCLI) Repo(ctx context.Context) (githubLocalRepo, error) {
	output, err := exec.CommandContext(ctx, "gh", "repo", "view", "--json", "owner,name").Output()
	if err != nil {
		return githubLocalRepo{}, fmt.Errorf("resolve github repo from gh cli: %w", err)
	}
	var repo githubLocalRepo
	if err := json.Unmarshal(output, &repo); err != nil {
		return githubLocalRepo{}, fmt.Errorf("decode github repo from gh cli: %w", err)
	}
	if strings.TrimSpace(repo.Owner.Login) == "" {
		return githubLocalRepo{}, fmt.Errorf("resolve github repo from gh cli: owner is required")
	}
	if strings.TrimSpace(repo.Name) == "" {
		return githubLocalRepo{}, fmt.Errorf("resolve github repo from gh cli: repo is required")
	}
	return repo, nil
}

func prepareSourceConfig(ctx context.Context, sourceID string, command string, config map[string]string) (map[string]string, error) {
	return prepareSourceConfigWithCLI(ctx, sourceID, command, config, execGitHubLocalCLI{})
}

func prepareSourceRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime) (*cerebrov1.SourceRuntime, error) {
	return prepareSourceRuntimeWithCLI(ctx, runtime, execGitHubLocalCLI{})
}

func prepareSourceConfigWithCLI(ctx context.Context, sourceID string, command string, config map[string]string, cli githubLocalCLI) (map[string]string, error) {
	cloned := cloneConfig(config)
	if strings.TrimSpace(sourceID) != githubSourceID {
		return cloned, nil
	}
	if cli == nil {
		return cloned, fmt.Errorf("github local cli is required")
	}
	return hydrateGitHubLocalConfig(
		ctx,
		cloned,
		cli,
		githubReadRequiresRepo(command, cloned),
		githubRequiresToken(cloned),
	)
}

func prepareSourceRuntimeWithCLI(ctx context.Context, runtime *cerebrov1.SourceRuntime, cli githubLocalCLI) (*cerebrov1.SourceRuntime, error) {
	if runtime == nil {
		return nil, nil
	}
	cloned := proto.Clone(runtime).(*cerebrov1.SourceRuntime)
	if strings.TrimSpace(cloned.GetSourceId()) != githubSourceID {
		return cloned, nil
	}
	if cli == nil {
		return nil, fmt.Errorf("github local cli is required")
	}
	// gh CLI auth tokens must never land in a persisted SourceRuntime config: they would be
	// written into the state store, possibly checkpointed, and shared across processes that have a
	// different (or no) gh session. Hydrate only the owner/repo identity here and let the token
	// flow per-call through prepareSourceConfigWithCLI for live read/discover/check requests.
	originalConfig := cloned.GetConfig()
	config, err := hydrateGitHubLocalConfig(
		ctx,
		originalConfig,
		cli,
		githubRuntimeRequiresRepo(originalConfig),
		false,
	)
	if err != nil {
		return nil, err
	}
	// Preserve a caller-supplied token (an explicit, persisted PAT) but never persist a token we
	// just hydrated from the local gh CLI session.
	if _, ok := originalConfig["token"]; !ok {
		delete(config, "token")
	}
	cloned.Config = config
	return cloned, nil
}

func hydrateGitHubLocalConfig(ctx context.Context, config map[string]string, cli githubLocalCLI, requireRepo bool, requireToken bool) (map[string]string, error) {
	config = cloneConfig(config)
	needsRepo := strings.TrimSpace(config["owner"]) == "" || (requireRepo && strings.TrimSpace(config["repo"]) == "")
	if needsRepo {
		repo, err := cli.Repo(ctx)
		if err != nil {
			return nil, err
		}
		ghOwner := strings.TrimSpace(repo.Owner.Login)
		ghRepo := strings.TrimSpace(repo.Name)
		if ghOwner == "" || ghRepo == "" {
			return nil, fmt.Errorf("resolve github repo from gh cli: owner and repo are required")
		}
		if existing := strings.TrimSpace(config["owner"]); existing != "" && existing != ghOwner {
			return nil, fmt.Errorf("resolve github repo from gh cli: owner mismatch (config=%q gh=%q)", existing, ghOwner)
		}
		if existing := strings.TrimSpace(config["repo"]); existing != "" && existing != ghRepo {
			return nil, fmt.Errorf("resolve github repo from gh cli: repo mismatch (config=%q gh=%q)", existing, ghRepo)
		}
		if strings.TrimSpace(config["owner"]) == "" {
			config["owner"] = ghOwner
		}
		if requireRepo && strings.TrimSpace(config["repo"]) == "" {
			config["repo"] = ghRepo
		}
	}
	if strings.TrimSpace(config["token"]) == "" && (requireToken || needsRepo) {
		token, err := cli.AuthToken(ctx)
		if err != nil {
			return nil, err
		}
		config["token"] = token
	}
	return config, nil
}

func githubReadRequiresRepo(command string, config map[string]string) bool {
	if strings.TrimSpace(command) != "read" {
		return false
	}
	return githubRuntimeRequiresRepo(config)
}

func githubRuntimeRequiresRepo(config map[string]string) bool {
	return strings.TrimSpace(config["family"]) != "audit"
}

func githubRequiresToken(config map[string]string) bool {
	return strings.TrimSpace(config["family"]) == "audit"
}

func cloneConfig(config map[string]string) map[string]string {
	cloned := make(map[string]string, len(config))
	for key, value := range config {
		cloned[key] = value
	}
	return cloned
}

package main

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type fakeGitHubLocalCLI struct {
	token          string
	tokenErr       error
	repo           githubLocalRepo
	repoErr        error
	authTokenCalls int
	repoCalls      int
}

func (f *fakeGitHubLocalCLI) AuthToken(context.Context) (string, error) {
	f.authTokenCalls++
	if f.tokenErr != nil {
		return "", f.tokenErr
	}
	return f.token, nil
}

func (f *fakeGitHubLocalCLI) Repo(context.Context) (githubLocalRepo, error) {
	f.repoCalls++
	if f.repoErr != nil {
		return githubLocalRepo{}, f.repoErr
	}
	return f.repo, nil
}

func TestPrepareSourceConfigWithCLIHydratesGitHubRead(t *testing.T) {
	cli := &fakeGitHubLocalCLI{
		token: "gh-token",
		repo: githubLocalRepo{
			Name: "cerebro",
			Owner: githubLocalRepoOwner{
				Login: "writer",
			},
		},
	}

	config, err := prepareSourceConfigWithCLI(context.Background(), githubSourceID, "read", map[string]string{"state": "all"}, cli)
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}
	if got := config["token"]; got != "gh-token" {
		t.Fatalf("config[token] = %q, want %q", got, "gh-token")
	}
	if got := config["owner"]; got != "writer" {
		t.Fatalf("config[owner] = %q, want %q", got, "writer")
	}
	if got := config["repo"]; got != "cerebro" {
		t.Fatalf("config[repo] = %q, want %q", got, "cerebro")
	}
	if cli.authTokenCalls != 1 {
		t.Fatalf("authTokenCalls = %d, want 1", cli.authTokenCalls)
	}
	if cli.repoCalls != 1 {
		t.Fatalf("repoCalls = %d, want 1", cli.repoCalls)
	}
}

func TestPrepareSourceConfigWithCLIPreservesExplicitValues(t *testing.T) {
	cli := &fakeGitHubLocalCLI{}

	config, err := prepareSourceConfigWithCLI(context.Background(), githubSourceID, "read", map[string]string{
		"owner": "writer",
		"repo":  "cerebro",
	}, cli)
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}
	if _, ok := config["token"]; ok {
		t.Fatalf("config[token] = %q, want omitted", config["token"])
	}
	if cli.authTokenCalls != 0 {
		t.Fatalf("authTokenCalls = %d, want 0", cli.authTokenCalls)
	}
	if cli.repoCalls != 0 {
		t.Fatalf("repoCalls = %d, want 0", cli.repoCalls)
	}
}

func TestPrepareSourceConfigWithCLIAuditHydratesOwnerAndToken(t *testing.T) {
	cli := &fakeGitHubLocalCLI{
		token: "gh-token",
		repo: githubLocalRepo{
			Name: "cerebro",
			Owner: githubLocalRepoOwner{
				Login: "writer",
			},
		},
	}

	config, err := prepareSourceConfigWithCLI(context.Background(), githubSourceID, "read", map[string]string{
		"family": "audit",
	}, cli)
	if err != nil {
		t.Fatalf("prepareSourceConfigWithCLI() error = %v", err)
	}
	if got := config["owner"]; got != "writer" {
		t.Fatalf("config[owner] = %q, want %q", got, "writer")
	}
	if got := config["token"]; got != "gh-token" {
		t.Fatalf("config[token] = %q, want %q", got, "gh-token")
	}
	if _, ok := config["repo"]; ok {
		t.Fatalf("config[repo] = %q, want omitted", config["repo"])
	}
}

func TestPrepareSourceRuntimeWithCLIHydratesGitHubRuntime(t *testing.T) {
	cli := &fakeGitHubLocalCLI{
		token: "gh-token",
		repo: githubLocalRepo{
			Name: "cerebro",
			Owner: githubLocalRepoOwner{
				Login: "writer",
			},
		},
	}

	runtime, err := prepareSourceRuntimeWithCLI(context.Background(), &cerebrov1.SourceRuntime{
		Id:       "writer-github",
		SourceId: githubSourceID,
		Config:   map[string]string{"state": "all"},
	}, cli)
	if err != nil {
		t.Fatalf("prepareSourceRuntimeWithCLI() error = %v", err)
	}
	if got := runtime.GetConfig()["owner"]; got != "writer" {
		t.Fatalf("runtime.Config[owner] = %q, want %q", got, "writer")
	}
	if got := runtime.GetConfig()["repo"]; got != "cerebro" {
		t.Fatalf("runtime.Config[repo] = %q, want %q", got, "cerebro")
	}
	if got := runtime.GetConfig()["token"]; got != "gh-token" {
		t.Fatalf("runtime.Config[token] = %q, want %q", got, "gh-token")
	}
}

func TestPrepareSourceConfigWithCLIReturnsGHError(t *testing.T) {
	cli := &fakeGitHubLocalCLI{
		tokenErr: errors.New("gh unavailable"),
	}

	_, err := prepareSourceConfigWithCLI(context.Background(), githubSourceID, "read", map[string]string{"state": "all"}, cli)
	if err == nil {
		t.Fatal("prepareSourceConfigWithCLI() error = nil, want non-nil")
	}
}

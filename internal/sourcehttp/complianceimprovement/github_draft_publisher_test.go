package complianceimprovementhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	improvement "github.com/writer/cerebro/internal/complianceimprovement"
)

var testNow = time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)

func TestGitHubDraftPublisherCreatesCommitBranchAndDraftPullRequest(t *testing.T) {
	baseSHA := strings.Repeat("b", 40)
	baseTreeSHA := strings.Repeat("d", 40)
	proposalTreeSHA := strings.Repeat("e", 40)
	headSHA := strings.Repeat("c", 40)
	request := githubPublisherRequest(baseSHA)

	var mu sync.Mutex
	writes := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := incoming.URL.Path
		switch {
		case incoming.Method == http.MethodGet && path == "/api/v3/repos/writer/cerebro/git/ref/heads/"+request.ProposalBranch:
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		case incoming.Method == http.MethodGet && path == "/api/v3/repos/writer/cerebro/git/ref/heads/main":
			writeGitHubJSON(writer, http.StatusOK, map[string]any{"object": map[string]string{"sha": baseSHA}})
		case incoming.Method == http.MethodGet && path == "/api/v3/repos/writer/cerebro/contents/internal/example/evidence_test.go":
			if incoming.URL.Query().Get("ref") != baseSHA {
				t.Errorf("contents ref = %q", incoming.URL.Query().Get("ref"))
			}
			writeGitHubJSON(writer, http.StatusOK, map[string]string{"sha": strings.Repeat("a", 40)})
		case incoming.Method == http.MethodGet && path == "/api/v3/repos/writer/cerebro/git/commits/"+baseSHA:
			writeGitHubJSON(writer, http.StatusOK, map[string]any{"sha": baseSHA, "tree": map[string]string{"sha": baseTreeSHA}, "parents": []any{}})
		case incoming.Method == http.MethodPost && path == "/api/v3/repos/writer/cerebro/git/trees":
			writes = append(writes, "tree")
			var payload struct {
				BaseTree string `json:"base_tree"`
				Tree     []struct {
					Path    string `json:"path"`
					Content string `json:"content"`
				} `json:"tree"`
			}
			decodeGitHubJSON(t, incoming, &payload)
			if payload.BaseTree != baseTreeSHA || len(payload.Tree) != 1 || payload.Tree[0].Path != request.Changes[0].Path || payload.Tree[0].Content != request.Changes[0].Content {
				t.Errorf("tree payload = %+v", payload)
			}
			writeGitHubJSON(writer, http.StatusCreated, map[string]string{"sha": proposalTreeSHA})
		case incoming.Method == http.MethodPost && path == "/api/v3/repos/writer/cerebro/git/commits":
			writes = append(writes, "commit")
			var payload struct {
				Message string   `json:"message"`
				Tree    string   `json:"tree"`
				Parents []string `json:"parents"`
			}
			decodeGitHubJSON(t, incoming, &payload)
			if payload.Tree != proposalTreeSHA || len(payload.Parents) != 1 || payload.Parents[0] != baseSHA || !strings.Contains(payload.Message, request.ProposalDigest) {
				t.Errorf("commit payload = %+v", payload)
			}
			writeGitHubJSON(writer, http.StatusCreated, map[string]string{"sha": headSHA})
		case incoming.Method == http.MethodPost && path == "/api/v3/repos/writer/cerebro/git/refs":
			writes = append(writes, "ref")
			var payload struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			}
			decodeGitHubJSON(t, incoming, &payload)
			if payload.Ref != "refs/heads/"+request.ProposalBranch || payload.SHA != headSHA {
				t.Errorf("ref payload = %+v", payload)
			}
			writeGitHubJSON(writer, http.StatusCreated, map[string]string{"ref": payload.Ref})
		case incoming.Method == http.MethodPost && path == "/api/v3/repos/writer/cerebro/pulls":
			writes = append(writes, "pull")
			var payload struct {
				Title string `json:"title"`
				Head  string `json:"head"`
				Base  string `json:"base"`
				Draft bool   `json:"draft"`
			}
			decodeGitHubJSON(t, incoming, &payload)
			if !payload.Draft || payload.Head != "writer:"+request.ProposalBranch || payload.Base != request.BaseBranch || payload.Title != request.Title {
				t.Errorf("pull payload = %+v", payload)
			}
			writeGitHubJSON(writer, http.StatusCreated, map[string]any{
				"number": 77, "html_url": "https://example.invalid/pulls/77", "draft": true,
				"created_at": testNow, "head": map[string]string{"sha": headSHA},
			})
		default:
			t.Errorf("unexpected GitHub request %s %s", incoming.Method, incoming.URL.String())
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "unexpected"})
		}
	}))
	t.Cleanup(server.Close)

	publisher := newTestGitHubDraftPublisher(t, server.URL)
	results, err := publisher.VerifyRepositoryChange(context.Background(), validPatch())
	if err != nil || improvement.HasBlockingVerification(results) {
		t.Fatalf("VerifyRepositoryChange() = %+v, %v", results, err)
	}
	receipt, err := publisher.OpenDraftPullRequest(context.Background(), request)
	if err != nil {
		t.Fatalf("OpenDraftPullRequest() error = %v", err)
	}
	if !receipt.Draft || receipt.Number != 77 || receipt.HeadCommitSHA != headSHA || receipt.BaseCommitSHA != baseSHA {
		t.Fatalf("receipt = %+v", receipt)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(writes, ",") != "tree,commit,ref,pull" {
		t.Fatalf("write sequence = %v", writes)
	}
	for _, write := range writes {
		if strings.Contains(write, "merge") || strings.Contains(write, "approve") {
			t.Fatalf("forbidden write = %q", write)
		}
	}
}

func TestGitHubDraftPublisherReusesExistingDraftWithoutNewWrites(t *testing.T) {
	baseSHA := strings.Repeat("b", 40)
	headSHA := strings.Repeat("c", 40)
	treeSHA := strings.Repeat("d", 40)
	request := githubPublisherRequest(baseSHA)
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		switch {
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/git/ref/heads/"+request.ProposalBranch:
			writeGitHubJSON(writer, http.StatusOK, map[string]any{"object": map[string]string{"sha": headSHA}})
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/git/commits/"+headSHA:
			writeGitHubJSON(writer, http.StatusOK, map[string]any{
				"sha": headSHA, "message": "Apply compliance program improvement\n\nCerebro-Proposal-Digest: " + request.ProposalDigest,
				"tree": map[string]string{"sha": treeSHA}, "parents": []map[string]string{{"sha": baseSHA}},
			})
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/pulls":
			if incoming.URL.Query().Get("head") != "writer:"+request.ProposalBranch || incoming.URL.Query().Get("base") != request.BaseBranch {
				t.Errorf("pull query = %s", incoming.URL.RawQuery)
			}
			writeGitHubJSON(writer, http.StatusOK, []map[string]any{{
				"number": 77, "html_url": "https://example.invalid/pulls/77", "draft": true,
				"created_at": testNow, "head": map[string]string{"sha": headSHA},
			}})
		default:
			if incoming.Method != http.MethodGet {
				writes++
			}
			t.Errorf("unexpected GitHub request %s %s", incoming.Method, incoming.URL.String())
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "unexpected"})
		}
	}))
	t.Cleanup(server.Close)

	publisher := newTestGitHubDraftPublisher(t, server.URL)
	first, err := publisher.OpenDraftPullRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publisher.OpenDraftPullRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || writes != 0 {
		t.Fatalf("idempotent receipts/writes = %+v %+v / %d", first, second, writes)
	}
}

func TestGitHubDraftPublisherRejectsExistingDraftAtDifferentHead(t *testing.T) {
	baseSHA := strings.Repeat("b", 40)
	headSHA := strings.Repeat("c", 40)
	differentHeadSHA := strings.Repeat("e", 40)
	treeSHA := strings.Repeat("d", 40)
	request := githubPublisherRequest(baseSHA)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		switch {
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/git/ref/heads/"+request.ProposalBranch:
			writeGitHubJSON(writer, http.StatusOK, map[string]any{"object": map[string]string{"sha": headSHA}})
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/git/commits/"+headSHA:
			writeGitHubJSON(writer, http.StatusOK, map[string]any{
				"sha": headSHA, "message": "Apply compliance program improvement\n\nCerebro-Proposal-Digest: " + request.ProposalDigest,
				"tree": map[string]string{"sha": treeSHA}, "parents": []map[string]string{{"sha": baseSHA}},
			})
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/pulls":
			writeGitHubJSON(writer, http.StatusOK, []map[string]any{{
				"number": 77, "html_url": "https://example.invalid/pulls/77", "draft": true,
				"created_at": testNow, "head": map[string]string{"sha": differentHeadSHA},
			}})
		default:
			t.Errorf("unexpected GitHub request %s %s", incoming.Method, incoming.URL.String())
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "unexpected"})
		}
	}))
	t.Cleanup(server.Close)

	_, err := newTestGitHubDraftPublisher(t, server.URL).OpenDraftPullRequest(context.Background(), request)
	if !errors.Is(err, improvement.ErrVerification) {
		t.Fatalf("OpenDraftPullRequest() error = %v, want improvement.ErrVerification", err)
	}
}

func TestGitHubDraftPublisherBlocksMovedBaseAndWrongFileOperation(t *testing.T) {
	wantBase := strings.Repeat("b", 40)
	currentBase := strings.Repeat("a", 40)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, incoming *http.Request) {
		switch {
		case incoming.Method == http.MethodGet && incoming.URL.Path == "/api/v3/repos/writer/cerebro/git/ref/heads/main":
			writeGitHubJSON(writer, http.StatusOK, map[string]any{"object": map[string]string{"sha": currentBase}})
		case incoming.Method == http.MethodGet && strings.Contains(incoming.URL.Path, "/contents/"):
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		case incoming.Method == http.MethodGet && strings.Contains(incoming.URL.Path, "/git/ref/heads/cerebro/"):
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "not found"})
		default:
			t.Errorf("unexpected GitHub request %s %s", incoming.Method, incoming.URL.String())
			writeGitHubJSON(writer, http.StatusNotFound, map[string]string{"message": "unexpected"})
		}
	}))
	t.Cleanup(server.Close)
	publisher := newTestGitHubDraftPublisher(t, server.URL)
	patch := validPatch()
	patch.BaseCommitSHA = wantBase
	results, err := publisher.VerifyRepositoryChange(context.Background(), patch)
	if err != nil || !improvement.HasBlockingVerification(results) {
		t.Fatalf("VerifyRepositoryChange() = %+v, %v", results, err)
	}
	_, err = publisher.OpenDraftPullRequest(context.Background(), githubPublisherRequest(wantBase))
	if !errors.Is(err, improvement.ErrConflict) {
		t.Fatalf("OpenDraftPullRequest() error = %v, want improvement.ErrConflict", err)
	}
}

func TestGitHubDraftPublisherRequiresAllowlistsAndDraftRequests(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	if _, err := NewGitHubDraftPublisher(server.Client(), GitHubDraftPublisherConfig{BaseURL: server.URL, AllowLoopback: true}); err == nil {
		t.Fatal("NewGitHubDraftPublisher() accepted missing allowlists")
	}
	publisher := newTestGitHubDraftPublisher(t, server.URL)
	request := githubPublisherRequest(strings.Repeat("b", 40))
	request.Draft = false
	if _, err := publisher.OpenDraftPullRequest(context.Background(), request); !errors.Is(err, improvement.ErrVerification) {
		t.Fatalf("OpenDraftPullRequest(non-draft) error = %v", err)
	}
}

func TestGitHubDraftPublisherHardensHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	original := &http.Client{}
	publisher, err := NewGitHubDraftPublisher(original, GitHubDraftPublisherConfig{
		BaseURL: server.URL, AllowLoopback: true,
		RepositoryAllowlist: []string{"writer/cerebro"}, BaseBranchAllowlist: []string{"main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if publisher.client == original || publisher.client.Timeout != 10*time.Second || publisher.client.CheckRedirect == nil {
		t.Fatalf("publisher client was not hardened: %+v", publisher.client)
	}
	if err := publisher.client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestGitHubDraftPublisherBlocksSensitiveRepositoryContentBeforeNetworkWrite(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeGitHubJSON(writer, http.StatusInternalServerError, map[string]string{"message": "should not be called"})
	}))
	t.Cleanup(server.Close)
	publisher, err := NewGitHubDraftPublisher(server.Client(), GitHubDraftPublisherConfig{
		BaseURL: server.URL, AllowLoopback: true, RepositoryAllowlist: []string{"writer/cerebro"},
		BaseBranchAllowlist: []string{"main"}, SensitiveValues: []string{"tenant-private"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := githubPublisherRequest(strings.Repeat("b", 40))
	request.Changes[0].Path = "internal/tenant-private/evidence_test.go"
	if _, err := publisher.OpenDraftPullRequest(context.Background(), request); !errors.Is(err, improvement.ErrVerification) {
		t.Fatalf("OpenDraftPullRequest(private path) error = %v", err)
	}
	request.Changes[0].Path = validPatch().Changes[0].Path
	request.Changes[0].Content = "const tenant = \"tenant-private\"\n"
	if _, err := publisher.OpenDraftPullRequest(context.Background(), request); !errors.Is(err, improvement.ErrVerification) {
		t.Fatalf("OpenDraftPullRequest(private data) error = %v", err)
	}
	request.Changes[0].Content = "token := \"" + "gh" + "p_" + strings.Repeat("a", 32) + "\"\n"
	results, err := publisher.VerifyRepositoryChange(context.Background(), improvement.RepositoryPatch{
		Repository: request.Repository, BaseBranch: request.BaseBranch, BaseCommitSHA: request.BaseCommitSHA,
		ProposalBranch: request.ProposalBranch, ChangeKind: improvement.ChangeKindAssessmentTest,
		Changes: request.Changes, ValidationSteps: []string{"go test ./..."}, RollbackSteps: []string{"Revert the commit."},
	})
	if err != nil || !improvement.HasBlockingVerification(results) {
		t.Fatalf("VerifyRepositoryChange(secret) = %+v, %v", results, err)
	}
	if requests != 0 {
		t.Fatalf("sensitive content triggered %d network requests", requests)
	}
}

func newTestGitHubDraftPublisher(t *testing.T, baseURL string) *GitHubDraftPublisher {
	t.Helper()
	publisher, err := NewGitHubDraftPublisher(http.DefaultClient, GitHubDraftPublisherConfig{
		BaseURL: baseURL, AllowLoopback: true,
		RepositoryAllowlist: []string{"writer/cerebro"}, BaseBranchAllowlist: []string{"main"},
	})
	if err != nil {
		t.Fatalf("NewGitHubDraftPublisher() error = %v", err)
	}
	publisher.now = func() time.Time { return testNow }
	return publisher
}

func githubPublisherRequest(baseSHA string) improvement.OpenDraftPullRequestRequest {
	return improvement.OpenDraftPullRequestRequest{
		ProposalDigest: "sha256:" + strings.Repeat("f", 64), Repository: "writer/cerebro",
		BaseBranch: "main", BaseCommitSHA: baseSHA, ProposalBranch: "cerebro/improvement/evidence-gap-1",
		Title: "Update compliance assessment tests", Body: "## Summary\n\n- update compliance assessment tests\n",
		Changes: validPatch().Changes, IdempotencyKey: "improvement-1:proposal", Draft: true,
	}
}

func validPatch() improvement.RepositoryPatch {
	return improvement.RepositoryPatch{
		Repository: "writer/cerebro", BaseBranch: "main", BaseCommitSHA: strings.Repeat("b", 40),
		ProposalBranch: "cerebro/improvement/evidence-gap-1", ChangeKind: improvement.ChangeKindAssessmentTest,
		Changes:         []improvement.FileChange{{Path: "internal/example/evidence_test.go", Operation: improvement.FileOperationUpdate, Content: "package example\n"}},
		ValidationSteps: []string{"go test ./internal/example"}, RollbackSteps: []string{"Revert the proposal commit."},
	}
}

func decodeGitHubJSON(t *testing.T, request *http.Request, target any) {
	t.Helper()
	if err := json.NewDecoder(request.Body).Decode(target); err != nil {
		t.Fatalf("decode %s %s: %v", request.Method, request.URL.Path, err)
	}
}

func writeGitHubJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

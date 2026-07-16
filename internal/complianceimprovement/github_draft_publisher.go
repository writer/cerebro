package complianceimprovement

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/sourcehttp"
)

const (
	githubAPIVersion       = "2022-11-28"
	maxGitHubResponseBytes = 2 * 1024 * 1024
)

type GitHubDraftPublisherConfig struct {
	BaseURL             string
	AllowLoopback       bool
	RepositoryAllowlist []string
	BaseBranchAllowlist []string
	SensitiveValues     []string
}

// GitHubDraftPublisher has only the Git data and draft pull-request operations
// required by the bounded publisher port. It has no merge, approval, readiness,
// retarget, close, or default-branch update operation.
type GitHubDraftPublisher struct {
	client          *http.Client
	baseURL         string
	repositories    map[string]struct{}
	baseBranches    map[string]struct{}
	sensitiveValues []string
	now             func() time.Time
}

func NewGitHubDraftPublisher(client *http.Client, config GitHubDraftPublisherConfig) (*GitHubDraftPublisher, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: GitHub HTTP client is required", ErrInvalidRequest)
	}
	baseURL, err := sourcehttp.NormalizeGitHubBaseURL(strings.TrimSpace(config.BaseURL), config.AllowLoopback)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse normalized GitHub base URL: %w", err)
	}
	if !sourcehttp.IsGitHubAPIHost(parsed.Hostname()) && !strings.HasSuffix(baseURL, "/api/v3") {
		baseURL += "/api/v3"
	}
	repositories := stringSet(config.RepositoryAllowlist)
	baseBranches := stringSet(config.BaseBranchAllowlist)
	if len(repositories) == 0 || len(baseBranches) == 0 {
		return nil, fmt.Errorf("%w: repository and base-branch allowlists are required", ErrInvalidRequest)
	}
	for repository := range repositories {
		if !repositoryPattern.MatchString(repository) {
			return nil, fmt.Errorf("%w: invalid allowlisted repository %q", ErrInvalidRequest, repository)
		}
	}
	return &GitHubDraftPublisher{
		client: client, baseURL: strings.TrimRight(baseURL, "/"), repositories: repositories,
		baseBranches: baseBranches, sensitiveValues: normalizeStrings(config.SensitiveValues, false),
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

// VerifyRepositoryChange performs the read-only exact-base and file-operation
// checks used before a proposal can enter the validated state.
func (p *GitHubDraftPublisher) VerifyRepositoryChange(ctx context.Context, patch RepositoryPatch) ([]VerificationResult, error) {
	if err := p.validatePatchPolicy(patch); err != nil {
		return []VerificationResult{{VerifierID: "repository-policy", Status: VerificationBlock, Message: err.Error()}}, nil
	}
	contentResults := p.verifyRepositoryContent(patch.Changes)
	if hasBlockingResult(contentResults) {
		return contentResults, nil
	}
	baseSHA, err := p.readRef(ctx, patch.Repository, patch.BaseBranch)
	if err != nil {
		return nil, err
	}
	results := append([]VerificationResult(nil), contentResults...)
	if baseSHA != patch.BaseCommitSHA {
		results = append(results, VerificationResult{
			VerifierID: "repository-exact-base", Status: VerificationBlock,
			Message: "The repository base branch moved after the proposal was authored.",
		})
	} else {
		results = append(results, VerificationResult{
			VerifierID: "repository-exact-base", Status: VerificationPass,
			Message: "The repository base branch matches the proposal's exact commit.",
		})
	}
	operationResults, err := p.verifyFileOperations(ctx, patch)
	if err != nil {
		return nil, err
	}
	results = append(results, operationResults...)
	if hasBlockingResult(results) {
		return normalizeVerificationResults(results), nil
	}
	results = append(results, VerificationResult{
		VerifierID: "repository-draft-capability", Status: VerificationPass,
		Message: "The configured repository capability can create proposal branches and draft pull requests only.",
	})
	return normalizeVerificationResults(results), nil
}

func (p *GitHubDraftPublisher) OpenDraftPullRequest(ctx context.Context, request OpenDraftPullRequestRequest) (DraftPullRequestReceipt, error) {
	if err := p.validateOpenRequest(request); err != nil {
		return DraftPullRequestReceipt{}, err
	}
	owner, _ := splitRepository(request.Repository)
	existingHead, exists, err := p.readOptionalRef(ctx, request.Repository, request.ProposalBranch)
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	if exists {
		if err := p.verifyProposalCommit(ctx, request, existingHead); err != nil {
			return DraftPullRequestReceipt{}, err
		}
		pull, found, err := p.findOpenPullRequest(ctx, request, owner)
		if err != nil {
			return DraftPullRequestReceipt{}, err
		}
		if found {
			return p.receiptFromPull(request, existingHead, pull)
		}
		if err := p.requireExactBase(ctx, request.Repository, request.BaseBranch, request.BaseCommitSHA); err != nil {
			return DraftPullRequestReceipt{}, err
		}
		return p.createDraftPullRequest(ctx, request, owner, existingHead)
	}
	if err := p.requireExactBase(ctx, request.Repository, request.BaseBranch, request.BaseCommitSHA); err != nil {
		return DraftPullRequestReceipt{}, err
	}
	operationResults, err := p.verifyFileOperations(ctx, RepositoryPatch{
		Repository: request.Repository, BaseBranch: request.BaseBranch, BaseCommitSHA: request.BaseCommitSHA,
		ProposalBranch: request.ProposalBranch, ChangeKind: ChangeKindDocumentation,
		Changes: request.Changes, ValidationSteps: []string{"validated"}, RollbackSteps: []string{"revert"},
	})
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	if hasBlockingResult(operationResults) {
		return DraftPullRequestReceipt{}, fmt.Errorf("%w: repository file operations no longer match the exact base commit", ErrVerification)
	}
	baseCommit, err := p.readCommit(ctx, request.Repository, request.BaseCommitSHA)
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	treeSHA, err := p.createTree(ctx, request, baseCommit.Tree.SHA)
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	headSHA, err := p.createCommit(ctx, request, treeSHA)
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	if err := p.createRef(ctx, request.Repository, request.ProposalBranch, headSHA); err != nil {
		return DraftPullRequestReceipt{}, err
	}
	return p.createDraftPullRequest(ctx, request, owner, headSHA)
}

func (p *GitHubDraftPublisher) validateOpenRequest(request OpenDraftPullRequestRequest) error {
	if p == nil || p.client == nil || p.baseURL == "" {
		return ErrUnavailable
	}
	patch := RepositoryPatch{
		Repository: request.Repository, BaseBranch: request.BaseBranch, BaseCommitSHA: request.BaseCommitSHA,
		ProposalBranch: request.ProposalBranch, ChangeKind: ChangeKindDocumentation,
		Changes: request.Changes, ValidationSteps: []string{"validated"}, RollbackSteps: []string{"revert"},
	}
	if err := p.validatePatchPolicy(patch); err != nil {
		return err
	}
	if !request.Draft {
		return fmt.Errorf("%w: publisher accepts draft pull requests only", ErrVerification)
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(request.ProposalDigest)); err != nil {
		return fmt.Errorf("%w: invalid proposal digest", ErrInvalidRequest)
	}
	if strings.TrimSpace(request.Title) == "" || len(request.Title) > 120 || strings.TrimSpace(request.Body) == "" || len(request.Body) > 16*1024 {
		return fmt.Errorf("%w: bounded pull-request title and body are required", ErrInvalidRequest)
	}
	if p.containsSensitiveMaterial(request.Title) || p.containsSensitiveMaterial(request.Body) || hasBlockingResult(p.verifyRepositoryContent(request.Changes)) {
		return fmt.Errorf("%w: pull-request metadata or patch contains material that cannot be published", ErrVerification)
	}
	if strings.TrimSpace(request.IdempotencyKey) == "" {
		return fmt.Errorf("%w: publication idempotency key is required", ErrInvalidRequest)
	}
	return nil
}

var builtInSensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{24,}`),
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{16,}`),
}

func (p *GitHubDraftPublisher) verifyRepositoryContent(changes []FileChange) []VerificationResult {
	for _, change := range changes {
		if strings.IndexByte(change.Content, 0) >= 0 || p.containsSensitiveMaterial(change.Content) {
			return []VerificationResult{{
				VerifierID: "repository-content-policy", Status: VerificationBlock,
				Message: "The repository patch contains private, secret, or binary material and cannot be published.",
			}}
		}
	}
	return []VerificationResult{{
		VerifierID: "repository-content-policy", Status: VerificationPass,
		Message: "The repository patch passed configured private-data and secret checks.",
	}}
}

func (p *GitHubDraftPublisher) containsSensitiveMaterial(value string) bool {
	for _, sensitive := range p.sensitiveValues {
		if sensitive != "" && strings.Contains(value, sensitive) {
			return true
		}
	}
	for _, pattern := range builtInSensitivePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func (p *GitHubDraftPublisher) validatePatchPolicy(patch RepositoryPatch) error {
	if p == nil || p.client == nil || p.baseURL == "" {
		return ErrUnavailable
	}
	patch = normalizePatch(patch)
	if err := validatePatch(patch); err != nil {
		return err
	}
	if _, ok := p.repositories[patch.Repository]; !ok {
		return fmt.Errorf("%w: repository %q is not allowlisted", ErrVerification, patch.Repository)
	}
	if _, ok := p.baseBranches[patch.BaseBranch]; !ok {
		return fmt.Errorf("%w: base branch %q is not allowlisted", ErrVerification, patch.BaseBranch)
	}
	if strings.HasPrefix(patch.ProposalBranch, "refs/") || strings.Contains(patch.ProposalBranch, "..") || strings.HasPrefix(patch.ProposalBranch, "/") || strings.HasSuffix(patch.ProposalBranch, "/") {
		return fmt.Errorf("%w: proposal branch is invalid", ErrInvalidRequest)
	}
	return nil
}

func (p *GitHubDraftPublisher) requireExactBase(ctx context.Context, repository, branch, wantSHA string) error {
	gotSHA, err := p.readRef(ctx, repository, branch)
	if err != nil {
		return err
	}
	if gotSHA != wantSHA {
		return fmt.Errorf("%w: repository base moved from %s to %s", ErrConflict, wantSHA, gotSHA)
	}
	return nil
}

func (p *GitHubDraftPublisher) verifyFileOperations(ctx context.Context, patch RepositoryPatch) ([]VerificationResult, error) {
	results := make([]VerificationResult, 0, len(patch.Changes)+1)
	blocked := false
	for _, change := range patch.Changes {
		exists, err := p.fileExists(ctx, patch.Repository, change.Path, patch.BaseCommitSHA)
		if err != nil {
			return nil, err
		}
		valid := (change.Operation == FileOperationCreate && !exists) || (change.Operation == FileOperationUpdate && exists)
		if !valid {
			blocked = true
			results = append(results, VerificationResult{
				VerifierID: "repository-file-operation", Status: VerificationBlock,
				Message: fmt.Sprintf("File %q does not match the requested %s operation at the exact base commit.", change.Path, change.Operation),
			})
		}
	}
	if !blocked {
		results = append(results, VerificationResult{
			VerifierID: "repository-file-operation", Status: VerificationPass,
			Message: "Every create and update operation matches the exact base commit.",
		})
	}
	return results, nil
}

func (p *GitHubDraftPublisher) fileExists(ctx context.Context, repository, filePath, ref string) (bool, error) {
	requestPath := fmt.Sprintf("/repos/%s/contents/%s?ref=%s", escapeRepository(repository), escapePath(filePath), url.QueryEscape(ref))
	status, _, err := p.request(ctx, http.MethodGet, requestPath, nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return false, err
	}
	return status == http.StatusOK, nil
}

type githubRefResponse struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

func (p *GitHubDraftPublisher) readRef(ctx context.Context, repository, branch string) (string, error) {
	sha, exists, err := p.readOptionalRef(ctx, repository, branch)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("%w: GitHub branch %q was not found", ErrVerification, branch)
	}
	return sha, nil
}

func (p *GitHubDraftPublisher) readOptionalRef(ctx context.Context, repository, branch string) (string, bool, error) {
	requestPath := fmt.Sprintf("/repos/%s/git/ref/heads/%s", escapeRepository(repository), escapePath(branch))
	status, body, err := p.request(ctx, http.MethodGet, requestPath, nil, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return "", false, err
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	var response githubRefResponse
	if err := json.Unmarshal(body, &response); err != nil || !commitSHAPattern.MatchString(response.Object.SHA) {
		return "", false, fmt.Errorf("%w: GitHub ref response is invalid", ErrVerification)
	}
	return response.Object.SHA, true, nil
}

type githubCommitResponse struct {
	SHA     string `json:"sha"`
	Message string `json:"message"`
	Tree    struct {
		SHA string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

func (p *GitHubDraftPublisher) readCommit(ctx context.Context, repository, sha string) (githubCommitResponse, error) {
	_, body, err := p.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/git/commits/%s", escapeRepository(repository), url.PathEscape(sha)), nil, http.StatusOK)
	if err != nil {
		return githubCommitResponse{}, err
	}
	var response githubCommitResponse
	if err := json.Unmarshal(body, &response); err != nil || !commitSHAPattern.MatchString(response.Tree.SHA) {
		return githubCommitResponse{}, fmt.Errorf("%w: GitHub commit response is invalid", ErrVerification)
	}
	return response, nil
}

func (p *GitHubDraftPublisher) verifyProposalCommit(ctx context.Context, request OpenDraftPullRequestRequest, headSHA string) error {
	commit, err := p.readCommit(ctx, request.Repository, headSHA)
	if err != nil {
		return err
	}
	trailer := "Cerebro-Proposal-Digest: " + request.ProposalDigest
	if len(commit.Parents) != 1 || commit.Parents[0].SHA != request.BaseCommitSHA || !strings.Contains(commit.Message, trailer) {
		return fmt.Errorf("%w: proposal branch already exists with different content or base", ErrConflict)
	}
	return nil
}

func (p *GitHubDraftPublisher) createTree(ctx context.Context, request OpenDraftPullRequestRequest, baseTreeSHA string) (string, error) {
	type treeEntry struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	entries := make([]treeEntry, 0, len(request.Changes))
	for _, change := range request.Changes {
		entries = append(entries, treeEntry{Path: change.Path, Mode: "100644", Type: "blob", Content: change.Content})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	payload := struct {
		BaseTree string      `json:"base_tree"`
		Tree     []treeEntry `json:"tree"`
	}{BaseTree: baseTreeSHA, Tree: entries}
	_, body, err := p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/trees", escapeRepository(request.Repository)), payload, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var response struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &response); err != nil || !commitSHAPattern.MatchString(response.SHA) {
		return "", fmt.Errorf("%w: GitHub create-tree response is invalid", ErrVerification)
	}
	return response.SHA, nil
}

func (p *GitHubDraftPublisher) createCommit(ctx context.Context, request OpenDraftPullRequestRequest, treeSHA string) (string, error) {
	payload := struct {
		Message string   `json:"message"`
		Tree    string   `json:"tree"`
		Parents []string `json:"parents"`
	}{
		Message: "Apply compliance program improvement\n\nCerebro-Proposal-Digest: " + request.ProposalDigest,
		Tree:    treeSHA, Parents: []string{request.BaseCommitSHA},
	}
	_, body, err := p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/commits", escapeRepository(request.Repository)), payload, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var response struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &response); err != nil || !commitSHAPattern.MatchString(response.SHA) {
		return "", fmt.Errorf("%w: GitHub create-commit response is invalid", ErrVerification)
	}
	return response.SHA, nil
}

func (p *GitHubDraftPublisher) createRef(ctx context.Context, repository, branch, sha string) error {
	payload := struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}{Ref: "refs/heads/" + branch, SHA: sha}
	_, _, err := p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/refs", escapeRepository(repository)), payload, http.StatusCreated)
	return err
}

type githubPullResponse struct {
	Number    uint64    `json:"number"`
	HTMLURL   string    `json:"html_url"`
	Draft     bool      `json:"draft"`
	CreatedAt time.Time `json:"created_at"`
	Head      struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

func (p *GitHubDraftPublisher) findOpenPullRequest(ctx context.Context, request OpenDraftPullRequestRequest, owner string) (githubPullResponse, bool, error) {
	query := url.Values{}
	query.Set("state", "open")
	query.Set("head", owner+":"+request.ProposalBranch)
	query.Set("base", request.BaseBranch)
	requestPath := fmt.Sprintf("/repos/%s/pulls?%s", escapeRepository(request.Repository), query.Encode())
	_, body, err := p.request(ctx, http.MethodGet, requestPath, nil, http.StatusOK)
	if err != nil {
		return githubPullResponse{}, false, err
	}
	var pulls []githubPullResponse
	if err := json.Unmarshal(body, &pulls); err != nil {
		return githubPullResponse{}, false, fmt.Errorf("decode GitHub pull-request list: %w", err)
	}
	if len(pulls) > 1 {
		return githubPullResponse{}, false, fmt.Errorf("%w: proposal branch has multiple open pull requests", ErrConflict)
	}
	if len(pulls) == 0 {
		return githubPullResponse{}, false, nil
	}
	return pulls[0], true, nil
}

func (p *GitHubDraftPublisher) createDraftPullRequest(ctx context.Context, request OpenDraftPullRequestRequest, owner, headSHA string) (DraftPullRequestReceipt, error) {
	payload := struct {
		Title string `json:"title"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Body  string `json:"body"`
		Draft bool   `json:"draft"`
	}{Title: request.Title, Head: owner + ":" + request.ProposalBranch, Base: request.BaseBranch, Body: request.Body, Draft: true}
	_, body, err := p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/pulls", escapeRepository(request.Repository)), payload, http.StatusCreated)
	if err != nil {
		return DraftPullRequestReceipt{}, err
	}
	var pull githubPullResponse
	if err := json.Unmarshal(body, &pull); err != nil {
		return DraftPullRequestReceipt{}, fmt.Errorf("decode GitHub draft pull request: %w", err)
	}
	if pull.Head.SHA != "" && pull.Head.SHA != headSHA {
		return DraftPullRequestReceipt{}, fmt.Errorf("%w: draft pull-request head does not match proposal commit", ErrVerification)
	}
	return p.receiptFromPull(request, headSHA, pull)
}

func (p *GitHubDraftPublisher) receiptFromPull(request OpenDraftPullRequestRequest, headSHA string, pull githubPullResponse) (DraftPullRequestReceipt, error) {
	if pull.Number == 0 || strings.TrimSpace(pull.HTMLURL) == "" || !pull.Draft {
		return DraftPullRequestReceipt{}, fmt.Errorf("%w: GitHub did not return a draft pull request", ErrVerification)
	}
	openedAt := canonicalTime(pull.CreatedAt)
	if openedAt.IsZero() {
		openedAt = canonicalTime(p.now())
	}
	return DraftPullRequestReceipt{
		Repository: request.Repository, Number: pull.Number, URL: pull.HTMLURL,
		HeadCommitSHA: headSHA, BaseCommitSHA: request.BaseCommitSHA, Draft: true,
		ProposalDigest: request.ProposalDigest, OpenedAt: openedAt,
	}, nil
}

func (p *GitHubDraftPublisher) request(ctx context.Context, method, requestPath string, payload any, expectedStatuses ...int) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encode GitHub request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, p.baseURL+requestPath, body)
	if err != nil {
		return 0, nil, fmt.Errorf("build GitHub request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.client.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("GitHub request %s %s: %w", method, requestPath, err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxGitHubResponseBytes+1))
	if readErr != nil {
		return response.StatusCode, nil, fmt.Errorf("read GitHub response: %w", readErr)
	}
	if len(responseBody) > maxGitHubResponseBytes {
		return response.StatusCode, nil, fmt.Errorf("%w: GitHub response exceeds %d bytes", ErrVerification, maxGitHubResponseBytes)
	}
	for _, expected := range expectedStatuses {
		if response.StatusCode == expected {
			return response.StatusCode, responseBody, nil
		}
	}
	return response.StatusCode, nil, &GitHubAPIError{Method: method, Path: requestPath, StatusCode: response.StatusCode}
}

type GitHubAPIError struct {
	Method     string
	Path       string
	StatusCode int
}

func (err *GitHubAPIError) Error() string {
	return fmt.Sprintf("GitHub request %s %s returned HTTP %d", err.Method, err.Path, err.StatusCode)
}

func (err *GitHubAPIError) HTTPStatus() int {
	if err == nil {
		return 0
	}
	return err.StatusCode
}

func IsGitHubAPIError(err error, status int) bool {
	var apiError *GitHubAPIError
	return errors.As(err, &apiError) && apiError.StatusCode == status
}

func splitRepository(repository string) (string, string) {
	owner, name, _ := strings.Cut(strings.TrimSpace(repository), "/")
	return owner, name
}

func escapeRepository(repository string) string {
	owner, name := splitRepository(repository)
	return url.PathEscape(owner) + "/" + url.PathEscape(name)
}

func escapePath(value string) string {
	parts := strings.Split(value, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/")
}

func stringSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

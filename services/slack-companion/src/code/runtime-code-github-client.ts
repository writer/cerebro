import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import { assessDangerousIntent } from "../security/safety.js";
import { assertRuntimeCodeAllowed } from "./runtime-code-access.js";
import { assertGithubOk, githubAppJwt, githubChecksSummary } from "./runtime-code-github.js";
import type {
  GithubAuthMode,
  GithubCheckRunsResponse,
  GithubCombinedStatusResponse,
  GithubCommitResponse,
  GithubContentResponse,
  GithubCreateCommitOnBranchResponse,
  GithubInstallationTokenResponse,
  GithubPullDetailResponse,
  GithubPullResponse,
  GithubRefResponse,
  GithubRepo,
  GithubRepoResponse,
  RuntimeCodeError,
  RuntimeCodeFileInput,
  RuntimeCodeGithubChecksInput,
  RuntimeCodeGithubCandidateStateInput,
  RuntimeCodeGithubCompleteCandidateInput,
  RuntimeCodeGithubPrStatusInput,
  RuntimeCodeGithubSourceListInput,
  RuntimeCodeGithubSourceReadInput,
  RuntimeCodePrInput,
  RuntimeSelfImprovementPrInput,
  RuntimeValidationResult,
} from "./runtime-code-types.js";
import { bounded, encodePath, normalizeRelativePath, sha256, slug, unique } from "./runtime-code-utils.js";
import {
  normalizeRepo,
  positiveInteger,
  validateCodeFile,
  validateCodePath,
  validateGithubRef,
  validateSelfImprovementCodeFile,
} from "./runtime-code-validators.js";

const GITHUB_SOURCE_MAX_ENTRIES = 200;
const GITHUB_SOURCE_MAX_FILES = 8;
const GITHUB_SOURCE_MAX_FILE_BYTES = 120_000;

export class RuntimeCodeGithubClient {
  private githubInstallationToken?: { token: string; expiresAtMs: number };

  constructor(private readonly config: Pick<AppConfig, "code">) {}

  authMode(): GithubAuthMode {
    if (this.config.code.githubToken) return "token";
    if (this.config.code.githubApp) return "app";
    return "not_configured";
  }

  async createPullRequest(input: RuntimeCodePrInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return noSideEffectStarted(allowed);
    if (this.authMode() === "not_configured") {
      return noSideEffectStarted({
        ok: false,
        error: "github_auth_not_configured",
        message: "Runtime code can write workspace files, but GitHub PR creation needs CEREBRO_CODE_GITHUB_TOKEN or GitHub App installation credentials.",
      });
    }

    const repoResult = this.writeAllowedRepo(input.repo);
    if (!repoResult.ok) return noSideEffectStarted(repoResult);
    const repo = repoResult.repo;
    if (!input.title.trim()) return noSideEffectStarted({ ok: false, error: "title_required" });
    const titleSafety = assessDangerousIntent([input.title, input.body ?? ""].join("\n"));
    if (!titleSafety.allowed) {
      return noSideEffectStarted({ ok: false, error: "unsafe_pr_text", category: titleSafety.category, message: titleSafety.refusal });
    }
    const files = input.files.slice(0, this.config.code.maxFiles);
    if (files.length === 0) return noSideEffectStarted({ ok: false, error: "files_required" });
    if (input.files.length > this.config.code.maxFiles) {
      return noSideEffectStarted({ ok: false, error: "too_many_files", max_files: this.config.code.maxFiles });
    }
    for (const file of files) {
      const valid = validateCodeFile(this.config, file);
      if (!valid.ok) return noSideEffectStarted(valid);
    }

    const baseBranch = input.base?.trim() || await this.defaultBranch(repo);
    const branchPrefix = this.config.code.branchPrefix.trim().replace(/\/+$/, "");
    const branchResult = validateGithubRef(input.branch?.trim() || `${branchPrefix}/${slug(input.title)}-${Date.now()}`);
    if (!branchResult.ok) return noSideEffectStarted(branchResult);
    const branch = branchResult.value;
    if (!branchPrefix || !branch.startsWith(`${branchPrefix}/`)) {
      return noSideEffectStarted({ ok: false, error: "branch_not_allowed", branch, branch_prefix: branchPrefix });
    }
    if (branch === baseBranch) return noSideEffectStarted({ ok: false, error: "base_branch_write_refused", branch });
    const baseSha = await this.baseSha(repo, baseBranch);
    if (input.expectedBaseSha && baseSha.toLowerCase() !== input.expectedBaseSha.toLowerCase()) {
      return noSideEffectStarted({
        ok: false,
        error: "base_sha_changed",
        expected_base_sha: input.expectedBaseSha,
        current_base_sha: baseSha,
      });
    }
    const branchState = await this.createBranch(repo, branch, baseSha);

    const existing = await this.request<GithubPullDetailResponse[]>(repo, `/pulls?head=${encodeURIComponent(`${repo.owner}:${branch}`)}&state=open&per_page=100`, { method: "GET" });
    if (input.draftBoundReuse) {
      const reusable = validateDraftBoundReuse({
        branch,
        branchState,
        pullRequests: existing,
        repo,
        baseBranch,
        baseSha,
        expectedHeadSha: input.expectedHeadSha,
      });
      if (!reusable.ok) return reusable;
    }
    const fileReceipts = files.map((file) => ({ path: normalizeRelativePath(file.path), bytes: Buffer.byteLength(file.content, "utf8") }));
    let committedHeadSha: string | undefined;
    if (input.draftBoundReuse) {
      const expectedHeadSha = branchState === "created" ? baseSha : input.expectedHeadSha!;
      const committed = await this.commitFilesAtExpectedHead(repo, branch, expectedHeadSha, files);
      if (!committed.ok) return committed;
      committedHeadSha = committed.headSha;
    } else {
      for (const file of files) {
        await this.putFile(repo, branch, file, `Cerebro runtime update ${file.path}`);
      }
    }

    if (existing[0]) {
      return {
        ok: true,
        repo: repo.fullName,
        branch,
        base: baseBranch,
        base_sha: baseSha,
        pull_request: {
          number: existing[0].number,
          url: existing[0].html_url,
          state: existing[0].state,
          head_sha: committedHeadSha ?? await this.baseSha(repo, branch),
        },
        reused_pull_request: true,
        files: fileReceipts,
      };
    }

    const pr = await this.request<GithubPullResponse>(repo, "/pulls", {
      method: "POST",
      body: {
        title: input.title,
        body: runtimePullRequestBody(input),
        head: branch,
        base: baseBranch,
        draft: input.draft ?? true,
      },
    });
    return {
      ok: true,
      repo: repo.fullName,
      branch,
      base: baseBranch,
      base_sha: baseSha,
      pull_request: {
        number: pr.number,
        url: pr.html_url,
        state: pr.state,
        head_sha: pr.head?.sha ?? committedHeadSha,
      },
      reused_pull_request: false,
      files: fileReceipts,
    };
  }

  async createSelfImprovementPullRequest(input: RuntimeSelfImprovementPrInput): Promise<Record<string, unknown>> {
    const candidateId = slug(input.candidateId);
    if (!/[a-z0-9]/i.test(input.candidateId)) {
      return noSideEffectStarted({ ok: false, error: "candidate_id_required" });
    }
    for (const file of input.files) {
      const valid = validateSelfImprovementCodeFile(this.config, file);
      if (!valid.ok) return noSideEffectStarted(valid);
    }
    const repo = normalizeRepo(this.config.code.defaultRepo);
    if (!repo) return noSideEffectStarted({ ok: false, error: "default_repo_required" });
    if (!input.baseSha || !/^[a-f0-9]{40}$/i.test(input.baseSha)) {
      return noSideEffectStarted({ ok: false, error: "base_sha_required", message: "Pass the immutable commit SHA returned by the source inspection." });
    }
    const candidateDigest = sha256(JSON.stringify({
      repo: repo.fullName,
      base_sha: input.baseSha.toLowerCase(),
      expected_head_sha: input.expectedHeadSha?.toLowerCase(),
      title: input.title,
      body: input.body ?? "",
      files: input.files.map((file) => ({ path: normalizeRelativePath(file.path), content: file.content })),
    }));
    const result = await this.createPullRequest({
      repo: repo.fullName,
      title: input.title,
      body: [
        input.body?.trim(),
        `Self-improvement candidate: ${candidateId}`,
        "This candidate is draft-only. Merge, deployment, and promotion require the normal reviewed path.",
      ].filter(Boolean).join("\n\n"),
      files: input.files.map((file) => ({ ...file, path: this.toRepoPath(repo, file.path) })),
      branch: `${this.config.code.branchPrefix.replace(/\/+$/, "")}/self-improve-${candidateId}`,
      expectedBaseSha: input.baseSha,
      expectedHeadSha: input.expectedHeadSha,
      draft: true,
      draftBoundReuse: true,
    });
    const resultFiles = Array.isArray(result.files)
      ? result.files.map((file) => {
          if (!file || typeof file !== "object") return file;
          const receipt = file as Record<string, unknown>;
          return typeof receipt.path === "string"
            ? { ...receipt, path: this.fromRepoPath(repo, receipt.path) }
            : receipt;
        })
      : result.files;
    return {
      ...result,
      ...(resultFiles ? { files: resultFiles } : {}),
      candidate_id: candidateId,
      candidate_digest: `sha256:${candidateDigest}`,
      ...(result.ok === true ? { draft: true } : {}),
    };
  }

  async candidatePullRequestState(input: RuntimeCodeGithubCandidateStateInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const repoResult = this.readRepo(input.repo);
    if (!repoResult.ok) return repoResult;
    const auth = this.assertConfigured();
    if (!auth.ok) return auth;
    const branch = validateGithubRef(input.branch);
    if (!branch.ok) return branch;
    const normalizedPaths = unique(input.paths.map((path) => normalizeRelativePath(path)).filter(Boolean));
    if (normalizedPaths.length === 0) return { ok: false, error: "paths_required" };
    if (normalizedPaths.length > this.config.code.maxFiles) {
      return { ok: false, error: "too_many_files", max_files: this.config.code.maxFiles };
    }
    for (const path of normalizedPaths) {
      const pathResult = validateCodePath(path);
      if (!pathResult.ok) return pathResult;
    }

    const repo = repoResult.repo;
    const repoPaths = normalizedPaths.map((path) => this.toRepoPath(repo, path));
    const [headSha, pulls] = await Promise.all([
      this.branchShaIfExists(repo, branch.value),
      this.request<GithubPullDetailResponse[]>(
        repo,
        `/pulls?head=${encodeURIComponent(`${repo.owner}:${branch.value}`)}&state=all&per_page=100`,
        { method: "GET" },
      ),
    ]);
    const files: Record<string, unknown>[] = [];
    let headCommit: GithubCommitResponse | undefined;
    if (headSha) {
      headCommit = await this.request<GithubCommitResponse>(repo, `/commits/${headSha}?per_page=100`, { method: "GET" });
      for (const path of repoPaths) {
        const file = await this.readSourceFile(repo, headSha, path);
        files.push({ ...file, path: this.fromRepoPath(repo, path) });
      }
    }
    return {
      ok: true,
      repo: repo.fullName,
      branch: branch.value,
      branch_exists: Boolean(headSha),
      head_sha: headSha,
      head_parent_shas: (headCommit?.parents ?? []).map((parent) => parent.sha).filter(Boolean),
      head_changed_paths: (headCommit?.files ?? [])
        .map((file) => file.filename)
        .filter((filename): filename is string => Boolean(filename))
        .map((filename) => this.fromRepoPath(repo, filename)),
      head_changes: (headCommit?.files ?? []).filter((file) => typeof file.filename === "string").map((file) => ({
        path: this.fromRepoPath(repo, file.filename!),
        status: file.status,
        ...(file.previous_filename ? { previous_path: this.fromRepoPath(repo, file.previous_filename) } : {}),
      })),
      head_changed_paths_truncated: (headCommit?.files?.length ?? 0) >= 100,
      pull_requests: pulls.map((pull) => ({
        number: pull.number,
        url: pull.html_url,
        title: pull.title,
        body: pull.body,
        state: pull.state,
        draft: pull.draft,
        merged: pull.merged,
        head_ref: pull.head?.ref,
        head_sha: pull.head?.sha,
        head_repo: pull.head?.repo?.full_name,
        base_ref: pull.base?.ref,
        base_sha: pull.base?.sha,
      })),
      pull_requests_truncated: pulls.length >= 100,
      files,
    };
  }

  async completeCandidatePullRequest(input: RuntimeCodeGithubCompleteCandidateInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    if (this.authMode() === "not_configured") return { ok: false, error: "github_auth_not_configured" };
    const repoResult = this.writeAllowedRepo(input.pullRequest.repo);
    if (!repoResult.ok) return repoResult;
    const pullRequest = input.pullRequest;
    if (!pullRequest.title.trim()) return { ok: false, error: "title_required" };
    const titleSafety = assessDangerousIntent([pullRequest.title, pullRequest.body ?? ""].join("\n"));
    if (!titleSafety.allowed) {
      return { ok: false, error: "unsafe_pr_text", category: titleSafety.category, message: titleSafety.refusal };
    }
    if (pullRequest.files.length === 0) return { ok: false, error: "files_required" };
    if (pullRequest.files.length > this.config.code.maxFiles) {
      return { ok: false, error: "too_many_files", max_files: this.config.code.maxFiles };
    }
    for (const file of pullRequest.files) {
      const valid = validateCodeFile(this.config, file);
      if (!valid.ok) return valid;
    }
    if (!pullRequest.base || !pullRequest.branch || !pullRequest.expectedBaseSha || !pullRequest.expectedHeadSha
      || pullRequest.draft !== true || pullRequest.draftBoundReuse !== true
      || !/^[a-f0-9]{40}$/i.test(input.expectedCandidateHeadSha)) {
      return { ok: false, error: "candidate_write_intent_required" };
    }
    const branch = validateGithubRef(pullRequest.branch);
    if (!branch.ok) return branch;
    const branchPrefix = this.config.code.branchPrefix.trim().replace(/\/+$/, "");
    if (!branchPrefix || !branch.value.startsWith(`${branchPrefix}/`)) {
      return { ok: false, error: "branch_not_allowed", branch: branch.value, branch_prefix: branchPrefix };
    }
    if (branch.value === pullRequest.base) return { ok: false, error: "base_branch_write_refused", branch: branch.value };
    const repo = repoResult.repo;
    const [baseSha, currentHeadSha, pulls] = await Promise.all([
      this.baseSha(repo, pullRequest.base),
      this.branchShaIfExists(repo, branch.value),
      this.request<GithubPullDetailResponse[]>(
        repo,
        `/pulls?head=${encodeURIComponent(`${repo.owner}:${branch.value}`)}&state=all&per_page=100`,
        { method: "GET" },
      ),
    ]);
    if (baseSha.toLowerCase() !== pullRequest.expectedBaseSha.toLowerCase()) {
      return { ok: false, error: "base_sha_changed", expected_base_sha: pullRequest.expectedBaseSha, current_base_sha: baseSha };
    }
    if (!currentHeadSha || currentHeadSha !== input.expectedCandidateHeadSha.toLowerCase()) {
      return {
        ok: false,
        error: "self_improvement_candidate_head_changed",
        expected_head_sha: input.expectedCandidateHeadSha,
        current_head_sha: currentHeadSha,
      };
    }
    if (pulls.length !== 0) {
      return {
        ok: false,
        error: "self_improvement_candidate_pr_ambiguous",
        pull_numbers: pulls.map((pull) => pull.number),
      };
    }
    const repoFiles = pullRequest.files.map((file) => ({ ...file, path: this.toRepoPath(repo, file.path) }));
    let candidateHeadSha = currentHeadSha;
    if (candidateHeadSha === pullRequest.expectedHeadSha.toLowerCase()) {
      const committed = await this.commitFilesAtExpectedHead(repo, branch.value, candidateHeadSha, repoFiles);
      if (!committed.ok) return committed;
      candidateHeadSha = committed.headSha.toLowerCase();
    }
    const pr = await this.request<GithubPullDetailResponse>(repo, "/pulls", {
      method: "POST",
      body: {
        title: pullRequest.title,
        body: runtimePullRequestBody(pullRequest),
        head: branch.value,
        base: pullRequest.base,
        draft: true,
      },
    });
    const finalHeadSha = await this.branchShaIfExists(repo, branch.value);
    if (pr.state !== "open" || pr.draft !== true
      || pr.title !== pullRequest.title || (pr.body ?? "") !== runtimePullRequestBody(pullRequest)
      || pr.head?.ref !== branch.value || pr.head.repo?.full_name?.toLowerCase() !== repo.fullName.toLowerCase()
      || pr.head.sha?.toLowerCase() !== candidateHeadSha
      || pr.base?.ref !== pullRequest.base || pr.base.sha?.toLowerCase() !== pullRequest.expectedBaseSha.toLowerCase()
      || finalHeadSha !== candidateHeadSha) {
      return { ok: false, error: "candidate_pr_completion_mismatch", pull_number: pr.number };
    }
    return {
      ok: true,
      repo: repo.fullName,
      branch: branch.value,
      base: pullRequest.base,
      base_sha: baseSha,
      pull_request: {
        number: pr.number,
        url: pr.html_url,
        state: pr.state,
        head_sha: finalHeadSha,
      },
      reused_pull_request: false,
      files: pullRequest.files.map((file) => ({ path: normalizeRelativePath(file.path), bytes: Buffer.byteLength(file.content, "utf8") })),
    };
  }

  async pullRequestStatus(input: RuntimeCodeGithubPrStatusInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const repoResult = this.readRepo(input.repo);
    if (!repoResult.ok) return repoResult;
    const auth = this.assertConfigured();
    if (!auth.ok) return auth;
    const pullNumber = positiveInteger(input.pullNumber, "pull_number");
    if (!pullNumber.ok) return pullNumber;

    const pull = await this.request<GithubPullDetailResponse>(repoResult.repo, `/pulls/${pullNumber.value}`, { method: "GET" });
    const headSha = pull.head?.sha;
    const checks = input.includeChecks === false || !headSha
      ? undefined
      : await this.checksForRef(repoResult.repo, headSha);
    return {
      ok: true,
      repo: repoResult.repo.fullName,
      pull_request: {
        number: pull.number,
        url: pull.html_url,
        title: pull.title,
        state: pull.state,
        draft: pull.draft,
        merged: pull.merged,
        mergeable_state: pull.mergeable_state,
        author: pull.user?.login,
        head_ref: pull.head?.ref,
        head_sha: headSha,
        head_repo: pull.head?.repo?.full_name,
        base_ref: pull.base?.ref,
        base_sha: pull.base?.sha,
        updated_at: pull.updated_at,
      },
      checks,
    };
  }

  async checksStatus(input: RuntimeCodeGithubChecksInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const repoResult = this.readRepo(input.repo);
    if (!repoResult.ok) return repoResult;
    const auth = this.assertConfigured();
    if (!auth.ok) return auth;
    const ref = validateGithubRef(input.ref);
    if (!ref.ok) return ref;

    return {
      ok: true,
      repo: repoResult.repo.fullName,
      ref: ref.value,
      checks: await this.checksForRef(repoResult.repo, ref.value),
    };
  }

  async sourceList(input: RuntimeCodeGithubSourceListInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const repoResult = this.readRepo(input.repo);
    if (!repoResult.ok) return repoResult;
    const auth = this.assertConfigured();
    if (!auth.ok) return auth;
    const ref = validateGithubRef(input.ref);
    if (!ref.ok) return ref;

    const path = normalizeRelativePath(input.path ?? "");
    if (path) {
      const pathResult = validateCodePath(path);
      if (!pathResult.ok) return pathResult;
    }
    const maxEntries = bounded(input.maxEntries, 1, GITHUB_SOURCE_MAX_ENTRIES, 100);
    const resolvedRef = await this.resolveCommitSha(repoResult.repo, ref.value);
    if (!resolvedRef.ok) return resolvedRef;
    const repoPath = this.toRepoPath(repoResult.repo, path);
    const pathSuffix = repoPath ? `/${encodePath(repoPath)}` : "";
    const decoded = await this.request<GithubContentResponse[] | GithubContentResponse>(
      repoResult.repo,
      `/contents${pathSuffix}?ref=${encodeURIComponent(resolvedRef.sha)}`,
      { method: "GET" },
    );
    if (!Array.isArray(decoded)) {
      return {
        ok: false,
        error: "not_a_directory",
        repo: repoResult.repo.fullName,
        requested_ref: ref.value,
        resolved_ref: resolvedRef.sha,
        path: path || ".",
      };
    }

    const safeEntries = decoded.filter((entry): entry is GithubContentResponse & { path: string } => (
      typeof entry.path === "string" && validateCodePath(entry.path).ok
    ));
    return {
      ok: true,
      repo: repoResult.repo.fullName,
      requested_ref: ref.value,
      resolved_ref: resolvedRef.sha,
      path: path || ".",
      entries: safeEntries.slice(0, maxEntries).map((entry) => ({
        path: this.fromRepoPath(repoResult.repo, entry.path),
        type: entry.type,
        sha: entry.sha,
        bytes: entry.size,
      })),
      truncated: safeEntries.length > maxEntries,
      max_entries: maxEntries,
      entries_skipped: decoded.length - safeEntries.length,
    };
  }

  async sourceRead(input: RuntimeCodeGithubSourceReadInput): Promise<Record<string, unknown>> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const repoResult = this.readRepo(input.repo);
    if (!repoResult.ok) return repoResult;
    const auth = this.assertConfigured();
    if (!auth.ok) return auth;
    const ref = validateGithubRef(input.ref);
    if (!ref.ok) return ref;

    const normalizedPaths = unique(input.paths.map((path) => normalizeRelativePath(path)).filter(Boolean));
    if (normalizedPaths.length === 0) return { ok: false, error: "paths_required" };
    const paths = normalizedPaths.slice(0, GITHUB_SOURCE_MAX_FILES);
    for (const path of paths) {
      const pathResult = validateCodePath(path);
      if (!pathResult.ok) return pathResult;
    }
    const resolvedRef = await this.resolveCommitSha(repoResult.repo, ref.value);
    if (!resolvedRef.ok) return resolvedRef;

    const files: Record<string, unknown>[] = [];
    for (const path of paths) {
      const repoPath = this.toRepoPath(repoResult.repo, path);
      const file = await this.readSourceFile(repoResult.repo, resolvedRef.sha, repoPath);
      files.push({ ...file, path: this.fromRepoPath(repoResult.repo, repoPath) });
    }
    return {
      ok: true,
      repo: repoResult.repo.fullName,
      requested_ref: ref.value,
      resolved_ref: resolvedRef.sha,
      files,
      truncated: normalizedPaths.length > paths.length,
      max_files: GITHUB_SOURCE_MAX_FILES,
      max_file_bytes: GITHUB_SOURCE_MAX_FILE_BYTES,
    };
  }

  private assertConfigured(): RuntimeValidationResult {
    if (this.authMode() !== "not_configured") return { ok: true };
    return {
      ok: false,
      error: "github_auth_not_configured",
      message: "GitHub reads need CEREBRO_CODE_GITHUB_TOKEN or GitHub App installation credentials.",
    };
  }

  private toRepoPath(repo: GithubRepo, inputPath: string): string {
    const path = normalizeRelativePath(inputPath);
    const prefix = this.repoPathPrefix(repo);
    if (!prefix || path === prefix || path.startsWith(`${prefix}/`)) return path;
    return path ? `${prefix}/${path}` : prefix;
  }

  private fromRepoPath(repo: GithubRepo, inputPath: string): string {
    const path = normalizeRelativePath(inputPath);
    const prefix = this.repoPathPrefix(repo);
    if (!prefix) return path;
    if (path === prefix) return "";
    return path.startsWith(`${prefix}/`) ? path.slice(prefix.length + 1) : path;
  }

  private repoPathPrefix(repo: GithubRepo): string {
    const defaultRepo = normalizeRepo(this.config.code.defaultRepo);
    if (!defaultRepo || defaultRepo.fullName.toLowerCase() !== repo.fullName.toLowerCase()) return "";
    const prefix = normalizeRelativePath(this.config.code.repoPathPrefix);
    if (!prefix) return "";
    const valid = validateCodePath(prefix);
    if (!valid.ok) throw new Error("CEREBRO_CODE_REPO_PATH_PREFIX is invalid.");
    return prefix;
  }

  private readRepo(repoInput: string | undefined): { ok: true; repo: GithubRepo } | RuntimeCodeError {
    const repo = normalizeRepo(repoInput || this.config.code.defaultRepo);
    if (!repo) {
      return { ok: false, error: "repo_required", repo: repoInput, message: "Pass a GitHub repo as owner/name or a github.com repo URL." };
    }
    return { ok: true, repo };
  }

  private writeAllowedRepo(repoInput: string | undefined): { ok: true; repo: GithubRepo } | RuntimeCodeError {
    const repo = normalizeRepo(repoInput || this.config.code.defaultRepo);
    if (!repo) {
      return { ok: false, error: "repo_required", repo: repoInput, message: "Pass a GitHub repo as owner/name or a github.com repo URL." };
    }
    if (!hasCaseInsensitive(this.config.code.writeAllowedOrgs, repo.owner)) {
      return {
        ok: false,
        error: "repo_write_not_allowed",
        repo: repo.fullName,
        allowed_write_orgs: [...this.config.code.writeAllowedOrgs],
        message: "GitHub PR creation is limited to configured Writer organization repositories.",
      };
    }
    return { ok: true, repo };
  }

  private async defaultBranch(repo: GithubRepo): Promise<string> {
    const response = await this.request<GithubRepoResponse>(repo, "", { method: "GET" });
    return response.default_branch || "main";
  }

  private async resolveCommitSha(repo: GithubRepo, ref: string): Promise<{ ok: true; sha: string } | RuntimeCodeError> {
    const response = await this.request<GithubCommitResponse>(repo, `/commits/${encodeURIComponent(ref)}`, { method: "GET" });
    const sha = response.sha?.trim();
    if (!sha || !/^[a-f0-9]{40}$/i.test(sha)) {
      return {
        ok: false,
        error: "github_ref_resolution_failed",
        repo: repo.fullName,
        requested_ref: ref,
      };
    }
    return { ok: true, sha };
  }

  private async baseSha(repo: GithubRepo, baseBranch: string): Promise<string> {
    const encodedBranch = baseBranch.split("/").map(encodeURIComponent).join("/");
    const response = await this.request<GithubRefResponse>(repo, `/git/ref/heads/${encodedBranch}`, { method: "GET" });
    const sha = response.object?.sha;
    if (!sha) throw new Error(`GitHub base ref did not return a SHA for ${repo.fullName}:${baseBranch}`);
    return sha;
  }

  private async branchShaIfExists(repo: GithubRepo, branch: string): Promise<string | undefined> {
    const encodedBranch = branch.split("/").map(encodeURIComponent).join("/");
    const response = await this.boundedFetch(`https://api.github.com/repos/${repo.owner}/${repo.name}/git/ref/heads/${encodedBranch}`, {
      method: "GET",
      headers: await this.headers(),
    });
    if (response.status === 404) return undefined;
    await assertGithubOk(response);
    const decoded = await response.json() as GithubRefResponse;
    const sha = decoded.object?.sha?.trim();
    if (!sha || !/^[a-f0-9]{40}$/i.test(sha)) {
      throw new Error(`GitHub candidate ref did not return a SHA for ${repo.fullName}:${branch}`);
    }
    return sha.toLowerCase();
  }

  private async createBranch(repo: GithubRepo, branch: string, baseSha: string): Promise<"created" | "existing"> {
    const response = await this.boundedFetch(`https://api.github.com/repos/${repo.owner}/${repo.name}/git/refs`, {
      method: "POST",
      headers: await this.headers(),
      body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: baseSha }),
    });
    if (response.status === 422 && /reference already exists/i.test(await response.clone().text())) return "existing";
    await assertGithubOk(response);
    return "created";
  }

  private async putFile(repo: GithubRepo, branch: string, file: RuntimeCodeFileInput, message: string): Promise<void> {
    const path = normalizeRelativePath(file.path);
    const existing = await this.getFileSha(repo, branch, path);
    await this.request(repo, `/contents/${encodePath(path)}`, {
      method: "PUT",
      body: {
        message,
        branch,
        content: Buffer.from(file.content, "utf8").toString("base64"),
        sha: existing,
      },
    });
  }

  private async commitFilesAtExpectedHead(
    repo: GithubRepo,
    branch: string,
    expectedHeadSha: string,
    files: RuntimeCodeFileInput[],
  ): Promise<{ ok: true; headSha: string } | RuntimeCodeError> {
    const response = await this.boundedFetch("https://api.github.com/graphql", {
      method: "POST",
      headers: await this.headers(),
      body: JSON.stringify({
        query: `mutation CerebroCreateCommit($input: CreateCommitOnBranchInput!) {
          createCommitOnBranch(input: $input) { commit { oid } }
        }`,
        variables: {
          input: {
            branch: {
              repositoryNameWithOwner: repo.fullName,
              branchName: branch,
            },
            expectedHeadOid: expectedHeadSha,
            message: { headline: "Cerebro self-improvement candidate" },
            fileChanges: {
              additions: files.map((file) => ({
                path: normalizeRelativePath(file.path),
                contents: Buffer.from(file.content, "utf8").toString("base64"),
              })),
            },
          },
        },
      }),
    });
    await assertGithubOk(response);
    const decoded = await response.json() as GithubCreateCommitOnBranchResponse;
    const headSha = decoded.data?.createCommitOnBranch?.commit?.oid?.trim();
    if (headSha && /^[a-f0-9]{40}$/i.test(headSha)) return { ok: true, headSha };

    const currentHeadSha = await this.baseSha(repo, branch);
    if (currentHeadSha.toLowerCase() !== expectedHeadSha.toLowerCase()) {
      return noSideEffectStarted({
        ok: false,
        error: "self_improvement_candidate_head_changed",
        branch,
        expected_head_sha: expectedHeadSha,
        current_head_sha: currentHeadSha,
        message: "The candidate branch moved after inspection. Read current PR status before preparing another repair.",
      });
    }
    return {
      ok: false,
      error: "self_improvement_candidate_commit_refused",
      branch,
      expected_head_sha: expectedHeadSha,
      message: redactSecurityText(decoded.errors?.map((error) => error.message).filter(Boolean).join("; ") || "GitHub did not create the candidate commit."),
    };
  }

  private async getFileSha(repo: GithubRepo, branch: string, path: string): Promise<string | undefined> {
    const response = await this.boundedFetch(`https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${encodePath(path)}?ref=${encodeURIComponent(branch)}`, {
      method: "GET",
      headers: await this.headers(),
    });
    if (response.status === 404) return undefined;
    await assertGithubOk(response);
    const decoded = await response.json() as GithubContentResponse;
    return decoded.sha;
  }

  private async readSourceFile(repo: GithubRepo, ref: string, path: string): Promise<Record<string, unknown>> {
    const response = await this.boundedFetch(
      `https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${encodePath(path)}?ref=${encodeURIComponent(ref)}`,
      { method: "GET", headers: await this.headers() },
    );
    if (response.status === 404) return { ok: false, error: "file_not_found", path };
    await assertGithubOk(response);
    const decoded = await response.json() as GithubContentResponse | GithubContentResponse[];
    if (Array.isArray(decoded) || decoded.type !== "file") return { ok: false, error: "not_a_file", path };
    if (typeof decoded.size === "number" && decoded.size > GITHUB_SOURCE_MAX_FILE_BYTES) {
      return {
        ok: false,
        error: "file_too_large",
        path,
        bytes: decoded.size,
        max_file_bytes: GITHUB_SOURCE_MAX_FILE_BYTES,
      };
    }
    if (decoded.encoding !== "base64" || typeof decoded.content !== "string") {
      return { ok: false, error: "github_file_content_unavailable", path };
    }
    const contentBytes = Buffer.from(decoded.content.replace(/\s/g, ""), "base64");
    if (contentBytes.byteLength > GITHUB_SOURCE_MAX_FILE_BYTES) {
      return {
        ok: false,
        error: "file_too_large",
        path,
        bytes: contentBytes.byteLength,
        max_file_bytes: GITHUB_SOURCE_MAX_FILE_BYTES,
      };
    }
    let content: string;
    try {
      if (contentBytes.includes(0)) throw new TypeError("NUL byte");
      content = new TextDecoder("utf-8", { fatal: true }).decode(contentBytes);
    } catch {
      return { ok: false, error: "binary_file_refused", path };
    }
    if (redactSecurityText(content) !== content) {
      return { ok: false, error: "secret_like_content_refused", path };
    }
    return {
      ok: true,
      path,
      sha: decoded.sha,
      bytes: contentBytes.byteLength,
      content,
    };
  }

  private async checksForRef(repo: GithubRepo, ref: string): Promise<Record<string, unknown>> {
    const encodedRef = encodeURIComponent(ref);
    const [checkRuns, combinedStatus] = await Promise.all([
      this.request<GithubCheckRunsResponse>(repo, `/commits/${encodedRef}/check-runs?per_page=50`, { method: "GET" }),
      this.request<GithubCombinedStatusResponse>(repo, `/commits/${encodedRef}/status`, { method: "GET" }),
    ]);
    const runs = (checkRuns.check_runs ?? []).map((run) => ({
      name: run.name,
      status: run.status,
      conclusion: run.conclusion,
      app: run.app?.slug,
      url: run.html_url ?? run.details_url,
      started_at: run.started_at,
      completed_at: run.completed_at,
    }));
    const statuses = (combinedStatus.statuses ?? []).map((status) => ({
      context: status.context,
      state: status.state,
      description: status.description,
      url: status.target_url,
      updated_at: status.updated_at,
    }));
    return {
      summary: githubChecksSummary(runs, statuses, combinedStatus.state),
      check_runs: runs,
      statuses,
      combined_status: combinedStatus.state,
      check_run_count: checkRuns.total_count ?? runs.length,
      status_count: combinedStatus.total_count ?? statuses.length,
    };
  }

  private async request<T>(repo: GithubRepo, path: string, input: { method: string; body?: unknown }): Promise<T> {
    const response = await this.boundedFetch(`https://api.github.com/repos/${repo.owner}/${repo.name}${path}`, {
      method: input.method,
      headers: await this.headers(),
      body: input.body === undefined ? undefined : JSON.stringify(input.body),
    });
    await assertGithubOk(response);
    return await response.json() as T;
  }

  private async headers(): Promise<Record<string, string>> {
    return {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${await this.bearerToken()}`,
      "Content-Type": "application/json",
      "User-Agent": "cerebro-slack-companion",
      "X-GitHub-Api-Version": "2022-11-28",
    };
  }

  private async bearerToken(): Promise<string> {
    if (this.config.code.githubToken) return this.config.code.githubToken;
    const app = this.config.code.githubApp;
    if (!app) throw new Error("GitHub PR auth is not configured.");

    const now = Date.now();
    if (this.githubInstallationToken && this.githubInstallationToken.expiresAtMs - now > 60_000) {
      return this.githubInstallationToken.token;
    }

    const response = await this.boundedFetch(`https://api.github.com/app/installations/${encodeURIComponent(app.installationId)}/access_tokens`, {
      method: "POST",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${githubAppJwt(app)}`,
        "Content-Type": "application/json",
        "User-Agent": "cerebro-slack-companion",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    await assertGithubOk(response);
    const decoded = await response.json() as GithubInstallationTokenResponse;
    if (!decoded.token) throw new Error("GitHub App installation token response did not include a token.");
    const expiresAtMs = decoded.expires_at ? Date.parse(decoded.expires_at) : now + 3_000_000;
    this.githubInstallationToken = { token: decoded.token, expiresAtMs };
    return decoded.token;
  }

  private async boundedFetch(url: string, init: RequestInit): Promise<Response> {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || parsed.hostname !== "api.github.com" || parsed.port) {
      throw new Error("Runtime GitHub calls are limited to https://api.github.com.");
    }
    return fetch(parsed, { ...init, signal: AbortSignal.timeout(15_000) });
  }
}

function hasCaseInsensitive(values: Set<string>, candidate: string): boolean {
  const normalized = candidate.trim().toLowerCase();
  for (const value of values) {
    if (value.trim().toLowerCase() === normalized) return true;
  }
  return false;
}

export function runtimePullRequestBody(input: Pick<RuntimeCodePrInput, "body">): string {
  return [
    input.body?.trim() || "Runtime-authored Cerebro code change.",
    "",
    "Created by Cerebro runtime code tools. Review before merge.",
  ].join("\n");
}

function validateDraftBoundReuse(input: {
  branch: string;
  branchState: "created" | "existing";
  pullRequests: GithubPullDetailResponse[];
  repo: GithubRepo;
  baseBranch: string;
  baseSha: string;
  expectedHeadSha: string | undefined;
}): RuntimeValidationResult {
  const refuse = <T extends RuntimeCodeError>(error: T): T => input.branchState === "existing"
    ? noSideEffectStarted(error)
    : error;
  if (input.pullRequests.length > 1) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_pr_ambiguous",
      branch: input.branch,
      pull_numbers: input.pullRequests.map((pull) => pull.number),
      message: "The stable candidate branch has multiple open PRs. Resolve them before another write.",
    });
  }
  const pull = input.pullRequests[0];
  if (!pull) {
    return input.branchState === "created"
      ? { ok: true }
      : refuse({
          ok: false,
          error: "self_improvement_candidate_pr_missing",
          branch: input.branch,
          message: "The stable candidate branch exists without its expected open draft PR. Inspect it before another write.",
        });
  }
  if (pull.draft !== true) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_not_draft",
      branch: input.branch,
      pull_number: pull.number,
    });
  }
  if (pull.head?.ref !== input.branch || pull.head.repo?.full_name?.toLowerCase() !== input.repo.fullName.toLowerCase()) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_head_changed",
      branch: input.branch,
      pull_number: pull.number,
    });
  }
  if (pull.base?.ref !== input.baseBranch || pull.base.sha?.toLowerCase() !== input.baseSha.toLowerCase()) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_base_changed",
      branch: input.branch,
      pull_number: pull.number,
      expected_base: input.baseBranch,
      expected_base_sha: input.baseSha,
      current_base: pull.base?.ref,
      current_base_sha: pull.base?.sha,
    });
  }
  if (!input.expectedHeadSha || !/^[a-f0-9]{40}$/i.test(input.expectedHeadSha)) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_head_sha_required",
      branch: input.branch,
      pull_number: pull.number,
      message: "Inspect the current draft PR and pass its exact head SHA before updating the candidate.",
    });
  }
  if (pull.head?.sha?.toLowerCase() !== input.expectedHeadSha.toLowerCase()) {
    return refuse({
      ok: false,
      error: "self_improvement_candidate_head_changed",
      branch: input.branch,
      pull_number: pull.number,
      expected_head_sha: input.expectedHeadSha,
      current_head_sha: pull.head?.sha,
    });
  }
  return { ok: true };
}

function noSideEffectStarted<T extends RuntimeCodeError>(error: T): T {
  return { ...error, side_effect_outcome: "not_started" };
}

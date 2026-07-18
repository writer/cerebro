import type { AppConfig } from "../config/index.js";
import { RuntimeCodeFiles } from "./runtime-code-files.js";
import { RuntimeCodeGithubClient } from "./runtime-code-github-client.js";
import type {
  RuntimeCodeFileInput,
  RuntimeCodeGithubChecksInput,
  RuntimeCodeGithubPrStatusInput,
  RuntimeCodeGithubSourceListInput,
  RuntimeCodeGithubSourceReadInput,
  RuntimeCodePrInput,
  RuntimeCodeReadManyInput,
  RuntimeCodeSearchInput,
  RuntimeSelfImprovementPrInput,
  RuntimeShellInput,
} from "./runtime-code-types.js";

export type {
  RuntimeCodeFileInput,
  RuntimeCodeGithubChecksInput,
  RuntimeCodeGithubPrStatusInput,
  RuntimeCodeGithubSourceListInput,
  RuntimeCodeGithubSourceReadInput,
  RuntimeCodePrInput,
  RuntimeCodeReadManyInput,
  RuntimeCodeSearchInput,
  RuntimeSelfImprovementPrInput,
  RuntimeShellInput,
} from "./runtime-code-types.js";

export class RuntimeCodeWorkspace {
  private readonly files: RuntimeCodeFiles;
  private readonly github: RuntimeCodeGithubClient;

  constructor(private readonly config: AppConfig) {
    this.files = new RuntimeCodeFiles(config);
    this.github = new RuntimeCodeGithubClient(config);
  }

  status(): Record<string, unknown> {
    const githubAuthMode = this.github.authMode();
    return {
      enabled: this.config.code.enabled,
      workspace_dir: this.config.code.workspaceDir,
      shell_enabled: false,
      shell_unavailable_reason: "OS sandbox is not configured.",
      github_pr_enabled: githubAuthMode !== "not_configured",
      github_auth_mode: githubAuthMode,
      default_repo: this.config.code.defaultRepo,
      github_read_scope: "any_repo",
      write_allowed_orgs: [...this.config.code.writeAllowedOrgs],
      branch_prefix: this.config.code.branchPrefix,
      max_file_bytes: this.config.code.maxFileBytes,
      max_files: this.config.code.maxFiles,
      safety: "Runtime code is limited to bounded workspace files and reviewable GitHub pull requests. Host shell execution is unavailable.",
    };
  }

  listFiles(prefix = ""): Record<string, unknown> {
    return this.files.listFiles(prefix);
  }

  readFile(path: string): Record<string, unknown> {
    return this.files.readFile(path);
  }

  readMany(input: RuntimeCodeReadManyInput): Record<string, unknown> {
    return this.files.readMany(input);
  }

  searchFiles(input: RuntimeCodeSearchInput): Record<string, unknown> {
    return this.files.searchFiles(input);
  }

  writeFile(input: RuntimeCodeFileInput): Record<string, unknown> {
    return this.files.writeFile(input);
  }

  patchFile(input: { path: string; oldText: string; newText: string }): Record<string, unknown> {
    return this.files.patchFile(input);
  }

  async createGithubPullRequest(input: RuntimeCodePrInput): Promise<Record<string, unknown>> {
    return this.github.createPullRequest(input);
  }

  async createSelfImprovementPullRequest(input: RuntimeSelfImprovementPrInput): Promise<Record<string, unknown>> {
    return this.github.createSelfImprovementPullRequest(input);
  }

  async githubPullRequestStatus(input: RuntimeCodeGithubPrStatusInput): Promise<Record<string, unknown>> {
    return this.github.pullRequestStatus(input);
  }

  async githubChecksStatus(input: RuntimeCodeGithubChecksInput): Promise<Record<string, unknown>> {
    return this.github.checksStatus(input);
  }

  async githubSourceList(input: RuntimeCodeGithubSourceListInput): Promise<Record<string, unknown>> {
    return this.github.sourceList(input);
  }

  async githubSourceRead(input: RuntimeCodeGithubSourceReadInput): Promise<Record<string, unknown>> {
    return this.github.sourceRead(input);
  }

  async runShell(_input: RuntimeShellInput): Promise<Record<string, unknown>> {
    return {
      ok: false,
      error: "runtime_shell_requires_os_sandbox",
      message: "Shell execution is unavailable until the runtime has enforced filesystem and network isolation.",
    };
  }
}

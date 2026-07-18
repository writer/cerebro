export interface RuntimeCodeFileInput {
  path: string;
  content: string;
}

export interface RuntimeCodePrInput {
  repo?: string;
  title: string;
  body?: string;
  files: RuntimeCodeFileInput[];
  branch?: string;
  base?: string;
  expectedBaseSha?: string;
  expectedHeadSha?: string;
  draft?: boolean;
  draftBoundReuse?: boolean;
}

export interface RuntimeSelfImprovementPrInput {
  candidateId: string;
  baseSha: string;
  expectedHeadSha?: string;
  title: string;
  body?: string;
  files: RuntimeCodeFileInput[];
}

export interface RuntimeCodeGithubPrStatusInput {
  repo?: string;
  pullNumber: number;
  includeChecks?: boolean;
}

export interface RuntimeCodeGithubCandidateStateInput {
  repo?: string;
  branch: string;
  paths: string[];
}

export interface RuntimeCodeGithubCompleteCandidateInput {
  pullRequest: RuntimeCodePrInput;
  expectedCandidateHeadSha: string;
}

export interface RuntimeCodeGithubChecksInput {
  repo?: string;
  ref: string;
}

export interface RuntimeCodeGithubSourceListInput {
  repo?: string;
  ref: string;
  path?: string;
  maxEntries?: number;
}

export interface RuntimeCodeGithubSourceReadInput {
  repo?: string;
  ref: string;
  paths: string[];
}

export interface RuntimeShellInput {
  command: string;
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface RuntimeCodeSearchInput {
  query: string;
  prefix?: string;
  maxResults?: number;
  caseSensitive?: boolean;
}

export interface RuntimeCodeReadManyInput {
  paths: string[];
}

export interface GithubRepo {
  owner: string;
  name: string;
  fullName: string;
}

export interface GithubRefResponse {
  object?: { sha?: string };
}

export interface GithubRepoResponse {
  default_branch?: string;
}

export interface GithubCommitResponse {
  sha?: string;
  parents?: Array<{ sha?: string }>;
  files?: Array<{ filename?: string; status?: string; previous_filename?: string }>;
}

export interface GithubCreateCommitOnBranchResponse {
  data?: {
    createCommitOnBranch?: {
      commit?: { oid?: string };
    };
  };
  errors?: Array<{ message?: string; type?: string }>;
}

export interface GithubContentResponse {
  content?: string;
  encoding?: string;
  name?: string;
  path?: string;
  sha?: string;
  size?: number;
  type?: string;
}

export interface GithubPullResponse {
  html_url?: string;
  number?: number;
  state?: string;
  head?: {
    ref?: string;
    sha?: string;
    repo?: { full_name?: string };
  };
}

export interface GithubPullDetailResponse extends GithubPullResponse {
  title?: string;
  body?: string | null;
  draft?: boolean;
  merged?: boolean;
  mergeable_state?: string;
  updated_at?: string;
  user?: { login?: string };
  base?: {
    ref?: string;
    sha?: string;
  };
}

export interface GithubCheckRunsResponse {
  total_count?: number;
  check_runs?: GithubCheckRunResponse[];
}

export interface GithubCheckRunResponse {
  name?: string;
  status?: string;
  conclusion?: string | null;
  html_url?: string;
  details_url?: string;
  started_at?: string | null;
  completed_at?: string | null;
  app?: { slug?: string };
}

export interface GithubCombinedStatusResponse {
  state?: string;
  total_count?: number;
  statuses?: GithubCommitStatusResponse[];
}

export interface GithubCommitStatusResponse {
  context?: string;
  state?: string;
  description?: string | null;
  target_url?: string | null;
  updated_at?: string;
}

export interface GithubInstallationTokenResponse {
  token?: string;
  expires_at?: string;
}

export type RuntimeCodeError = {
  ok: false;
  error: string;
  side_effect_outcome?: "not_started";
  [key: string]: unknown;
};
export type RuntimeCodeOk = { ok: true };
export type RuntimePathResult = { ok: true; path: string } | RuntimeCodeError;
export type RuntimeValidationResult = RuntimeCodeOk | RuntimeCodeError;
export type GithubAuthMode = "token" | "app" | "not_configured";

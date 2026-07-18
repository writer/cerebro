import { z } from "zod";
import type { AppConfig } from "./types.js";
import { csvSet, parseBoolean } from "./parsing.js";

const workerEnvSchema = z.object({
  CEREBRO_IMPROVEMENT_WORKER_LANE: z.enum(["all", "author", "verifier"]).default("all"),
  CEREBRO_IMPROVEMENT_TABLE_NAME: z.string().min(1),
  CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET: z.string().min(1),
  CEREBRO_IMPROVEMENT_QUEUE_URL: z.string().url(),
  CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID: z.string().min(1).optional(),
  CEREBRO_IMPROVEMENT_EVIDENCE_KEY_ID: z.string().min(1).optional(),
  CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID: z.string().min(1).optional(),
  CEREBRO_IMPROVEMENT_DELEGATION_POLICY_VERSION: z.string().min(1).max(100).default("cerebro-improvement-author-v1"),
  CEREBRO_IMPROVEMENT_DELEGATION_TOOLSET_VERSION: z.string().min(1).max(100).default("candidate-author-v1"),
  CEREBRO_IMPROVEMENT_POLL_INTERVAL_MS: z.coerce.number().int().positive().default(5_000),
  CEREBRO_IMPROVEMENT_STALE_RUN_HOURS: z.coerce.number().int().positive().default(72),
  CEREBRO_IMPROVEMENT_AUTHOR_TIMEOUT_MS: z.coerce.number().int().min(30_000).max(600_000).default(300_000),
  CEREBRO_IMPROVEMENT_AUTHOR_PROVIDER: z.string().default("amazon-bedrock"),
  CEREBRO_IMPROVEMENT_AUTHOR_MODEL: z.string().default("us.anthropic.claude-opus-4-8"),
  CEREBRO_IMPROVEMENT_AUTHOR_THINKING_LEVEL: z.enum(["off", "minimal", "low", "medium", "high", "xhigh"]).default("medium"),
  CEREBRO_IMPROVEMENT_AUTHOR_MAX_SOURCE_CALLS: z.coerce.number().int().min(2).max(8).default(8),
  CEREBRO_CODE_WRITE_ENABLED: z.string().default("true"),
  CEREBRO_CODE_WORKSPACE_DIR: z.string().default("/tmp/cerebro-improvement-code"),
  CEREBRO_CODE_DEFAULT_REPO: z.string().default("writer/cerebro"),
  CEREBRO_CODE_REPO_PATH_PREFIX: z.string().default("services/slack-companion"),
  CEREBRO_CODE_WRITE_ALLOWED_ORGS: z.string().default("WriterInternal"),
  CEREBRO_CODE_BRANCH_PREFIX: z.string().default("cerebro/improvement"),
  CEREBRO_CODE_MAX_FILE_BYTES: z.coerce.number().int().positive().default(120_000),
  CEREBRO_CODE_MAX_FILES: z.coerce.number().int().positive().default(12),
  CEREBRO_CODE_GITHUB_APP_ID: z.string().min(1).optional(),
  CEREBRO_CODE_GITHUB_INSTALLATION_ID: z.string().min(1).optional(),
  CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64: z.string().min(1).optional(),
}).superRefine((value, context) => {
  if (value.CEREBRO_IMPROVEMENT_WORKER_LANE !== "author" && !value.CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID) {
    context.addIssue({ code: "custom", message: "Verifier workers require the promotion verification key.", path: ["CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID"] });
  }
  if (value.CEREBRO_IMPROVEMENT_WORKER_LANE !== "author" && !value.CEREBRO_IMPROVEMENT_EVIDENCE_KEY_ID) {
    context.addIssue({ code: "custom", message: "Verifier workers require the evidence verification key.", path: ["CEREBRO_IMPROVEMENT_EVIDENCE_KEY_ID"] });
  }
  if (value.CEREBRO_IMPROVEMENT_WORKER_LANE !== "verifier"
    && (!value.CEREBRO_CODE_GITHUB_APP_ID || !value.CEREBRO_CODE_GITHUB_INSTALLATION_ID || !value.CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64)) {
    context.addIssue({ code: "custom", message: "Author workers require the scoped GitHub App credential.", path: ["CEREBRO_CODE_GITHUB_APP_ID"] });
  }
  if (value.CEREBRO_IMPROVEMENT_WORKER_LANE === "author" && !value.CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID) {
    context.addIssue({ code: "custom", message: "Author workers require the delegation verification key.", path: ["CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID"] });
  }
});

export type ImprovementWorkerLane = "all" | "author" | "verifier";

export interface ImprovementWorkerConfig {
  lane: ImprovementWorkerLane;
  tableName: string;
  artifactBucket: string;
  queueUrl: string;
  promotionKeyId?: string;
  evidenceKeyId?: string;
  delegationKeyId?: string;
  delegationPolicyVersion: string;
  delegationToolsetVersion: string;
  pollIntervalMs: number;
  staleRunHours: number;
  author: {
    provider: string;
    model: string;
    thinkingLevel: "off" | "minimal" | "low" | "medium" | "high" | "xhigh";
    timeoutMs: number;
    maxSourceCalls: number;
  };
  code: AppConfig["code"];
}

export function loadImprovementWorkerConfig(env: NodeJS.ProcessEnv = process.env): ImprovementWorkerConfig {
  const parsed = workerEnvSchema.parse(env);
  const githubApp = parsed.CEREBRO_CODE_GITHUB_APP_ID
    && parsed.CEREBRO_CODE_GITHUB_INSTALLATION_ID
    && parsed.CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64
    ? {
        appId: parsed.CEREBRO_CODE_GITHUB_APP_ID,
        installationId: parsed.CEREBRO_CODE_GITHUB_INSTALLATION_ID,
        privateKeyBase64: parsed.CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64,
      }
    : undefined;
  return {
    lane: parsed.CEREBRO_IMPROVEMENT_WORKER_LANE,
    tableName: parsed.CEREBRO_IMPROVEMENT_TABLE_NAME,
    artifactBucket: parsed.CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET,
    queueUrl: parsed.CEREBRO_IMPROVEMENT_QUEUE_URL,
    promotionKeyId: parsed.CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID,
    evidenceKeyId: parsed.CEREBRO_IMPROVEMENT_EVIDENCE_KEY_ID,
    delegationKeyId: parsed.CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID,
    delegationPolicyVersion: parsed.CEREBRO_IMPROVEMENT_DELEGATION_POLICY_VERSION,
    delegationToolsetVersion: parsed.CEREBRO_IMPROVEMENT_DELEGATION_TOOLSET_VERSION,
    pollIntervalMs: parsed.CEREBRO_IMPROVEMENT_POLL_INTERVAL_MS,
    staleRunHours: parsed.CEREBRO_IMPROVEMENT_STALE_RUN_HOURS,
    author: {
      provider: parsed.CEREBRO_IMPROVEMENT_AUTHOR_PROVIDER,
      model: parsed.CEREBRO_IMPROVEMENT_AUTHOR_MODEL,
      thinkingLevel: parsed.CEREBRO_IMPROVEMENT_AUTHOR_THINKING_LEVEL,
      timeoutMs: parsed.CEREBRO_IMPROVEMENT_AUTHOR_TIMEOUT_MS,
      maxSourceCalls: parsed.CEREBRO_IMPROVEMENT_AUTHOR_MAX_SOURCE_CALLS,
    },
    code: {
      enabled: parsed.CEREBRO_IMPROVEMENT_WORKER_LANE === "verifier" ? false : parseBoolean(parsed.CEREBRO_CODE_WRITE_ENABLED),
      workspaceDir: parsed.CEREBRO_CODE_WORKSPACE_DIR,
      defaultRepo: parsed.CEREBRO_CODE_DEFAULT_REPO,
      repoPathPrefix: parsed.CEREBRO_CODE_REPO_PATH_PREFIX,
      writeAllowedOrgs: csvSet(parsed.CEREBRO_CODE_WRITE_ALLOWED_ORGS),
      branchPrefix: parsed.CEREBRO_CODE_BRANCH_PREFIX,
      maxFileBytes: parsed.CEREBRO_CODE_MAX_FILE_BYTES,
      maxFiles: parsed.CEREBRO_CODE_MAX_FILES,
      shellEnabled: false,
      shellTimeoutMs: 1_000,
      shellMaxOutputBytes: 1_000,
      shellMaxCommandBytes: 1_000,
      githubApp,
    },
  };
}

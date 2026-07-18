import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import type { GithubRepo, RuntimeCodeError, RuntimeCodeFileInput, RuntimeValidationResult } from "./runtime-code-types.js";
import { normalizeRelativePath } from "./runtime-code-utils.js";

export function validateCodeFile(config: Pick<AppConfig, "code">, input: RuntimeCodeFileInput): RuntimeValidationResult {
  const pathValidation = validateCodePath(input.path);
  if (!pathValidation.ok) return pathValidation;
  if (typeof input.content !== "string") return { ok: false, error: "content_required", path: input.path };
  const bytes = Buffer.byteLength(input.content, "utf8");
  if (bytes > config.code.maxFileBytes) {
    return { ok: false, error: "file_too_large", path: input.path, bytes, max_file_bytes: config.code.maxFileBytes };
  }
  if (redactSecurityText(input.content) !== input.content) {
    return { ok: false, error: "secret_like_content_refused", path: input.path };
  }
  return { ok: true };
}

const SELF_IMPROVEMENT_PROTECTED_PATHS = [
  ".github/",
  "catalog-info.yaml",
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "src/auth.ts",
  "src/agent/code-mode/",
  "src/agent/flue-security-assistant.ts",
  "src/agent/research-state.ts",
  "src/agent/security-assistant.ts",
  "src/agent/security-assistant-tool-hooks.ts",
  "src/agent/tool-catalog.ts",
  "src/agent/tool-policy.ts",
  "src/agent/tool-packs.ts",
  "src/agent/tools/index.ts",
  "src/agent/tools/operator-tools.ts",
  "src/agent/tools/tool-metadata.ts",
  "src/code/runtime-code",
  "src/config/",
  "src/improvement/",
  "src/security/",
  "src/slack/actions/",
  "src/slack/app.ts",
  "src/slack/commands/",
  "src/slack/events/",
  "src/work/companion-work-loop.ts",
  "src/learning/assistant-frontier-eval.ts",
  "src/learning/assistant-offline-judge.ts",
  "src/learning/traffic-replay.ts",
];

export function validateSelfImprovementCodeFile(
  config: Pick<AppConfig, "code">,
  input: RuntimeCodeFileInput,
): RuntimeValidationResult {
  const valid = validateCodeFile(config, input);
  if (!valid.ok) return valid;
  const normalized = normalizeRelativePath(input.path).toLowerCase();
  if (SELF_IMPROVEMENT_PROTECTED_PATHS.some((path) => normalized === path || normalized.startsWith(path))) {
    return {
      ok: false,
      error: "self_improvement_protected_path",
      path: input.path,
      message: "This path changes the assistant's authority, Slack actor ingress, release gates, credentials, dependencies, or Code Mode boundary and requires the normal reviewed code-change path.",
    };
  }
  if (!/^(docs\/|src\/|test\/|readme\.md$|telemetry(?:\.spec)?\.md$)/.test(normalized)) {
    return {
      ok: false,
      error: "self_improvement_path_not_allowed",
      path: input.path,
    };
  }
  return { ok: true };
}

export function validateCodePath(path: string): RuntimeValidationResult {
  const normalized = normalizeRelativePath(path);
  if (!normalized || normalized === ".") return { ok: false, error: "path_required" };
  if (normalized.startsWith("/") || /^[A-Za-z]:\//.test(normalized)) return { ok: false, error: "absolute_path_refused", path };
  const parts = normalized.split("/");
  if (parts.includes("..")) return { ok: false, error: "path_traversal_refused", path };
  if (parts.some((part) => part === ".git" || part === "node_modules" || part === ".aws" || part === ".ssh")) {
    return { ok: false, error: "unsafe_path_refused", path };
  }
  const basename = parts.at(-1)?.toLowerCase() ?? "";
  if (basename === ".env" || basename.endsWith(".pem") || basename.endsWith(".key") || basename.includes("secret")) {
    return { ok: false, error: "secret_path_refused", path };
  }
  return { ok: true };
}

export function validateGithubRef(ref: string): { ok: true; value: string } | RuntimeCodeError {
  const trimmed = ref.trim();
  if (!trimmed) return { ok: false, error: "ref_required" };
  if (trimmed.length > 200) return { ok: false, error: "ref_too_long" };
  if (redactSecurityText(trimmed) !== trimmed) return { ok: false, error: "secret_like_ref_refused" };
  if (/[\u0000-\u001f\s]/.test(trimmed) || trimmed.includes("..") || trimmed.startsWith("/") || trimmed.endsWith("/") || trimmed.endsWith(".")) {
    return { ok: false, error: "invalid_ref", ref };
  }
  return { ok: true, value: trimmed };
}

export function positiveInteger(value: number, field: string): { ok: true; value: number } | RuntimeCodeError {
  if (!Number.isInteger(value) || value <= 0) return { ok: false, error: `${field}_required` };
  return { ok: true, value };
}

export function normalizeRepo(value: string): GithubRepo | undefined {
  const trimmed = value.trim();
  const urlMatch = trimmed.match(/^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)(?:\/(?:pull|issues|tree|commit)\/.*)?$/i);
  const match = urlMatch ?? trimmed.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  if (!match) return undefined;
  return { owner: match[1]!, name: match[2]!, fullName: `${match[1]}/${match[2]}` };
}

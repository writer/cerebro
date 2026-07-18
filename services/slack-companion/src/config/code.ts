import type { ParsedEnv } from "./env.js";
import { csvSet, parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildCodeConfig(parsed: ParsedEnv): AppConfig["code"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_CODE_WRITE_ENABLED),
    workspaceDir: parsed.CEREBRO_CODE_WORKSPACE_DIR,
    defaultRepo: parsed.CEREBRO_CODE_DEFAULT_REPO,
    repoPathPrefix: parsed.CEREBRO_CODE_REPO_PATH_PREFIX,
    writeAllowedOrgs: csvSet(parsed.CEREBRO_CODE_WRITE_ALLOWED_ORGS),
    branchPrefix: parsed.CEREBRO_CODE_BRANCH_PREFIX,
    maxFileBytes: parsed.CEREBRO_CODE_MAX_FILE_BYTES,
    maxFiles: parsed.CEREBRO_CODE_MAX_FILES,
    shellEnabled: parseBoolean(parsed.CEREBRO_CODE_SHELL_ENABLED),
    shellTimeoutMs: parsed.CEREBRO_CODE_SHELL_TIMEOUT_MS,
    shellMaxOutputBytes: parsed.CEREBRO_CODE_SHELL_MAX_OUTPUT_BYTES,
    shellMaxCommandBytes: parsed.CEREBRO_CODE_SHELL_MAX_COMMAND_BYTES,
    githubToken: parsed.CEREBRO_CODE_GITHUB_TOKEN,
    githubApp: githubAppConfig(parsed),
  };
}

function githubAppConfig(parsed: ParsedEnv): AppConfig["code"]["githubApp"] {
  const appId = parsed.CEREBRO_CODE_GITHUB_APP_ID?.trim();
  const installationId = parsed.CEREBRO_CODE_GITHUB_INSTALLATION_ID?.trim();
  const privateKeyBase64 = parsed.CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64?.trim();
  const provided = [appId, installationId, privateKeyBase64].filter(Boolean).length;
  if (provided === 0) return undefined;
  if (provided !== 3) {
    throw new Error("GitHub App runtime PR auth needs CEREBRO_CODE_GITHUB_APP_ID, CEREBRO_CODE_GITHUB_INSTALLATION_ID, and CEREBRO_CODE_GITHUB_PRIVATE_KEY_BASE64.");
  }
  return {
    appId: appId!,
    installationId: installationId!,
    privateKeyBase64: privateKeyBase64!,
  };
}

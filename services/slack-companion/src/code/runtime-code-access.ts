import { resolve, sep } from "node:path";
import type { AppConfig } from "../config/index.js";
import type { RuntimePathResult, RuntimeValidationResult } from "./runtime-code-types.js";
import { normalizeRelativePath } from "./runtime-code-utils.js";
import { validateCodePath } from "./runtime-code-validators.js";

export function assertRuntimeCodeAllowed(config: Pick<AppConfig, "code">): RuntimeValidationResult {
  if (!config.code.enabled) return { ok: false, error: "runtime_code_disabled" };
  return { ok: true };
}

export function workspacePath(config: Pick<AppConfig, "code">, path: string, options: { allowRoot?: boolean } = {}): RuntimePathResult {
  const validation = validateCodePath(path);
  if (!validation.ok && !(options.allowRoot && validation.error === "path_required" && normalizeRelativePath(path || ".") === ".")) {
    return validation;
  }
  const root = resolve(config.code.workspaceDir);
  const target = resolve(root, normalizeRelativePath(path || "."));
  if (target !== root && !target.startsWith(`${root}${sep}`)) {
    return { ok: false, error: "path_outside_workspace", path };
  }
  return { ok: true, path: target };
}

import path from "node:path";
import { minimatch } from "minimatch";

export function normalizeRepoPath(file: string, cwd = process.cwd()): string {
  const raw = file.trim().replace(/^"|"$/g, "").replace(/\\/g, "/");
  if (!raw || raw === "/dev/null" || raw === "dev/null") {
    return raw;
  }

  const withoutDiffPrefix = raw.replace(/^(?:a|b)\//, "").replace(/^\.\//, "");
  const cwdPath = path.resolve(cwd).replace(/\\/g, "/");
  const candidates = [withoutDiffPrefix];
  if (!withoutDiffPrefix.startsWith("/")) {
    candidates.push(`/${withoutDiffPrefix}`);
  }

  for (const candidate of candidates) {
    const normalized = path.normalize(candidate).replace(/\\/g, "/");
    if (normalized === cwdPath) {
      return "";
    }
    if (normalized.startsWith(`${cwdPath}/`)) {
      return normalized.slice(cwdPath.length + 1);
    }
  }

  return withoutDiffPrefix.replace(/^\/+/, "");
}

export function matchesRepoPattern(file: string, pattern: string): boolean {
  const normalized = normalizeRepoPath(file);
  if (minimatch(normalized, pattern, { dot: true })) {
    return true;
  }
  const nestedPattern = pattern.startsWith("**/") ? pattern : `**/${pattern}`;
  return minimatch(normalized, nestedPattern, { dot: true });
}

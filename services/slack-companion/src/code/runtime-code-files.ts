import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, relative } from "node:path";
import type { AppConfig } from "../config/index.js";
import { redactSecurityText } from "../security/redaction.js";
import { assertRuntimeCodeAllowed, workspacePath } from "./runtime-code-access.js";
import type {
  RuntimeCodeFileInput,
  RuntimeCodeReadManyInput,
  RuntimeCodeSearchInput,
} from "./runtime-code-types.js";
import { atomicWrite, bounded, normalizeRelativePath, occurrences, sha256, unifiedDiff, unique, walk } from "./runtime-code-utils.js";
import { validateCodeFile } from "./runtime-code-validators.js";

export class RuntimeCodeFiles {
  constructor(private readonly config: AppConfig) {}

  listFiles(prefix = ""): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const root = workspacePath(this.config, prefix || ".");
    if (!root.ok) return root;
    if (!existsSync(root.path)) return { ok: true, files: [] };
    const files: Array<{ path: string; bytes: number; updated_at: string }> = [];
    walk(root.path, (file) => {
      const stats = statSync(file);
      files.push({
        path: normalizeRelativePath(relative(this.config.code.workspaceDir, file)),
        bytes: stats.size,
        updated_at: stats.mtime.toISOString(),
      });
    });
    return { ok: true, files: files.slice(0, 200) };
  }

  readFile(path: string): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const target = workspacePath(this.config, path);
    if (!target.ok) return target;
    if (!existsSync(target.path)) return { ok: false, error: "file_not_found", path };
    const stats = statSync(target.path);
    if (!stats.isFile()) return { ok: false, error: "not_a_file", path };
    if (stats.size > this.config.code.maxFileBytes) {
      return { ok: false, error: "file_too_large", path, bytes: stats.size, max_file_bytes: this.config.code.maxFileBytes };
    }
    return {
      ok: true,
      path: normalizeRelativePath(path),
      content: readFileSync(target.path, "utf8"),
      bytes: stats.size,
      sha256: sha256(readFileSync(target.path)),
    };
  }

  readMany(input: RuntimeCodeReadManyInput): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const paths = unique(input.paths.map((path) => normalizeRelativePath(path)).filter(Boolean)).slice(0, 8);
    if (paths.length === 0) return { ok: false, error: "paths_required" };
    return {
      ok: true,
      files: paths.map((path) => this.readFile(path)),
      truncated: input.paths.length > paths.length,
      max_files: 8,
    };
  }

  searchFiles(input: RuntimeCodeSearchInput): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const query = input.query.trim();
    if (!query) return { ok: false, error: "query_required" };
    if (redactSecurityText(query) !== query) return { ok: false, error: "secret_like_query_refused" };
    const root = workspacePath(this.config, input.prefix || ".", { allowRoot: true });
    if (!root.ok) return root;
    if (!existsSync(root.path)) return { ok: true, query, files_searched: 0, matches: [] };
    const maxResults = bounded(input.maxResults, 1, 100, 25);
    const needle = input.caseSensitive ? query : query.toLowerCase();
    const matches: Array<{ path: string; line_number: number; line: string }> = [];
    let filesSearched = 0;
    let filesSkipped = 0;
    walk(root.path, (file) => {
      if (matches.length >= maxResults) return;
      const stats = statSync(file);
      if (!stats.isFile() || stats.size > this.config.code.maxFileBytes) {
        filesSkipped += 1;
        return;
      }
      const relativePath = normalizeRelativePath(relative(this.config.code.workspaceDir, file));
      const content = readFileSync(file, "utf8");
      filesSearched += 1;
      const lines = content.split(/\r?\n/);
      for (const [index, line] of lines.entries()) {
        if (matches.length >= maxResults) break;
        const haystack = input.caseSensitive ? line : line.toLowerCase();
        if (!haystack.includes(needle)) continue;
        matches.push({
          path: relativePath,
          line_number: index + 1,
          line: redactSecurityText(line).replace(/\s+/g, " ").trim().slice(0, 500),
        });
      }
    });
    return {
      ok: true,
      query,
      prefix: normalizeRelativePath(input.prefix || ".") || ".",
      files_searched: filesSearched,
      files_skipped: filesSkipped,
      match_count: matches.length,
      matches,
      truncated: matches.length >= maxResults,
    };
  }

  writeFile(input: RuntimeCodeFileInput): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const valid = validateCodeFile(this.config, input);
    if (!valid.ok) return valid;
    const target = workspacePath(this.config, input.path);
    if (!target.ok) return target;
    mkdirSync(dirname(target.path), { recursive: true });
    const previous = existsSync(target.path) ? readFileSync(target.path, "utf8") : undefined;
    atomicWrite(target.path, input.content);
    return {
      ok: true,
      path: normalizeRelativePath(input.path),
      bytes: Buffer.byteLength(input.content, "utf8"),
      sha256: sha256(input.content),
      changed: previous !== input.content,
      diff: unifiedDiff(normalizeRelativePath(input.path), previous ?? "", input.content),
    };
  }

  patchFile(input: { path: string; oldText: string; newText: string }): Record<string, unknown> {
    const allowed = assertRuntimeCodeAllowed(this.config);
    if (!allowed.ok) return allowed;
    const target = workspacePath(this.config, input.path);
    if (!target.ok) return target;
    if (!existsSync(target.path)) return { ok: false, error: "file_not_found", path: input.path };
    const previous = readFileSync(target.path, "utf8");
    const count = occurrences(previous, input.oldText);
    if (count === 0) return { ok: false, error: "old_text_not_found", path: input.path };
    if (count > 1) return { ok: false, error: "old_text_not_unique", path: input.path, matches: count };
    const content = previous.replace(input.oldText, input.newText);
    const valid = validateCodeFile(this.config, { path: input.path, content });
    if (!valid.ok) return valid;
    atomicWrite(target.path, content);
    return {
      ok: true,
      path: normalizeRelativePath(input.path),
      bytes: Buffer.byteLength(content, "utf8"),
      sha256: sha256(content),
      diff: unifiedDiff(normalizeRelativePath(input.path), previous, content),
    };
  }
}

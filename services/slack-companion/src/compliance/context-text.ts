import { createHash } from "node:crypto";
import { redactSecurityText } from "../security/redaction.js";
import type { ComplianceCorpus, CorpusChunk, LoadedSource } from "./context-types.js";

export const DEFAULT_CONTEXT_LIMIT = 6;
export const MAX_CONTEXT_LIMIT = 12;
const CHUNK_TARGET_CHARS = 2200;
const CHUNK_MIN_CHARS = 550;
const MAX_EXCERPT_CHARS = 900;

const STOP_WORDS = new Set([
  "about",
  "after",
  "again",
  "all",
  "also",
  "and",
  "are",
  "can",
  "for",
  "from",
  "have",
  "how",
  "into",
  "our",
  "that",
  "the",
  "their",
  "this",
  "what",
  "when",
  "where",
  "which",
  "with",
  "would",
]);

export function chunkSource(source: LoadedSource): CorpusChunk[] {
  if (!source.content.trim()) return [];
  const lines = source.content.replace(/\r\n/g, "\n").split("\n");
  const chunks: CorpusChunk[] = [];
  let current: string[] = [];
  let start = 1;
  let currentTitle = titleFromPath(source.path);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    const heading = markdownHeading(line) ?? yamlTitle(line);
    const currentLength = current.join("\n").length;
    if (heading && current.length > 0 && currentLength >= CHUNK_MIN_CHARS) {
      chunks.push(makeChunk(source, current, start, index, currentTitle));
      current = [];
      start = index + 1;
    }
    if (heading) currentTitle = heading;
    if (current.length > 0 && currentLength + line.length > CHUNK_TARGET_CHARS) {
      chunks.push(makeChunk(source, current, start, index, currentTitle));
      current = [];
      start = index + 1;
    }
    current.push(line);
  }
  if (current.length > 0) {
    chunks.push(makeChunk(source, current, start, lines.length, currentTitle));
  }
  return chunks;
}

export function scoreChunk(chunk: CorpusChunk, queryTokens: string[], rawQuery: string): number {
  const uniqueQueryTokens = [...new Set(queryTokens)];
  let score = 0;
  let matched = 0;
  for (const token of uniqueQueryTokens) {
    const textHits = chunk.tokens.get(token) ?? 0;
    const pathHit = chunk.pathTokens.has(token);
    const titleHit = chunk.titleTokens.has(token);
    if (textHits > 0 || pathHit || titleHit) matched += 1;
    score += Math.min(textHits, 6);
    if (pathHit) score += 4;
    if (titleHit) score += 3;
  }
  const normalizedQuery = rawQuery.toLowerCase().replace(/\s+/g, " ").trim();
  if (normalizedQuery.length >= 8 && chunk.textLower.replace(/\s+/g, " ").includes(normalizedQuery)) {
    score += 12;
  }
  const coverage = uniqueQueryTokens.length === 0 ? 0 : matched / uniqueQueryTokens.length;
  return score * (1 + coverage);
}

export function excerptFor(chunk: CorpusChunk, queryTokens: string[]): string {
  const lower = chunk.textLower;
  const positions = queryTokens
    .map((token) => lower.indexOf(token))
    .filter((position) => position >= 0);
  const first = positions.length > 0 ? Math.min(...positions) : 0;
  const start = Math.max(0, first - 220);
  const end = Math.min(chunk.text.length, start + MAX_EXCERPT_CHARS);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < chunk.text.length ? "..." : "";
  return redactSecurityText(`${prefix}${chunk.text.slice(start, end)}${suffix}`)
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function corpusOverview(corpus: ComplianceCorpus): Record<string, unknown> {
  const categories = new Map<string, number>();
  for (const chunk of corpus.chunks) {
    categories.set(chunk.category, (categories.get(chunk.category) ?? 0) + 1);
  }
  return {
    categories: Object.fromEntries([...categories.entries()].sort(([left], [right]) => left.localeCompare(right))),
    loaded_paths: [...new Set(corpus.chunks.map((chunk) => chunk.path))].sort(),
  };
}

export function tokenize(value: string): string[] {
  const matches = value.toLowerCase().match(/[a-z0-9][a-z0-9._:-]*/g) ?? [];
  return matches
    .map((token) => token.replace(/^[_:.-]+|[_:.-]+$/g, ""))
    .filter((token) => token.length >= 2 && !STOP_WORDS.has(token));
}

export function expandQueryTokens(tokens: string[]): string[] {
  const expanded = new Set(tokens);
  const addIfPresent = (needle: string, values: string[]) => {
    if (expanded.has(needle)) {
      values.forEach((value) => expanded.add(value));
    }
  };
  addIfPresent("compliance", ["grc", "audit", "control", "controls"]);
  addIfPresent("grc", ["compliance", "audit", "control"]);
  addIfPresent("audit", ["compliance", "evidence", "control"]);
  addIfPresent("policy", ["rule", "finding", "lifecycle"]);
  addIfPresent("soc2", ["soc", "cc6", "cc7"]);
  addIfPresent("soc", ["soc2"]);
  addIfPresent("gdpr", ["privacy", "data", "policy"]);
  addIfPresent("risk", ["assessment", "treatment", "readiness"]);
  addIfPresent("evidence", ["packet", "expectation", "freshness"]);
  return [...expanded];
}

export function normalizeRepoPath(path: string): string {
  return path.trim().replace(/^\/+/, "").replace(/\/+/g, "/");
}

export function normalizeRepoName(value: string): string | undefined {
  const trimmed = value.trim();
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(trimmed) ? trimmed : undefined;
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function sourceUrl(repo: string, ref: string, path: string, lineStart: number, lineEnd: number): string {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${repo}/blob/${encodeURIComponent(ref)}/${encodedPath}#L${lineStart}-L${lineEnd}`;
}

export function bounded(value: number | undefined, min: number, max: number, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

export function shortError(error: unknown): string {
  if (error instanceof Error) return error.message.slice(0, 160);
  return String(error).slice(0, 160);
}

export async function mapLimit<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      const item = items[index];
      if (item === undefined) continue;
      results[index] = await fn(item);
    }
  });
  await Promise.all(workers);
  return results;
}

export async function readBoundedResponseText(response: Response, maxBytes: number): Promise<{ content: string; bytes: number; tooLarge: boolean }> {
  const body = response.body;
  if (!body) {
    const content = await response.text();
    const bytes = Buffer.byteLength(content, "utf8");
    return { content: bytes > maxBytes ? "" : content, bytes, tooLarge: bytes > maxBytes };
  }
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    bytes += value.byteLength;
    if (bytes > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return { content: "", bytes, tooLarge: true };
    }
    chunks.push(Buffer.from(value));
  }
  const content = Buffer.concat(chunks).toString("utf8");
  return { content, bytes, tooLarge: false };
}

function makeChunk(source: LoadedSource, lines: string[], lineStart: number, lineEnd: number, title: string): CorpusChunk {
  const text = lines.join("\n").trim();
  return {
    path: source.path,
    category: source.category,
    title,
    text,
    textLower: text.toLowerCase(),
    lineStart,
    lineEnd,
    tokens: tokenCounts(text),
    pathTokens: new Set(tokenize(source.path)),
    titleTokens: new Set(tokenize(title)),
  };
}

function markdownHeading(line: string): string | undefined {
  const match = /^(#{1,4})\s+(.+?)\s*$/.exec(line);
  return match?.[2]?.trim();
}

function yamlTitle(line: string): string | undefined {
  const match = /^\s*(name|title|description):\s*"?([^"]+?)"?\s*$/.exec(line);
  const value = match?.[2]?.trim();
  return value && value.length <= 120 ? value : undefined;
}

function titleFromPath(path: string): string {
  const file = path.split("/").at(-1) ?? path;
  return file.replace(/\.(md|go|ya?ml|json)$/i, "").replace(/[-_]+/g, " ");
}

function tokenCounts(value: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const token of tokenize(value)) {
    counts.set(token, (counts.get(token) ?? 0) + 1);
  }
  return counts;
}

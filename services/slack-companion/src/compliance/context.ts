import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { AppConfig } from "../config/index.js";
import { COMPLIANCE_CONTEXT_EXCLUDED_PATHS, COMPLIANCE_CONTEXT_SOURCE_PATHS } from "./context-sources.js";
import {
  bounded,
  chunkSource,
  corpusOverview,
  DEFAULT_CONTEXT_LIMIT,
  excerptFor,
  expandQueryTokens,
  mapLimit,
  MAX_CONTEXT_LIMIT,
  normalizeRepoName,
  normalizeRepoPath,
  readBoundedResponseText,
  scoreChunk,
  sha256,
  shortError,
  sourceUrl,
  tokenize,
} from "./context-text.js";
import type {
  ComplianceContextSearchInput,
  ComplianceContextServiceOptions,
  ComplianceCorpus,
  CorpusSource,
  LoadedSource,
  SkippedSource,
} from "./context-types.js";

const serviceByConfig = new WeakMap<AppConfig, ComplianceContextService>();

export function complianceContextService(config: AppConfig): ComplianceContextService {
  const existing = serviceByConfig.get(config);
  if (existing) return existing;
  const service = new ComplianceContextService(config);
  serviceByConfig.set(config, service);
  return service;
}

export class ComplianceContextService {
  private cache?: ComplianceCorpus;
  private loading?: Promise<ComplianceCorpus>;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;

  constructor(private readonly config: AppConfig, options: ComplianceContextServiceOptions = {}) {
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? (() => Date.now());
  }

  async search(input: ComplianceContextSearchInput): Promise<Record<string, unknown>> {
    if (!this.config.complianceContext.enabled) {
      return {
        ok: false,
        error: "compliance_context_disabled",
        message: "Compliance context retrieval is disabled by configuration.",
      };
    }
    const query = input.query.trim();
    if (!query) return { ok: false, error: "query_required" };
    const corpus = await this.loadCorpus();
    const queryTokens = expandQueryTokens(tokenize(query));
    const limit = bounded(input.limit, 1, MAX_CONTEXT_LIMIT, DEFAULT_CONTEXT_LIMIT);
    const pathFilter = new Set((input.paths ?? []).map(normalizeRepoPath).filter(Boolean));
    const scored = corpus.chunks
      .filter((chunk) => pathFilter.size === 0 || pathFilter.has(chunk.path))
      .map((chunk) => ({ chunk, score: scoreChunk(chunk, queryTokens, query) }))
      .filter((item) => item.score > 0)
      .sort((left, right) => right.score - left.score || left.chunk.path.localeCompare(right.chunk.path))
      .slice(0, limit);

    return {
      ok: true,
      query,
      source: {
        repo: corpus.repo,
        ref: corpus.ref,
        mode: corpus.mode,
        digest: corpus.digest,
        loaded_at: new Date(corpus.loadedAtMs).toISOString(),
        cache_age_ms: Math.max(0, this.now() - corpus.loadedAtMs),
        source_count: corpus.sourceCount,
        chunk_count: corpus.chunks.length,
        bytes: corpus.bytes,
      },
      results: scored.map(({ chunk, score }) => ({
        path: chunk.path,
        category: chunk.category,
        title: chunk.title,
        line_start: chunk.lineStart,
        line_end: chunk.lineEnd,
        source_url: sourceUrl(corpus.repo, corpus.ref, chunk.path, chunk.lineStart, chunk.lineEnd),
        score: Number(score.toFixed(3)),
        excerpt: excerptFor(chunk, queryTokens),
      })),
      skipped_sources: input.includeOverview ? [...corpus.skipped, ...COMPLIANCE_CONTEXT_EXCLUDED_PATHS] : COMPLIANCE_CONTEXT_EXCLUDED_PATHS,
      overview: input.includeOverview ? corpusOverview(corpus) : undefined,
      note: "Use these snippets as source context from writer/cerebro. Verify tenant-specific state, current findings, and current evidence with live Cerebro tools before making present-tense claims.",
    };
  }

  async status(): Promise<Record<string, unknown>> {
    if (!this.config.complianceContext.enabled) {
      return { enabled: false };
    }
    const corpus = await this.loadCorpus();
    return {
      enabled: true,
      repo: corpus.repo,
      ref: corpus.ref,
      mode: corpus.mode,
      local_dir_configured: Boolean(this.config.complianceContext.localDir),
      source_count: corpus.sourceCount,
      chunk_count: corpus.chunks.length,
      bytes: corpus.bytes,
      digest: corpus.digest,
      cache_ttl_ms: this.config.complianceContext.cacheTtlMs,
      cache_age_ms: Math.max(0, this.now() - corpus.loadedAtMs),
      skipped_sources: [...corpus.skipped, ...COMPLIANCE_CONTEXT_EXCLUDED_PATHS],
    };
  }

  private async loadCorpus(): Promise<ComplianceCorpus> {
    const now = this.now();
    if (this.cache && this.cache.expiresAtMs > now) return this.cache;
    if (this.loading) return this.loading;
    this.loading = this.buildCorpus()
      .then((corpus) => {
        this.cache = corpus;
        return corpus;
      })
      .finally(() => {
        this.loading = undefined;
      });
    return this.loading;
  }

  private async buildCorpus(): Promise<ComplianceCorpus> {
    const repo = normalizeRepoName(this.config.complianceContext.repo) ?? "writer/cerebro";
    const ref = this.config.complianceContext.ref.trim() || "main";
    const sources: LoadedSource[] = [];
    const skipped: SkippedSource[] = [];
    let totalBytes = 0;
    const loaded = await mapLimit(COMPLIANCE_CONTEXT_SOURCE_PATHS, 6, (source) => this.loadSource(source, repo, ref));
    for (const result of loaded) {
      if ("skip" in result) {
        skipped.push(result.skip);
        continue;
      }
      if (totalBytes + result.source.bytes > this.config.complianceContext.maxTotalBytes) {
        skipped.push({ path: result.source.path, reason: "corpus_total_bytes_limit", bytes: result.source.bytes });
        continue;
      }
      totalBytes += result.source.bytes;
      sources.push(result.source);
    }
    const chunks = sources.flatMap((source) => chunkSource(source));
    const digest = sha256(sources.map((source) => `${source.path}:${source.sha256}`).join("\n"));
    const now = this.now();
    return {
      loadedAtMs: now,
      expiresAtMs: now + this.config.complianceContext.cacheTtlMs,
      mode: this.config.complianceContext.localDir ? "local" : "github",
      repo,
      ref,
      sourceCount: sources.length,
      skipped,
      bytes: totalBytes,
      chunks,
      digest,
    };
  }

  private async loadSource(source: CorpusSource, repo: string, ref: string): Promise<{ source: LoadedSource } | { skip: SkippedSource }> {
    try {
      const loaded = this.config.complianceContext.localDir
        ? await this.loadLocalSource(source)
        : await this.loadGithubSource(source, repo, ref);
      if (!loaded) return { skip: { path: source.path, reason: "not_found" } };
      if (loaded.bytes > this.config.complianceContext.maxFileBytes) {
        return { skip: { path: source.path, reason: "file_bytes_limit", bytes: loaded.bytes } };
      }
      return { source: loaded };
    } catch (error) {
      return { skip: { path: source.path, reason: shortError(error) } };
    }
  }

  private async loadLocalSource(source: CorpusSource): Promise<LoadedSource | undefined> {
    const localDir = this.config.complianceContext.localDir;
    if (!localDir) return undefined;
    const target = join(localDir, source.path);
    const stats = await stat(target).catch(() => undefined);
    if (!stats?.isFile()) return undefined;
    if (stats.size > this.config.complianceContext.maxFileBytes) {
      return {
        ...source,
        mode: "local",
        content: "",
        bytes: stats.size,
        sha256: "",
      };
    }
    const content = await readFile(target, "utf8");
    return {
      ...source,
      mode: "local",
      content,
      bytes: Buffer.byteLength(content, "utf8"),
      sha256: sha256(content),
    };
  }

  private async loadGithubSource(source: CorpusSource, repo: string, ref: string): Promise<LoadedSource | undefined> {
    const [owner, name] = repo.split("/");
    if (!owner || !name) return undefined;
    const path = source.path.split("/").map(encodeURIComponent).join("/");
    const url = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/${encodeURIComponent(ref)}/${path}`;
    const response = await this.fetchImpl(url, {
      method: "GET",
      signal: AbortSignal.timeout(this.config.complianceContext.fetchTimeoutMs),
      headers: {
        "Accept": "text/plain",
        "User-Agent": "cerebro-slack-companion",
      },
    });
    if (response.status === 404) return undefined;
    if (!response.ok) throw new Error(`github_raw_${response.status}`);
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (contentLength > this.config.complianceContext.maxFileBytes) {
      return {
        ...source,
        mode: "github",
        content: "",
        bytes: contentLength,
        sha256: "",
      };
    }
    const boundedBody = await readBoundedResponseText(response, this.config.complianceContext.maxFileBytes);
    if (boundedBody.tooLarge) {
      return {
        ...source,
        mode: "github",
        content: "",
        bytes: boundedBody.bytes,
        sha256: "",
      };
    }
    return {
      ...source,
      mode: "github",
      content: boundedBody.content,
      bytes: boundedBody.bytes,
      sha256: sha256(boundedBody.content),
    };
  }
}

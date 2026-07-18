import type { AppConfig } from "../config/index.js";

export interface EvidenceCasReference {
  uri?: string;
  bucket?: string;
  key?: string;
  digest?: string;
  refType?: string;
  sourcePath?: string;
}

export interface EvidenceCasResolveInput {
  uri?: string;
  bucket?: string;
  key?: string;
  digest?: string;
  verify?: boolean;
}

interface EvidenceCasClientOptions {
  readTokenProvider?: () => Promise<string | undefined>;
  readTokenProviderName?: string;
}

export class EvidenceCasClient {
  private cachedReadToken?: string;

  constructor(private readonly config: AppConfig, private readonly options: EvidenceCasClientOptions = {}) {}

  get enabled(): boolean {
    return Boolean(this.config.evidenceCas.baseUrl);
  }

  async status() {
    if (!this.config.evidenceCas.baseUrl) {
      return {
        configured: false,
        authenticated: Boolean(this.config.evidenceCas.readToken),
        note: "EVIDENCE_CAS_BASE_URL is not configured. Cerebro can still use graph evidence, but CAS manifest resolution is unavailable.",
      };
    }

    const [health, ready, version, contract, tokenState] = await Promise.all([
      this.requestJson("GET", "/healthz", { auth: false }).catch((error) => ({ error: shortError(error) })),
      this.requestJson("GET", "/readyz", { auth: false }).catch((error) => ({ error: shortError(error) })),
      this.requestJson("GET", "/version", { auth: false }).catch((error) => ({ error: shortError(error) })),
      this.requestJson("GET", "/v1/contract", { auth: false }).catch((error) => ({ error: shortError(error) })),
      this.readTokenState(),
    ]);

    return {
      configured: true,
      authenticated: Boolean(tokenState.token),
      read_token_source: tokenState.source,
      read_token_error: tokenState.error,
      base_url: this.config.evidenceCas.baseUrl,
      default_bucket: this.config.evidenceCas.defaultBucket,
      health,
      ready,
      version,
      accepted_ref_types: nestedArray(contract, ["observability_contract", "accepted_ref_types"]),
      note: tokenState.token
        ? "EvidenceCAS read endpoints are available for manifest refs surfaced by Cerebro evidence."
        : "EvidenceCAS is reachable, but no read token is available from EVIDENCE_CAS_READ_TOKEN or the configured Infisical mirror. Protected manifest/ref/verify lookups will be skipped.",
    };
  }

  async resolve(input: EvidenceCasResolveInput) {
    if (!this.config.evidenceCas.baseUrl) {
      return {
        configured: false,
        resolved: false,
        note: "EVIDENCE_CAS_BASE_URL is not configured, so CAS evidence cannot be resolved from Slack.",
      };
    }
    const tokenState = await this.readTokenState();
    if (!tokenState.token) {
      return {
        configured: true,
        authenticated: false,
        resolved: false,
        read_token_source: tokenState.source,
        read_token_error: tokenState.error,
        note: "No EvidenceCAS read token is available. Set EVIDENCE_CAS_READ_TOKEN, configure evidenceCasReadTokenSecretArn, or store the token in the configured Infisical secret mirror before resolving protected evidence refs.",
      };
    }

    const reference = normalizeReference(input, this.config.evidenceCas.defaultBucket);
    const path = objectPath(reference.bucket, reference.key);
    const [ref, manifest] = await Promise.all([
      this.requestJson("GET", `${path}/ref`, { auth: true }),
      this.requestJson("GET", `${path}/manifest`, { auth: true }),
    ]);
    const verification = input.verify
      ? await this.requestJson("POST", `${path}/verify`, { auth: true })
      : undefined;
    const observedDigest = digestFrom(ref) ?? digestFrom(manifest);
    const requestedDigest = input.digest?.trim() || reference.digest;

    return {
      configured: true,
      authenticated: true,
      resolved: true,
      reference,
      ref: compactReference(ref),
      manifest: compactManifest(manifest),
      verification: verification ? compactVerification(verification) : undefined,
      requested_digest: requestedDigest,
      digest_match: requestedDigest && observedDigest ? requestedDigest === observedDigest : undefined,
      note: "EvidenceCAS is an evidence content plane. Use this to verify a specific artifact ref surfaced by Cerebro, not as a source-of-truth finding search.",
    };
  }

  private async requestJson(method: "GET" | "POST", path: string, options: { auth: boolean }) {
    const baseUrl = this.config.evidenceCas.baseUrl;
    if (!baseUrl) throw new Error("EvidenceCAS base URL is not configured");
    const headers: Record<string, string> = { Accept: "application/json" };
    if (options.auth) {
      const token = (await this.readTokenState()).token;
      if (!token) throw new Error("EvidenceCAS read token is not configured");
      headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      headers,
      signal: AbortSignal.timeout(this.config.evidenceCas.timeoutMs),
    });
    const text = await response.text();
    let body: unknown = text;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text.slice(0, 500);
      }
    }
    if (!response.ok) {
      throw new Error(`EvidenceCAS ${method} ${path} failed with ${response.status}: ${JSON.stringify(body).slice(0, 500)}`);
    }
    return body;
  }

  private async readTokenState(): Promise<{ token?: string; source: string; error?: string }> {
    const envToken = this.config.evidenceCas.readToken?.trim();
    if (envToken) return { token: envToken, source: "env" };
    if (this.cachedReadToken) return { token: this.cachedReadToken, source: this.options.readTokenProviderName ?? "provider" };
    if (!this.options.readTokenProvider) return { source: "missing" };
    try {
      const provided = (await this.options.readTokenProvider())?.trim();
      if (!provided) return { source: this.options.readTokenProviderName ?? "provider", error: "provider returned no token" };
      this.cachedReadToken = provided;
      return { token: provided, source: this.options.readTokenProviderName ?? "provider" };
    } catch (error) {
      return {
        source: this.options.readTokenProviderName ?? "provider",
        error: shortError(error),
      };
    }
  }
}

export function extractEvidenceCasRefs(value: unknown): EvidenceCasReference[] {
  const refs: EvidenceCasReference[] = [];
  const seen = new Set<string>();

  function add(ref: EvidenceCasReference): void {
    const normalized = normalizeLooseReference(ref);
    if (!normalized) return;
    const key = [normalized.uri, normalized.bucket, normalized.key, normalized.digest].filter(Boolean).join("|");
    if (seen.has(key)) return;
    seen.add(key);
    refs.push(normalized);
  }

  function walk(item: unknown, path: string): void {
    if (typeof item === "string") {
      for (const uri of item.match(/evidencecas:\/\/[^\s<>"')]+/gi) ?? []) {
        add({ uri: trimTrailingPunctuation(uri), sourcePath: path });
      }
      return;
    }
    if (!item || typeof item !== "object") return;
    if (Array.isArray(item)) {
      item.forEach((child, index) => walk(child, `${path}[${index}]`));
      return;
    }

    const record = item as Record<string, unknown>;
    const uri = firstString(record, ["evidence_cas_uri", "evidenceCasUri", "uri", "ref", "reference"]);
    const nested = objectValue(record.evidence_cas) ?? objectValue(record.evidenceCas);
    if (uri?.startsWith("evidencecas://")) {
      add({
        uri,
        digest: firstString(record, ["evidence_cas_digest", "evidenceCasDigest", "digest"]),
        refType: firstString(record, ["evidence_cas_ref_type", "evidenceCasRefType", "ref_type"]),
        sourcePath: path,
      });
    }
    if (nested) {
      add({
        uri: firstString(nested, ["uri", "ref", "reference"]),
        bucket: firstString(nested, ["bucket"]),
        key: firstString(nested, ["key"]),
        digest: firstString(nested, ["digest"]),
        refType: firstString(nested, ["ref_type", "refType"]),
        sourcePath: `${path}.evidence_cas`,
      });
    }
    const bucket = firstString(record, ["evidence_cas_bucket", "evidenceCasBucket", "bucket"]);
    const key = firstString(record, ["evidence_cas_key", "evidenceCasKey", "key"]);
    if (bucket && key && hasEvidenceCasField(record)) {
      add({
        bucket,
        key,
        digest: firstString(record, ["evidence_cas_digest", "evidenceCasDigest", "digest"]),
        refType: firstString(record, ["evidence_cas_ref_type", "evidenceCasRefType", "ref_type"]),
        sourcePath: path,
      });
    }

    for (const [childKey, child] of Object.entries(record)) {
      walk(child, path ? `${path}.${childKey}` : childKey);
    }
  }

  walk(value, "");
  return refs.slice(0, 20);
}

function normalizeReference(input: EvidenceCasResolveInput, defaultBucket: string): Required<Pick<EvidenceCasReference, "bucket" | "key">> & EvidenceCasReference {
  const uriRef = input.uri ? parseEvidenceCasUri(input.uri) : undefined;
  const bucket = input.bucket?.trim() || uriRef?.bucket || defaultBucket;
  const key = input.key?.trim().replace(/^\/+/, "") || uriRef?.key;
  if (!bucket || !key) {
    throw new Error("EvidenceCAS reference requires either evidencecas://bucket/key or bucket plus key");
  }
  return {
    uri: input.uri ?? `evidencecas://${bucket}/${key}`,
    bucket,
    key,
    digest: input.digest?.trim(),
  };
}

function normalizeLooseReference(input: EvidenceCasReference): EvidenceCasReference | undefined {
  const uriRef = input.uri ? parseEvidenceCasUri(input.uri) : undefined;
  const bucket = input.bucket?.trim() || uriRef?.bucket;
  const key = input.key?.trim().replace(/^\/+/, "") || uriRef?.key;
  const uri = input.uri?.trim() || (bucket && key ? `evidencecas://${bucket}/${key}` : undefined);
  if (!uri && !input.digest) return undefined;
  return {
    uri,
    bucket,
    key,
    digest: input.digest?.trim(),
    refType: input.refType,
    sourcePath: input.sourcePath,
  };
}

function parseEvidenceCasUri(uri: string): { bucket: string; key: string } | undefined {
  const match = uri.trim().match(/^evidencecas:\/\/([^/]+)\/(.+)$/i);
  if (!match) return undefined;
  return {
    bucket: decodeURIComponent(match[1] ?? ""),
    key: decodeURIComponent(match[2] ?? "").replace(/^\/+/, ""),
  };
}

function objectPath(bucket: string, key: string): string {
  return `/v1/b/${encodeURIComponent(bucket)}/objects/${encodeKey(key)}`;
}

function encodeKey(key: string): string {
  return key.split("/").map((part) => encodeURIComponent(part)).join("/");
}

function compactReference(value: unknown) {
  const record = objectValue(value);
  if (!record) return value;
  return pick(record, [
    "ref_type",
    "uri",
    "bucket",
    "key",
    "digest",
    "size",
    "content_type",
    "manifest_version",
    "chunking",
    "merkle_root",
    "commit_id",
    "blocks_count",
    "tags",
    "metadata",
    "updated_at",
  ]);
}

function compactManifest(value: unknown) {
  const record = objectValue(value);
  if (!record) return value;
  const blocks = Array.isArray(record.blocks) ? record.blocks : [];
  return {
    ...pick(record, [
      "bucket",
      "key",
      "digest",
      "size",
      "content_type",
      "manifest_version",
      "chunking",
      "block_size",
      "merkle_root",
      "commit_id",
      "tags",
      "metadata",
      "created_at",
      "updated_at",
      "version",
    ]),
    blocks_count: blocks.length,
    blocks_preview: blocks.slice(0, 4),
  };
}

function compactVerification(value: unknown) {
  const record = objectValue(value);
  if (!record) return value;
  return pick(record, [
    "ok",
    "bucket",
    "key",
    "digest",
    "size",
    "merkle_root",
    "computed_merkle_root",
    "commit_id",
    "missing_blocks",
    "corrupt_blocks",
    "offset_errors",
    "provenance_errors",
  ]);
}

function pick(record: Record<string, unknown>, keys: string[]) {
  return Object.fromEntries(keys.filter((key) => record[key] !== undefined).map((key) => [key, record[key]]));
}

function digestFrom(value: unknown): string | undefined {
  return firstString(objectValue(value) ?? {}, ["digest"]);
}

function nestedArray(value: unknown, path: string[]): unknown[] | undefined {
  let current = value;
  for (const key of path) {
    const record = objectValue(current);
    if (!record) return undefined;
    current = record[key];
  }
  return Array.isArray(current) ? current : undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function firstString(record: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return undefined;
}

function hasEvidenceCasField(record: Record<string, unknown>): boolean {
  return Object.keys(record).some((key) => key.toLowerCase().includes("evidence_cas") || key.toLowerCase().includes("evidencecas"));
}

function trimTrailingPunctuation(value: string): string {
  return value.replace(/[.,;:]+$/, "");
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 240);
}

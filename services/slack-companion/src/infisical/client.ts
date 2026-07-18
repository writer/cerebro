import { createHash } from "node:crypto";
import { defaultProvider } from "@aws-sdk/credential-provider-node";
import { Hash } from "@smithy/hash-node";
import { SignatureV4 } from "@smithy/signature-v4";
import type { AwsCredentialIdentity, HttpRequest, Provider } from "@smithy/types";
import type { AppConfig } from "../config/index.js";

export interface InfisicalSecretLookupInput {
  secretName: string;
  environment?: string;
  secretPath?: string;
  includeImports?: boolean;
}

export interface InfisicalStatusInput {
  checkConnection?: boolean;
}

interface InfisicalAwsAuthPayload {
  iamHttpRequestMethod: "POST";
  iamRequestUrl: string;
  iamRequestBody: string;
  iamRequestHeaders: Record<string, string> | string;
}

interface InfisicalLoginResponse {
  accessToken?: string;
  expiresIn?: number;
  accessTokenMaxTTL?: number;
  tokenType?: string;
}

interface InfisicalSecretResponse {
  secret?: Record<string, unknown>;
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
}

interface InfisicalClientOptions {
  fetchImpl?: typeof fetch;
  authPayloadProvider?: () => Promise<InfisicalAwsAuthPayload>;
  credentialsProvider?: Provider<AwsCredentialIdentity>;
  nowMs?: () => number;
}

export class InfisicalClient {
  private cachedToken?: CachedToken;
  private readonly fetchImpl: typeof fetch;
  private readonly nowMs: () => number;

  constructor(private readonly config: AppConfig, private readonly options: InfisicalClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.nowMs = options.nowMs ?? (() => Date.now());
  }

  async status(input: InfisicalStatusInput = {}): Promise<Record<string, unknown>> {
    const missing = this.missingConfig();
    const base = {
      enabled: this.config.infisical.enabled,
      configured: this.config.infisical.enabled && missing.length === 0,
      auth_method: "aws",
      base_url: this.config.infisical.baseUrl,
      project_id_configured: Boolean(this.config.infisical.projectId),
      project_slug: this.config.infisical.projectSlug,
      identity_id_configured: Boolean(this.config.infisical.identityId),
      environment: this.config.infisical.environment,
      secret_path: this.config.infisical.secretPath,
      aws_region: this.config.infisical.awsRegion,
      sts_endpoint_configured: Boolean(this.config.infisical.stsEndpoint),
      timeout_ms: this.config.infisical.timeoutMs,
      cache_ttl_ms: this.config.infisical.cacheTtlMs,
      raw_secret_values_returned: false,
      missing,
      note: "Cerebro can use Infisical to check secret presence, metadata, and fingerprints. It does not return raw secret values to Slack.",
    };
    if (!input.checkConnection || missing.length > 0) {
      return base;
    }
    try {
      await this.accessToken();
      return { ...base, authenticated: true };
    } catch (error) {
      return {
        ...base,
        authenticated: false,
        error: shortError(error),
      };
    }
  }

  async secretMetadata(input: InfisicalSecretLookupInput): Promise<Record<string, unknown>> {
    this.assertConfigured();
    const secret = await this.fetchSecret(input, false);
    return {
      ok: true,
      secret: sanitizeSecret(secret),
      query: this.querySummary(input),
      note: "Secret value was not requested from Infisical.",
    };
  }

  async secretFingerprint(input: InfisicalSecretLookupInput): Promise<Record<string, unknown>> {
    this.assertConfigured();
    const secret = await this.fetchSecret(input, true);
    const value = typeof secret.secretValue === "string" ? secret.secretValue : undefined;
    return {
      ok: true,
      secret: sanitizeSecret(secret),
      query: this.querySummary(input),
      value_present: value !== undefined,
      value_bytes: value === undefined ? undefined : Buffer.byteLength(value, "utf8"),
      value_sha256_prefix: value === undefined ? undefined : createHash("sha256").update(value).digest("hex").slice(0, 16),
      raw_secret_value_returned: false,
      note: "Fingerprint is for rotation or mirror comparison only. Raw secret value is intentionally omitted.",
    };
  }

  async secretValueForRuntime(
    input: InfisicalSecretLookupInput,
    options: { requireAllowSecretValues?: boolean } = {},
  ): Promise<string | undefined> {
    if (options.requireAllowSecretValues !== false && !this.config.infisical.allowSecretValues) {
      throw new Error("INFISICAL_ALLOW_SECRET_VALUES is false");
    }
    this.assertConfigured();
    const secret = await this.fetchSecret(input, true);
    return typeof secret.secretValue === "string" ? secret.secretValue : undefined;
  }

  private async fetchSecret(input: InfisicalSecretLookupInput, viewSecretValue: boolean): Promise<Record<string, unknown>> {
    const secretName = normalizeSecretName(input.secretName);
    const query = new URLSearchParams();
    query.set("projectId", this.config.infisical.projectId ?? "");
    query.set("environment", input.environment?.trim() || this.config.infisical.environment);
    query.set("secretPath", normalizeSecretPath(input.secretPath ?? this.config.infisical.secretPath));
    query.set("type", "shared");
    query.set("viewSecretValue", String(viewSecretValue));
    query.set("expandSecretReferences", "false");
    query.set("includeImports", String(input.includeImports ?? true));

    const response = await this.requestJson<InfisicalSecretResponse>(
      "GET",
      `/api/v4/secrets/${encodeURIComponent(secretName)}?${query.toString()}`,
      { auth: true },
    );
    if (!response.secret || typeof response.secret !== "object") {
      throw new Error(`Infisical did not return secret metadata for ${secretName}`);
    }
    return response.secret;
  }

  private querySummary(input: InfisicalSecretLookupInput): Record<string, unknown> {
    return {
      secret_name: normalizeSecretName(input.secretName),
      environment: input.environment?.trim() || this.config.infisical.environment,
      secret_path: normalizeSecretPath(input.secretPath ?? this.config.infisical.secretPath),
      include_imports: input.includeImports ?? true,
    };
  }

  private async accessToken(): Promise<string> {
    const cached = this.cachedToken;
    if (cached && cached.expiresAtMs > this.nowMs() + 30_000) {
      return cached.token;
    }
    const payload = this.options.authPayloadProvider
      ? await this.options.authPayloadProvider()
      : await this.buildAwsAuthPayload();
    const response = await this.login(payload).catch(async (error) => {
      if (!isRetryableLoginError(error)) throw error;
      return this.login(base64AuthPayload(payload));
    });
    if (!response.accessToken) {
      throw new Error("Infisical AWS auth did not return an access token");
    }
    const ttlMs = Math.max(60_000, Math.min(this.config.infisical.cacheTtlMs, (response.expiresIn ?? 900) * 1000));
    this.cachedToken = {
      token: response.accessToken,
      expiresAtMs: this.nowMs() + ttlMs,
    };
    return response.accessToken;
  }

  private async login(payload: InfisicalAwsAuthPayload): Promise<InfisicalLoginResponse> {
    const identityId = this.config.infisical.identityId;
    if (!identityId) throw new Error("INFISICAL_IDENTITY_ID is not configured");
    return this.requestJson<InfisicalLoginResponse>("POST", "/api/v1/auth/aws-auth/login", {
      auth: false,
      body: { ...payload, identityId },
    });
  }

  private async buildAwsAuthPayload(): Promise<InfisicalAwsAuthPayload> {
    const region = this.config.infisical.awsRegion || process.env.AWS_REGION || "us-east-1";
    const requestBody = "Action=GetCallerIdentity&Version=2011-06-15";
    const endpoint = normalizeStsEndpoint(this.config.infisical.stsEndpoint, region);
    const url = new URL(endpoint);
    const request: HttpRequest = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port ? Number(url.port) : undefined,
      path: url.pathname || "/",
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        host: url.host,
        "content-length": String(Buffer.byteLength(requestBody)),
      },
      body: requestBody,
    };
    const signer = new SignatureV4({
      credentials: this.options.credentialsProvider ?? defaultProvider(),
      region,
      service: "sts",
      sha256: Hash.bind(null, "sha256"),
    });
    const signed = await signer.sign(request) as HttpRequest;
    return {
      iamHttpRequestMethod: "POST",
      iamRequestUrl: endpoint,
      iamRequestBody: requestBody,
      iamRequestHeaders: stringHeaders(signed.headers),
    };
  }

  private async requestJson<T>(
    method: "GET" | "POST",
    path: string,
    options: { auth: boolean; body?: unknown },
  ): Promise<T> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "User-Agent": "cerebro-slack-companion",
    };
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (options.auth) {
      headers.Authorization = `Bearer ${await this.accessToken()}`;
    }

    const response = await this.fetchImpl(`${this.config.infisical.baseUrl}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: AbortSignal.timeout(this.config.infisical.timeoutMs),
    });
    const text = await response.text();
    const body = parseJson(text);
    if (!response.ok) {
      throw new InfisicalRequestError(response.status, method, path, body);
    }
    return body as T;
  }

  private assertConfigured(): void {
    const missing = this.missingConfig();
    if (missing.length > 0) {
      throw new Error(`Infisical is not configured: missing ${missing.join(", ")}`);
    }
  }

  private missingConfig(): string[] {
    if (!this.config.infisical.enabled) return ["INFISICAL_ENABLED=false"];
    return [
      this.config.infisical.baseUrl ? undefined : "INFISICAL_BASE_URL",
      this.config.infisical.projectId ? undefined : "INFISICAL_PROJECT_ID",
      this.config.infisical.identityId ? undefined : "INFISICAL_IDENTITY_ID",
      this.config.infisical.environment ? undefined : "INFISICAL_ENVIRONMENT",
    ].filter((item): item is string => Boolean(item));
  }
}

class InfisicalRequestError extends Error {
  constructor(readonly status: number, method: string, path: string, readonly body: unknown) {
    super(`Infisical ${method} ${path} failed with ${status}: ${JSON.stringify(body).slice(0, 300)}`);
    this.name = "InfisicalRequestError";
  }
}

function isRetryableLoginError(error: unknown): boolean {
  return error instanceof InfisicalRequestError && [400, 415, 422].includes(error.status);
}

function base64AuthPayload(payload: InfisicalAwsAuthPayload): InfisicalAwsAuthPayload {
  const headers = typeof payload.iamRequestHeaders === "string"
    ? payload.iamRequestHeaders
    : JSON.stringify(payload.iamRequestHeaders);
  return {
    iamHttpRequestMethod: payload.iamHttpRequestMethod,
    iamRequestUrl: Buffer.from(payload.iamRequestUrl).toString("base64"),
    iamRequestBody: Buffer.from(payload.iamRequestBody).toString("base64"),
    iamRequestHeaders: Buffer.from(headers).toString("base64"),
  };
}

function sanitizeSecret(secret: Record<string, unknown>): Record<string, unknown> {
  return {
    id: stringValue(secret.id ?? secret._id),
    workspace: stringValue(secret.workspace),
    environment: stringValue(secret.environment),
    version: numberValue(secret.version),
    type: stringValue(secret.type),
    secret_key: stringValue(secret.secretKey),
    secret_comment_present: Boolean(stringValue(secret.secretComment)),
    created_at: stringValue(secret.createdAt),
    updated_at: stringValue(secret.updatedAt),
    secret_value_hidden: Boolean(secret.secretValueHidden),
    secret_path: stringValue(secret.secretPath),
    reminder_note_present: Boolean(stringValue(secret.secretReminderNote)),
    reminder_repeat_days: numberValue(secret.secretReminderRepeatDays),
    is_rotated_secret: Boolean(secret.isRotatedSecret),
    rotation_id: stringValue(secret.rotationId),
    tags: Array.isArray(secret.tags) ? secret.tags.map(sanitizeTag).filter(Boolean) : [],
    metadata: Array.isArray(secret.secretMetadata) ? secret.secretMetadata.map(sanitizeMetadata).filter(Boolean) : [],
    actor: sanitizeActor(secret.actor),
    raw_secret_value_returned: false,
  };
}

function sanitizeTag(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") return undefined;
  const tag = value as Record<string, unknown>;
  return {
    id: stringValue(tag.id),
    slug: stringValue(tag.slug),
    name: stringValue(tag.name),
  };
}

function sanitizeMetadata(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") return undefined;
  const item = value as Record<string, unknown>;
  return {
    key: stringValue(item.key),
    value_present: typeof item.value === "string" && item.value.length > 0,
    is_encrypted: Boolean(item.isEncrypted),
  };
}

function sanitizeActor(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object") return undefined;
  const actor = value as Record<string, unknown>;
  return {
    actor_id: stringValue(actor.actorId),
    actor_type: stringValue(actor.actorType),
    name: stringValue(actor.name),
    membership_id: stringValue(actor.membershipId),
    group_id: stringValue(actor.groupId),
  };
}

function normalizeSecretName(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("secret_name is required");
  if (trimmed.length > 512) throw new Error("secret_name is too long");
  if (/[\u0000-\u001F\u007F]/.test(trimmed)) throw new Error("secret_name contains control characters");
  return trimmed;
}

function normalizeSecretPath(value: string): string {
  const trimmed = value.trim() || "/";
  if (/[\u0000-\u001F\u007F]/.test(trimmed)) throw new Error("secret_path contains control characters");
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function normalizeStsEndpoint(value: string | undefined, region: string): string {
  const endpoint = value?.trim() || `https://sts.${region}.amazonaws.com/`;
  return endpoint.endsWith("/") ? endpoint : `${endpoint}/`;
}

function stringHeaders(headers: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).flatMap(([key, value]) =>
      typeof value === "string" ? [[key, value]] : []),
  );
}

function parseJson(text: string): unknown {
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return text.slice(0, 500);
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.replace(/\s+/g, " ").slice(0, 300);
}

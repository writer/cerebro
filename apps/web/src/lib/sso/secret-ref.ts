export type SecretRef =
  | { kind: "env"; name: string }
  | { kind: "aws-sm"; region: string; secretId: string; field?: string };

export class SecretRefError extends Error {}

const MAX_REF_LENGTH = 512;
const CACHE_TTL_MS = 5 * 60_000;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const AWS_REGION = /^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d$/;
const SECRET_ID = /^[A-Za-z0-9/_+=.@:-]+$/;
const JSON_FIELD = /^[A-Za-z0-9_.-]{1,128}$/;
const DEFAULT_ENV_PREFIX = "CEREBRO_SSO_";

/** Parses `env:NAME` or `aws-sm:<region>/<secret-id>[#json-field]`; throws on anything else. */
export const parseSecretRef = (ref: string): SecretRef => {
  if (typeof ref !== "string" || ref.length === 0 || ref.length > MAX_REF_LENGTH || /\s/.test(ref)) {
    throw new SecretRefError("Secret reference is empty, too long, or contains whitespace.");
  }
  if (ref.startsWith("env:")) {
    const name = ref.slice("env:".length);
    if (!ENV_NAME.test(name)) throw new SecretRefError("env secret reference has an invalid variable name.");
    return { kind: "env", name };
  }
  if (ref.startsWith("aws-sm:")) {
    const rest = ref.slice("aws-sm:".length);
    const hashIndex = rest.indexOf("#");
    const locator = hashIndex >= 0 ? rest.slice(0, hashIndex) : rest;
    const field = hashIndex >= 0 ? rest.slice(hashIndex + 1) : undefined;
    let region: string;
    let secretId: string;
    if (locator.startsWith("arn:")) {
      // arn:<partition>:secretsmanager:<region>:<account>:secret:<name>
      const parts = locator.split(":");
      if (parts.length < 7 || parts[2] !== "secretsmanager" || parts[5] !== "secret") {
        throw new SecretRefError("aws-sm secret reference has an invalid ARN.");
      }
      region = parts[3];
      secretId = locator;
    } else {
      // Both aws-sm:<region>/<id> and the connector-store form aws-sm:<region>:<id> are accepted.
      const separator = /^[a-z0-9-]+[:/]/.exec(locator);
      if (!separator) throw new SecretRefError("aws-sm secret reference must be aws-sm:<region>/<secret-id>.");
      region = locator.slice(0, separator[0].length - 1);
      secretId = locator.slice(separator[0].length);
    }
    if (!AWS_REGION.test(region)) throw new SecretRefError("aws-sm secret reference has an invalid region.");
    if (!secretId || !SECRET_ID.test(secretId)) throw new SecretRefError("aws-sm secret reference has an invalid secret id.");
    if (field !== undefined && !JSON_FIELD.test(field)) throw new SecretRefError("aws-sm secret reference has an invalid field.");
    return field === undefined ? { kind: "aws-sm", region, secretId } : { kind: "aws-sm", region, secretId, field };
  }
  throw new SecretRefError("Secret reference must start with env: or aws-sm:.");
};

const splitList = (value: string | undefined) =>
  (value ?? "").split(",").map((entry) => entry.trim()).filter(Boolean);

/**
 * Connection admins choose the reference and also choose the IdP that receives the resolved value, so an
 * unrestricted reference would let them send any server secret to a host they control. env references are
 * limited to CEREBRO_SSO_* (or CEREBRO_SSO_SECRET_ENV_ALLOWLIST); aws-sm ids must match
 * CEREBRO_SSO_AWS_SECRET_PREFIXES, and aws-sm is refused entirely until that is set.
 */
export const secretRefAllowed = (ref: SecretRef) => {
  if (ref.kind === "env") {
    return ref.name.startsWith(DEFAULT_ENV_PREFIX) || splitList(process.env.CEREBRO_SSO_SECRET_ENV_ALLOWLIST).includes(ref.name);
  }
  const prefixes = splitList(process.env.CEREBRO_SSO_AWS_SECRET_PREFIXES);
  if (prefixes.length === 0) return false;
  return prefixes.some((prefix) => ref.secretId.startsWith(prefix));
};

type CacheEntry = { value: string; expiresAt: number };
const cache = new Map<string, CacheEntry>();

export const clearSecretRefCache = () => cache.clear();

type SecretsManagerFetcher = (region: string, secretId: string) => Promise<string>;

const defaultSecretsManagerFetcher: SecretsManagerFetcher = async (region, secretId) => {
  const { SecretsManagerClient, GetSecretValueCommand } = await import("@aws-sdk/client-secrets-manager");
  const client = new SecretsManagerClient({ region });
  try {
    const result = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    if (typeof result.SecretString === "string") return result.SecretString;
    if (result.SecretBinary) return Buffer.from(result.SecretBinary).toString("utf8");
    throw new SecretRefError("Secret has no value.");
  } finally {
    client.destroy();
  }
};

let secretsManagerFetcher: SecretsManagerFetcher = defaultSecretsManagerFetcher;

export const setSecretsManagerFetcherForTests = (fetcher: SecretsManagerFetcher | null) => {
  secretsManagerFetcher = fetcher ?? defaultSecretsManagerFetcher;
};

const extractField = (raw: string, field: string | undefined) => {
  if (field === undefined) return raw;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SecretRefError("Secret value is not JSON, so the requested field cannot be read.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Object.hasOwn(parsed, field)) {
    throw new SecretRefError("Secret JSON does not contain the requested field.");
  }
  const value = (parsed as Record<string, unknown>)[field];
  if (typeof value !== "string") throw new SecretRefError("Secret JSON field is not a string.");
  return value;
};

/** Resolves a reference to its value. Errors never include the value. */
export const resolveSecretRef = async (rawRef: string, nowMs = Date.now()): Promise<string> => {
  const ref = parseSecretRef(rawRef);
  if (!secretRefAllowed(ref)) {
    throw new SecretRefError("Secret reference is not in the allowed namespace for SSO client secrets.");
  }
  if (ref.kind === "env") {
    const value = process.env[ref.name];
    if (!value) throw new SecretRefError("Referenced environment variable is not set.");
    return value;
  }
  const cached = cache.get(rawRef);
  if (cached && cached.expiresAt > nowMs) return cached.value;
  const raw = await secretsManagerFetcher(ref.region, ref.secretId).catch((error: unknown) => {
    if (error instanceof SecretRefError) throw error;
    throw new SecretRefError("Secret could not be read from AWS Secrets Manager.");
  });
  const value = extractField(raw, ref.field);
  if (!value) throw new SecretRefError("Secret value is empty.");
  cache.set(rawRef, { value, expiresAt: nowMs + CACHE_TTL_MS });
  return value;
};

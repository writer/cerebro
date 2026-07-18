import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildInfisicalConfig(parsed: ParsedEnv): AppConfig["infisical"] {
  return {
    enabled: parseBoolean(parsed.INFISICAL_ENABLED),
    baseUrl: parsed.INFISICAL_BASE_URL.replace(/\/$/, ""),
    projectId: parsed.INFISICAL_PROJECT_ID,
    projectSlug: parsed.INFISICAL_PROJECT_SLUG,
    environment: parsed.INFISICAL_ENVIRONMENT,
    secretPath: parsed.INFISICAL_SECRET_PATH || "/",
    identityId: parsed.INFISICAL_IDENTITY_ID,
    awsRegion: parsed.INFISICAL_AWS_REGION,
    stsEndpoint: parsed.INFISICAL_STS_ENDPOINT,
    timeoutMs: parsed.INFISICAL_TIMEOUT_MS,
    cacheTtlMs: parsed.INFISICAL_CACHE_TTL_MS,
    allowSecretValues: parseBoolean(parsed.INFISICAL_ALLOW_SECRET_VALUES),
  };
}

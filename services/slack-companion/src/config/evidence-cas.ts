import type { ParsedEnv } from "./env.js";
import type { AppConfig } from "./types.js";

export function buildEvidenceCasConfig(parsed: ParsedEnv): AppConfig["evidenceCas"] {
  return {
    baseUrl: parsed.EVIDENCE_CAS_BASE_URL?.replace(/\/$/, ""),
    readToken: parsed.EVIDENCE_CAS_READ_TOKEN,
    readTokenInfisicalSecretName: parsed.EVIDENCE_CAS_READ_TOKEN_INFISICAL_SECRET_NAME,
    defaultBucket: parsed.EVIDENCE_CAS_DEFAULT_BUCKET,
    timeoutMs: parsed.EVIDENCE_CAS_TIMEOUT_MS,
  };
}

import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildComplianceContextConfig(parsed: ParsedEnv): AppConfig["complianceContext"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_COMPLIANCE_CONTEXT_ENABLED),
    repo: parsed.CEREBRO_COMPLIANCE_CONTEXT_REPO,
    ref: parsed.CEREBRO_COMPLIANCE_CONTEXT_REF,
    localDir: parsed.CEREBRO_COMPLIANCE_CONTEXT_LOCAL_DIR,
    cacheTtlMs: parsed.CEREBRO_COMPLIANCE_CONTEXT_CACHE_TTL_MS,
    fetchTimeoutMs: parsed.CEREBRO_COMPLIANCE_CONTEXT_FETCH_TIMEOUT_MS,
    maxFileBytes: parsed.CEREBRO_COMPLIANCE_CONTEXT_MAX_FILE_BYTES,
    maxTotalBytes: parsed.CEREBRO_COMPLIANCE_CONTEXT_MAX_TOTAL_BYTES,
  };
}

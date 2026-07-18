export type ResilientToolResult<T> = {
  ok: boolean;
  data?: T;
  error?: string;
  via?: string;
  degraded?: boolean;
};

const TRANSIENT_PATTERNS: RegExp[] = [
  /\b503\b/i,
  /service unavailable/i,
  /nats:\s*no response from stream/i,
  /not valid answer json/i,
  /memory curator .*json/i,
  /timeout|timed out|ETIMEDOUT|ECONNRESET/i,
];

const OVERSIZED_CONTEXT_PATTERNS: RegExp[] = [
  /prompt is too long/i,
  /\btokens?\b[^.]*\b(maximum|max)\b/i,
  /\bcontext\b[^.]*\b(too\s+large|exceeds|overflow|window)\b/i,
  /\b(input|payload|request)\b[^.]*\btoo\s+large\b/i,
  /\btoo many tokens\b/i,
];

export function isTransient(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? "");
  if (isOversizedContext(message)) return false;
  return TRANSIENT_PATTERNS.some((pattern) => pattern.test(message));
}

export function isOversizedContext(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return OVERSIZED_CONTEXT_PATTERNS.some((pattern) => pattern.test(message));
}

export interface ResilientOptions<T> {
  name: string;
  run: () => Promise<T>;
  fallbacks?: Array<{ name: string; run: () => Promise<T> }>;
  retries?: number;
  backoffMs?: number;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function runResilient<T>(options: ResilientOptions<T>): Promise<ResilientToolResult<T>> {
  const retries = Math.max(1, options.retries ?? 2);
  const backoffMs = Math.max(0, options.backoffMs ?? 250);

  const attempt = async (
    label: string,
    work: () => Promise<T>,
  ): Promise<ResilientToolResult<T> | null> => {
    let lastError: unknown;
    for (let attemptNumber = 1; attemptNumber <= retries; attemptNumber++) {
      try {
        const data = await work();
        return {
          ok: true,
          data,
          via: attemptNumber > 1 ? `${label}:retry:${attemptNumber}` : label,
        };
      } catch (error) {
        lastError = error;
        if (isOversizedContext(error)) {
          return {
            ok: false,
            error: error instanceof Error ? error.message : String(error),
            via: `${label}:oversized_context`,
          };
        }
        if (!isTransient(error) || attemptNumber === retries) break;
        await sleep(backoffMs * attemptNumber);
      }
    }

    if (isTransient(lastError)) return null;
    return {
      ok: false,
      error: lastError instanceof Error ? lastError.message : String(lastError),
      via: label,
    };
  };

  const primary = await attempt("primary", options.run);
  if (primary?.ok) return primary;
  if (primary && !primary.ok) return primary;

  for (const fallback of options.fallbacks ?? []) {
    const fallbackResult = await attempt(`fallback:${fallback.name}`, fallback.run);
    if (fallbackResult?.ok) return { ...fallbackResult, degraded: true };
    if (fallbackResult && !fallbackResult.ok) return { ...fallbackResult, degraded: true };
  }

  return {
    ok: false,
    error: `${options.name}: all paths failed after transient errors`,
    degraded: true,
  };
}

export function boundInput(text: string, maxChars = 1200): { text: string; truncated: boolean } {
  if (text.length <= maxChars) return { text, truncated: false };
  return { text: text.slice(0, maxChars), truncated: true };
}

export const DEFAULT_TOOL_CONTEXT_MAX_CHARS = 60_000;

export interface GuardContextSizeResult<T> {
  value: T;
  truncated: boolean;
  size: number;
  limit: number;
}

export function guardContextSize<T>(value: T, options: { maxChars?: number } = {}): GuardContextSizeResult<T> {
  const limit = Math.max(2048, options.maxChars ?? DEFAULT_TOOL_CONTEXT_MAX_CHARS);
  const serialized = safeStringify(value);
  if (serialized.length <= limit) {
    return { value, truncated: false, size: serialized.length, limit };
  }
  return {
    value: shrinkValue(value, limit) as T,
    truncated: true,
    size: serialized.length,
    limit,
  };
}

function safeStringify(value: unknown): string {
  try {
    return typeof value === "string" ? value : JSON.stringify(value) ?? "";
  } catch {
    return String(value ?? "");
  }
}

function shrinkValue(value: unknown, limit: number): unknown {
  if (typeof value === "string") {
    if (value.length <= limit) return value;
    return `${value.slice(0, limit)}…[truncated]`;
  }
  if (Array.isArray(value)) return shrinkArray(value, limit);
  if (value && typeof value === "object") return shrinkObject(value as Record<string, unknown>, limit);
  return value;
}

function shrinkArray(items: unknown[], limit: number): unknown[] {
  if (items.length === 0) return items;
  const targetCount = Math.max(1, Math.min(items.length, Math.floor(limit / 512)));
  const kept = items.slice(0, targetCount).map((item) => shrinkValue(item, Math.max(256, Math.floor(limit / Math.max(1, targetCount)))));
  if (kept.length < items.length) {
    kept.push({ context_truncated: true, dropped_items: items.length - kept.length });
  }
  return kept;
}

function shrinkObject(record: Record<string, unknown>, limit: number): Record<string, unknown> {
  const entries = Object.entries(record);
  const result: Record<string, unknown> = {};
  let used = 0;
  let dropped = 0;
  for (const [key, child] of entries) {
    const childLimit = Math.max(1024, limit - used);
    const reduced = shrinkValue(child, childLimit);
    const childSize = safeStringify(reduced).length + key.length + 4;
    if (used + childSize > limit && Object.keys(result).length > 0) {
      dropped += 1;
      continue;
    }
    result[key] = reduced;
    used += childSize;
  }
  if (dropped > 0) {
    result.context_truncated = true;
    result.dropped_fields = dropped;
  }
  return result;
}

export interface ResilientDetailsOptions {
  maxContextChars?: number;
  guardContext?: boolean;
}

export function resilientDetails<T extends Record<string, unknown>>(
  result: ResilientToolResult<T>,
  extra?: Record<string, unknown>,
  options: ResilientDetailsOptions = {},
): Record<string, unknown> {
  if (!result.ok) {
    return {
      error: result.error,
      via: result.via,
      degraded: result.degraded,
      ...extra,
    };
  }
  const guardEnabled = options.guardContext !== false;
  const raw = result.data as Record<string, unknown> | undefined;
  const guard = guardEnabled
    ? guardContextSize(raw ?? {}, { maxChars: options.maxContextChars })
    : { value: raw ?? {}, truncated: false, size: 0, limit: 0 };
  const data = guard.value as Record<string, unknown>;
  return {
    ...data,
    via: guard.truncated ? `${result.via ?? "primary"}:context_truncated` : result.via,
    degraded: result.degraded || guard.truncated || undefined,
    context_truncated: guard.truncated || undefined,
    context_size_bytes: guard.truncated ? guard.size : undefined,
    context_limit_bytes: guard.truncated ? guard.limit : undefined,
    ...extra,
  };
}

export interface PageRequest {
  cursor?: string | null;
  limit?: number;
}

export interface CursorPage<T> {
  items: T[];
  nextCursor: string | null;
}

export interface EncodedCursor {
  payload: Record<string, unknown>;
  version: number;
}

const DEFAULT_VERSION = 1;

export function encodeCursor(payload: Record<string, unknown>): string {
  const encoded: EncodedCursor = {
    payload,
    version: DEFAULT_VERSION,
  };

  const json = JSON.stringify(encoded);
  const base64 = toBase64(json);
  return toUrlSafe(base64);
}

export function decodeCursor(token: string): EncodedCursor {
  const padded = fromUrlSafe(token);
  const json = fromBase64(padded);

  const parsed = JSON.parse(json) as EncodedCursor;
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Invalid cursor payload");
  }

  if (typeof parsed.version !== "number" || typeof parsed.payload !== "object" || parsed.payload === null) {
    throw new Error("Invalid cursor payload structure");
  }

  return parsed;
}

function toUrlSafe(base64: string): string {
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromUrlSafe(token: string): string {
  const normalized = token.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  if (padding === 0) {
    return normalized;
  }
  return normalized + "=".repeat(4 - padding);
}

function toBase64(value: string): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value, "utf8").toString("base64");
  }

  if (typeof btoa === "function") {
    return btoa(value);
  }

  throw new Error("Base64 encoding not supported in this environment");
}

function fromBase64(value: string): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value, "base64").toString("utf8");
  }

  if (typeof atob === "function") {
    return atob(value);
  }

  throw new Error("Base64 decoding not supported in this environment");
}

export async function* iterateCursor<T>(
  fetchPage: (cursor?: string | null) => Promise<CursorPage<T>>,
  initialCursor: string | null = null,
): AsyncGenerator<T, void, undefined> {
  let cursor: string | null = initialCursor;

  while (true) {
    const page = await fetchPage(cursor ?? undefined);
    for (const item of page.items) {
      yield item;
    }

    if (!page.nextCursor) {
      break;
    }

    cursor = page.nextCursor;
  }
}

export async function collectCursor<T>(
  fetchPage: (cursor?: string | null) => Promise<CursorPage<T>>,
  initialCursor: string | null = null,
): Promise<T[]> {
  const results: T[] = [];
  for await (const item of iterateCursor(fetchPage, initialCursor)) {
    results.push(item);
  }
  return results;
}

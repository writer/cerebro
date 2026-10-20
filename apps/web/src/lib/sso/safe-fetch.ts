import { lookup } from "dns/promises";
import { isIP } from "net";

import { isDevelopment } from "./config";

export class UnsafeUrlError extends Error {}

const ipv4Private = (address: string) => {
  const parts = address.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
};

const ipv6Private = (address: string) => {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "::" || normalized === "::1") return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(normalized);
  if (mapped) return ipv4Private(mapped[1]);
  if (/^::ffff:/.test(normalized)) return true;
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  return (
    (first & 0xfe00) === 0xfc00 || // unique local
    (first & 0xffc0) === 0xfe80 || // link local
    (first & 0xff00) === 0xff00 || // multicast
    normalized.startsWith("64:ff9b:") ||
    normalized.startsWith("2001:db8:")
  );
};

export const isPrivateAddress = (address: string) => {
  const family = isIP(address.replace(/^\[|\]$/g, ""));
  if (family === 4) return ipv4Private(address);
  if (family === 6) return ipv6Private(address);
  return true;
};

const loopbackHostname = (hostname: string) =>
  hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "127.0.0.1" || hostname === "[::1]";

/**
 * Rejects URLs that could reach internal infrastructure. Outside development only https URLs whose
 * hostname resolves exclusively to public addresses are allowed. DNS is re-resolved on every call, but a
 * resolver that changes answers between this check and the connection (rebinding) is not fully covered.
 */
export const assertSafeOutboundUrl = async (input: string | URL) => {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UnsafeUrlError("URL is not valid.");
  }
  if (url.username || url.password) throw new UnsafeUrlError("URL must not contain credentials.");
  const dev = isDevelopment();
  if (dev && url.protocol === "http:" && loopbackHostname(url.hostname)) return url;
  if (url.protocol !== "https:") throw new UnsafeUrlError("URL must use https.");
  if (dev && loopbackHostname(url.hostname)) return url;
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new UnsafeUrlError("URL must not target a private or loopback address.");
    return url;
  }
  if (loopbackHostname(hostname) || hostname.endsWith(".internal") || hostname.endsWith(".local")) {
    throw new UnsafeUrlError("URL must not target an internal host.");
  }
  let addresses: { address: string }[];
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new UnsafeUrlError("URL host could not be resolved.");
  }
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new UnsafeUrlError("URL must not target a private or loopback address.");
  }
  return url;
};

const requestUrl = (input: RequestInfo | URL) => {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input;
  return input.url;
};

export type SafeFetchOptions = {
  timeoutMs?: number;
  maxBytes?: number;
};

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 1024 * 1024;

const readCapped = async (response: Response, maxBytes: number) => {
  const declared = Number.parseInt(response.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel();
    throw new UnsafeUrlError("Response is too large.");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new UnsafeUrlError("Response is too large.");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
};

/**
 * fetch() for admin- or IdP-supplied URLs: SSRF-checked, no redirects, bounded time and size. The
 * returned Response has a fully buffered body.
 */
export const safeFetch = async (
  input: RequestInfo | URL,
  init: RequestInit = {},
  { timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES }: SafeFetchOptions = {},
): Promise<Response> => {
  const url = await assertSafeOutboundUrl(requestUrl(input));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const parentSignal = init.signal ?? (input instanceof Request ? input.signal : undefined);
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  try {
    const request = input instanceof Request ? new Request(input, init) : null;
    const response = await fetch(request ?? url, {
      ...(request ? {} : init),
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new UnsafeUrlError("Redirects are not followed for identity provider requests.");
    }
    const body = await readCapped(response, maxBytes);
    return new Response(body.byteLength > 0 ? body : null, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abort);
  }
};

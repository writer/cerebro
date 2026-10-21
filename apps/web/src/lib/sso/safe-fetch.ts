import { lookup } from "dns/promises";
import { request as httpRequest, type IncomingMessage } from "http";
import { request as httpsRequest } from "https";
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

type SafeTarget = {
  url: URL;
  /** Address the connection must use: the one that passed the private-address check. */
  address: string;
};

const DEV_LOOPBACK_V4 = "127.0.0.1";
const DEV_LOOPBACK_V6 = "::1";

/**
 * Validates an outbound URL and picks the address to connect to. Outside development only https URLs whose
 * hostname resolves exclusively to public addresses are allowed. Callers connect to the returned address
 * rather than re-resolving the hostname, so a resolver that changes answers after the check (DNS rebinding)
 * cannot redirect the request to an internal address.
 */
const resolveSafeTarget = async (input: string | URL): Promise<SafeTarget> => {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UnsafeUrlError("URL is not valid.");
  }
  if (url.username || url.password) throw new UnsafeUrlError("URL must not contain credentials.");
  const dev = isDevelopment();
  if (dev && loopbackHostname(url.hostname) && (url.protocol === "http:" || url.protocol === "https:")) {
    return { url, address: url.hostname === "[::1]" ? DEV_LOOPBACK_V6 : DEV_LOOPBACK_V4 };
  }
  if (url.protocol !== "https:") throw new UnsafeUrlError("URL must use https.");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!isIP(hostname) && (loopbackHostname(hostname) || hostname.endsWith(".internal") || hostname.endsWith(".local"))) {
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
  return { url, address: addresses[0].address };
};

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 1024 * 1024;

const abortedError = () => new UnsafeUrlError("Identity provider request timed out or was aborted.");

/** Settles with `work`, or rejects as soon as `signal` aborts (the work itself keeps running unobserved). */
const untilAborted = <T>(work: Promise<T>, signal: AbortSignal): Promise<T> => {
  if (signal.aborted) return Promise.reject(abortedError());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortedError());
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
};

/** Rejects URLs that could reach internal infrastructure; see resolveSafeTarget. DNS is bounded by timeoutMs. */
export const assertSafeOutboundUrl = async (input: string | URL, timeoutMs = DEFAULT_TIMEOUT_MS) => {
  const signal = AbortSignal.timeout(timeoutMs);
  return (await untilAborted(resolveSafeTarget(input), signal)).url;
};

export type SafeFetchOptions = {
  timeoutMs?: number;
  maxBytes?: number;
};

const requestBody = (body: RequestInit["body"]): Buffer | undefined => {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  throw new UnsafeUrlError("Unsupported request body for identity provider requests.");
};

const responseHeaders = (message: IncomingMessage) => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(message.headers)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }
  return headers;
};

const readCapped = (message: IncomingMessage, maxBytes: number) =>
  new Promise<Buffer>((resolve, reject) => {
    const declared = Number.parseInt(message.headers["content-length"] ?? "", 10);
    if (Number.isFinite(declared) && declared > maxBytes) {
      message.destroy();
      reject(new UnsafeUrlError("Response is too large."));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    message.on("data", (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > maxBytes) {
        message.destroy();
        reject(new UnsafeUrlError("Response is too large."));
        return;
      }
      chunks.push(chunk);
    });
    message.on("end", () => resolve(Buffer.concat(chunks)));
    message.on("error", reject);
  });

/**
 * fetch() for admin- or IdP-supplied URLs: SSRF-checked, pinned to the checked address, no redirects, bounded
 * time and size. The returned Response has a fully buffered body.
 */
export const safeFetch = async (
  input: string | URL,
  init: RequestInit = {},
  { timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES }: SafeFetchOptions = {},
): Promise<Response> => {
  const parentSignal = init.signal;
  if (parentSignal?.aborted) throw abortedError();
  // The deadline starts before DNS resolution so a slow resolver cannot stretch the bound.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  try {
    const { url, address } = await untilAborted(resolveSafeTarget(input), controller.signal);
    const body = requestBody(init.body);
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((value, name) => {
      headers[name] = value;
    });
    headers.host = url.host;
    if (body) headers["content-length"] = String(body.byteLength);
    const send = url.protocol === "https:" ? httpsRequest : httpRequest;
    const message = await new Promise<IncomingMessage>((resolve, reject) => {
      const request = send(
        {
          protocol: url.protocol,
          host: address,
          port: url.port || undefined,
          path: `${url.pathname}${url.search}`,
          method: (init.method ?? "GET").toUpperCase(),
          headers,
          // The connection goes to the pinned address; the certificate must still match the URL's hostname.
          servername: isIP(url.hostname.replace(/^\[|\]$/g, "")) ? undefined : url.hostname,
          signal: controller.signal,
        },
        resolve,
      );
      request.on("error", reject);
      request.end(body);
    });
    const status = message.statusCode ?? 0;
    if (status >= 300 && status < 400) {
      message.destroy();
      throw new UnsafeUrlError("Redirects are not followed for identity provider requests.");
    }
    const payload = await readCapped(message, maxBytes);
    const nullBody = status === 204 || status === 205 || status === 304;
    return new Response(nullBody || payload.byteLength === 0 ? null : new Uint8Array(payload), {
      status,
      statusText: message.statusMessage ?? "",
      headers: responseHeaders(message),
    });
  } catch (error) {
    if (controller.signal.aborted && !(error instanceof UnsafeUrlError)) {
      throw new UnsafeUrlError("Identity provider request timed out or was aborted.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abort);
  }
};

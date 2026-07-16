import { setTimeout as sleep } from "node:timers/promises";

const JAVASCRIPT_CONTENT_TYPES = [
  "application/javascript",
  "application/ecmascript",
  "text/javascript",
  "application/x-javascript",
];

export const extractNextScriptSrcs = (html) => {
  const scripts = new Set();
  const scriptPattern = /<script\b[^>]*\bsrc=["']([^"']*\/_next\/static\/[^"']+\.js(?:\?[^"']*)?)["'][^>]*>/gi;
  let match;
  while ((match = scriptPattern.exec(html))) {
    scripts.add(match[1].replace(/&amp;/g, "&"));
  }
  return [...scripts];
};

export const scriptUrlFor = (baseUrl, src) =>
  new URL(src, baseUrl).toString();

export const isJavaScriptContentType = (contentType) => {
  const normalized = (contentType ?? "").split(";")[0].trim().toLowerCase();
  return JAVASCRIPT_CONTENT_TYPES.includes(normalized) || normalized.endsWith("+javascript");
};

export async function fetchText(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    headers: options.headers,
  });
  const body = await response.text();
  return { body, headers: response.headers, status: response.status, url };
}

export async function waitForHttp(url, options = {}) {
  const timeoutMs = options.timeoutMs ?? 90_000;
  const intervalMs = options.intervalMs ?? 750;
  const deadline = Date.now() + timeoutMs;
  let lastError;

  while (Date.now() < deadline) {
    try {
      const response = await fetchText(url, { timeoutMs: options.requestTimeoutMs ?? 5_000 });
      if (response.status >= 200 && response.status < 500) {
        return response;
      }
      lastError = new Error(`${url} returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }

  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}`);
}

export function assertJavaScriptChunkResponse(response) {
  const contentType = response.headers.get("content-type") ?? "";
  if (response.status !== 200) {
    throw new Error(`Expected JavaScript chunk ${response.url} to return 200, got ${response.status}`);
  }
  if (!isJavaScriptContentType(contentType)) {
    throw new Error(`Expected JavaScript MIME type for ${response.url}, got ${contentType || "missing content-type"}`);
  }
  if (!response.body.trim()) {
    throw new Error(`JavaScript chunk ${response.url} returned an empty body`);
  }
}

export async function smokeBaseUrl(baseUrl, options = {}) {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const healthUrl = new URL("/api/health", normalizedBase).toString();
  const appUrl = new URL("/", normalizedBase).toString();
  const health = await fetchText(healthUrl, { timeoutMs: options.timeoutMs });
  if (health.status !== 200) {
    throw new Error(`Expected ${healthUrl} to return 200, got ${health.status}: ${health.body.slice(0, 200)}`);
  }

  const app = await fetchText(appUrl, { timeoutMs: options.timeoutMs });
  if (app.status !== 200) {
    throw new Error(`Expected ${appUrl} to return 200, got ${app.status}: ${app.body.slice(0, 200)}`);
  }

  const scripts = extractNextScriptSrcs(app.body);
  if (scripts.length === 0) {
    throw new Error(`No Next.js script chunks were referenced by ${appUrl}`);
  }

  const chunkUrls = scripts.slice(0, options.chunkLimit ?? 5).map((src) => scriptUrlFor(normalizedBase, src));
  const chunkResponses = [];
  for (const chunkUrl of chunkUrls) {
    const response = await fetchText(chunkUrl, { timeoutMs: options.timeoutMs });
    assertJavaScriptChunkResponse(response);
    chunkResponses.push({
      contentType: response.headers.get("content-type") ?? "",
      status: response.status,
      url: response.url,
    });
  }

  return {
    appUrl,
    chunkResponses,
    healthUrl,
    scriptCount: scripts.length,
  };
}

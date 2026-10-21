import { createServer, type IncomingMessage, type Server } from "http";
import type { AddressInfo } from "net";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const dns = vi.hoisted(() => ({
  answers: new Map<string, { address: string; family: number }[]>(),
  hang: new Set<string>(),
  lookups: [] as string[],
}));

vi.mock("dns/promises", () => ({
  lookup: vi.fn(async (hostname: string) => {
    dns.lookups.push(hostname);
    if (dns.hang.has(hostname)) return new Promise(() => undefined);
    const answer = dns.answers.get(hostname);
    if (!answer) throw new Error("ENOTFOUND");
    return answer;
  }),
}));

const { assertSafeOutboundUrl, safeFetch, UnsafeUrlError } = await import("./safe-fetch");

type Seen = { method?: string; url?: string; host?: string; body: string };
let server: Server;
let port = 0;
let seen: Seen[] = [];

const readBody = (request: IncomingMessage) =>
  new Promise<string>((resolve) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => resolve(body));
  });

beforeAll(async () => {
  server = createServer(async (request, response) => {
    seen.push({ method: request.method, url: request.url, host: request.headers.host, body: await readBody(request) });
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "http://169.254.169.254/latest/meta-data" }).end();
      return;
    }
    if (request.url === "/large") {
      response.writeHead(200, { "content-type": "text/plain" }).end("x".repeat(64));
      return;
    }
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

afterEach(() => {
  seen = [];
  dns.answers.clear();
  dns.hang.clear();
  dns.lookups = [];
  vi.unstubAllEnvs();
});

describe("assertSafeOutboundUrl", () => {
  it("rejects plain http, credentials, and internal hostnames outside development", async () => {
    vi.stubEnv("NODE_ENV", "production");
    await expect(assertSafeOutboundUrl("http://idp.example.com/")).rejects.toBeInstanceOf(UnsafeUrlError);
    await expect(assertSafeOutboundUrl("https://user:pass@idp.example.com/")).rejects.toBeInstanceOf(UnsafeUrlError);
    await expect(assertSafeOutboundUrl("https://metadata.internal/")).rejects.toBeInstanceOf(UnsafeUrlError);
    await expect(assertSafeOutboundUrl("https://localhost/")).rejects.toBeInstanceOf(UnsafeUrlError);
  });

  it("rejects hostnames and IP literals that resolve to private addresses", async () => {
    vi.stubEnv("NODE_ENV", "production");
    dns.answers.set("rebind.example.com", [
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ]);
    dns.answers.set("169.254.169.254", [{ address: "169.254.169.254", family: 4 }]);
    await expect(assertSafeOutboundUrl("https://rebind.example.com/")).rejects.toThrow(/private/);
    await expect(assertSafeOutboundUrl("https://169.254.169.254/")).rejects.toThrow(/private/);
  });

  it("accepts https hostnames that resolve only to public addresses", async () => {
    vi.stubEnv("NODE_ENV", "production");
    dns.answers.set("idp.example.com", [{ address: "93.184.216.34", family: 4 }]);
    await expect(assertSafeOutboundUrl("https://idp.example.com/metadata")).resolves.toBeInstanceOf(URL);
  });
});

describe("safeFetch", () => {
  it("connects to the checked address and keeps the URL's host header", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const response = await safeFetch(`http://idp.localhost:${port}/meta?x=1`, { headers: { Accept: "application/xml" } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    expect(seen).toEqual([{ method: "GET", url: "/meta?x=1", host: `idp.localhost:${port}`, body: "" }]);
  });

  it("sends form bodies for token requests", async () => {
    vi.stubEnv("NODE_ENV", "development");
    await safeFetch(`http://127.0.0.1:${port}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code: "abc" }),
    });
    expect(seen[0]).toMatchObject({ method: "POST", url: "/token", body: "grant_type=authorization_code&code=abc" });
  });

  it("refuses redirects instead of following them", async () => {
    vi.stubEnv("NODE_ENV", "development");
    await expect(safeFetch(`http://127.0.0.1:${port}/redirect`)).rejects.toThrow(/Redirects/);
    expect(seen).toHaveLength(1);
  });

  it("caps response size", async () => {
    vi.stubEnv("NODE_ENV", "development");
    await expect(safeFetch(`http://127.0.0.1:${port}/large`, {}, { maxBytes: 16 })).rejects.toThrow(/too large/);
  });

  it("does not send a request when the target fails the check", async () => {
    vi.stubEnv("NODE_ENV", "production");
    await expect(safeFetch(`http://127.0.0.1:${port}/meta`)).rejects.toBeInstanceOf(UnsafeUrlError);
    expect(seen).toEqual([]);
  });

  it("bounds DNS resolution by the request deadline", async () => {
    vi.stubEnv("NODE_ENV", "production");
    dns.hang.add("slow-resolver.example.com");
    const started = Date.now();
    await expect(safeFetch("https://slow-resolver.example.com/metadata", {}, { timeoutMs: 50 })).rejects.toThrow(/timed out/);
    expect(Date.now() - started).toBeLessThan(2_000);
    await expect(assertSafeOutboundUrl("https://slow-resolver.example.com/", 50)).rejects.toBeInstanceOf(UnsafeUrlError);
  });

  it("refuses an already-aborted signal before any lookup or request", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const controller = new AbortController();
    controller.abort();
    await expect(safeFetch(`http://127.0.0.1:${port}/meta`, { signal: controller.signal })).rejects.toBeInstanceOf(UnsafeUrlError);
    vi.stubEnv("NODE_ENV", "production");
    dns.answers.set("idp.example.com", [{ address: "93.184.216.34", family: 4 }]);
    await expect(safeFetch("https://idp.example.com/meta", { signal: controller.signal })).rejects.toBeInstanceOf(UnsafeUrlError);
    expect(dns.lookups).toEqual([]);
    expect(seen).toEqual([]);
  });
});

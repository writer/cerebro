import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server";

import { GRC_UPLOAD_MAX_BYTES } from "./lib/grc-upload-limits";
import { ASK_AGENT_REQUEST_MAX_BYTES } from "./lib/ask-images";
import { nonceFromContentSecurityPolicy } from "./lib/content-security-policy";
import { config, proxy } from "./proxy";

const request = (method: string, path: string, headers?: Record<string, string>) =>
  new NextRequest(new URL(path, "http://localhost:3000"), { method, headers });

const scriptSrcOf = (policy: string | null) =>
  (policy ?? "")
    .split(";")
    .map((directive) => directive.trim())
    .find((directive) => directive.startsWith("script-src "));

describe("proxy content security policy", () => {
  it("runs on document routes but not static assets", () => {
    for (const url of ["/", "/findings", "/findings/f-1", "/developer/audit-log", "/missing-route"]) {
      expect(unstable_doesMiddlewareMatch({ config, nextConfig: {}, url })).toBe(true);
    }
    for (const url of ["/_next/static/chunks/app.js", "/_next/image?url=x", "/favicon.ico"]) {
      expect(unstable_doesMiddlewareMatch({ config, nextConfig: {}, url })).toBe(false);
    }
  });

  it("skips router prefetches, which reuse the page nonce", () => {
    expect(unstable_doesMiddlewareMatch({
      config,
      nextConfig: {},
      url: "/findings",
      headers: { "next-router-prefetch": "1" },
    })).toBe(false);
    expect(unstable_doesMiddlewareMatch({
      config,
      nextConfig: {},
      url: "/findings",
      headers: { purpose: "prefetch" },
    })).toBe(false);
  });

  it("sets a nonce-based script-src with no unsafe-inline", () => {
    const response = proxy(request("GET", "/findings"));
    expect(response.status).toBe(200);
    const policy = response.headers.get("content-security-policy");
    const nonce = nonceFromContentSecurityPolicy(policy);
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(scriptSrcOf(policy)).toBe(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
    expect(policy).toContain("default-src 'self'");
    expect(policy).toContain("frame-ancestors 'none'");
  });

  it("forwards the same nonce and policy to the app router as request headers", () => {
    const response = proxy(request("GET", "/"));
    const policy = response.headers.get("content-security-policy");
    const nonce = nonceFromContentSecurityPolicy(policy);
    expect(nonce).toBeTruthy();
    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
    expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(policy);
  });

  it("ignores nonce and policy headers supplied by the client", () => {
    const response = proxy(request("GET", "/", {
      "x-nonce": "attacker",
      "content-security-policy": "script-src 'unsafe-inline'",
    }));
    const policy = response.headers.get("content-security-policy");
    expect(policy).not.toContain("'unsafe-inline' ");
    expect(scriptSrcOf(policy)).not.toContain("'unsafe-inline'");
    expect(response.headers.get("x-middleware-request-x-nonce")).not.toBe("attacker");
    expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonceFromContentSecurityPolicy(policy));
  });

  it("uses a fresh nonce for every request", () => {
    const nonces = new Set(
      Array.from({ length: 8 }, () => nonceFromContentSecurityPolicy(proxy(request("GET", "/")).headers.get("content-security-policy"))),
    );
    expect(nonces.size).toBe(8);
  });

  it("applies the policy to API responses too", () => {
    const response = proxy(request("GET", "/api/cerebro/grc/findings"));
    expect(nonceFromContentSecurityPolicy(response.headers.get("content-security-policy"))).toBeTruthy();
  });
});

describe("proxy", () => {
  it("matches API requests in the Next.js runtime", () => {
    expect(unstable_doesMiddlewareMatch({
      config,
      nextConfig: {},
      url: "/api/cerebro/grc/findings",
    })).toBe(true);
    expect(unstable_doesMiddlewareMatch({
      config,
      nextConfig: {},
      url: "/_next/static/chunks/main.js",
    })).toBe(false);
  });

  it("passes normal API requests through", () => {
    const response = proxy(request("GET", "/api/cerebro/grc/findings"));
    expect(response.status).toBe(200);
  });

  it("passes POST requests with reasonable body size", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/ask", {
      "content-length": "1024",
    }));
    expect(response.status).toBe(200);
  });

  it("rejects oversized POST requests to API routes", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/ask", {
      "content-length": String(10 * 1024 * 1024),
    }));
    expect(response.status).toBe(413);
  });

  it("allows image-bearing agent requests up to the image request limit", () => {
    const response = proxy(request("POST", "/api/agent/ask", {
      "content-length": String(ASK_AGENT_REQUEST_MAX_BYTES - 1024),
      "content-type": "application/json",
    }));
    expect(response.status).toBe(200);
  });

  it("rejects agent requests above the image request limit", () => {
    const response = proxy(request("POST", "/api/agent/ask", {
      "content-length": String(ASK_AGENT_REQUEST_MAX_BYTES + 1),
      "content-type": "application/json",
    }));
    expect(response.status).toBe(413);
  });

  it("allows GRC policy uploads up to the backend upload limit", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/policy-lifecycle/uploads", {
      "content-length": String(GRC_UPLOAD_MAX_BYTES - 1024),
      "content-type": "multipart/form-data; boundary=test",
    }));
    expect(response.status).toBe(200);
  });

  it("allows GRC vendor uploads up to the backend upload limit", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/vendors/uploads", {
      "content-length": String(GRC_UPLOAD_MAX_BYTES - 1024),
      "content-type": "multipart/form-data; boundary=test",
    }));
    expect(response.status).toBe(200);
  });

  it("rejects GRC uploads above the backend upload limit", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/policy-lifecycle/uploads", {
      "content-length": String(GRC_UPLOAD_MAX_BYTES + 1),
      "content-type": "multipart/form-data; boundary=test",
    }));
    expect(response.status).toBe(413);
  });

  it("rejects oversized PUT requests to API routes", () => {
    const response = proxy(request("PUT", "/api/cerebro/grc/inventory/asset-reports", {
      "content-length": String(5 * 1024 * 1024),
    }));
    expect(response.status).toBe(413);
  });

  it("does not reject large GET requests", () => {
    const response = proxy(request("GET", "/api/cerebro/grc/findings", {
      "content-length": String(10 * 1024 * 1024),
    }));
    expect(response.status).toBe(200);
  });

  it("passes bodyless DELETE requests without content-length", () => {
    const response = proxy(request("DELETE", "/api/cerebro/grc/dashboards/dashboard-1"));
    expect(response.status).toBe(200);
  });

  it("rejects write requests without content-length", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/ask"));
    expect(response.status).toBe(411);
  });

  it("rejects malformed content-length", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/ask", {
      "content-length": "1024garbage",
    }));
    expect(response.status).toBe(400);
  });
});

import { describe, expect, it } from "vitest";

import {
  assertJavaScriptChunkResponse,
  assertNonceContentSecurityPolicy,
  extractNextScriptSrcs,
  isJavaScriptContentType,
  scriptUrlFor,
} from "./smoke-http.mjs";

const documentResponse = (policy, body) => ({
  body,
  headers: new Headers(policy ? { "content-security-policy": policy } : {}),
  status: 200,
  url: "http://127.0.0.1/",
});

describe("smoke-http helpers", () => {
  it("accepts a document whose scripts all carry the CSP nonce", () => {
    const nonce = "dGVzdC1ub25jZQ==";
    const response = documentResponse(
      `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
      `<script src="/_next/static/chunks/app.js" async="" nonce="${nonce}"></script>
       <script nonce="${nonce}">self.__next_f=[]</script>`,
    );
    expect(assertNonceContentSecurityPolicy(response)).toEqual({ nonce, scriptTagCount: 2 });
  });

  it("rejects a document without a nonce-based script-src", () => {
    expect(() => assertNonceContentSecurityPolicy(documentResponse(undefined, "<script></script>")))
      .toThrow("no header");
    expect(() => assertNonceContentSecurityPolicy(documentResponse("default-src 'self'; script-src 'self' 'unsafe-inline'", "")))
      .toThrow("'unsafe-inline'");
    expect(() => assertNonceContentSecurityPolicy(documentResponse("default-src 'self'; script-src 'self'", "")))
      .toThrow("carry a nonce");
  });

  it("rejects a document with a script tag that lacks the nonce", () => {
    const response = documentResponse(
      "script-src 'self' 'nonce-abc123' 'strict-dynamic'",
      `<script nonce="abc123"></script><script src="/_next/static/chunks/x.js"></script>`,
    );
    expect(() => assertNonceContentSecurityPolicy(response)).toThrow("1 script tag(s)");
  });

  it("extracts Next.js script chunk URLs from rendered HTML", () => {
    const html = `
      <script src="/_next/static/chunks/app.js" async></script>
      <script src="/_next/static/chunks/app.js" async></script>
      <script src="https://cerebro.example.com/_next/static/chunks/runtime.js?dpl=1"></script>
    `;
    expect(extractNextScriptSrcs(html)).toEqual([
      "/_next/static/chunks/app.js",
      "https://cerebro.example.com/_next/static/chunks/runtime.js?dpl=1",
    ]);
  });

  it("accepts JavaScript MIME types and rejects text/plain", () => {
    expect(isJavaScriptContentType("application/javascript; charset=utf-8")).toBe(true);
    expect(isJavaScriptContentType("text/javascript")).toBe(true);
    expect(isJavaScriptContentType("application/activity+javascript")).toBe(true);
    expect(isJavaScriptContentType("text/plain")).toBe(false);
  });

  it("resolves relative chunk URLs against a deployment base URL", () => {
    expect(scriptUrlFor("https://cerebro.example.com/app/", "/_next/static/chunks/a.js"))
      .toBe("https://cerebro.example.com/_next/static/chunks/a.js");
  });

  it("rejects a malformed JavaScript chunk even when status and MIME type pass", () => {
    expect(() => assertJavaScriptChunkResponse({
      body: "this is not valid JavaScript {{{",
      headers: new Headers({ "content-type": "application/javascript" }),
      status: 200,
      url: "http://127.0.0.1/chunk.js",
    })).toThrow("was not executable");
  });
});

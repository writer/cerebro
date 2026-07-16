import { describe, expect, it } from "vitest";

import {
  extractNextScriptSrcs,
  isJavaScriptContentType,
  scriptUrlFor,
} from "./smoke-http.mjs";

describe("smoke-http helpers", () => {
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
});

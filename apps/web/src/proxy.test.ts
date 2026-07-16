import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";

import { GRC_UPLOAD_MAX_BYTES } from "./lib/grc-upload-limits";
import { proxy } from "./proxy";

const request = (method: string, path: string, headers?: Record<string, string>) =>
  new NextRequest(new URL(path, "http://localhost:3000"), { method, headers });

describe("proxy", () => {
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

  it("passes requests without content-length", () => {
    const response = proxy(request("POST", "/api/cerebro/grc/ask"));
    expect(response.status).toBe(200);
  });
});

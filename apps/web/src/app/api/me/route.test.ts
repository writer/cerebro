import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const originalAuthorityMode = process.env.CEREBRO_AUTHORITY_MODE;

afterEach(() => {
  if (originalAuthorityMode === undefined) delete process.env.CEREBRO_AUTHORITY_MODE;
  else process.env.CEREBRO_AUTHORITY_MODE = originalAuthorityMode;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("current user route", () => {
  it("returns the Rust identity response without interpreting it", async () => {
    process.env.CEREBRO_AUTHORITY_MODE = "rust";
    const rustIdentity = {
      authenticated: true,
      fallback: false,
      user: {
        actorId: "subject-1",
        confidence: "signature-verified",
        source: "jwt",
      },
    };
    let upstreamHeaders = new Headers();
    vi.stubGlobal("fetch", vi.fn(async (_url: URL | RequestInfo, init?: RequestInit) => {
      upstreamHeaders = new Headers(init?.headers);
      return new Response(JSON.stringify(rustIdentity), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }));

    const response = await GET(
      new NextRequest("http://localhost/api/me", {
        headers: { authorization: "Bearer signed-browser-token" },
      }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(upstreamHeaders.get("authorization")).toBe("Bearer signed-browser-token");
    await expect(response.json()).resolves.toEqual(rustIdentity);
  });
});

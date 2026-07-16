import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET, PATCH, PUT } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalIdentityRequired = process.env.CEREBRO_IDENTITY_REQUIRED;
const originalLocalIdentityFallback = process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;

afterEach(() => {
  if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
  else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
  if (originalIdentityRequired === undefined) delete process.env.CEREBRO_IDENTITY_REQUIRED;
  else process.env.CEREBRO_IDENTITY_REQUIRED = originalIdentityRequired;
  if (originalLocalIdentityFallback === undefined) delete process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK;
  else process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = originalLocalIdentityFallback;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("Cerebro proxy route", () => {
  it("translates a shared inflight rejection for every deduplicated request", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    let rejectFetch: ((reason?: unknown) => void) | undefined;
    const pendingFetch = new Promise<Response>((_resolve, reject) => {
      rejectFetch = reject;
    });
    const fetchMock = vi.fn(() => pendingFetch);
    vi.stubGlobal("fetch", fetchMock);
    const context = { params: Promise.resolve({ path: ["grc", "findings"] }) };
    const requestURL = "http://localhost/api/cerebro/grc/findings?dedupe=rejection";

    const first = GET(new NextRequest(requestURL), context);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    const second = GET(new NextRequest(requestURL), context);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(fetchMock).toHaveBeenCalledOnce();

    rejectFetch?.(new Error("network failed"));
    const [firstResponse, secondResponse] = await Promise.all([first, second]);

    expect(firstResponse.status).toBe(502);
    expect(secondResponse.status).toBe(502);
    expect(firstResponse.headers.get("x-cerebro-web-trace-id")).toMatch(/^[0-9a-f]{32}$/);
    expect(secondResponse.headers.get("x-cerebro-web-trace-id")).toMatch(/^[0-9a-f]{32}$/);
    await expect(secondResponse.json()).resolves.toMatchObject({ error: "Unable to reach Cerebro API" });
  });

  it.each([
    ["PATCH", PATCH],
    ["PUT", PUT],
  ] as const)("does not read a %s body before authorization", async (method, handler) => {
    process.env.CEREBRO_IDENTITY_REQUIRED = "true";
    process.env.CEREBRO_LOCAL_IDENTITY_FALLBACK = "false";
    const request = new NextRequest("http://localhost/api/cerebro/grc/findings/finding-1", {
      method,
      body: JSON.stringify({ status: "resolved" }),
    });
    const readBody = vi.spyOn(request, "text");

    const response = await handler(request, {
      params: Promise.resolve({ path: ["grc", "findings", "finding-1"] }),
    });

    expect(response.status).toBe(401);
    expect(readBody).not.toHaveBeenCalled();
  });
});

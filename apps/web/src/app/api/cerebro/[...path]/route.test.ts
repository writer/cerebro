import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;

afterEach(() => {
  if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
  else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
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
});

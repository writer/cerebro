import { NextRequest } from "next/server";
import { afterEach, describe, expect, it } from "vitest";

import { GET } from "./route";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalApiBase = process.env.CEREBRO_API_BASE;

afterEach(() => {
  if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
  else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
  if (originalApiBase === undefined) delete process.env.CEREBRO_API_BASE;
  else process.env.CEREBRO_API_BASE = originalApiBase;
});

const get = async () => GET(new NextRequest("http://localhost/api/identity/health"));

describe("identity health fixture mode", () => {
  it("reports a usable console without a signed identity", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";

    const response = await get();
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload.status).toBe("ready");
    expect(payload.current.source).toBe("local-fallback");
  });

  it("does not claim the viewer is authenticated", async () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";

    const payload = await (await get()).json();

    expect(payload.current.authenticated).toBe(false);
    expect(payload.current.confidence).toBe("fallback");
  });

  it("keeps the fixture off unless it is asked for", async () => {
    delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    process.env.CEREBRO_API_BASE = "https://cerebro.example.invalid";

    const payload = await (await get()).json();

    expect(payload.current?.source).not.toBe("local-fallback");
  });
});

import { afterEach, describe, expect, it } from "vitest";

import { cerebroFixtureResponseFor, resetCerebroFixtureStateForTests } from "./cerebro-fixtures";

const originalFixtureMode = process.env.CEREBRO_WEB_FIXTURE_MODE;
const originalApiBase = process.env.CEREBRO_API_BASE;

const parseFixture = (response: NonNullable<ReturnType<typeof cerebroFixtureResponseFor>>) =>
  JSON.parse(response.body) as Record<string, unknown>;

describe("finding audit preview fixtures", () => {
  afterEach(() => {
    resetCerebroFixtureStateForTests();
    if (originalFixtureMode === undefined) delete process.env.CEREBRO_WEB_FIXTURE_MODE;
    else process.env.CEREBRO_WEB_FIXTURE_MODE = originalFixtureMode;
    if (originalApiBase === undefined) delete process.env.CEREBRO_API_BASE;
    else process.env.CEREBRO_API_BASE = originalApiBase;
  });

  it("resolves live finding previews through the finding-scoped route", () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_API_BASE;

    const response = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/findings/demo-finding-critical/audit-preview",
    });

    expect(response?.status).toBe(200);
    expect(parseFixture(response!)).toMatchObject({
      finding: { id: "demo-finding-critical" },
    });
  });

  it("keeps immutable packet lookup keyed by packet ID", () => {
    process.env.CEREBRO_WEB_FIXTURE_MODE = "1";
    delete process.env.CEREBRO_API_BASE;

    const findingIDLookup = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/audit-packets/demo-finding-critical",
    });
    const packetIDLookup = cerebroFixtureResponseFor({
      method: "GET",
      path: "grc/audit-packets/packet-demo-finding-critical",
    });

    expect(findingIDLookup?.status).toBe(404);
    expect(packetIDLookup?.status).toBe(200);
    expect(parseFixture(packetIDLookup!)).toMatchObject({
      id: "packet-demo-finding-critical",
      finding: { id: "demo-finding-critical" },
    });
  });
});

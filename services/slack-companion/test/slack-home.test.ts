import assert from "node:assert/strict";
import test from "node:test";
import { publishHome } from "../src/slack/home.js";
import { testConfig } from "./fixtures.js";

test("publishHome keeps fleet and successful sources visible when one findings source fails", async () => {
  const published: any[] = [];
  const config = testConfig({ cerebro: { defaultRuntimeIds: ["writer-okta", "missing-runtime"] } });
  const client = {
    views: {
      publish: async (input: any) => {
        published.push(input);
      },
    },
  };
  const cerebro = {
    listRuntimeHealth: async () => [{ runtime_id: "writer-okta", sync_status: "healthy" }],
    listFindings: async (runtimeId: string) => {
      if (runtimeId === "missing-runtime") throw new Error("Cerebro request failed with status 404");
      return [{ id: "finding-1", title: "Privileged account active", status: "open" }];
    },
  };
  const a2a = {
    listInstances: async () => [{
      instanceId: "primary-instance-1",
      label: "primary",
      role: "generalist",
      commit: "sha-current",
      capabilities: ["slack", "security"],
      state: "active",
      startedAt: "2026-07-16T08:00:00.000Z",
      heartbeatAt: new Date().toISOString(),
      expiresAt: Math.floor(Date.now() / 1_000) + 30,
    }],
  };

  await publishHome(client as any, "U123", config, cerebro as any, a2a as any);

  assert.equal(published.length, 1);
  const encoded = JSON.stringify(published[0]);
  assert.match(encoded, /Cerebro fleet/);
  assert.match(encoded, /primary-instance-1/);
  assert.match(encoded, /Privileged account active/);
  assert.match(encoded, /Data unavailable/);
  assert.match(encoded, /Open findings for missing-runtime/);
});

test("publishHome still publishes fleet when runtime health and findings are unavailable", async () => {
  const published: any[] = [];
  const config = testConfig({ cerebro: { defaultRuntimeIds: ["missing-runtime"] } });
  const client = { views: { publish: async (input: any) => published.push(input) } };
  const cerebro = {
    listRuntimeHealth: async () => { throw new Error("unavailable"); },
    listFindings: async () => { throw new Error("unavailable"); },
  };
  const a2a = {
    listInstances: async () => [{
      instanceId: "primary-instance-1",
      label: "primary",
      role: "generalist",
      commit: "sha-current",
      capabilities: ["slack"],
      state: "active",
      startedAt: "2026-07-16T08:00:00.000Z",
      heartbeatAt: new Date().toISOString(),
      expiresAt: Math.floor(Date.now() / 1_000) + 30,
    }],
  };

  await publishHome(client as any, "U123", config, cerebro as any, a2a as any);

  assert.equal(published.length, 1);
  const encoded = JSON.stringify(published[0]);
  assert.match(encoded, /primary-instance-1/);
  assert.match(encoded, /Runtime health/);
  assert.match(encoded, /Open findings for missing-runtime/);
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  ComputerSandboxGatewayProvider,
  createComputerSandboxRuntime,
} from "../src/runtime/computer-sandbox-gateway.js";
import { loadSlackRuntimeConfig } from "../src/runtime/config.js";

test("runtime config binds multiple gateways without placing tokens in JSON", () => {
  const config = loadSlackRuntimeConfig({
    ...baseEnv(),
    CEREBRO_COMPUTER_SANDBOX_GATEWAYS_JSON: JSON.stringify([
      {
        base_url: "https://sandbox-one.example.com",
        provider_id: "managed-desktop",
        timeout_ms: 30_000,
        token_env: "CEREBRO_COMPUTER_SANDBOX_TOKEN_ONE",
      },
      {
        base_url: "https://sandbox-two.example.com",
        provider_id: "managed-container",
        timeout_ms: 45_000,
        token_env: "CEREBRO_COMPUTER_SANDBOX_TOKEN_TWO",
      },
    ]),
    CEREBRO_COMPUTER_SANDBOX_TOKEN_ONE: "token-one",
    CEREBRO_COMPUTER_SANDBOX_TOKEN_TWO: "token-two",
  });

  assert.deepEqual(
    config.computerSandboxGateways.map(({ providerId, baseUrl }) => ({
      baseUrl,
      providerId,
    })),
    [
      {
        baseUrl: "https://sandbox-one.example.com",
        providerId: "managed-desktop",
      },
      {
        baseUrl: "https://sandbox-two.example.com",
        providerId: "managed-container",
      },
    ],
  );
});

test("gateway adapter sends bounded authenticated protocol requests", async () => {
  const requests: Request[] = [];
  const adapter = new ComputerSandboxGatewayProvider({
    baseUrl: "https://sandbox.example.com/",
    fetchImpl: async (input, init) => {
      requests.push(new Request(input, init));
      return Response.json({
        capabilities: ["desktop"],
        max_session_seconds: 3_600,
        observed_at: "2026-07-28T12:00:00.000Z",
        provider_id: "managed-desktop",
        provider_version: "1.0.0",
        schema_version: "computer-sandbox-provider/v1",
        state: "ready",
        supported_actions: ["observe"],
        valid_until: "2026-07-28T12:05:00.000Z",
      });
    },
    providerId: "managed-desktop",
    timeoutMs: 30_000,
    token: "bound-at-runtime",
  });

  const descriptor = await adapter.describe();
  assert.equal(descriptor.provider_id, "managed-desktop");
  assert.equal(requests[0]?.url, "https://sandbox.example.com/v1/computer-sandbox/provider");
  assert.equal(requests[0]?.headers.get("authorization"), "Bearer bound-at-runtime");
});

test("empty gateway configuration leaves computer access disabled", () => {
  assert.equal(createComputerSandboxRuntime([]), undefined);
  assert.deepEqual(
    loadSlackRuntimeConfig({
      ...baseEnv(),
      CEREBRO_COMPUTER_SANDBOX_GATEWAYS_JSON: "[]",
    }).computerSandboxGateways,
    [],
  );
});

test("gateway adapter bounds streamed responses without content length", async () => {
  const adapter = new ComputerSandboxGatewayProvider({
    baseUrl: "https://sandbox.example.com",
    fetchImpl: async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(700_000));
        controller.enqueue(new Uint8Array(700_000));
        controller.close();
      },
    })),
    providerId: "managed-desktop",
    timeoutMs: 30_000,
    token: "bound-at-runtime",
  });

  await assert.rejects(() => adapter.describe(), /response is too large/);
});

function baseEnv(): NodeJS.ProcessEnv {
  return {
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro Development",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "development",
    CEREBRO_SLACK_PRODUCTION: "false",
    CEREBRO_TENANT_ID: "tenant-one",
    SLACK_ALLOWED_TEAM_IDS: "T-ONE",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  };
}

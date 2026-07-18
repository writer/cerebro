import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import test from "node:test";
import { InfisicalClient } from "../src/infisical/client.js";
import { testConfig } from "./fixtures.js";

const authPayload = {
  iamHttpRequestMethod: "POST" as const,
  iamRequestUrl: "https://sts.us-east-1.amazonaws.com/",
  iamRequestBody: "Action=GetCallerIdentity&Version=2011-06-15",
  iamRequestHeaders: {
    host: "sts.us-east-1.amazonaws.com",
    authorization: "AWS4-HMAC-SHA256 SignedHeaders=host;x-amz-date",
    "x-amz-date": "20260626T000000Z",
  },
};

test("Infisical status reports missing generated ids without fetching", async () => {
  let called = false;
  const client = new InfisicalClient(testConfig({
    infisical: {
      projectId: undefined,
      identityId: undefined,
    },
  }), {
    fetchImpl: (async () => {
      called = true;
      return new Response("{}");
    }) as typeof fetch,
  });

  const status = await client.status({ checkConnection: true });
  assert.equal(status.configured, false);
  assert.deepEqual(status.missing, ["INFISICAL_PROJECT_ID", "INFISICAL_IDENTITY_ID"]);
  assert.equal(called, false);
});

test("Infisical metadata does not request or return secret values", async () => {
  const calls: Array<{ url: string; body?: string }> = [];
  const client = new InfisicalClient(testConfig(), {
    authPayloadProvider: async () => authPayload,
    fetchImpl: fakeInfisicalFetch(calls, "super-secret-value"),
  });

  const metadata = await client.secretMetadata({ secretName: "SLACK_BOT_TOKEN" });
  const details = metadata as any;
  const serialized = JSON.stringify(metadata);

  assert.equal(calls.some((call) => call.url.includes("/api/v1/auth/aws-auth/login")), true);
  assert.equal(calls.some((call) => call.url.includes("viewSecretValue=false")), true);
  assert.equal(details.secret.secret_key, "SLACK_BOT_TOKEN");
  assert.equal(details.secret.secret_comment_present, true);
  assert.equal(details.secret.raw_secret_value_returned, false);
  assert.doesNotMatch(serialized, /super-secret-value|human comment|metadata value/);
});

test("Infisical fingerprint returns only length and hash prefix", async () => {
  const calls: Array<{ url: string; body?: string }> = [];
  const secretValue = "rotated-secret-value";
  const client = new InfisicalClient(testConfig(), {
    authPayloadProvider: async () => authPayload,
    fetchImpl: fakeInfisicalFetch(calls, secretValue),
  });

  const fingerprint = await client.secretFingerprint({
    secretName: "CEREBRO_READ_API_KEY",
    secretPath: "/runtime",
    includeImports: false,
  });
  const details = fingerprint as any;
  const expectedPrefix = createHash("sha256").update(secretValue).digest("hex").slice(0, 16);
  const serialized = JSON.stringify(fingerprint);

  assert.equal(calls.some((call) => call.url.includes("viewSecretValue=true")), true);
  assert.equal(calls.some((call) => call.url.includes("secretPath=%2Fruntime")), true);
  assert.equal(details.value_present, true);
  assert.equal(details.value_bytes, Buffer.byteLength(secretValue, "utf8"));
  assert.equal(details.value_sha256_prefix, expectedPrefix);
  assert.equal(details.raw_secret_value_returned, false);
  assert.doesNotMatch(serialized, new RegExp(secretValue));
});

test("Infisical raw value path is disabled for runtime by default", async () => {
  const client = new InfisicalClient(testConfig(), {
    authPayloadProvider: async () => authPayload,
    fetchImpl: fakeInfisicalFetch([], "super-secret-value"),
  });

  await assert.rejects(
    () => client.secretValueForRuntime({ secretName: "SLACK_BOT_TOKEN" }),
    /INFISICAL_ALLOW_SECRET_VALUES is false/,
  );
});

function fakeInfisicalFetch(calls: Array<{ url: string; body?: string }>, secretValue: string): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, body: typeof init?.body === "string" ? init.body : undefined });
    if (url.includes("/api/v1/auth/aws-auth/login")) {
      return new Response(JSON.stringify({
        accessToken: "fixture-access",
        expiresIn: 900,
        tokenType: "Bearer",
      }));
    }
    if (url.includes("/api/v4/secrets/")) {
      return new Response(JSON.stringify({
        secret: {
          id: "secret-id",
          workspace: "project-test",
          environment: "dev",
          version: 3,
          type: "shared",
          secretKey: decodeURIComponent(url.split("/api/v4/secrets/")[1]!.split("?")[0]!),
          secretValue,
          secretComment: "human comment",
          createdAt: "2026-06-26T10:00:00.000Z",
          updatedAt: "2026-06-26T11:00:00.000Z",
          secretValueHidden: true,
          secretPath: "/runtime",
          isRotatedSecret: true,
          rotationId: "rotation-id",
          tags: [{ id: "tag-id", slug: "security", name: "Security", color: "#ff0000" }],
          secretMetadata: [{ key: "owner", value: "metadata value", isEncrypted: false }],
          actor: { actorId: "actor-id", actorType: "identity", name: "runtime" },
        },
      }));
    }
    return new Response(JSON.stringify({ error: "unexpected" }), { status: 404 });
  }) as typeof fetch;
}

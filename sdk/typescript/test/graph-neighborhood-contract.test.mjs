import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { APIError, Client } from "../src/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const generatedOpenAPIPath = path.resolve(here, "../src/generated/openapi-types.ts");

const fixtureToken = ["fixture", "sdk", "token"].join("-");
const rootUrn = "urn:cerebro:tenant-a:repository:writer/cerebro";

test("graph neighborhood caller uses the bounded product route and preserves auth and scope", async () => {
  const requests = [];
  const client = new Client({
    baseUrl: "https://cerebro.example.com/api/",
    apiKey: fixtureToken,
    fetchImpl: async (url, init = {}) => {
      requests.push({ url: String(url), headers: new Headers(init.headers) });
      return new Response(JSON.stringify({
        root: { urn: rootUrn, entity_type: "repository", label: "cerebro" },
        neighbors: [{ urn: "urn:cerebro:tenant-a:user:alice", entity_type: "user", label: "Alice" }],
        relations: [{ from_urn: rootUrn, relation: "owned_by", to_urn: "urn:cerebro:tenant-a:user:alice" }],
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    },
  });

  const response = await client.getEntityNeighborhood(` ${rootUrn} `, 50);

  assert.deepEqual(response, {
    root: { urn: rootUrn, entity_type: "repository", label: "cerebro" },
    neighbors: [{ urn: "urn:cerebro:tenant-a:user:alice", entity_type: "user", label: "Alice" }],
    relations: [{ from_urn: rootUrn, relation: "owned_by", to_urn: "urn:cerebro:tenant-a:user:alice" }],
  });
  assert.equal(requests.length, 1);
  assert.equal(
    requests[0].url,
    "https://cerebro.example.com/api/platform/graph/neighborhood?root_urn=urn%3Acerebro%3Atenant-a%3Arepository%3Awriter%2Fcerebro&limit=50",
  );
  assert.equal(requests[0].headers.get("authorization"), `Bearer ${fixtureToken}`);
  assert.equal(requests[0].headers.get("accept"), "application/json");
  assert.equal(requests[0].headers.get("x-cerebro-tenant"), null);
  assert.equal(requests[0].headers.get("x-cerebro-workspace"), null);
  const requestURL = new URL(requests[0].url);
  assert.equal(requestURL.searchParams.has("tenant_id"), false);
  assert.equal(requestURL.searchParams.has("workspace_id"), false);
});

test("graph neighborhood caller forwards limits for authority-side clamping and preserves typed errors", async () => {
  const requests = [];
  const client = new Client({
    baseUrl: "https://cerebro.example.com",
    apiKey: fixtureToken,
    fetchImpl: async (url, init = {}) => {
      requests.push({ url: String(url), headers: new Headers(init.headers) });
      return new Response(JSON.stringify({
        error: "graph runtime unavailable",
        code: "graph_unavailable",
      }), { status: 503, headers: { "Content-Type": "application/json" } });
    },
  });

  await assert.rejects(
    client.getEntityNeighborhood(rootUrn, 51),
    (error) => {
      assert.ok(error instanceof APIError);
      assert.equal(error.statusCode, 503);
      assert.equal(error.code, "graph_unavailable");
      assert.match(error.message, /graph runtime unavailable/);
      assert.doesNotMatch(error.message, new RegExp(fixtureToken));
      return true;
    },
  );
  assert.equal(new URL(requests[0].url).pathname, "/platform/graph/neighborhood");
  assert.equal(new URL(requests[0].url).searchParams.get("limit"), "51");
  assert.equal(requests[0].headers.get("authorization"), `Bearer ${fixtureToken}`);
});

test("graph neighborhood caller rejects an empty root before making a request", async () => {
  let requests = 0;
  const client = new Client({
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async () => {
      requests += 1;
      return new Response("{}", { status: 200 });
    },
  });

  await assert.rejects(client.getEntityNeighborhood("  \t"), /rootUrn is required/);
  assert.equal(requests, 0);
});

test("generated OpenAPI graph types retain the public neighborhood wire contract", async () => {
  const generated = await readFile(generatedOpenAPIPath, "utf8");
  const generatedType = (name) => {
    const match = generated.match(new RegExp(`export type ${name} = \\{([\\s\\S]*?)\\n\\};`));
    assert.ok(match, `generated type ${name} is missing`);
    return match[1];
  };

  const entity = generatedType("GraphEntity");
  assert.match(entity, /\n  entity_type: string;/);
  assert.match(entity, /\n  label: string;/);
  assert.match(entity, /\n  urn: string;/);

  const relation = generatedType("GraphRelation");
  assert.match(relation, /\n  from_urn: string;/);
  assert.match(relation, /\n  relation: string;/);
  assert.match(relation, /\n  to_urn: string;/);

  const response = generatedType("GetEntityNeighborhoodResponse");
  assert.match(response, /\n  neighbors\?: GraphEntity\[\];/);
  assert.match(response, /\n  relations\?: GraphRelation\[\];/);
  assert.match(response, /\n  root\?: GraphEntity;/);
  assert.doesNotMatch(response, /tenant_id|workspace_id/);
});

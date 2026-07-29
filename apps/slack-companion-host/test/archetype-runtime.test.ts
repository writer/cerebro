import assert from "node:assert/strict";
import test from "node:test";

import type { HomeView } from "@slack/types";

import {
  ArchetypeWorkspaceClient,
  ArchetypeWorkspaceClientError,
  type SlackUserLookupPort,
} from "../src/archetype-client.js";
import { loadSlackRuntimeConfig } from "../src/runtime/config.js";
import { ArchetypeSlackWorkspace } from "../src/runtime/archetype-workspace.js";

const finding = {
  assignee: null,
  description: "A reachable production dependency has a critical advisory.",
  due_at: "2026-07-23T18:00:00.000Z",
  finding_uuid: "018f6b96-a7b8-8c9d-8e0f-123456789abc",
  fingerprint: "a".repeat(64),
  priority_reasons: ["critical severity", "runtime reachable"],
  priority_score: 98,
  repository: "writer/service",
  severity: "critical",
  sla_state: "overdue",
  status: "actionable",
};

const digest = {
  actor_id: "person@writer.com",
  date: "2026-07-23",
  generated_at: "2026-07-23T16:00:00.000Z",
  saved_views: [],
  today: {
    actor_id: "person@writer.com",
    assigned_to_me: [],
    counts: {
      assigned_to_me: 0,
      changed_last_24_hours: 1,
      due_soon: 0,
      overdue: 1,
      unassigned_critical: 1,
    },
    generated_at: "2026-07-23T16:00:00.000Z",
    needs_attention: [finding],
    recent_changes: [],
  },
};

const pendingIntent = {
  action: "start_work",
  created_at: "2026-07-23T16:05:00.000Z",
  executed_at: null,
  expires_at: "2026-07-23T16:20:00.000Z",
  finding_ref: finding.finding_uuid,
  id: "018f6b96-a7b8-8c9d-8e0f-123456789abe",
  status: "pending",
  summary: "Assign this finding to Person Writer and mark it in progress.",
};

const slack: SlackUserLookupPort = {
  users: {
    info: async ({ user }) => ({
      ok: true,
      user: {
        id: user,
        profile: {
          display_name: "Person Writer",
          email: "person@writer.com",
          real_name: "Person Writer",
        },
        team_id: "T-ONE",
      },
    }),
  },
};

test("runtime config activates Archetype only with complete private bindings", () => {
  const base = {
    CEREBRO_BASE_URL: "https://cerebro.example.com",
    CEREBRO_READ_API_KEY: "bound-at-runtime",
    CEREBRO_SLACK_APP_NAME: "Cerebro",
    CEREBRO_SLACK_ENVIRONMENT_LABEL: "production",
    CEREBRO_SLACK_PRODUCTION: "true",
    CEREBRO_TENANT_ID: "writer",
    SLACK_ALLOWED_TEAM_IDS: "T-ONE",
    SLACK_APP_TOKEN: "bound-at-runtime",
    SLACK_BOT_TOKEN: "bound-at-runtime",
  };
  assert.equal(loadSlackRuntimeConfig(base).archetype, undefined);

  const config = loadSlackRuntimeConfig({
    ...base,
    ARCHETYPE_ALLOWED_EMAIL_DOMAINS: "writer.com",
    ARCHETYPE_BASE_URL: "https://archetype.internal/",
    ARCHETYPE_REQUEST_TIMEOUT_MS: "8000",
    ARCHETYPE_WORKSPACE_ENABLED: "true",
    OKTA_API_TOKEN: "bound-at-runtime",
    OKTA_DOMAIN: "https://writer.okta.com/",
  });
  assert.equal(config.archetype?.baseUrl, "https://archetype.internal");
  assert.equal(config.archetype?.oktaDomain, "https://writer.okta.com");
  assert.equal(config.archetype?.timeoutMs, 8_000);
  assert.deepEqual(
    [...(config.archetype?.allowedEmailDomains ?? [])],
    ["writer.com"],
  );

  assert.throws(
    () => loadSlackRuntimeConfig({
      ...base,
      ARCHETYPE_BASE_URL: "https://archetype.internal",
    }),
    /require ARCHETYPE_WORKSPACE_ENABLED=true/,
  );
});

test("uses the signed-in Slack actor, active Okta user, and actor-scoped Archetype work", async () => {
  const requests: Request[] = [];
  const workspace = new ArchetypeSlackWorkspace(new ArchetypeWorkspaceClient({
    allowedEmailDomains: new Set(["writer.com"]),
    archetypeBaseUrl: "https://archetype.internal",
    fetchImpl: async (input, init) => {
      const request = new Request(input, init);
      requests.push(request);
      switch (new URL(request.url).pathname) {
        case "/api/v1/users/person%40writer.com":
          return json({
            id: "00u-active",
            profile: {
              email: "person@writer.com",
              firstName: "Person",
              lastName: "Writer",
              login: "person@writer.com",
            },
            status: "ACTIVE",
          });
        case "/api/v1/users/00u-active/groups":
          return json([{
            id: "group-security",
            profile: { name: "writer-okta-user" },
          }]);
        case "/api/v1/workspace/digest":
          return json(digest);
        case "/api/v1/workspace/action-intents":
          assert.equal(request.method, "POST");
          assert.deepEqual(await request.json(), {
            action: "start_work",
            finding_ref: finding.finding_uuid,
          });
          return json(pendingIntent, 201);
        case `/api/v1/workspace/action-intents/${pendingIntent.id}/execute`:
          assert.equal(request.method, "POST");
          return json({
            finding: {
              ...finding,
              assignee: {
                display_name: "Person Writer",
                email: "person@writer.com",
                id: "00u-active",
                kind: "user",
                source: "okta",
              },
              status: "in_progress",
            },
            intent: {
              ...pendingIntent,
              executed_at: "2026-07-23T16:06:00.000Z",
              status: "executed",
            },
          });
        default:
          return new Response("not found", { status: 404 });
      }
    },
    oktaApiToken: "secret-not-logged",
    oktaDomain: "https://writer.okta.com",
    timeoutMs: 10_000,
  }));

  const home = await workspace.home({
    slack,
    teamId: "T-ONE",
    userId: "U-ONE",
  });
  const previewValue = buttonValues(home)[0];
  assert.ok(previewValue);
  const preview = await workspace.preview({
    actionValue: previewValue,
    slack,
    teamId: "T-ONE",
    userId: "U-ONE",
  });
  const confirmValue = buttonValues(preview)[0];
  assert.ok(confirmValue);
  const result = await workspace.confirm({
    actionValue: confirmValue,
    slack,
    teamId: "T-ONE",
    userId: "U-ONE",
  });

  assert.match(JSON.stringify(home), /writer\/service/);
  assert.match(JSON.stringify(preview), /Assign this finding/);
  assert.match(JSON.stringify(result), /Assigned to Person Writer/);
  const archetypeRequests = requests.filter((request) =>
    new URL(request.url).hostname === "archetype.internal"
  );
  assert.equal(archetypeRequests.length, 3);
  for (const request of archetypeRequests) {
    assert.equal(request.headers.get("x-okta-email"), "person@writer.com");
    assert.equal(request.headers.get("x-okta-user"), "person@writer.com");
    assert.equal(
      request.headers.get("x-archetype-groups"),
      "writer-okta-user",
    );
    assert.equal(request.headers.has("authorization"), false);
  }
  const oktaRequest = requests.find((request) =>
    new URL(request.url).hostname === "writer.okta.com"
  );
  assert.equal(oktaRequest?.headers.get("authorization"), "SSWS secret-not-logged");
});

test("fails closed when Slack does not map to the exact active Okta identity", async () => {
  const client = new ArchetypeWorkspaceClient({
    allowedEmailDomains: new Set(["writer.com"]),
    archetypeBaseUrl: "https://archetype.internal",
    fetchImpl: async (input) => {
      const path = new URL(String(input)).pathname;
      if (path.includes("/users/")) {
        return json({
          id: "00u-other",
          profile: {
            email: "other@writer.com",
            login: "other@writer.com",
          },
          status: "ACTIVE",
        });
      }
      return json([]);
    },
    oktaApiToken: "bound-at-runtime",
    oktaDomain: "https://writer.okta.com",
    timeoutMs: 10_000,
  });
  await assert.rejects(
    () => client.resolveIdentity({
      slack,
      teamId: "T-ONE",
      userId: "U-ONE",
    }),
    (error: unknown) =>
      error instanceof ArchetypeWorkspaceClientError
      && error.state === "identity_unverified",
  );
});

function buttonValues(view: HomeView | {
  blocks: HomeView["blocks"];
}): string[] {
  return view.blocks.flatMap((block) => {
    if (
      block.type !== "actions"
      || !("elements" in block)
      || !Array.isArray(block.elements)
    ) return [];
    return block.elements.flatMap((element: unknown) => {
      if (
        element === null
        || typeof element !== "object"
        || !("type" in element)
        || element.type !== "button"
        || !("value" in element)
        || typeof element.value !== "string"
      ) return [];
      return [element.value];
    });
  });
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status,
  });
}

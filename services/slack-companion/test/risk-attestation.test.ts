import assert from "node:assert/strict";
import test from "node:test";
import { createSlackTools } from "../src/agent/tools/slack-tools.js";
import { encodeAction } from "../src/slack/action-codec.js";
import { registerRiskAttestationActions } from "../src/slack/actions/risk-attestation.js";
import { actionIds } from "../src/slack/blocks/index.js";
import { RiskAttestationService } from "../src/slack/risk-attestation.js";
import { testConfig } from "./fixtures.js";

test("risk attestation asks one person, records their answer, and reports it to Security", async () => {
  const dmPosts: any[] = [];
  const originPosts: any[] = [];
  const updates: any[] = [];
  let userLookups = 0;
  const slackClient = {
    users: {
      info: async ({ user }: { user: string }) => {
        userLookups += 1;
        return { user: { id: user, profile: { display_name: "Maya Chen" } } };
      },
    },
    conversations: { open: async () => ({ channel: { id: "DPERSON" } }) },
    chat: {
      postMessage: async (input: any) => {
        if (input.channel === "DPERSON") {
          dmPosts.push(input);
          return { channel: "DPERSON", ts: "1710000000.001" };
        }
        originPosts.push(input);
        return { channel: input.channel, ts: "1710000000.002" };
      },
      update: async (input: any) => {
        updates.push(input);
        return { channel: input.channel, ts: input.ts };
      },
    },
  };
  let now = new Date("2026-07-15T12:00:00.000Z");
  const service = new RiskAttestationService(testConfig({ learning: { enabled: false } }), {
    slackClient: slackClient as any,
    now: () => now,
  });
  const request = {
    riskRef: "finding-123",
    sourceChannelId: "CSEC",
    sourceThreadTs: "1709999999.001",
    requestedByUserId: "USECURITY",
    targetUserId: "UMAYA",
    activitySummary: "A new administrator role was granted to the production account.",
    sourceName: "Okta",
    observedAt: "2026-07-15 04:52 UTC",
    identityBasis: "Okta actor id maps to Maya's verified company account.",
    evidenceRefs: ["private-evidence-ref-123"],
  };

  const first = await service.request(request);
  const duplicate = await service.request(request);

  assert.equal(first.status, "pending");
  assert.equal(first.legitimacy, "unverified");
  assert.equal(first.evidentiary_weight, "self_attestation");
  assert.equal(first.can_disposition_risk, false);
  assert.equal(duplicate.duplicate, true);
  assert.equal(userLookups, 1);
  assert.equal(dmPosts.length, 1);
  assert.equal(dmPosts[0].text, "Security is checking activity associated with your account.");
  const dmBody = JSON.stringify(dmPosts[0]);
  assert.match(dmBody, /Did you perform or approve this activity/);
  assert.match(dmBody, /Yes, this was me/);
  assert.match(dmBody, /No, this wasn't me/);
  assert.match(dmBody, /I'm not sure/);
  assert.match(dmBody, /does not close the risk by itself/);
  assert.doesNotMatch(dmBody, /private-evidence-ref-123/);
  assert.doesNotMatch(dmBody, /Okta actor id maps/);

  await assert.rejects(
    () => service.respond({ id: first.request_id, responderUserId: "USOMEONE", answer: "yes" }),
    /Only the person who received this security check/,
  );

  now = new Date("2026-07-15T12:05:00.000Z");
  const response = await service.respond({ id: first.request_id, responderUserId: "UMAYA", answer: "no" });
  const repeated = await service.respond({ id: first.request_id, responderUserId: "UMAYA", answer: "no" });
  const status = await service.status(first.request_id, "CSEC");

  assert.equal(response.changed, true);
  assert.equal(repeated.changed, false);
  assert.equal(updates.length, 1);
  assert.match(JSON.stringify(updates[0]), /Security check recorded/);
  assert.equal(originPosts.length, 1);
  assert.equal(originPosts[0].channel, "CSEC");
  assert.equal(originPosts[0].thread_ts, "1709999999.001");
  assert.match(originPosts[0].text, /Maya Chen answered \*No, this wasn't me\.\*/);
  assert.match(originPosts[0].text, /self-reported/);
  assert.doesNotMatch(originPosts[0].text, /<@UMAYA>/);
  assert.equal(status?.status, "subject_said_no");
  assert.equal(status?.origin_notified, true);
  assert.equal(status?.can_disposition_risk, false);
  assert.match(status?.required_next_step ?? "", /Escalate the risk/);
});

test("risk attestation blocks non-security channels and bot accounts before delivery", async () => {
  let userLookups = 0;
  let messagePosts = 0;
  const slackClient = {
    users: {
      info: async ({ user }: { user: string }) => {
        userLookups += 1;
        return { user: { id: user, is_bot: true, profile: { display_name: "Alert Bot" } } };
      },
    },
    conversations: { open: async () => ({ channel: { id: "DBOT" } }) },
    chat: {
      postMessage: async () => {
        messagePosts += 1;
        return { ts: "1.1" };
      },
      update: async () => ({ ts: "1.1" }),
    },
  };
  const service = new RiskAttestationService(testConfig({ learning: { enabled: false } }), { slackClient: slackClient as any });
  const request = {
    riskRef: "risk-1",
    sourceThreadTs: "1.1",
    targetUserId: "UBOT",
    activitySummary: "A production role was granted to this account.",
    identityBasis: "The current source record maps the account to this Slack identity.",
    evidenceRefs: ["evidence-1"],
  };

  await assert.rejects(
    () => service.request({ ...request, sourceChannelId: "COTHER" }),
    /only in configured security channels/,
  );
  assert.equal(userLookups, 0);
  await assert.rejects(
    () => service.request({ ...request, sourceChannelId: "CSEC" }),
    /active human Slack user/,
  );
  assert.equal(userLookups, 1);
  assert.equal(messagePosts, 0);
});

test("risk attestation persists tenant-scoped state with a 90-day TTL", async () => {
  let item: Record<string, any> | undefined;
  const dynamo = {
    send: async (command: any) => {
      const input = command.input as any;
      if (command.constructor.name === "GetCommand") return { Item: item ? structuredClone(item) : undefined };
      if (input.ConditionExpression?.includes("attribute_not_exists") && item) {
        throw Object.assign(new Error("conditional"), { name: "ConditionalCheckFailedException" });
      }
      if (input.ConditionExpression === "#status = :expected_status" && item?.status !== input.ExpressionAttributeValues[":expected_status"]) {
        throw Object.assign(new Error("conditional"), { name: "ConditionalCheckFailedException" });
      }
      item = structuredClone(input.Item);
      return {};
    },
  };
  const slackClient = {
    users: { info: async () => ({ user: { id: "UMAYA", profile: { real_name: "Maya Chen" } } }) },
    conversations: { open: async () => ({ channel: { id: "DPERSON" } }) },
    chat: {
      postMessage: async () => ({ channel: "DPERSON", ts: "1.2" }),
      update: async () => ({ channel: "DPERSON", ts: "1.2" }),
    },
  };
  let now = new Date("2026-07-15T12:00:00.000Z");
  const config = testConfig({ learning: { enabled: true, tableName: "learning-table" } });
  const service = new RiskAttestationService(config, { dynamo, slackClient: slackClient as any, now: () => now });
  const request = await service.request({
    riskRef: "finding/123",
    sourceChannelId: "CSEC",
    sourceThreadTs: "1.1",
    targetUserId: "UMAYA",
    activitySummary: "A new administrator role was granted to the production account.",
    identityBasis: "Current directory evidence maps the account to Maya's company identity.",
    evidenceRefs: ["receipt-1"],
  });

  assert.equal(item?.pk, "tenant#writer#risk-attestations");
  assert.equal(item?.sk, request.request_id);
  assert.equal(item?.recordType, "risk_attestation");
  assert.equal(item?.riskRef, "finding/123");
  assert.equal(item?.expires_at, Math.floor(now.getTime() / 1_000) + 90 * 86_400);
  const reloaded = new RiskAttestationService(config, { dynamo, slackClient: slackClient as any, now: () => now });
  assert.equal((await reloaded.status(request.request_id, "CSEC"))?.status, "pending");
  now = new Date("2026-10-14T12:00:00.000Z");
  assert.equal(await reloaded.status(request.request_id, "CSEC"), undefined);
});

test("Slack risk attestation tools inject the current security thread context", async () => {
  const requests: any[] = [];
  const tools = createSlackTools({
    config: testConfig(),
    cerebro: {} as any,
    memory: {} as any,
    researchState: { hasCurrentEvidenceReceipt: (receipt: string) => receipt === "evidence-1" } as any,
    requestContext: { channelId: "CSEC", threadTs: "1709999999.001", userId: "USECURITY" },
    riskAttestations: {
      request: async (input: any) => {
        requests.push(input);
        return { request_id: "risk-attestation-123" } as any;
      },
      status: async () => undefined,
    },
  });
  const requestTool = tools.find((tool) => tool.name === "slack_risk_attestation_request");
  const statusTool = tools.find((tool) => tool.name === "slack_risk_attestation_status");
  assert.ok(requestTool);
  assert.ok(statusTool);

  const result = await requestTool.execute("call-1", {
    target_user_id: "UMAYA",
    risk_ref: "finding-123",
    activity_summary: "A production administrator role was granted.",
    identity_basis: "Current directory evidence maps the account to this user.",
    evidence_receipts: ["evidence-1"],
  } as any);

  assert.equal((result as any).details.request_id, "risk-attestation-123");
  assert.equal(requests[0].sourceChannelId, "CSEC");
  assert.equal(requests[0].sourceThreadTs, "1709999999.001");
  assert.equal(requests[0].requestedByUserId, "USECURITY");

  const rejected = await requestTool.execute("call-2", {
    target_user_id: "UMAYA",
    risk_ref: "finding-123",
    activity_summary: "A production administrator role was granted.",
    identity_basis: "An unverified model claim maps the account to this user.",
    evidence_receipts: ["invented-receipt"],
  } as any);
  assert.match((rejected as any).details.error, /evidence receipt from a successful source check/);
  assert.equal(requests.length, 1);
});

test("risk attestation action acknowledges and records the target user's answer", async () => {
  const handlers = new Map<string, (input: any) => Promise<void>>();
  const calls: any[] = [];
  registerRiskAttestationActions({
    action: (id: string, handler: (input: any) => Promise<void>) => handlers.set(id, handler),
  }, {
    riskAttestations: {
      respond: async (input: any) => {
        calls.push(input);
        return { record: {} as any, changed: true };
      },
    },
  } as any);
  let acknowledged = false;
  await handlers.get(actionIds.riskAttestationResponse)!({
    body: { user: { id: "UMAYA" } },
    action: {
      value: encodeAction({
        kind: "risk_attestation_response",
        confirmationId: "risk-attestation-aaaaaaaaaaaaaaaaaaaaaaaa",
        confirmationResponse: "unsure",
      }),
    },
    ack: async () => { acknowledged = true; },
    respond: async () => undefined,
  });

  assert.equal(acknowledged, true);
  assert.deepEqual(calls, [{
    id: "risk-attestation-aaaaaaaaaaaaaaaaaaaaaaaa",
    responderUserId: "UMAYA",
    answer: "unsure",
  }]);
});

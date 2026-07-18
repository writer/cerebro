import assert from "node:assert/strict";
import test from "node:test";
import { CompliancePacketStore } from "../src/compliance/packet-store.js";
import { buildCompliancePacket } from "../src/compliance/work-packets.js";
import { testConfig } from "./fixtures.js";

test("CompliancePacketStore persists sanitized packets and preserves created time on update", async () => {
  let now = new Date("2026-06-28T12:00:00.000Z");
  const store = new CompliancePacketStore(testConfig(), { now: () => now });
  const packet = buildCompliancePacket({
    packet_type: "audit_safe_report",
    title: "Privileged access summary",
    scope: "Okta admins",
    audience: "internal audit",
    period: "2026-Q2",
    facts: ["token=should-not-leak was found in a source log."],
    evidence_refs: ["evidencecas://cases/access/q2.json"],
  }) as any;

  const first = await store.put(packet, { slackUserId: "U1", actorId: "slack:U1" });
  now = new Date("2026-06-28T12:05:00.000Z");
  const second = await store.put(packet);

  assert.equal(first.storage_mode, "memory");
  assert.equal(second.createdAt, first.createdAt);
  assert.equal(second.updatedAt, "2026-06-28T12:05:00.000Z");
  assert.equal(second.createdBy?.actorId, "slack:U1");
  assert.equal(second.secret_values_stored, false);
  assert.doesNotMatch(JSON.stringify(second), /should-not-leak/);
  assert.match(JSON.stringify(second.packet), /\[redacted_secret\]/);

  const fetched = await store.get(packet.packet_id);
  assert.equal(fetched?.packet_id, packet.packet_id);
  fetched!.packet.title = "mutated";
  assert.equal((await store.get(packet.packet_id))?.packet.title, "Privileged access summary");
  assert.deepEqual((await store.list()).map((record) => record.packet_id), [packet.packet_id]);
});

test("CompliancePacketStore writes DynamoDB records under tenant packet keys", async () => {
  const calls: any[] = [];
  const store = new CompliancePacketStore(testConfig({
    schedules: { tableName: "security-learning" },
  }), {
    now: () => new Date("2026-06-28T12:00:00.000Z"),
    dynamo: {
      send: async (command: any) => {
        calls.push(command.input);
        if (command.constructor.name === "GetCommand") return {};
        return {};
      },
    },
  });
  const packet = buildCompliancePacket({
    packet_type: "policy_system_map",
    title: "Access map",
    owner: "security",
    policy_refs: ["policy:access"],
    control_ids: ["CC-6.1"],
    system_refs: ["system:okta"],
    source_refs: ["source:okta"],
  }) as any;

  const record = await store.put(packet);

  assert.equal(record.storage_mode, "dynamodb");
  assert.equal(calls[0].TableName, "security-learning");
  assert.equal(calls[0].Key.pk, "tenant#writer#compliance-packets");
  assert.equal(calls[1].Item.pk, "tenant#writer#compliance-packets");
  assert.equal(calls[1].Item.sk, `packet#${packet.packet_id}`);
});

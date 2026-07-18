import assert from "node:assert/strict";
import test from "node:test";
import { A2AFleetService, InMemoryA2AFleetStore } from "../src/a2a/index.js";
import type { A2AMessage, A2APart } from "../src/a2a/index.js";
import { testConfig } from "./fixtures.js";

test("fleet discovery differentiates concurrent Cerebros by identity, role, commit, and capabilities", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const primary = service(store, {
    instanceId: "primary-task-1",
    label: "primary",
    role: "generalist",
    capabilities: ["slack", "security", "goals"],
    version: "sha-main123",
  });
  const canary = service(store, {
    instanceId: "response-canary-task-1",
    label: "response-canary",
    role: "analyst",
    capabilities: ["security", "research", "goals"],
    version: "sha-pr4567",
  });
  t.after(() => { primary.stop(); canary.stop(); });

  await primary.start();
  await canary.start();

  const fleet = await primary.listInstances();
  assert.deepEqual(fleet.map((item) => ({
    id: item.instanceId,
    label: item.label,
    role: item.role,
    commit: item.commit,
    capabilities: item.capabilities,
  })).sort((left, right) => left.id.localeCompare(right.id)), [
    { id: "primary-task-1", label: "primary", role: "generalist", commit: "sha-main123", capabilities: ["slack", "security", "goals"] },
    { id: "response-canary-task-1", label: "response-canary", role: "analyst", commit: "sha-pr4567", capabilities: ["security", "research", "goals"] },
  ]);
  assert.equal(canary.agentCard().version, "sha-pr4567");
  assert.equal(canary.agentCard().name, "Cerebro response-canary");
});

test("shutdown marks the sender draining, transfers active goals, and waits for peer acknowledgement", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const received: string[] = [];
  const primary = service(store, {
    instanceId: "primary-task-1",
    label: "primary",
    role: "generalist",
    capabilities: ["slack", "goals"],
    version: "sha-main123",
  });
  const peer = service(store, {
    instanceId: "coordinator-task-1",
    label: "coordinator",
    role: "generalist",
    capabilities: ["goals", "coordination", "research"],
    version: "sha-next456",
    onMessage: async (message) => {
      received.push(JSON.stringify(message.parts));
    },
  });
  t.after(() => { primary.stop(); peer.stop(); });
  await primary.start();
  await peer.start();

  const result = await primary.drain("SIGTERM", ["goal-1", "goal-2", "goal-1"], [{
    packet_id: "packet-1",
    coordinator_id: "coordinator-task-1",
    context_id: "work:test",
    task_id: "task-1",
    request: { protocol: "test" },
  }]);

  assert.equal(result.state, "acknowledged");
  assert.equal(result.peerId, "coordinator-task-1");
  assert.deepEqual(result.goalIds, ["goal-1", "goal-2"]);
  assert.deepEqual(result.workPacketIds, ["packet-1"]);
  assert.equal(received.length, 1);
  assert.match(received[0]!, /goal-1/);
  assert.match(received[0]!, /Resume shared active goals/);
  assert.match(received[0]!, /packet-1/);
  const fleet = await peer.listInstances();
  assert.equal(fleet.find((item) => item.instanceId === "primary-task-1")?.state, "stopped");
});

test("shutdown completes without blocking when no compatible peer is active", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const primary = service(store, {
    instanceId: "primary-task-1",
    label: "primary",
    role: "generalist",
    capabilities: ["slack", "goals"],
    version: "sha-main123",
  });
  t.after(() => primary.stop());
  await primary.start();

  const result = await primary.drain("SIGTERM", ["goal-1"]);

  assert.deepEqual(result, { state: "no_peer", goalIds: ["goal-1"], workPacketIds: [] });
});

test("A2A messages redact credential-shaped data before entering the shared mailbox", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const sender = service(store, {
    instanceId: "sender-1",
    label: "sender",
    role: "analyst",
    capabilities: ["research"],
    version: "sha-test",
  });
  t.after(() => sender.stop());
  await sender.start();

  await sender.send({
    to: "receiver-1",
    kind: "task",
    parts: [{ kind: "data", data: { finding_id: "finding-1", api_token: "do-not-store", question: "check token=do-not-store", nested: { password: "also-secret" }, list: [{ credential: "hidden" }] } }],
  });
  const inbox = await store.listInbox("receiver-1", Math.floor(Date.now() / 1000));

  assert.equal(inbox.length, 1);
  assert.deepEqual(inbox[0]?.parts[0]?.data, {
    finding_id: "finding-1",
    api_token: "[redacted]",
    question: "check token=[redacted_secret]",
    nested: { password: "[redacted]" },
    list: [{ credential: "[redacted]" }],
  });
});

test("A2A messages reject mailbox payloads above the bounded DynamoDB envelope", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const sender = service(store, {
    instanceId: "sender-1",
    label: "sender",
    role: "analyst",
    capabilities: ["research"],
    version: "sha-test",
  });
  t.after(() => sender.stop());
  await sender.start();

  await assert.rejects(() => sender.send({
    to: "receiver-1",
    kind: "task",
    parts: Array.from({ length: 12 }, (_, index) => ({ kind: "text" as const, text: `${index}:${"x".repeat(4_000)}` })),
  }), /32 KB mailbox limit/);
});

test("A2A requests return only the correlated peer reply", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const sender = service(store, {
    instanceId: "sender-1", label: "sender", role: "coordinator", capabilities: ["security"], version: "sha-test",
  });
  const peer = service(store, {
    instanceId: "peer-1", label: "peer", role: "analyst", capabilities: ["security"], version: "sha-test",
    onMessage: async (message) => [{ kind: "data", data: { reviewed_message_id: message.messageId, verdict: "revise" } }],
  });
  t.after(() => { sender.stop(); peer.stop(); });
  await sender.start();
  await peer.start();

  const reply = await sender.request({
    to: "peer-1",
    contextId: "ensemble:test",
    parts: [{ kind: "data", data: { protocol: "test" } }],
    timeoutMs: 1_000,
    ttlSeconds: 30,
  });

  assert.equal(reply?.from, "peer-1");
  assert.equal(reply?.kind, "status");
  assert.equal(reply?.contextId, "ensemble:test");
  assert.equal(reply?.parts[0]?.data?.verdict, "revise");
});

test("A2A requests time out cleanly when a peer does not reply", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const sender = service(store, {
    instanceId: "sender-1", label: "sender", role: "coordinator", capabilities: ["security"], version: "sha-test",
  });
  t.after(() => sender.stop());
  await sender.start();

  const reply = await sender.request({
    to: "missing-peer",
    parts: [{ kind: "data", data: { protocol: "test" } }],
    timeoutMs: 250,
  });

  assert.equal(reply, undefined);
});

test("A2A requests deliver progress without completing before the terminal result", async (t) => {
  const store = new InMemoryA2AFleetStore();
  const sender = service(store, {
    instanceId: "sender-1", label: "sender", role: "coordinator", capabilities: ["security"], version: "sha-test",
  });
  const peer = service(store, {
    instanceId: "peer-1", label: "peer", role: "researcher", capabilities: ["security", "research"], version: "sha-test",
    onMessage: async (message) => {
      await peer.send({
        to: message.from,
        kind: "status",
        contextId: message.contextId,
        taskId: message.taskId,
        parts: [{ kind: "data", data: { phase: "progress", detail: "source check started" } }],
      });
      return [{ kind: "data", data: { phase: "completed", finding: "verified" } }];
    },
  });
  t.after(() => { sender.stop(); peer.stop(); });
  await sender.start();
  await peer.start();
  const progress: string[] = [];

  const reply = await sender.request({
    to: "peer-1",
    contextId: "work:test",
    parts: [{ kind: "data", data: { protocol: "work-test" } }],
    timeoutMs: 1_000,
    isTerminal: (message) => message.parts[0]?.data?.phase === "completed",
    onProgress: (message) => { progress.push(String(message.parts[0]?.data?.detail)); },
  });

  assert.deepEqual(progress, ["source check started"]);
  assert.equal(reply?.parts[0]?.data?.finding, "verified");
});

function service(store: InMemoryA2AFleetStore, input: {
  instanceId: string;
  label: string;
  role: string;
  capabilities: string[];
  version: string;
  onMessage?: (message: A2AMessage) => Promise<A2APart[] | void>;
}): A2AFleetService {
  const config = testConfig({
    learning: { tableName: "learning" },
    coordination: { version: input.version },
    a2a: {
      enabled: true,
      instanceId: input.instanceId,
      label: input.label,
      role: input.role,
      capabilities: input.capabilities,
      heartbeatIntervalMs: 50,
      inboxPollIntervalMs: 10,
      instanceTtlSeconds: 30,
      drainTimeoutMs: 1_000,
    },
  });
  return new A2AFleetService(config, { store, onMessage: input.onMessage });
}

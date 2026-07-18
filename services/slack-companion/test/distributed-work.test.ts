import assert from "node:assert/strict";
import test from "node:test";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { InMemorySharedRateLimitStore, SharedRateLimitCoordinator } from "../src/a2a/index.js";
import type { A2AMessage } from "../src/a2a/index.js";
import {
  CerebroDistributedWorkService,
  DISTRIBUTED_WORK_PROTOCOL,
  type DistributedWorkComplete,
} from "../src/agent/distributed-work.js";
import { toolResult } from "../src/agent/tools/index.js";
import { testConfig } from "./fixtures.js";

const question = {
  interactionId: "interaction-1",
  channelId: "CSEC",
  userId: "U123",
  senderKind: "human" as const,
  question: "Compare the current deployment and GitHub checks, then tell me what is actually blocked.",
  ts: "1700000000.000001",
};

const plan = {
  user_intent: "Determine current deployment and code-check state.",
  execution_lane: "investigate" as const,
  execution_style: "direct" as const,
  selected_tools: ["cerebro_code_status", "cerebro_code_github_checks"],
  required_sources: ["cerebro_code_status", "cerebro_code_github_checks"],
  research_plan: ["Check deployment", "Check GitHub checks"],
  user_visible_work: ["Deployment and check state"],
  missing_context_questions: [],
  claims: [
    { id: "deploy", claim: "Current deployment state", required: true, source_candidates: ["cerebro_code_status"] },
    { id: "checks", claim: "Current GitHub check state", required: true, source_candidates: ["cerebro_code_github_checks"] },
  ],
};

test("Opus coordinator decomposes independent sources into parallel A2A packets", async () => {
  const requests: Array<Parameters<FakeFleet["request"]>[0]> = [];
  const fleet = new FakeFleet();
  fleet.request = async (input) => {
    requests.push(input);
    const data = input.parts[0]?.data as { packet?: { packet_id?: string; tool_names?: string[] } };
    return reply(input.to, data.packet?.packet_id ?? "missing", data.packet?.tool_names?.[0] ?? "missing");
  };
  const service = createService(fleet, async ({ stage }) => {
    assert.equal(stage, "decompose");
    return JSON.stringify({
      strategy: "distributed",
      reason: "The two sources are independent.",
      packets: [
        { packet_id: "deployment", objective: "Check deployment", deliverables: ["Current deployment state"], tool_names: ["cerebro_code_status"], claim_ids: ["deploy"] },
        { packet_id: "checks", objective: "Check GitHub", deliverables: ["Current check state"], tool_names: ["cerebro_code_github_checks"], claim_ids: ["checks"] },
      ],
    });
  });

  const result = await service.coordinate(question, plan);

  assert.equal(requests.length, 2);
  assert.deepEqual(requests.map((request) => request.to), ["peer-1", "peer-2"]);
  assert.deepEqual(result?.receipts.map((receipt) => receipt.packet_id), ["deployment", "checks"]);
});

test("coordinator removes duplicate tool assignments before dispatch", async () => {
  const fleet = new FakeFleet();
  let requestCount = 0;
  fleet.request = async () => { requestCount += 1; return undefined; };
  const service = createService(fleet, async () => JSON.stringify({
    strategy: "distributed",
    reason: "proposed duplicate",
    packets: [
      { packet_id: "one", objective: "First", deliverables: ["First"], tool_names: ["cerebro_code_status"], claim_ids: [] },
      { packet_id: "two", objective: "Second", deliverables: ["Second"], tool_names: ["cerebro_code_status"], claim_ids: [] },
    ],
  }));

  assert.equal(await service.coordinate(question, plan), undefined);
  assert.equal(requestCount, 0);
});

test("coordinator reassigns a missing peer packet within the original timeout budget", async () => {
  const fleet = new FakeFleet();
  const attempts: string[] = [];
  fleet.request = async (input) => {
    const packet = (input.parts[0]?.data as { packet?: { packet_id?: string; tool_names?: string[] } }).packet;
    attempts.push(`${input.to}:${packet?.packet_id}`);
    if (input.to === "peer-1" && packet?.packet_id === "deployment") return undefined;
    return reply(input.to, packet?.packet_id ?? "missing", packet?.tool_names?.[0] ?? "missing");
  };
  const service = createService(fleet, async () => JSON.stringify({ strategy: "distributed", reason: "independent", packets: [
    { packet_id: "deployment", objective: "Check deployment", deliverables: ["state"], tool_names: ["cerebro_code_status"], claim_ids: ["deploy"] },
    { packet_id: "checks", objective: "Check checks", deliverables: ["state"], tool_names: ["cerebro_code_github_checks"], claim_ids: ["checks"] },
  ] }));

  const result = await service.coordinate(question, plan);

  assert.deepEqual(attempts, ["peer-1:deployment", "peer-2:checks", "peer-2:deployment"]);
  assert.deepEqual(result?.receipts.map((receipt) => receipt.packet_id), ["deployment", "checks"]);
});

test("offline hillclimb uses the production decomposition and worker execution path", async () => {
  const fleet = new FakeFleet();
  const tools = [
    fakeTool("cerebro_code_status", () => undefined),
    fakeTool("cerebro_code_github_checks", () => undefined),
  ];
  const service = createService(fleet, async (input) => {
    if (input.stage === "decompose") {
      return JSON.stringify({ strategy: "distributed", reason: "independent", packets: [
        { packet_id: "deployment", objective: "Check deployment", deliverables: ["state"], tool_names: ["cerebro_code_status"], claim_ids: ["deploy"] },
        { packet_id: "checks", objective: "Check checks", deliverables: ["state"], tool_names: ["cerebro_code_github_checks"], claim_ids: ["checks"] },
      ] });
    }
    await input.tools?.[0]?.execute("call-1", {}, new AbortController().signal);
    const packet = JSON.parse(input.userPrompt) as { packet: { packet_id: string } };
    return JSON.stringify({ packet_id: packet.packet.packet_id, status: "completed", findings: ["verified"], recommendations: [], blockers: [], tool_observations: [], confidence: 0.8 });
  }, () => tools);

  const result = await service.coordinateLocally(question, plan, 2);

  assert.deepEqual(result?.receipts.map((receipt) => receipt.packet_id), ["deployment", "checks"]);
  assert.equal(result?.receipts.every((receipt) => receipt.tool_observations.length === 1), true);
});

test("peer worker executes only read tools and returns bounded observations", async () => {
  const fleet = new FakeFleet();
  let readCalls = 0;
  let writeCalls = 0;
  const tools: AgentTool[] = [
    fakeTool("cerebro_code_status", () => { readCalls += 1; }),
    fakeTool("cerebro_code_workspace_write", () => { writeCalls += 1; }),
  ];
  const complete: DistributedWorkComplete = async (input) => {
    assert.equal(input.stage, "worker");
    await Promise.all((input.tools ?? []).map((tool) => tool.execute("call-1", {}, new AbortController().signal)));
    return JSON.stringify({
      packet_id: "deployment",
      status: "completed",
      findings: ["Deployment is current."],
      recommendations: ["No deployment action is needed."],
      blockers: [],
      tool_observations: [],
      confidence: 0.9,
    });
  };
  const service = createService(fleet, complete, () => tools);

  const response = await service.handleMessage(taskMessage({
    packet_id: "deployment",
    objective: "Check deployment",
    deliverables: ["Current state"],
    tool_names: ["cerebro_code_status", "cerebro_code_workspace_write"],
    claim_ids: ["deploy"],
  }));

  assert.equal(readCalls, 1);
  assert.equal(writeCalls, 0);
  assert.equal(response?.[0]?.data?.phase, "completed");
  const receipt = response?.[0]?.data?.receipt as { tool_observations?: unknown[] };
  assert.equal(receipt.tool_observations?.length, 1);
  assert.equal(fleet.sent[0]?.parts[0]?.data?.phase, "started");
});

test("concurrent requests with the same model packet id keep separate shutdown handoffs", async () => {
  const fleet = new FakeFleet();
  const releases: Array<() => void> = [];
  const service = createService(fleet, async () => new Promise<string>((resolve) => {
    releases.push(() => resolve(JSON.stringify({ packet_id: "deployment", status: "completed", findings: [], recommendations: [], blockers: [], tool_observations: [], confidence: 0.5 })));
  }), () => [fakeTool("cerebro_code_status", () => undefined)]);
  const first = taskMessage({ packet_id: "deployment", objective: "First", deliverables: ["state"], tool_names: ["cerebro_code_status"], claim_ids: [] });
  const second = { ...taskMessage({ packet_id: "deployment", objective: "Second", deliverables: ["state"], tool_names: ["cerebro_code_status"], claim_ids: [] }), messageId: "task-2", taskId: "task-2" };

  const firstRun = service.handleMessage(first);
  const secondRun = service.handleMessage(second);
  while (releases.length < 2) await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(service.activeWorkHandoffs().length, 2);
  releases.forEach((release) => release());
  await Promise.all([firstRun, secondRun]);
  assert.equal(service.activeWorkHandoffs().length, 0);
});

test("handoff peer resumes unfinished read-only work and replies to the original coordinator", async () => {
  const fleet = new FakeFleet();
  const service = createService(fleet, async (input) => {
    await input.tools?.[0]?.execute("call-1", {}, new AbortController().signal);
    return JSON.stringify({ packet_id: "deployment", status: "completed", findings: ["resumed"], recommendations: [], blockers: [], tool_observations: [], confidence: 0.8 });
  }, () => [fakeTool("cerebro_code_status", () => undefined)]);
  const request = taskMessage({
    packet_id: "deployment",
    objective: "Check deployment",
    deliverables: ["Current state"],
    tool_names: ["cerebro_code_status"],
    claim_ids: ["deploy"],
  }).parts[0]?.data;

  await service.handleHandoff({
    messageId: "handoff-1",
    contextId: "shutdown:worker-1",
    kind: "handoff",
    from: "worker-1",
    to: "peer-2",
    parts: [{ kind: "data", data: { active_work_packets: [{ packet_id: "deployment", coordinator_id: "coordinator-1", context_id: "work:interaction-1", task_id: "task-original", request }] } }],
    createdAt: new Date().toISOString(),
    expiresAt: 2_000_000_000,
  });

  const reply = fleet.sent.at(-1);
  assert.equal(reply?.to, "coordinator-1");
  assert.equal(reply?.taskId, "task-original");
  assert.equal(reply?.parts[0]?.data?.resumed_from_handoff, true);
});

function createService(
  fleet: FakeFleet,
  complete: DistributedWorkComplete,
  toolFactory = () => [] as AgentTool[],
): CerebroDistributedWorkService {
  const config = testConfig({
    learning: { tableName: "learning" },
    a2a: { instanceId: "primary-1", workFleetTimeoutMs: 1_000, rateWaitMs: 0 },
  });
  return new CerebroDistributedWorkService(
    config,
    fleet,
    {} as never,
    {} as never,
    new SharedRateLimitCoordinator(new InMemorySharedRateLimitStore(), config.a2a.instanceId),
    { complete, toolFactory },
  );
}

class FakeFleet {
  sent: Array<Parameters<FakeFleet["send"]>[0]> = [];

  async listInstances() {
    return [
      instance("primary-1", "generalist"),
      instance("peer-1", "researcher"),
      instance("peer-2", "analyst"),
    ];
  }

  async request(_input: {
    to: string;
    contextId?: string;
    parts: A2AMessage["parts"];
    timeoutMs: number;
    ttlSeconds?: number;
    isTerminal?: (message: A2AMessage) => boolean;
    onProgress?: (message: A2AMessage) => Promise<void> | void;
  }): Promise<A2AMessage | undefined> {
    return undefined;
  }

  async send(input: {
    to: string;
    kind: "task" | "handoff" | "status";
    contextId?: string;
    taskId?: string;
    parts: A2AMessage["parts"];
    ttlSeconds?: number;
  }): Promise<A2AMessage> {
    this.sent.push(input);
    return { messageId: "sent-1", contextId: input.contextId ?? "context", taskId: input.taskId, kind: input.kind, from: "primary-1", to: input.to, parts: input.parts, createdAt: new Date().toISOString(), expiresAt: 2_000_000_000 };
  }
}

function fakeTool(name: string, called: () => void): AgentTool {
  return {
    name,
    label: name,
    description: name,
    parameters: Type.Object({}),
    execute: async () => {
      called();
      return toolResult({ success: true, source: name, records: [{ id: "record-1", status: "current" }] });
    },
  };
}

function instance(instanceId: string, role: string) {
  return { instanceId, label: instanceId, role, commit: "sha", capabilities: ["security", "research"], state: "active" as const, startedAt: "2026-07-16T00:00:00.000Z", heartbeatAt: `2026-07-16T00:00:0${instanceId === "peer-1" ? "3" : "2"}.000Z`, expiresAt: 2_000_000_000 };
}

function reply(from: string, packetId: string, toolName: string): A2AMessage {
  return {
    messageId: `reply-${packetId}`,
    contextId: "work:interaction-1",
    taskId: `task-${packetId}`,
    kind: "status",
    from,
    to: "primary-1",
    parts: [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase: "completed", receipt: { packet_id: packetId, status: "completed", findings: ["verified"], recommendations: [], blockers: [], tool_observations: [{ tool_name: toolName, status: "completed", details: { success: true } }], confidence: 0.8 } } }],
    createdAt: new Date().toISOString(),
    expiresAt: 2_000_000_000,
  };
}

function taskMessage(packet: Record<string, unknown>): A2AMessage {
  return {
    messageId: "task-1",
    contextId: "work:interaction-1",
    taskId: "task-1",
    kind: "task",
    from: "coordinator-1",
    to: "primary-1",
    parts: [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase: "assigned", question: question.question, request_context: { channel_id: question.channelId, user_id: question.userId, thread_ts: question.ts }, packet } }],
    createdAt: new Date().toISOString(),
    expiresAt: 2_000_000_000,
  };
}

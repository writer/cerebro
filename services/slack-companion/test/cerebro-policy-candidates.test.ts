import assert from "node:assert/strict";
import test from "node:test";
import { createSecurityAgentTools } from "../src/agent/tools/index.js";
import { CerebroClient } from "../src/cerebro/client.js";
import { parsePolicyCandidate, type PolicyCandidateGraphEvidence } from "../src/cerebro/policy-candidates.js";
import { testConfig } from "./fixtures.js";

const graphEvidence: PolicyCandidateGraphEvidence = {
  nodes: [
    { id: "actor", source_id: "aws", entity_type: "aws.assumed_role_session" },
    { id: "task", source_id: "aws", entity_type: "aws.ecs.task", attributes: { status: "ACTIVE" } },
    { id: "role", source_id: "aws", entity_type: "aws.role", attributes: { role_usage: "execution" } },
  ],
  edges: [
    { from_id: "actor", to_id: "task", source_id: "aws", relation: "acted_on" },
    { from_id: "task", to_id: "role", source_id: "aws", relation: "runs_as" },
  ],
  critical_edge: { from_id: "task", to_id: "role", relation: "runs_as" },
  evidence_node_ids: ["task"],
};

test("policy candidate client follows the exact private candidate contract and credential split", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    requests.push({ url, init });
    const body = url.includes("?tenant_id=") ? { candidates: [serverCandidate()] } : serverCandidate();
    return new Response(JSON.stringify(body), {
      status: init?.method === "POST" && url.endsWith("/policy-candidates") ? 201 : 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new CerebroClient(testConfig({
    cerebro: { apiKeys: { read: "read-key", findings: "policy-authoring-key" } },
  }), { fetchImpl });

  const created = await client.createPolicyCandidate({
    hypothesis: "aws policy candidate; entity types: aws.ecs.task, aws.role; relations: runs_as",
    domain: "aws",
    origin: { kind: "slack", external_ref: "slack-origin-opaque" },
    graph_evidence: graphEvidence,
    grounding: { bindings: groundingBindings() },
  });
  const listed = await client.listPolicyCandidates({ status: "ready_for_review", limit: 7 });
  await client.getPolicyCandidate("pc_1234567890abcdef");
  await client.provePolicyCandidate("pc_1234567890abcdef");
  await client.shadowPolicyCandidate("pc_1234567890abcdef");

  assert.equal(created.hypothesis.startsWith("aws policy candidate"), true);
  assert.equal(created.artifacts?.safe_for_review, true, "multiline YAML remains reviewable");
  assert.equal(created.shadow?.receipt_id, "shadow-receipt-1");
  assert.equal(listed.length, 1);
  assert.match(requests[1]!.url, /\/policy-candidates\?tenant_id=writer&status=ready_for_review&limit=7$/);
  assert.equal(requests[2]!.url.endsWith("/policy-candidates/pc_1234567890abcdef"), true);
  assert.equal(requests[3]!.url.endsWith("/policy-candidates/pc_1234567890abcdef/prove"), true);
  assert.equal(requests[4]!.url.endsWith("/policy-candidates/pc_1234567890abcdef/shadow"), true);
  const createBody = JSON.parse(String(requests[0]!.init?.body));
  assert.deepEqual(createBody, {
    tenant_id: "writer",
    hypothesis: "aws policy candidate; entity types: aws.ecs.task, aws.role; relations: runs_as",
    domain: "aws",
    origin: { kind: "slack", external_ref: "slack-origin-opaque" },
    graph_evidence: graphEvidence,
    grounding: { bindings: groundingBindings() },
  });
  assert.equal("prompt" in createBody, false);
  assert.equal("context" in createBody, false);
  assert.equal(requests.some((request) => /promot|merge|pull-request/.test(request.url)), false);
  assert.equal(new Headers(requests[0]!.init?.headers).get("Authorization"), "Bearer policy-authoring-key");
  assert.equal(new Headers(requests[1]!.init?.headers).get("Authorization"), "Bearer read-key");
  assert.equal(new Headers(requests[3]!.init?.headers).get("Authorization"), "Bearer policy-authoring-key");
});

test("policy candidate create derives hypothesis and origin while stripping Slack and cloud identifiers", async () => {
  const calls: unknown[] = [];
  const rawSlackUser = "U123PRIVATE";
  const rawChannel = "CPRIVATE123";
  const rawThread = "1712345678.000100";
  const rawArn = "arn:aws:ecs:us-east-1:123456789012:task/private-task";
  const tools = policyTools({
    slack: { operatorUserIds: new Set([rawSlackUser]), triageChannelIds: new Set<string>() },
    requestContext: { channelId: rawChannel, threadTs: rawThread, userId: rawSlackUser },
    cerebro: {
      createPolicyCandidate: async (request: unknown) => {
        calls.push(request);
        return parsePolicyCandidate(serverCandidate());
      },
    },
  });
  const create = requiredTool(tools, "cerebro_policy_candidate_create");
  const result = await create.execute("create-1", {
    ...toolGraphInput(),
    hypothesis: `Copy this private Slack message and ${rawArn}`,
  }) as any;

  assert.equal(calls.length, 1);
  const requestText = JSON.stringify(calls[0]);
  const resultText = JSON.stringify(result.details);
  for (const privateValue of [rawSlackUser, rawChannel, rawThread, rawArn, "123456789012", "private-task"]) {
    assert.doesNotMatch(requestText, new RegExp(escapeRegExp(privateValue)));
    assert.doesNotMatch(resultText, new RegExp(escapeRegExp(privateValue)));
  }
  const request = calls[0] as any;
  assert.match(request.origin.external_ref, /^slack-origin-[a-f0-9]{32}$/);
  assert.match(request.hypothesis, /entity types: aws\.assumed_role_session, aws\.ecs\.task, aws\.role/);
  assert.match(request.hypothesis, /relations: acted_on, runs_as/);
  assert.deepEqual(request.grounding.bindings, groundingBindings());
  assert.equal("hypothesis" in toolGraphInput(), false);
  assert.deepEqual(result.details.candidate.graph.entity_types, ["aws.assumed_role_session", "aws.ecs.task", "aws.role"]);
  assert.equal("origin_kind" in result.details.candidate, false);
  assert.equal("policy_yaml" in result.details.candidate.artifacts, false);
  assert.equal("test_yaml" in result.details.candidate.artifacts, false);
  assert.equal(result.details.pr_ready, true);
  assert.equal(result.details.boundaries.promotes_policy, false);
  assert.equal(result.details.boundaries.opens_pull_request, false);
});

test("configured security-triage channels may create, prove, and shadow without a user id", async () => {
  const calls: string[] = [];
  const tools = policyTools({
    slack: { operatorUserIds: new Set<string>(), triageChannelIds: new Set(["CSEC"]) },
    requestContext: { channelId: "CSEC", threadTs: "1712345678.000200" },
    cerebro: {
      createPolicyCandidate: async () => { calls.push("create"); return parsePolicyCandidate(serverCandidate({ status: "grounded", pr_ready: false, artifacts: undefined, proof: undefined, shadow: undefined })); },
      provePolicyCandidate: async () => { calls.push("prove"); return parsePolicyCandidate(serverCandidate({ status: "proved", pr_ready: false, shadow: undefined })); },
      shadowPolicyCandidate: async () => { calls.push("shadow"); return parsePolicyCandidate(serverCandidate()); },
      getPolicyCandidate: async () => { calls.push("get"); return parsePolicyCandidate(serverCandidate()); },
      listPolicyCandidates: async () => { calls.push("list"); return [parsePolicyCandidate(serverCandidate())]; },
    },
  });

  const created = await requiredTool(tools, "cerebro_policy_candidate_create").execute("create", toolGraphInput()) as any;
  const proved = await requiredTool(tools, "cerebro_policy_candidate_prove").execute("prove", { candidate_id: "pc_1234567890abcdef" }) as any;
  const shadowed = await requiredTool(tools, "cerebro_policy_candidate_shadow").execute("shadow", { candidate_id: "pc_1234567890abcdef" }) as any;
  const get = await requiredTool(tools, "cerebro_policy_candidate_get").execute("get", { candidate_id: "pc_1234567890abcdef" }) as any;
  const list = await requiredTool(tools, "cerebro_policy_candidate_list").execute("list", {}) as any;
  const exported = await requiredTool(tools, "cerebro_policy_candidate_export").execute("export", { candidate_id: "pc_1234567890abcdef" }) as any;

  assert.equal(created.details.candidate.status, "grounded");
  assert.equal(proved.details.candidate.status, "proved");
  assert.equal(shadowed.details.candidate.status, "ready_for_review");
  assert.equal(get.details.error, "trusted_operator_required");
  assert.equal(list.details.error, "trusted_operator_required");
  assert.equal(exported.details.error, "trusted_operator_required");
  assert.deepEqual(calls, ["create", "prove", "shadow"]);
});

test("operator export returns exactly two bounded ready files and fails closed for unready or sensitive artifacts", async () => {
  const ready = parsePolicyCandidate(serverCandidate());
  const unready = parsePolicyCandidate(serverCandidate({
    status: "grounded",
    pr_ready: false,
    artifacts: undefined,
    proof: undefined,
    shadow: undefined,
  }));
  const sensitiveRecord = serverCandidate();
  const sensitiveArtifacts = sensitiveRecord.artifacts as Record<string, unknown>;
  sensitiveRecord.artifacts = {
    ...sensitiveArtifacts,
    policy_yaml: `${String(sensitiveArtifacts.policy_yaml)}resource: arn:aws:iam::123456789012:role/PrivateRole\n`,
  };
  const sensitive = parsePolicyCandidate(sensitiveRecord);
  const candidates = new Map([
    ["pc_ready", ready],
    ["pc_unready", unready],
    ["pc_sensitive", sensitive],
  ]);
  const tools = policyTools({
    slack: { operatorUserIds: new Set(["UOP"]), triageChannelIds: new Set<string>() },
    requestContext: { channelId: "COTHER", threadTs: "1712345678.000400", userId: "UOP" },
    cerebro: {
      getPolicyCandidate: async (id: string) => candidates.get(id),
    },
  });
  const exportTool = requiredTool(tools, "cerebro_policy_candidate_export");

  const result = await exportTool.execute("ready", { candidate_id: "pc_ready" }) as any;
  const unreadyResult = await exportTool.execute("unready", { candidate_id: "pc_unready" }) as any;
  const sensitiveResult = await exportTool.execute("sensitive", { candidate_id: "pc_sensitive" }) as any;

  assert.deepEqual(Object.keys(result.details).sort(), ["candidate_id", "digests", "files"]);
  assert.equal(result.details.candidate_id, "pc_1234567890abcdef");
  assert.deepEqual(result.details.files, [
    {
      path: "policies/aws/aws-safe-path.yaml",
      content: "apiVersion: cerebro.writer.com/v1\nkind: PolicyFindingRule\nmetadata:\n  id: aws-safe-path\n",
    },
    {
      path: "policies/aws/aws-safe-path.test.yaml",
      content: "apiVersion: cerebro.writer.com/v1\nkind: PolicyRuleTestSuite\ncases:\n  - name: finding\n",
    },
  ]);
  assert.deepEqual(result.details.digests, { policy: "a".repeat(64), test: "b".repeat(64) });
  assert.match(unreadyResult.details.error, /proved, shadowed, and ready_for_review/);
  assert.match(sensitiveResult.details.error, /not safe for review/);
  assert.doesNotMatch(JSON.stringify(result.details), /origin|graph|arn:aws|123456789012/);
});

test("policy discovery refuses unconfigured channels and source identifiers in graph handles", async () => {
  let calls = 0;
  const tools = policyTools({
    slack: { operatorUserIds: new Set<string>(), triageChannelIds: new Set(["CSEC"]) },
    requestContext: { channelId: "COTHER", threadTs: "1712345678.000300" },
    cerebro: { createPolicyCandidate: async () => { calls += 1; return parsePolicyCandidate(serverCandidate()); } },
  });
  const create = requiredTool(tools, "cerebro_policy_candidate_create");
  const denied = await create.execute("denied", toolGraphInput()) as any;
  assert.equal(denied.details.error, "policy_discovery_context_required");

  const operatorTools = policyTools({
    slack: { operatorUserIds: new Set(["UOP"]), triageChannelIds: new Set<string>() },
    requestContext: { channelId: "COTHER", threadTs: "1712345678.000300", userId: "UOP" },
    cerebro: { createPolicyCandidate: async () => { calls += 1; return parsePolicyCandidate(serverCandidate()); } },
  });
  const unsafe = toolGraphInput();
  unsafe.graph_nodes[0]!.ref = "arn:aws:sts::123456789012:assumed-role/Admin/session";
  const refused = await requiredTool(operatorTools, "cerebro_policy_candidate_create").execute("unsafe", unsafe) as any;
  assert.match(refused.details.error, /opaque local reference/);
  assert.equal(calls, 0);

  const crossTenant = toolGraphInput();
  crossTenant.graph_nodes[0]!.entity_urn = "urn:cerebro:other:aws.assumed_role_session:actor";
  const crossTenantResult = await requiredTool(operatorTools, "cerebro_policy_candidate_create").execute("cross-tenant", crossTenant) as any;
  assert.match(crossTenantResult.details.error, /tenant-scoped Cerebro graph URN/);
  assert.equal(calls, 0);
});

function policyTools(input: {
  slack: { operatorUserIds: Set<string>; triageChannelIds: Set<string> };
  requestContext: { channelId: string; threadTs: string; userId?: string };
  cerebro: Record<string, unknown>;
}) {
  return createSecurityAgentTools({
    config: testConfig({ slack: input.slack }),
    requestContext: input.requestContext,
    memory: { readWorkingMemory: () => [], writeWorkingMemory: () => ({ success: true }), search: async () => [] } as any,
    cerebro: input.cerebro as any,
  });
}

function requiredTool(tools: ReturnType<typeof createSecurityAgentTools>, name: string) {
  const tool = tools.find((candidate) => candidate.name === name);
  assert.ok(tool, `${name} should be registered`);
  return tool;
}

function toolGraphInput() {
  return {
    domain: "aws",
    graph_nodes: [
      { ref: "actor", entity_urn: "urn:cerebro:writer:aws.assumed_role_session:actor", source_id: "aws", entity_type: "aws.assumed_role_session" },
      { ref: "task", entity_urn: "urn:cerebro:writer:aws.ecs.task:task", source_id: "aws", entity_type: "aws.ecs.task", attributes: { status: "ACTIVE" } },
      { ref: "role", entity_urn: "urn:cerebro:writer:aws.role:role", source_id: "aws", entity_type: "aws.role", attributes: { role_usage: "execution" } },
    ],
    graph_edges: [
      { from_ref: "actor", to_ref: "task", source_id: "aws", relation: "acted_on" },
      { from_ref: "task", to_ref: "role", source_id: "aws", relation: "runs_as" },
    ],
    critical_edge: { from_ref: "task", to_ref: "role", relation: "runs_as" },
    evidence_node_refs: ["task"],
  };
}

function groundingBindings() {
  return [
    { node_id: "actor", entity_urn: "urn:cerebro:writer:aws.assumed_role_session:actor" },
    { node_id: "task", entity_urn: "urn:cerebro:writer:aws.ecs.task:task" },
    { node_id: "role", entity_urn: "urn:cerebro:writer:aws.role:role" },
  ];
}

function serverCandidate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: "pc_1234567890abcdef",
    tenant_id: "writer",
    status: "ready_for_review",
    revision: 3,
    hypothesis: "aws policy candidate; entity types: aws.assumed_role_session, aws.ecs.task, aws.role; relations: acted_on, runs_as",
    domain: "aws",
    origin_kind: "slack",
    graph: {
      node_count: 3,
      edge_count: 2,
      entity_types: ["aws.assumed_role_session", "aws.ecs.task", "aws.role"],
      relations: ["acted_on", "runs_as"],
    },
    grounding: {
      execution: "graph_store",
      node_count: 3,
      edge_count: 2,
      receipt_id: "ground-receipt-1",
      observed_at: "2026-07-16T11:30:00Z",
    },
    coverage_gap: {
      execution: "finding_rule_catalog",
      catalog_digest: "c".repeat(64),
      compared_rule_count: 17,
      candidate_signature: "d".repeat(64),
      observed_at: "2026-07-16T11:45:00Z",
    },
    artifacts: {
      rule: { metadata: { id: "aws-safe-path" } },
      policy_path: "policies/aws/aws-safe-path.yaml",
      policy_yaml: "apiVersion: cerebro.writer.com/v1\nkind: PolicyFindingRule\nmetadata:\n  id: aws-safe-path\n",
      policy_digest: "a".repeat(64),
      suite: { cases: [{ name: "finding" }, { name: "passing" }] },
      test_path: "policies/aws/aws-safe-path.test.yaml",
      test_yaml: "apiVersion: cerebro.writer.com/v1\nkind: PolicyRuleTestSuite\ncases:\n  - name: finding\n",
      test_digest: "b".repeat(64),
    },
    proof: {
      policy_id: "aws-safe-path",
      policy_path: "policies/aws/aws-safe-path.yaml",
      test_path: "policies/aws/aws-safe-path.test.yaml",
      policy_digest: "a".repeat(64),
      test_digest: "b".repeat(64),
      receipts: [
        { gate: "graph_fixture_contract", passed: true, execution: "in_process", detail: "safe" },
        { gate: "graph_execution", passed: true, execution: "graph_store", detail: "safe" },
      ],
    },
    shadow: {
      execution: "graph_store",
      match_count: 1,
      truncated: false,
      receipt_id: "shadow-receipt-1",
      observed_at: "2026-07-16T12:00:00Z",
    },
    pr_ready: true,
    created_at: "2026-07-16T11:00:00Z",
    updated_at: "2026-07-16T12:00:00Z",
    ...overrides,
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

import { Agent, type AgentTool, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { z } from "zod";
import type { A2AFleetService } from "../a2a/fleet.js";
import type { SharedRateLimitCoordinator } from "../a2a/rate-limit.js";
import type { A2AInstance, A2AMessage, A2APart, A2AWorkHandoff } from "../a2a/types.js";
import type { CerebroClient } from "../cerebro/client.js";
import type { AppConfig } from "../config/index.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import { captureTelemetryError, telemetryErrorKind, telemetryEvent } from "../telemetry.js";
import type { FlueSecurityAssistantResearchPlanInput } from "./flue-security-assistant.js";
import { SecurityResearchState } from "./research-state.js";
import { latestAssistantText } from "./security-assistant-transcript.js";
import { SecurityAssistantToolHooks } from "./security-assistant-tool-hooks.js";
import type { SecurityAssistantInput } from "./security-assistant-types.js";
import { SourceHealthRegistry } from "./source-health.js";
import { createSecurityAgentTools } from "./tools/index.js";
import { securityAgentToolMetadata, securityAgentToolMetadataIsExplicit } from "./tools/tool-metadata.js";
import { boundedToolDetails } from "./tools/tool-result.js";
import type { SecurityToolFactory } from "./tools/types.js";
import { inferSecurityAgentIntent } from "./tool-policy.js";

export const DISTRIBUTED_WORK_PROTOCOL = "cerebro-distributed-work-v1";

const packetSchema = z.object({
  packet_id: z.string().min(1).max(80),
  objective: z.string().min(1).max(1_000),
  deliverables: z.array(z.string().min(1).max(600)).min(1).max(6),
  tool_names: z.array(z.string().min(1).max(120)).min(1).max(6),
  claim_ids: z.array(z.string().min(1).max(80)).max(8).default([]),
});

const decompositionSchema = z.object({
  strategy: z.enum(["single", "distributed"]),
  reason: z.string().min(1).max(1_000),
  packets: z.array(packetSchema).max(6).default([]),
});

const toolObservationSchema = z.object({
  tool_name: z.string().min(1).max(120),
  status: z.enum(["completed", "failed"]),
  details: z.record(z.string(), z.unknown()).default({}),
});

const workReceiptSchema = z.object({
  packet_id: z.string().min(1).max(80),
  status: z.enum(["completed", "blocked"]),
  findings: z.array(z.string().min(1).max(1_000)).max(12).default([]),
  recommendations: z.array(z.string().min(1).max(1_000)).max(8).default([]),
  blockers: z.array(z.string().min(1).max(1_000)).max(8).default([]),
  tool_observations: z.array(toolObservationSchema).max(8).default([]),
  confidence: z.number().min(0).max(1),
});

const requestSchema = z.object({
  protocol: z.literal(DISTRIBUTED_WORK_PROTOCOL),
  phase: z.literal("assigned"),
  question: z.string().min(1).max(8_000),
  request_context: z.object({
    channel_id: z.string().min(1).max(160),
    user_id: z.string().max(160).optional(),
    thread_ts: z.string().max(160).optional(),
  }),
  packet: packetSchema,
});

const handoffSchema = z.object({
  packet_id: z.string().min(1).max(80),
  coordinator_id: z.string().min(1).max(160),
  context_id: z.string().min(1).max(160),
  task_id: z.string().min(1).max(160),
  request: requestSchema,
});

export type DistributedWorkPacket = z.infer<typeof packetSchema>;
export type DistributedWorkReceipt = z.infer<typeof workReceiptSchema>;

export interface DistributedWorkAugmentation {
  receipts: DistributedWorkReceipt[];
  progress: Array<{ peerId: string; packetId: string; phase: string }>;
}

export type DistributedWorkComplete = (input: {
  stage: "decompose" | "worker";
  systemPrompt: string;
  userPrompt: string;
  timeoutMs: number;
  tools?: AgentTool[];
  beforeToolCall?: (input: { toolCall: { name: string } }) => Promise<{ block: true; reason?: string } | undefined>;
  afterToolCall?: (input: { toolCall: { name: string }; isError: boolean }) => Promise<undefined>;
}) => Promise<string>;

interface DistributedFleet {
  listInstances(): ReturnType<A2AFleetService["listInstances"]>;
  request(input: Parameters<A2AFleetService["request"]>[0]): ReturnType<A2AFleetService["request"]>;
  send(input: Parameters<A2AFleetService["send"]>[0]): ReturnType<A2AFleetService["send"]>;
}

export class CerebroDistributedWorkService {
  private readonly complete: DistributedWorkComplete;
  private readonly toolFactory: SecurityToolFactory;
  private readonly activePackets = new Map<string, { packetId: string; request: z.infer<typeof requestSchema>; message: A2AMessage }>();

  constructor(
    private readonly config: AppConfig,
    private readonly fleet: DistributedFleet,
    private readonly cerebro: CerebroClient,
    private readonly memory: SecurityMemoryStore,
    private readonly rateLimits: SharedRateLimitCoordinator,
    options: { complete?: DistributedWorkComplete; toolFactory?: SecurityToolFactory; isReadOnlyTool?: (toolName: string) => boolean } = {},
  ) {
    this.complete = options.complete ?? ((input) => completeWithConfiguredModel(config, input));
    this.toolFactory = options.toolFactory ?? createSecurityAgentTools;
    this.readOnlyTool = options.isReadOnlyTool ?? productionReadOnlyTool;
  }

  private readonly readOnlyTool: (toolName: string) => boolean;

  activeWorkPacketIds(): string[] {
    return [...this.activePackets.values()].map((active) => active.packetId).slice(0, 50);
  }

  activeWorkHandoffs(): A2AWorkHandoff[] {
    return [...this.activePackets.values()].slice(0, 8).flatMap((active) => active.message.taskId ? [{
      packet_id: active.packetId,
      coordinator_id: active.message.from,
      context_id: active.message.contextId,
      task_id: active.message.taskId,
      request: active.request as unknown as Record<string, unknown>,
    }] : []);
  }

  async coordinate(input: SecurityAssistantInput, plan: FlueSecurityAssistantResearchPlanInput): Promise<DistributedWorkAugmentation | undefined> {
    if (!this.shouldDistribute(input, plan)) return undefined;
    const startedAt = Date.now();
    try {
      const peers = this.eligiblePeers(await this.fleet.listInstances());
      if (peers.length === 0) return undefined;
      const allowedTools = allowedReadTools(plan, this.readOnlyTool);
      if (allowedTools.length < 2) return undefined;
      const decomposition = await this.withModelPermit(() => this.decompose(input, plan, peers, allowedTools));
      const packets = validPackets(decomposition, allowedTools, this.readOnlyTool).slice(0, Math.min(peers.length, this.config.a2a.workFleetMaxPeers));
      if (decomposition.strategy !== "distributed" || packets.length < 2) return undefined;
      const progress: DistributedWorkAugmentation["progress"] = [];
      const attemptTimeoutMs = Math.max(1_000, Math.floor(this.config.a2a.workFleetTimeoutMs / 2));
      const firstReplies = await Promise.all(packets.map((packet, index) =>
        this.requestPacket(peers[index]!, packet, input, progress, attemptTimeoutMs)));
      let retryCount = 0;
      const replies = await Promise.all(firstReplies.map((reply, index) => {
        if (reply || peers.length < 2) return reply;
        retryCount += 1;
        return this.requestPacket(peers[(index + 1) % peers.length]!, packets[index]!, input, progress, attemptTimeoutMs);
      }));
      const receipts = replies.flatMap((reply) => {
        const receipt = reply ? receiptFromParts(reply.parts) : undefined;
        return receipt ? [receipt] : [];
      });
      telemetryEvent("assistant.distributed_work.completed", {
        component: "distributed-work",
        operation: "coordinate",
        "distributed_work.peer_count": peers.length,
        "distributed_work.packet_count": packets.length,
        "distributed_work.receipt_count": receipts.length,
        "distributed_work.completed_count": receipts.filter((receipt) => receipt.status === "completed").length,
        "distributed_work.retry_count": retryCount,
        "distributed_work.duration_ms": Date.now() - startedAt,
      });
      return receipts.length > 0 ? { receipts, progress } : undefined;
    } catch (error) {
      captureTelemetryError("assistant.distributed_work.error", error, {
        component: "distributed-work",
        operation: "coordinate",
        error_kind: telemetryErrorKind(error),
      });
      return undefined;
    }
  }

  async coordinateLocally(
    input: SecurityAssistantInput,
    plan: FlueSecurityAssistantResearchPlanInput,
    workerCount = 3,
  ): Promise<DistributedWorkAugmentation | undefined> {
    if (!this.shouldDistribute(input, plan)) return undefined;
    const count = Math.min(Math.max(Math.floor(workerCount), 2), this.config.a2a.workFleetMaxPeers);
    const peers = Array.from({ length: count }, (_, index): A2AInstance => ({
      instanceId: `offline-worker-${index + 1}`,
      label: `offline-worker-${index + 1}`,
      role: index === 0 ? "researcher" : index === 1 ? "analyst" : "qa",
      commit: this.config.coordination.version,
      capabilities: ["security", "research"],
      state: "active",
      startedAt: new Date(0).toISOString(),
      heartbeatAt: new Date(index + 1).toISOString(),
      expiresAt: 2_000_000_000,
    }));
    const allowedTools = allowedReadTools(plan, this.readOnlyTool);
    if (allowedTools.length < 2) return undefined;
    const decomposition = await this.withModelPermit(() => this.decompose(input, plan, peers, allowedTools));
    const packets = validPackets(decomposition, allowedTools, this.readOnlyTool).slice(0, count);
    if (decomposition.strategy !== "distributed" || packets.length < 2) return undefined;
    const receipts = await Promise.all(packets.map((packet) => this.executePacket(requestSchema.parse({
      protocol: DISTRIBUTED_WORK_PROTOCOL,
      phase: "assigned",
      question: input.question,
      request_context: { channel_id: input.channelId, user_id: input.userId, thread_ts: input.threadTs ?? input.ts },
      packet,
    })).catch((): DistributedWorkReceipt => ({
      packet_id: packet.packet_id,
      status: "blocked",
      findings: [],
      recommendations: [],
      blockers: ["The local evaluation worker could not complete this work packet."],
      tool_observations: [],
      confidence: 0,
    }))));
    return { receipts, progress: [] };
  }

  async handleMessage(message: A2AMessage): Promise<A2APart[] | void> {
    if (message.kind !== "task") return;
    const data = message.parts.find((part) => part.kind === "data")?.data;
    const request = requestSchema.safeParse(data);
    if (!request.success) return;
    const packet = request.data.packet;
    const activeKey = `${message.taskId ?? message.messageId}:${packet.packet_id}`;
    this.activePackets.set(activeKey, { packetId: packet.packet_id, request: request.data, message });
    try {
      await this.sendProgress(message, packet.packet_id, "started");
      const receipt = await this.executePacket(request.data);
      return [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase: "completed", receipt } }];
    } catch (error) {
      captureTelemetryError("assistant.distributed_work.worker_error", error, {
        component: "distributed-work",
        operation: "execute_packet",
        error_kind: telemetryErrorKind(error),
      });
      const receipt: DistributedWorkReceipt = {
        packet_id: packet.packet_id,
        status: "blocked",
        findings: [],
        recommendations: [],
        blockers: ["The assigned peer could not complete this work packet."],
        tool_observations: [],
        confidence: 0,
      };
      return [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase: "completed", receipt } }];
    } finally {
      this.activePackets.delete(activeKey);
    }
  }

  async handleHandoff(message: A2AMessage): Promise<void> {
    if (message.kind !== "handoff") return;
    const data = message.parts.find((part) => part.kind === "data")?.data;
    const packets = Array.isArray(data?.active_work_packets) ? data.active_work_packets : [];
    await Promise.all(packets.slice(0, 8).map(async (item) => {
      const handoff = handoffSchema.safeParse(item);
      if (!handoff.success) return;
      const receipt = await this.executePacket(handoff.data.request).catch((): DistributedWorkReceipt => ({
        packet_id: handoff.data.packet_id,
        status: "blocked",
        findings: [],
        recommendations: [],
        blockers: ["The handoff peer could not resume this work packet."],
        tool_observations: [],
        confidence: 0,
      }));
      await this.fleet.send({
        to: handoff.data.coordinator_id,
        kind: "status",
        contextId: handoff.data.context_id,
        taskId: handoff.data.task_id,
        parts: [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase: "completed", receipt, resumed_from_handoff: true } }],
        ttlSeconds: 60,
      });
    }));
  }

  private shouldDistribute(input: SecurityAssistantInput, plan: FlueSecurityAssistantResearchPlanInput): boolean {
    return this.config.a2a.enabled
      && this.config.a2a.workFleetEnabled
      && input.senderKind !== "bot"
      && (plan.execution_lane === "investigate" || plan.execution_lane === "act")
      && this.config.triage.pi.model.toLowerCase().includes("anthropic.claude-opus");
  }

  private eligiblePeers(instances: A2AInstance[]): A2AInstance[] {
    return instances.filter((instance) => instance.instanceId !== this.config.a2a.instanceId
      && instance.state === "active"
      && instance.capabilities.includes("security")
      && instance.capabilities.includes("research"))
      .sort((left, right) => right.heartbeatAt.localeCompare(left.heartbeatAt))
      .slice(0, this.config.a2a.workFleetMaxPeers);
  }

  private async decompose(
    input: SecurityAssistantInput,
    plan: FlueSecurityAssistantResearchPlanInput,
    peers: A2AInstance[],
    allowedTools: string[],
  ): Promise<z.infer<typeof decompositionSchema>> {
    const raw = await this.complete({
      stage: "decompose",
      systemPrompt: [
        "You are the Opus coordinator for a fleet of security agents.",
        "Decide whether the planned investigation contains at least two genuinely independent read-only work packets that can run concurrently and change the answer.",
        "Choose single when work is sequential, one source is sufficient, packets would duplicate calls, or coordination overhead is larger than the work.",
        "For distributed work, assign non-overlapping tools and claim ids. Each packet must be independently executable, have concrete deliverables, and contain no writes, approvals, Slack messages, tickets, shell, workspace changes, goals, or infrastructure changes.",
        "Do not invent tool names. Use only allowed_tools. Return JSON only.",
        "Contract: {\"strategy\":\"single|distributed\",\"reason\":\"...\",\"packets\":[{\"packet_id\":\"...\",\"objective\":\"...\",\"deliverables\":[\"...\"],\"tool_names\":[\"...\"],\"claim_ids\":[\"...\"]}]}.",
      ].join("\n"),
      userPrompt: JSON.stringify({
        question: input.question,
        research_plan: plan,
        allowed_tools: allowedTools,
        available_peers: peers.map((peer) => ({ role: peer.role, capabilities: peer.capabilities })),
        max_packets: Math.min(peers.length, this.config.a2a.workFleetMaxPeers),
      }),
      timeoutMs: Math.min(this.config.a2a.workFleetTimeoutMs, 45_000),
    });
    return decompositionSchema.parse(parseJsonObject(raw));
  }

  private requestPacket(
    peer: A2AInstance,
    packet: DistributedWorkPacket,
    input: SecurityAssistantInput,
    progress: DistributedWorkAugmentation["progress"],
    timeoutMs: number,
  ): Promise<A2AMessage | undefined> {
    return this.fleet.request({
      to: peer.instanceId,
      contextId: `work:${input.interactionId ?? input.ts}`,
      parts: [{
        kind: "data",
        data: {
          protocol: DISTRIBUTED_WORK_PROTOCOL,
          phase: "assigned",
          question: input.question,
          request_context: {
            channel_id: input.channelId,
            user_id: input.userId,
            thread_ts: input.threadTs ?? input.ts,
          },
          packet,
        },
      }],
      timeoutMs,
      ttlSeconds: Math.max(30, Math.ceil(timeoutMs / 1_000) + 20),
      isTerminal: (message) => statusPhase(message) === "completed",
      onProgress: (message) => {
        progress.push({ peerId: peer.instanceId, packetId: packet.packet_id, phase: statusPhase(message) ?? "progress" });
      },
    }).catch(() => undefined);
  }

  private async executePacket(request: z.infer<typeof requestSchema>): Promise<DistributedWorkReceipt> {
    const researchState = new SecurityResearchState(new SourceHealthRegistry(), request.request_context.channel_id);
    const baseTools = this.toolFactory({
      config: this.config,
      cerebro: this.cerebro,
      memory: this.memory,
      researchState,
      requestContext: {
        channelId: request.request_context.channel_id,
        userId: request.request_context.user_id,
        threadTs: request.request_context.thread_ts,
      },
    });
    const requested = new Set(request.packet.tool_names);
    const observations: z.infer<typeof toolObservationSchema>[] = [];
    const tools = baseTools
      .filter((tool) => requested.has(tool.name) && this.readOnlyTool(tool.name))
      .map((tool) => this.rateLimitedTool(tool, observations));
    if (tools.length === 0) throw new Error("No authorized read-only tools remain in the work packet.");
    researchState.setAvailableTools(tools.map((tool) => tool.name));
    researchState.seedStagedPlan({
      user_intent: request.packet.objective,
      execution_lane: "investigate",
      execution_style: "direct",
      selected_tools: tools.map((tool) => tool.name),
      required_sources: tools.map((tool) => tool.name),
      research_plan: request.packet.deliverables,
      claims: request.packet.claim_ids.map((id) => ({ id, claim: request.packet.objective, source_candidates: tools.map((tool) => tool.name) })),
    });
    const hooks = new SecurityAssistantToolHooks({
      allowedTools: new Set(tools.map((tool) => tool.name)),
      inferredIntent: inferSecurityAgentIntent({ question: request.question }),
      maxResearchSteps: Math.min(this.config.triage.maxResearchSteps, 8),
      researchState,
      researchTrail: [],
      trustedOperator: false,
    });
    const raw = await this.withModelPermit(() => this.complete({
      stage: "worker",
      systemPrompt: [
        "You are a read-only Cerebro security worker executing one bounded work packet for another Cerebro.",
        "Use the supplied tools to complete the objective. Run independent tool calls concurrently when useful.",
        "Never perform or propose a write, contact a person, create a ticket or goal, change code or infrastructure, or answer the human directly.",
        "Keep every fact bound to the exact subject, source, and time returned. Qualify negative results by source scope and coverage.",
        "Inspect facts and records before interpreting tool status. A partial result with non-empty facts or records is usable for those exact returned subjects; report only the explicitly missing lookup as a blocker and never call the whole source unavailable.",
        "Return concise findings and recommendations for the coordinator. The host will attach bounded tool observations; do not invent evidence receipts.",
        "Return JSON only: {\"packet_id\":\"...\",\"status\":\"completed|blocked\",\"findings\":[\"...\"],\"recommendations\":[\"...\"],\"blockers\":[\"...\"],\"tool_observations\":[],\"confidence\":0.0}.",
      ].join("\n"),
      userPrompt: JSON.stringify({ question: request.question, packet: request.packet }),
      timeoutMs: this.config.a2a.workFleetTimeoutMs,
      tools,
      beforeToolCall: hooks.beforePi,
      afterToolCall: hooks.afterPi,
    }));
    const modelReceipt = workReceiptSchema.parse(parseJsonObject(raw));
    return workReceiptSchema.parse({ ...modelReceipt, packet_id: request.packet.packet_id, tool_observations: observations });
  }

  private rateLimitedTool(tool: AgentTool, observations: z.infer<typeof toolObservationSchema>[]): AgentTool {
    const family = securityAgentToolMetadata(tool.name).family;
    return {
      ...tool,
      execute: async (...args: Parameters<AgentTool["execute"]>) => this.rateLimits.withPermit(
        `source:${family}`,
        this.sourcePermitOptions(),
        async () => {
          try {
            const result = await tool.execute(...args);
            observations.push({ tool_name: tool.name, status: "completed", details: boundedRecord(result.details) });
            return result;
          } catch (error) {
            observations.push({ tool_name: tool.name, status: "failed", details: { error: "Source check failed." } });
            throw error;
          }
        },
      ),
    };
  }

  private async sendProgress(message: A2AMessage, packetId: string, phase: string): Promise<void> {
    if (!message.taskId) return;
    await this.fleet.send({
      to: message.from,
      kind: "status",
      contextId: message.contextId,
      taskId: message.taskId,
      parts: [{ kind: "data", data: { protocol: DISTRIBUTED_WORK_PROTOCOL, phase, packet_id: packetId } }],
      ttlSeconds: Math.max(30, message.expiresAt - Math.floor(Date.now() / 1_000)),
    });
  }

  private withModelPermit<T>(work: () => Promise<T>): Promise<T> {
    return this.rateLimits.withPermit("model:opus-workflow", {
      maxConcurrent: this.config.a2a.modelMaxConcurrent,
      leaseMs: this.config.a2a.rateLeaseMs,
      waitMs: this.config.a2a.rateWaitMs,
    }, work);
  }

  private sourcePermitOptions() {
    return {
      maxConcurrent: this.config.a2a.sourceMaxConcurrent,
      leaseMs: this.config.a2a.rateLeaseMs,
      waitMs: this.config.a2a.rateWaitMs,
    };
  }
}

function allowedReadTools(plan: FlueSecurityAssistantResearchPlanInput, isReadOnly: (toolName: string) => boolean): string[] {
  const names = [...new Set([
    ...(plan.selected_tools ?? []),
    ...(plan.required_sources ?? []),
    ...(plan.claims ?? []).flatMap((claim) => claim.source_candidates ?? []),
  ])];
  return names.filter(isReadOnly).slice(0, 18);
}

function productionReadOnlyTool(toolName: string): boolean {
  if (!securityAgentToolMetadataIsExplicit(toolName)) return false;
  const metadata = securityAgentToolMetadata(toolName);
  return metadata.authority === "read" && metadata.sideEffect === "none";
}

function validPackets(
  decomposition: z.infer<typeof decompositionSchema>,
  allowedTools: string[],
  isReadOnly: (toolName: string) => boolean,
): DistributedWorkPacket[] {
  const allowed = new Set(allowedTools);
  const assigned = new Set<string>();
  return decomposition.packets.flatMap((packet) => {
    const tools = packet.tool_names.filter((tool) => allowed.has(tool) && isReadOnly(tool) && !assigned.has(tool));
    if (tools.length === 0) return [];
    tools.forEach((tool) => assigned.add(tool));
    return [{ ...packet, tool_names: tools }];
  });
}

function receiptFromParts(parts: A2APart[]): DistributedWorkReceipt | undefined {
  for (const part of parts) {
    if (part.kind !== "data" || part.data?.protocol !== DISTRIBUTED_WORK_PROTOCOL || part.data?.phase !== "completed") continue;
    const parsed = workReceiptSchema.safeParse(part.data.receipt);
    if (parsed.success) return parsed.data;
  }
  return undefined;
}

function statusPhase(message: A2AMessage): string | undefined {
  const data = message.parts.find((part) => part.kind === "data" && part.data?.protocol === DISTRIBUTED_WORK_PROTOCOL)?.data;
  return typeof data?.phase === "string" ? data.phase : undefined;
}

function boundedRecord(value: unknown): Record<string, unknown> {
  const bounded = boundedToolDetails(value ?? null);
  return bounded && typeof bounded === "object" && !Array.isArray(bounded) ? bounded as Record<string, unknown> : { value: bounded };
}

async function completeWithConfiguredModel(config: AppConfig, input: Parameters<DistributedWorkComplete>[0]): Promise<string> {
  if (!config.triage.pi.model.toLowerCase().includes("anthropic.claude-opus")) {
    throw new Error("Distributed Cerebro coordination requires an Anthropic Claude Opus model.");
  }
  const models = builtinModels();
  const model = models.getModel(config.triage.pi.provider, config.triage.pi.model);
  if (!model) throw new Error("Configured distributed Cerebro model is unavailable.");
  const agent = new Agent({
    initialState: {
      systemPrompt: input.systemPrompt,
      model,
      thinkingLevel: config.triage.pi.thinkingLevel as ThinkingLevel,
      tools: input.tools ?? [],
    },
    streamFn: (requestModel, context, options) => models.streamSimple(requestModel, context, options),
    toolExecution: "parallel",
    beforeToolCall: input.beforeToolCall,
    afterToolCall: input.afterToolCall,
  });
  const timeout = setTimeout(() => agent.abort(), input.timeoutMs);
  timeout.unref?.();
  try {
    await agent.prompt(input.userPrompt);
  } finally {
    clearTimeout(timeout);
  }
  if (agent.state.errorMessage) throw new Error(`Distributed Cerebro ${input.stage} failed.`);
  const text = latestAssistantText(agent.state.messages);
  if (!text) throw new Error(`Distributed Cerebro ${input.stage} returned no answer.`);
  return text;
}

function parseJsonObject(raw: string): unknown {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("Distributed Cerebro returned invalid JSON.");
  return JSON.parse(cleaned.slice(start, end + 1)) as unknown;
}

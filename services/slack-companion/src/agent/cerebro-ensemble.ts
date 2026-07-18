import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { z } from "zod";
import type { A2AFleetService } from "../a2a/fleet.js";
import type { SharedRateLimitCoordinator } from "../a2a/rate-limit.js";
import type { A2AMessage, A2APart } from "../a2a/types.js";
import type { AppConfig } from "../config/index.js";
import { captureTelemetryError, telemetryErrorKind, telemetryEvent } from "../telemetry.js";
import { latestAssistantText } from "./security-assistant-transcript.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "./security-assistant-types.js";

const ENSEMBLE_PROTOCOL = "cerebro-ensemble-review-v1";

export const ENSEMBLE_REVIEW_LENSES = [
  "Evidence challenger: find subject swaps, stale/current confusion, unsupported conclusions, missing source boundaries, and needless uncertainty. Preserve every supported fact.",
  "Decision analyst: decide what matters, what the evidence actually permits, what should happen first, and whether the answer completes the human's request instead of merely reporting data.",
  "Action QA: verify every claimed action state, identify unfinished ownership or verification, reduce human burden, and make the response sound like a concise friendly security teammate.",
] as const;

export const ENSEMBLE_REVIEW_POLICY = [
  "Review the candidate as a read-only peer. Do not call tools, perform actions, invent evidence, or ask the human a question that the supplied context already answers.",
  "The candidate's evidence packet is the complete authority boundary. Failed or partial coverage can justify a narrow caveat, never a positive conclusion.",
  "A missing citation marker, private receipt, model detail, or orchestration detail is not a reason to suppress a useful answer.",
  "Prefer a direct qualified answer such as 'I'm not sure about X because Y was unavailable' over an internal failure message or silence.",
  "Recommend revision only for a material improvement in correctness, decision quality, action closure, or teammate usefulness. Do not reward length.",
] as const;

export const ENSEMBLE_CHAIR_POLICY = [
  "Act as the independent Opus chair. Peer reviews are advisory and may be wrong; resolve disagreements from the supplied candidate and evidence.",
  "Return one answer that completes the human request. Lead with the result, preserve supported facts and actual completed actions, make the useful judgment, and own the smallest supported next step.",
  "Never invent a source result, mutable subject, action, owner, timestamp, or certainty. If a material point is unresolved, say exactly what you are not sure about and why, while still returning the supported work.",
  "Do not mention peers, ensemble, arbitration, prompts, models, receipts, schemas, or private work. Do not turn an internal coverage gap into a human non-answer.",
  "Use the ensemble only when it is materially better than the candidate. Concision is part of quality.",
] as const;

const reviewRequestSchema = z.object({
  protocol: z.literal(ENSEMBLE_PROTOCOL),
  lens: z.string().min(1).max(1_000),
  question: z.string().min(1).max(4_000),
  candidate: z.record(z.string(), z.unknown()),
});

const reviewSchema = z.object({
  recommendation: z.enum(["keep", "revise"]),
  material_issues: z.array(z.string().min(1).max(1_000)).max(8).default([]),
  preserve: z.array(z.string().min(1).max(1_000)).max(8).default([]),
  replacement_answer: z.string().max(12_000).default(""),
  replacement_key_points: z.array(z.string().min(1).max(1_000)).max(10).default([]),
  replacement_next_actions: z.array(z.string().min(1).max(1_000)).max(10).default([]),
  confidence: z.number().min(0).max(1),
});

const chairSchema = z.object({
  use_ensemble: z.boolean(),
  answer: z.string().min(1).max(12_000),
  key_points: z.array(z.string().min(1).max(1_000)).max(10).default([]),
  next_actions: z.array(z.string().min(1).max(1_000)).max(10).default([]),
});

export type EnsembleReview = z.infer<typeof reviewSchema>;
export type EnsembleComplete = (input: {
  stage: "peer_review" | "chair";
  systemPrompt: string;
  userPrompt: string;
  timeoutMs: number;
}) => Promise<string>;

interface EnsembleFleet {
  listInstances(): ReturnType<A2AFleetService["listInstances"]>;
  request(input: Parameters<A2AFleetService["request"]>[0]): ReturnType<A2AFleetService["request"]>;
}

export class CerebroEnsembleService {
  private readonly complete: EnsembleComplete;

  constructor(
    private readonly config: AppConfig,
    private readonly fleet?: EnsembleFleet,
    options: { complete?: EnsembleComplete; rateLimits?: Pick<SharedRateLimitCoordinator, "withPermit"> } = {},
  ) {
    this.complete = options.complete ?? ((input) => completeWithOpus(config, input));
    this.rateLimits = options.rateLimits;
  }

  private readonly rateLimits?: Pick<SharedRateLimitCoordinator, "withPermit">;

  async refine(input: SecurityAssistantInput, answer: SecurityAssistantAnswer): Promise<SecurityAssistantAnswer> {
    if (!this.shouldRun(input, answer) || !this.fleet) return answer;
    const startedAt = Date.now();
    try {
      const peers = (await this.fleet.listInstances())
        .filter((instance) => instance.instanceId !== this.config.a2a.instanceId
          && instance.state === "active"
          && instance.capabilities.includes("security"))
        .sort((left, right) => right.heartbeatAt.localeCompare(left.heartbeatAt))
        .slice(0, this.config.a2a.ensembleMaxPeers);
      if (peers.length === 0) return answer;
      const candidate = compactCandidate(answer);
      const replies = await Promise.all(peers.map((peer, index) => this.fleet!.request({
        to: peer.instanceId,
        contextId: `ensemble:${input.interactionId ?? input.ts}`,
        parts: [{
          kind: "data",
          data: {
            protocol: ENSEMBLE_PROTOCOL,
            lens: ENSEMBLE_REVIEW_LENSES[index % ENSEMBLE_REVIEW_LENSES.length],
            question: input.question,
            candidate,
          },
        }],
        timeoutMs: this.config.a2a.ensembleTimeoutMs,
        ttlSeconds: Math.max(30, Math.ceil(this.config.a2a.ensembleTimeoutMs / 1_000) + 15),
      }).catch(() => undefined)));
      const reviews = replies.flatMap((reply) => {
        const review = reply ? reviewFromParts(reply.parts) : undefined;
        return review ? [review] : [];
      });
      if (reviews.length === 0) return answer;
      const refined = await this.arbitrate(input, answer, reviews);
      telemetryEvent("assistant.ensemble.completed", {
        component: "cerebro-ensemble",
        operation: "refine",
        "ensemble.peer.requested_count": peers.length,
        "ensemble.peer.completed_count": reviews.length,
        "ensemble.used": refined !== answer,
        "ensemble.duration_ms": Date.now() - startedAt,
      });
      return refined;
    } catch (error) {
      captureTelemetryError("assistant.ensemble.error", error, {
        component: "cerebro-ensemble",
        operation: "refine",
        error_kind: telemetryErrorKind(error),
      });
      return answer;
    }
  }

  async refineWithLocalReviews(
    input: SecurityAssistantInput,
    answer: SecurityAssistantAnswer,
    reviewerCount = 2,
  ): Promise<SecurityAssistantAnswer> {
    if (!this.shouldRun(input, answer)) return answer;
    const count = Math.min(Math.max(Math.floor(reviewerCount), 1), ENSEMBLE_REVIEW_LENSES.length);
    const reviews = (await Promise.all(ENSEMBLE_REVIEW_LENSES.slice(0, count).map((lens) => this.review({
      protocol: ENSEMBLE_PROTOCOL,
      lens,
      question: input.question,
      candidate: compactCandidate(answer),
    }).catch((error) => {
      captureTelemetryError("assistant.ensemble.local_peer_error", error, {
        component: "cerebro-ensemble",
        operation: "local_peer_review",
        error_kind: telemetryErrorKind(error),
      });
      return undefined;
    })))).filter((review): review is EnsembleReview => Boolean(review));
    if (reviews.length === 0) return answer;
    return this.arbitrate(input, answer, reviews);
  }

  async handleMessage(message: A2AMessage): Promise<A2APart[] | void> {
    if (message.kind !== "task") return;
    const data = message.parts.find((part) => part.kind === "data")?.data;
    const parsed = reviewRequestSchema.safeParse(data);
    if (!parsed.success) return;
    try {
      const review = await this.review(parsed.data);
      return [{ kind: "data", data: { protocol: ENSEMBLE_PROTOCOL, review } }];
    } catch (error) {
      captureTelemetryError("assistant.ensemble.peer_error", error, {
        component: "cerebro-ensemble",
        operation: "peer_review",
        error_kind: telemetryErrorKind(error),
      });
      return [{ kind: "data", data: { protocol: ENSEMBLE_PROTOCOL, status: "unavailable" } }];
    }
  }

  private shouldRun(input: SecurityAssistantInput, answer: SecurityAssistantAnswer): boolean {
    return this.config.a2a.ensembleEnabled
      && this.config.a2a.enabled
      && input.senderKind !== "bot"
      && (answer.executionLane === "investigate" || answer.executionLane === "act")
      && answer.source !== "blocked"
      && answer.delivery !== "suppress"
      && this.config.triage.pi.model.toLowerCase().includes("anthropic.claude-opus");
  }

  private async review(request: z.infer<typeof reviewRequestSchema>): Promise<EnsembleReview> {
    const raw = await this.completeWithPermit({
      stage: "peer_review",
      systemPrompt: [...ENSEMBLE_REVIEW_POLICY, `Assigned lens: ${request.lens}`, reviewOutputContract()].join("\n"),
      userPrompt: JSON.stringify({ question: request.question, candidate: request.candidate }),
      timeoutMs: this.config.a2a.ensembleTimeoutMs,
    });
    return reviewSchema.parse(parseJsonObject(raw));
  }

  private async arbitrate(
    input: SecurityAssistantInput,
    answer: SecurityAssistantAnswer,
    reviews: EnsembleReview[],
  ): Promise<SecurityAssistantAnswer> {
    try {
      const raw = await this.completeWithPermit({
        stage: "chair",
        systemPrompt: [...ENSEMBLE_CHAIR_POLICY, chairOutputContract()].join("\n"),
        userPrompt: JSON.stringify({
          question: input.question,
          candidate: compactCandidate(answer),
          independent_peer_reviews: reviews,
        }),
        timeoutMs: this.config.a2a.ensembleTimeoutMs,
      });
      const decision = chairSchema.parse(parseJsonObject(raw));
      if (!decision.use_ensemble) return answer;
      return {
        ...answer,
        answer: decision.answer,
        messages: [],
        keyPoints: decision.key_points,
        nextActions: decision.next_actions,
        presentationReady: false,
      };
    } catch (error) {
      captureTelemetryError("assistant.ensemble.chair_error", error, {
        component: "cerebro-ensemble",
        operation: "chair",
        error_kind: telemetryErrorKind(error),
      });
      return answer;
    }
  }

  private completeWithPermit(input: Parameters<EnsembleComplete>[0]): Promise<string> {
    if (!this.rateLimits) return this.complete(input);
    return this.rateLimits.withPermit("model:opus-workflow", {
      maxConcurrent: this.config.a2a.modelMaxConcurrent,
      leaseMs: this.config.a2a.rateLeaseMs,
      waitMs: this.config.a2a.rateWaitMs,
    }, () => this.complete(input));
  }
}

function compactCandidate(answer: SecurityAssistantAnswer): Record<string, unknown> {
  return {
    answer: answer.answer.slice(0, 12_000),
    key_points: answer.keyPoints.slice(0, 10),
    visible_evidence: answer.evidence.slice(0, 16),
    actions_taken: answer.actionsTaken.slice(0, 10),
    next_actions: answer.nextActions.slice(0, 10),
    execution_lane: answer.executionLane,
    claims: (answer.claimEvidence ?? []).filter((claim) => claim.visible).slice(0, 20).map((claim) => ({
      claim: claim.claimText,
      temporal_scope: claim.temporalScope,
      verification: claim.verification,
      sources: claim.sourceTools,
      evidence: claim.evidence.slice(0, 8).map((evidence) => ({
        title: evidence.title,
        basis: evidence.basis,
        subject: evidence.subjectId ?? evidence.sourceRef,
        verified_at: evidence.verifiedAt,
        conflicted: evidence.conflicted,
      })),
    })),
  };
}

function reviewFromParts(parts: A2APart[]): EnsembleReview | undefined {
  for (const part of parts) {
    if (part.kind !== "data" || part.data?.protocol !== ENSEMBLE_PROTOCOL) continue;
    const parsed = reviewSchema.safeParse(part.data.review);
    if (parsed.success) return parsed.data;
  }
  return undefined;
}

function reviewOutputContract(): string {
  return "Return JSON only: {\"recommendation\":\"keep|revise\",\"material_issues\":[\"...\"],\"preserve\":[\"...\"],\"replacement_answer\":\"...\",\"replacement_key_points\":[\"...\"],\"replacement_next_actions\":[\"...\"],\"confidence\":0.0}.";
}

function chairOutputContract(): string {
  return "Return JSON only: {\"use_ensemble\":true,\"answer\":\"...\",\"key_points\":[\"...\"],\"next_actions\":[\"...\"]}.";
}

async function completeWithOpus(
  config: AppConfig,
  input: Parameters<EnsembleComplete>[0],
): Promise<string> {
  if (!config.triage.pi.model.toLowerCase().includes("anthropic.claude-opus")) {
    throw new Error("Cerebro ensemble requires an Anthropic Claude Opus model.");
  }
  const models = builtinModels();
  const model = models.getModel(config.triage.pi.provider, config.triage.pi.model);
  if (!model) throw new Error("Configured Cerebro ensemble model is unavailable.");
  const agent = new Agent({
    initialState: {
      systemPrompt: input.systemPrompt,
      model,
      thinkingLevel: config.triage.pi.thinkingLevel as ThinkingLevel,
      tools: [],
    },
    streamFn: (requestModel, context, options) => models.streamSimple(requestModel, context, options),
  });
  const timeout = setTimeout(() => agent.abort(), input.timeoutMs);
  timeout.unref?.();
  try {
    await agent.prompt(input.userPrompt);
  } finally {
    clearTimeout(timeout);
  }
  if (agent.state.errorMessage) throw new Error(`Cerebro ensemble ${input.stage} failed.`);
  const text = latestAssistantText(agent.state.messages);
  if (!text) throw new Error(`Cerebro ensemble ${input.stage} returned no answer.`);
  return text;
}

function parseJsonObject(raw: string): unknown {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start < 0 || end <= start) throw new Error("Cerebro ensemble returned invalid JSON.");
  return JSON.parse(cleaned.slice(start, end + 1)) as unknown;
}

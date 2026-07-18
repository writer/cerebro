import type { AppConfig } from "../config/index.js";
import { createHash } from "node:crypto";
import type { SecurityAssistantInput, SecurityAssistantAnswer, SecurityAssistantService } from "../agent/security-assistant.js";
import { resolveClaimEvidencePermalinks } from "../agent/evidence.js";
import type { EvidenceGovernanceService } from "../agent/evidence-governance.js";
import type { DailyNotesService } from "../learning/daily-notes.js";
import type { AssistantFeedbackService } from "../learning/assistant-feedback.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import type { ImprovementSignalRecorder } from "../improvement/types.js";
import { buildConversationCorpusCase } from "../learning/assistant-conversation-corpus.js";
import { SelfImprovementService } from "../learning/self-improvement.js";
import { logger } from "../logger.js";
import { askFailureBlocks, assistantFeedbackBlocks, securityAnswerMessages } from "../slack/blocks/index.js";
import { trimForSlack } from "../slack/format.js";
import { SlackQuestionWorkScheduler } from "./slack-question-work.js";
import type { SlackQuestionWorkRecord } from "./slack-question-work-model.js";
import {
  annotateMainDependency,
  annotateMainPhase,
  annotateSpan,
  captureTelemetryError,
  hashTelemetryId,
  recordGauge,
  recordMetric,
  slackTelemetryAttributes,
  telemetryErrorKind,
  telemetryEvent,
  withTelemetrySpan,
} from "../telemetry.js";

export interface SlackQuestionWorkInput extends SecurityAssistantInput {
  replyThreadTs: string;
}

export interface CompanionWorkLoopStats {
  queued: number;
  active: number;
  activeThreads: number;
  oldestQueuedAgeMs: number;
}

export interface SlackQuestionEnqueueResult {
  id: string;
  position: number;
  accepted: boolean;
  reason: "queued" | "duplicate_event" | "duplicate_question";
}

interface CompanionWorkLoopDeps {
  config: AppConfig;
  assistant: SecurityAssistantService;
  memory: SecurityMemoryStore;
  notes: DailyNotesService;
  feedback?: Pick<AssistantFeedbackService, "registerAnswer">;
  evidenceGovernance?: Pick<EvidenceGovernanceService, "recordAnswer">;
  improvement?: ImprovementSignalRecorder;
}

interface QueuedSlackQuestionJob {
  id: string;
  threadKey: string;
  client: any;
  input: SlackQuestionWorkInput;
  enqueuedAt: string;
}

interface AssistantDeliveryReceipt {
  answerTs?: string;
  plannedMessages: number;
  postedMessages: number;
  complete: boolean;
}

interface SlackQuestionRunResult {
  completed: boolean;
  error?: string;
}

interface RecentHumanInteraction {
  interactionId: string;
  answerHash: string;
  question: string;
  answer: string;
}

class AssistantDeliveryError extends Error {
  constructor(
    message: string,
    readonly receipt: AssistantDeliveryReceipt,
  ) {
    super(message);
    this.name = "AssistantDeliveryError";
  }
}

export class CompanionWorkLoop {
  private readonly queue: QueuedSlackQuestionJob[] = [];
  private readonly idleWaiters: Array<() => void> = [];
  private readonly selfImprovement: SelfImprovementService;
  private readonly activeThreadKeys = new Set<string>();
  private readonly activeWorkIds = new Set<string>();
  private readonly recentQuestionFingerprints = new Map<string, number>();
  private readonly recentHumanInteractions = new Map<string, RecentHumanInteraction>();
  private readonly durableWork?: SlackQuestionWorkScheduler;
  private slackClient?: any;
  private active = 0;
  private stopped = false;

  constructor(private readonly deps: CompanionWorkLoopDeps) {
    this.selfImprovement = new SelfImprovementService(deps.config, deps.memory, { improvement: deps.improvement });
    if (deps.config.triage.workQueueEnabled) {
      this.durableWork = new SlackQuestionWorkScheduler(deps.config, {
        run: (record) => this.runDurableSlackQuestion(record),
      });
    }
  }

  start(client?: any): void {
    this.stopped = false;
    this.slackClient = client ?? this.slackClient;
    if (this.durableWork) {
      if (!this.slackClient) throw new Error("Durable Slack question work requires a Slack client before start.");
      this.durableWork.start();
      return;
    }
    this.drain();
  }

  stop(): void {
    this.stopped = true;
    this.durableWork?.stop();
  }

  stats(): CompanionWorkLoopStats {
    return {
      queued: this.queue.length,
      active: this.active,
      activeThreads: this.activeThreadKeys.size,
      oldestQueuedAgeMs: this.oldestQueuedAgeMs(),
    };
  }

  enqueueSlackQuestion(client: any, input: SlackQuestionWorkInput): SlackQuestionEnqueueResult | Promise<SlackQuestionEnqueueResult> {
    const id = stableWorkId(input);
    const threadKey = stableThreadKey(input);
    const duplicate = this.duplicateReason(id, input);
    if (duplicate) {
      telemetryEvent("companion.work.dropped", {
        component: "work-loop",
        operation: "enqueue",
        "work.id_hash": hashTelemetryId(id),
        "work.drop.reason": duplicate,
        ...assistantTrafficAttributes(input),
        ...slackTelemetryAttributes(input),
      });
      recordMetric("cerebro_slack_companion_work_dropped_total", { kind: "slack_question", reason: duplicate }, 1);
      return {
        id,
        position: this.queue.length + this.active,
        accepted: false,
        reason: duplicate,
      };
    }

    if (this.durableWork) {
      this.slackClient = client;
      return this.enqueueDurableSlackQuestion(id, threadKey, input);
    }

    const position = this.queue.length + this.active + 1;
    this.recordHumanFollowUp(input);
    this.queue.push({
      id,
      threadKey,
      client,
      input,
      enqueuedAt: new Date().toISOString(),
    });
    this.activeWorkIds.add(id);
    this.rememberQuestionFingerprint(input);
    telemetryEvent("companion.work.enqueued", {
      component: "work-loop",
      operation: "enqueue",
      "work.id_hash": hashTelemetryId(id),
      "work.thread_key_hash": hashTelemetryId(threadKey),
      "work.queue.position": position,
      "work.queue.depth": this.queue.length,
      "work.active.count": this.active,
      "assistant.question.length": input.question.length,
      ...assistantTrafficAttributes(input),
      ...slackTelemetryAttributes(input),
    });
    recordMetric("cerebro_slack_companion_work_enqueued_total", { kind: "slack_question", traffic: trafficKind(input) }, 1);
    this.recordQueueGauges();
    this.drain();
    return { id, position, accepted: true, reason: "queued" };
  }

  private async enqueueDurableSlackQuestion(id: string, threadKey: string, input: SlackQuestionWorkInput): Promise<SlackQuestionEnqueueResult> {
    this.activeWorkIds.add(id);
    try {
      const result = await this.durableWork!.enqueue(id, threadKey, input);
      if (!result.created) {
        this.activeWorkIds.delete(id);
        return { id, position: 0, accepted: false, reason: "duplicate_event" };
      }
      this.recordHumanFollowUp(input);
      this.rememberQuestionFingerprint(input);
      telemetryEvent("companion.work.enqueued", {
        component: "work-loop",
        operation: "enqueue_durable",
        "work.id_hash": hashTelemetryId(id),
        "work.thread_key_hash": hashTelemetryId(threadKey),
        "work.queue.position": 1,
        "assistant.question.length": input.question.length,
        ...assistantTrafficAttributes(input),
        ...slackTelemetryAttributes(input),
      });
      recordMetric("cerebro_slack_companion_work_enqueued_total", { kind: "slack_question", traffic: trafficKind(input), durability: "durable" }, 1);
      return { id, position: 1, accepted: true, reason: "queued" };
    } catch (error) {
      this.activeWorkIds.delete(id);
      throw error;
    }
  }

  private async runDurableSlackQuestion(record: SlackQuestionWorkRecord): Promise<SlackQuestionRunResult> {
    if (!this.slackClient) return { completed: false, error: "Slack client is not ready." };
    this.active += 1;
    this.activeThreadKeys.add(record.threadKey);
    this.recordQueueGauges();
    try {
      return await this.runSlackQuestion({
        id: record.workId,
        threadKey: record.threadKey,
        client: this.slackClient,
        input: record.input,
        enqueuedAt: record.enqueuedAt,
      });
    } finally {
      this.active -= 1;
      this.activeThreadKeys.delete(record.threadKey);
      this.activeWorkIds.delete(record.workId);
      this.recordQueueGauges();
      this.notifyIdleIfNeeded();
    }
  }

  async onIdle(): Promise<void> {
    if (this.active === 0 && this.queue.length === 0) return;
    await new Promise<void>((resolve) => this.idleWaiters.push(resolve));
  }

  private drain(): void {
    if (this.stopped) return;
    while (this.active < this.deps.config.triage.maxConcurrent && this.queue.length > 0) {
      const jobIndex = this.queue.findIndex((candidate) => !this.activeThreadKeys.has(candidate.threadKey));
      if (jobIndex < 0) return;
      const [job] = this.queue.splice(jobIndex, 1);
      if (!job) return;
      this.activeThreadKeys.add(job.threadKey);
      this.active += 1;
      this.recordQueueGauges();
      void this.runSlackQuestion(job)
        .catch((error) => logger.warn("companion work loop job failed", { id: job.id, error: String(error) }))
        .finally(() => {
          this.active -= 1;
          this.activeThreadKeys.delete(job.threadKey);
          this.activeWorkIds.delete(job.id);
          this.recordQueueGauges();
          this.notifyIdleIfNeeded();
          this.drain();
        });
    }
  }

  private async runSlackQuestion(job: QueuedSlackQuestionJob): Promise<SlackQuestionRunResult> {
    let finalStatus: "completed" | "failed" = "completed";
    const queueLatencyMs = Math.max(0, Date.now() - Date.parse(job.enqueuedAt));
    recordMetric("cerebro_slack_companion_work_queue_latency_seconds_sum", { kind: "slack_question" }, queueLatencyMs / 1000);
    recordMetric("cerebro_slack_companion_work_queue_latency_seconds_count", { kind: "slack_question" }, 1);
    return withTelemetrySpan("companion.work.slack_question", {
      component: "work-loop",
      operation: "slack_question",
      "work.id_hash": hashTelemetryId(job.id),
      "work.thread_key_hash": hashTelemetryId(job.threadKey),
      "work.queue.latency_ms": queueLatencyMs,
      "work.queue.depth_at_start": this.queue.length,
      "work.active.count": this.active,
      "assistant.question.length": job.input.question.length,
      ...assistantTrafficAttributes(job.input),
      ...slackTelemetryAttributes(job.input),
    }, async (span) => {
    const { client } = job;
    const input = { ...job.input, interactionId: hashTelemetryId(job.id) };
    try {
      const answer = await this.deps.assistant.answer(input);
      annotateSpan(span, {
        "assistant.answer.source": answer.source,
        "assistant.answer.message_count": answer.messages.length,
        "assistant.answer.evidence_count": answer.evidence.length,
        "assistant.answer.research_count": answer.research.length,
        "assistant.answer.delivery": answer.delivery ?? "respond",
      });
      if (answer.delivery === "suppress") {
        annotateMainPhase("work.assistant_answer", "completed", {
          "assistant.answer.source": answer.source,
          "assistant.answer.delivery": "suppress",
        });
        await clearAssistantThreadStatus(client, input.channelId, input.replyThreadTs);
        await this.recordIgnoredHandoff(input, answer);
        annotateMainPhase("work.record_ignored_handoff", "completed");
        annotateMainDependency("slack", "work-loop", "post_answer", "skipped", {
          "slack.reply.message_count": 0,
        });
        return { completed: true };
      }
      if (answer.source === "blocked") {
        finalStatus = "failed";
      }
      annotateMainPhase("work.assistant_answer", answer.source === "blocked" ? "failed" : "completed", {
        "assistant.answer.source": answer.source,
      });
      await clearAssistantThreadStatus(client, input.channelId, input.replyThreadTs);
      const answerForDelivery = {
        ...answer,
        claimEvidence: await resolveClaimEvidencePermalinks(client, answer.claimEvidence, input.channelId),
      };
      const deliveryReceipt = await postAssistantMessages(client, input.channelId, input.replyThreadTs, securityAnswerMessages(input.question, answerForDelivery), job.id);
      await this.deps.assistant.recordDelivery?.(input, deliveryReceipt).catch((error) => {
        captureTelemetryError("work.mission_delivery.error", error, { component: "work-loop", operation: "record_mission_delivery" });
      });
      if (deliveryReceipt.answerTs && this.deps.evidenceGovernance) {
        await this.deps.evidenceGovernance.recordAnswer({
          answerId: `${input.channelId}:${deliveryReceipt.answerTs}`,
          channelId: input.channelId,
          threadTs: input.replyThreadTs,
          answer,
        }).catch((error) => {
          captureTelemetryError("work.evidence_receipt.error", error, { component: "work-loop", operation: "record_evidence_receipt" });
          logger.warn("evidence receipt write failed", { event: "work.evidence_receipt_write_failed", error: String(error), channel: input.channelId, ts: input.ts });
        });
      }
      annotateSpan(span, {
        "assistant.delivery.planned_count": deliveryReceipt.plannedMessages,
        "assistant.delivery.posted_count": deliveryReceipt.postedMessages,
        "assistant.delivery.complete": deliveryReceipt.complete,
      });
      telemetryEvent("assistant.answer.delivered", {
        component: "work-loop",
        operation: "post_answer",
        "assistant.delivery.planned_count": deliveryReceipt.plannedMessages,
        "assistant.delivery.posted_count": deliveryReceipt.postedMessages,
        "assistant.delivery.complete": deliveryReceipt.complete,
        ...assistantTrafficAttributes(input),
      });
      if (deliveryReceipt.answerTs && this.deps.feedback && input.senderKind !== "bot" && answer.source !== "blocked") {
        await postAssistantFeedback(this.deps.feedback, client, input, answer, deliveryReceipt).catch((error) => {
          captureTelemetryError("work.assistant_feedback.error", error, { component: "work-loop", operation: "post_assistant_feedback" });
          logger.warn("assistant feedback controls failed", { error: String(error), channel: input.channelId, ts: input.ts });
        });
      }
      await setAssistantSuggestedPrompts(client, input.channelId, input.replyThreadTs, input.question);
      await addReaction(client, input.channelId, input.ts, answer.reaction ?? "white_check_mark");
      annotateMainDependency("slack", "work-loop", "post_answer", "completed", {
        "slack.reply.message_count": deliveryReceipt.postedMessages,
      });
      await this.recordAnswerNote(input, answer, deliveryReceipt);
      await this.recordAnswerStory(input, answer, deliveryReceipt);
      if (input.senderKind !== "bot" && this.deps.improvement?.recordInteraction) {
        const answerHash = hashTelemetryId(`${input.channelId}:${deliveryReceipt.answerTs ?? input.ts}`);
        const answerText = [answer.answer, ...answer.messages].filter(Boolean).join("\n");
        const prior = input.userId ? this.recentHumanInteractions.get(humanContinuityKey(input)) : undefined;
        const sourceSubjectCount = new Set((answer.claimEvidence ?? []).flatMap((packet) => packet.evidence.map((evidence) => evidence.subjectId ?? evidence.sourceRef ?? evidence.id))).size;
        await this.deps.improvement.recordInteraction({
          interactionId: input.interactionId,
          answerHash,
          channelHash: hashTelemetryId(input.channelId),
          threadHash: hashTelemetryId(input.replyThreadTs),
          requester: input.userId ? { slackUserId: input.userId } : undefined,
          occurredAt: new Date().toISOString(),
          question: input.question,
          answer: answerText,
          executionLane: answer.executionLane,
          answerSource: answer.source,
          toolNames: answer.research.map((item) => item.split(":", 1)[0] ?? "").filter(Boolean),
          evidenceCount: answer.evidence.length,
          actionCount: answer.actionsTaken.length,
          commitmentStates: answer.teammate?.commitments.map((item) => item.status) ?? [],
          deliveryComplete: deliveryReceipt.complete,
          queueLatencyMs,
          totalLatencyMs: Math.max(0, Date.now() - Date.parse(job.enqueuedAt)),
          sourceSubjectCount,
          followsInteractionId: prior?.interactionId,
        }).catch((error) => {
          captureTelemetryError("work.improvement_ledger.error", error, { component: "work-loop", operation: "record_interaction" });
          logger.warn("improvement interaction ledger write failed", { error: String(error), channel: input.channelId, ts: input.ts });
        });
        const conversationCase = buildConversationCorpusCase({
          interactionId: input.interactionId,
          question: input.question,
          answer,
          prior: prior ? { question: prior.question, answer: prior.answer } : undefined,
        });
        if (conversationCase && this.deps.improvement.recordConversationCase) {
          await this.deps.improvement.recordConversationCase(conversationCase).catch((error) => {
            captureTelemetryError("work.improvement_corpus.error", error, { component: "work-loop", operation: "record_conversation_case" });
            logger.warn("improvement conversation case write failed", {
              event: "work.improvement_conversation_case.error",
              error: String(error),
              channel: input.channelId,
              ts: input.ts,
            });
          });
        }
        await this.deps.improvement.recordOutcomeEvent?.({
          interactionId: input.interactionId,
          answerHash: hashTelemetryId(`${input.channelId}:${deliveryReceipt.answerTs ?? input.ts}`),
          occurredAt: new Date().toISOString(),
          type: "delivery",
          result: deliveryReceipt.complete ? "complete" : "partial",
          confidence: 1,
        }).catch((error) => logger.warn("improvement delivery outcome write failed", {
          event: "work.improvement_delivery_outcome.error",
          error: String(error),
          channel: input.channelId,
          ts: input.ts,
        }));
        const completedActions = answer.actionsTaken.length > 0 || (answer.teammate?.commitments ?? []).some((item) => item.status === "completed");
        if (completedActions) {
          await this.deps.improvement.recordOutcomeEvent?.({ interactionId: input.interactionId, answerHash, occurredAt: new Date().toISOString(), type: "action_closure", result: "verified_action_reported", confidence: 0.9 }).catch(() => undefined);
        }
        const missionCompleted = Boolean(answer.teammate && answer.teammate.openLoops.length === 0
          && answer.teammate.commitments.length > 0
          && answer.teammate.commitments.every((item) => item.status === "completed" || item.status === "cancelled"));
        if (missionCompleted) {
          await this.deps.improvement.recordOutcomeEvent?.({ interactionId: input.interactionId, answerHash, occurredAt: new Date().toISOString(), type: "mission_completion", result: "acceptance_state_closed", confidence: 0.9 }).catch(() => undefined);
        }
        if (input.userId && input.interactionId) {
          this.recentHumanInteractions.set(humanContinuityKey(input), {
            interactionId: input.interactionId,
            answerHash,
            question: input.question,
            answer: answerText,
          });
        }
      }
      annotateMainPhase("work.record_answer", "completed");
      await this.selfImprovement.observeSlackAnswer(input, answer)
        .then(() => annotateMainPhase("work.self_improvement", "completed"))
        .catch((error) => {
          annotateMainPhase("work.self_improvement", "failed", { error_kind: telemetryErrorKind(error) });
          captureTelemetryError("work.self_improvement.error", error, { component: "work-loop", operation: "observe_slack_answer" });
          logger.warn("self-improvement review failed", { error: String(error), channel: input.channelId, ts: input.ts });
        });
      return { completed: true };
    } catch (error) {
      finalStatus = "failed";
      const message = error instanceof Error ? error.message : String(error);
      annotateMainPhase("work.slack_question", "failed", { error_kind: telemetryErrorKind(error) });
      captureTelemetryError("work.slack_question.error", error, { component: "work-loop", operation: "slack_question" });
      logger.warn("background security answer failed", { error: message, channel: input.channelId, ts: input.ts });
      const delivery = error instanceof AssistantDeliveryError ? error.receipt : undefined;
      if (delivery) {
        await this.deps.assistant.recordDelivery?.(input, delivery).catch(() => undefined);
        telemetryEvent("assistant.answer.delivery_failed", {
          component: "work-loop",
          operation: "post_answer",
          "assistant.delivery.planned_count": delivery.plannedMessages,
          "assistant.delivery.posted_count": delivery.postedMessages,
          "assistant.delivery.complete": false,
          ...assistantTrafficAttributes(input),
        });
        recordMetric("cerebro_slack_companion_assistant_delivery_failures_total", {
          traffic: trafficKind(input),
          partial: delivery.postedMessages > 0 ? "true" : "false",
        }, 1);
      }
      await clearAssistantThreadStatus(client, input.channelId, input.replyThreadTs);
      await addReaction(client, input.channelId, input.ts, "warning");
      const failureSummary = delivery && delivery.postedMessages > 0
        ? `Cerebro posted ${delivery.postedMessages} of ${delivery.plannedMessages} reply parts. Slack rejected the next part after three delivery attempts.`
        : "Slack rejected the response after three delivery attempts.";
      await client.chat.postMessage({
        channel: input.channelId,
        thread_ts: input.replyThreadTs,
        client_msg_id: deliveryMessageId(job.id, 10_000),
        text: failureSummary,
        blocks: askFailureBlocks("The failed delivery is recorded. A retry will keep the current mission and source subjects."),
        unfurl_links: false,
        unfurl_media: false,
      });
      await this.recordEncounter({
        title: `Failed Slack work: ${questionTitle(input.question)}`,
        summary: "Cerebro could not complete background research for a Slack mention.",
        details: message,
        channelId: input.channelId,
        sourceTs: input.ts,
        outcome: "failed",
        tags: ["failure", ...trafficTags(input)],
        ...trafficFields(input),
      });
      await this.selfImprovement.observeSlackFailure(input, message)
        .then(() => annotateMainPhase("work.self_improvement_failure", "completed"))
        .catch((reviewError) => {
          annotateMainPhase("work.self_improvement_failure", "failed", { error_kind: telemetryErrorKind(reviewError) });
          captureTelemetryError("work.self_improvement_failure.error", reviewError, { component: "work-loop", operation: "observe_slack_failure" });
          logger.warn("self-improvement failure review failed", { error: String(reviewError), channel: input.channelId, ts: input.ts });
        });
      return { completed: false, error: message };
    }
    }, { main: true, statusForResult: () => finalStatus, errorEventName: "work.slack_question.error" });
  }

  private async recordAnswerNote(input: SlackQuestionWorkInput, answer: SecurityAssistantAnswer, delivery: AssistantDeliveryReceipt): Promise<void> {
    await this.deps.notes.record({
      kind: "assistant_answer",
      title: `Slack question: ${questionTitle(input.question)}`,
      summary: answer.answer,
      details: [
        answer.keyPoints.length > 0 ? `Key points: ${answer.keyPoints.join(" | ")}` : "",
        answer.evidence.length > 0 ? `Evidence: ${answer.evidence.join(" | ")}` : "",
        answer.actionsTaken.length > 0 ? `Actions taken: ${answer.actionsTaken.join(" | ")}` : "",
        answer.nextActions.length > 0 ? `Next actions: ${answer.nextActions.join(" | ")}` : "",
        answer.research.length > 0 ? `Research: ${answer.research.join(" | ")}` : "",
        `Delivery: ${delivery.postedMessages}/${delivery.plannedMessages} message parts posted.`,
      ].filter(Boolean).join("\n"),
      tags: ["slack-question", "work-loop", answer.source, ...trafficTags(input)],
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "answered",
      ...trafficFields(input),
    }).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: "assistant_answer" }));
  }

  private async recordIgnoredHandoff(input: SlackQuestionWorkInput, answer: SecurityAssistantAnswer): Promise<void> {
    const reason = trimForSlack(answer.dispositionReason ?? "Automated handoff did not need a reply.", 500);
    await this.recordEncounter({
      title: `Ignored automated handoff: ${questionTitle(input.question)}`,
      summary: reason,
      details: "No Slack reply, reaction, follow-up prompt, answer memory, or self-improvement task was created.",
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "ignored",
      tags: ["ignored", "automated-handoff", ...trafficTags(input)],
      ...trafficFields(input),
    });
  }

  private async recordAnswerStory(input: SlackQuestionWorkInput, answer: SecurityAssistantAnswer, delivery: AssistantDeliveryReceipt): Promise<void> {
    const summary = trimForSlack([
      `Cerebro received a Slack question: ${input.question}`,
      `It answered: ${answer.answer}`,
    ].join(" "), 900);
    const details = [
      `Question: ${input.question}`,
      `Answer: ${answer.answer}`,
      answer.actionsTaken.length > 0 ? `Actions taken: ${answer.actionsTaken.join(" | ")}` : "",
      answer.research.length > 0 ? `Research trail: ${answer.research.join(" | ")}` : "",
      answer.nextActions.length > 0 ? `Next actions: ${answer.nextActions.join(" | ")}` : "",
      `Delivery: ${delivery.postedMessages}/${delivery.plannedMessages} message parts posted.`,
    ].filter(Boolean).join("\n");
    await this.recordEncounter({
      title: `Answered Slack work: ${questionTitle(input.question)}`,
      summary,
      details,
      channelId: input.channelId,
      sourceTs: input.ts,
      outcome: "answered",
      tags: ["answered", answer.source, ...trafficTags(input)],
      ...trafficFields(input),
    });
    await this.deps.memory.remember({
      kind: "encounter_story",
      topic: `Slack encounter: ${questionTitle(input.question)}`,
      summary,
      details,
      tags: ["story", "slack-question", "work-loop", answer.source, ...trafficTags(input)],
      channelId: input.channelId,
      sourceTs: input.ts,
      classification: "encounter_story",
      confidence: 0.8,
      sourceKind: "tool",
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    }).catch((error) => logger.warn("encounter story memory write failed", { error: String(error), channel: input.channelId, ts: input.ts }));
  }

  private async recordEncounter(input: {
    title: string;
    summary: string;
    details?: string;
    channelId?: string;
    sourceTs?: string;
    outcome?: string;
    tags?: string[];
    senderKind?: "human" | "bot";
    trafficKind?: "human_request" | "machine_handoff";
  }): Promise<void> {
    await this.deps.notes.record({
      kind: "encounter_story",
      title: input.title,
      summary: input.summary,
      details: input.details,
      tags: ["story", "work-loop", ...(input.tags ?? [])],
      channelId: input.channelId,
      sourceTs: input.sourceTs,
      outcome: input.outcome,
      senderKind: input.senderKind,
      trafficKind: input.trafficKind,
    }).catch((error) => logger.warn("encounter story note failed", { error: String(error), title: input.title }));
  }

  private notifyIdleIfNeeded(): void {
    if (this.active !== 0 || this.queue.length !== 0) return;
    const waiters = this.idleWaiters.splice(0);
    for (const resolve of waiters) resolve();
  }

  private duplicateReason(id: string, input: SlackQuestionWorkInput): SlackQuestionEnqueueResult["reason"] | undefined {
    if (this.activeWorkIds.has(id) || this.queue.some((job) => job.id === id)) return "duplicate_event";
    const cooldownMs = Math.max(0, this.deps.config.triage.duplicateQuestionCooldownMs);
    if (cooldownMs <= 0) return undefined;
    const now = Date.now();
    const staleBefore = now - cooldownMs;
    for (const [fingerprint, seenAt] of this.recentQuestionFingerprints) {
      if (seenAt < staleBefore) this.recentQuestionFingerprints.delete(fingerprint);
    }
    const fingerprint = questionFingerprint(input);
    const lastSeen = this.recentQuestionFingerprints.get(fingerprint);
    if (lastSeen !== undefined && now - lastSeen < cooldownMs) return "duplicate_question";
    return undefined;
  }

  private rememberQuestionFingerprint(input: SlackQuestionWorkInput): void {
    const cooldownMs = Math.max(0, this.deps.config.triage.duplicateQuestionCooldownMs);
    if (cooldownMs <= 0) return;
    this.recentQuestionFingerprints.set(questionFingerprint(input), Date.now());
    if (this.recentQuestionFingerprints.size <= 2_000) return;
    for (const key of [...this.recentQuestionFingerprints.keys()].slice(0, 1_000)) {
      this.recentQuestionFingerprints.delete(key);
    }
  }

  private oldestQueuedAgeMs(): number {
    const oldest = this.queue[0]?.enqueuedAt;
    return oldest ? Math.max(0, Date.now() - Date.parse(oldest)) : 0;
  }

  private recordQueueGauges(): void {
    recordGauge("cerebro_slack_companion_work_queue_depth", { kind: "slack_question" }, this.queue.length);
    recordGauge("cerebro_slack_companion_work_active", { kind: "slack_question" }, this.active);
    recordGauge("cerebro_slack_companion_work_active_threads", { kind: "slack_question" }, this.activeThreadKeys.size);
    recordGauge("cerebro_slack_companion_work_oldest_queue_age_seconds", { kind: "slack_question" }, this.oldestQueuedAgeMs() / 1000);
  }

  private recordHumanFollowUp(input: SlackQuestionWorkInput): void {
    if (input.senderKind === "bot" || !input.userId || !this.deps.improvement?.recordOutcomeEvent) return;
    const prior = this.recentHumanInteractions.get(humanContinuityKey(input));
    if (!prior) return;
    const correction = /^(?:\^+|again\b|do better\b|try again\b)|\b(?:wrong|failed|missed|not what|better query|thought you|grounded citation)\b/i.test(input.question.trim());
    const followUp = correction || input.question.trim().split(/\s+/).length <= 12 || /\b(?:this|that|it|those|them|previous|prior|same|link|source)\b/i.test(input.question);
    if (!followUp) return;
    void this.deps.improvement.recordOutcomeEvent({
      interactionId: prior.interactionId,
      answerHash: prior.answerHash,
      occurredAt: new Date().toISOString(),
      type: correction ? "implicit_correction" : "follow_up",
      result: correction ? "human_requested_rework" : "human_continued_mission",
      confidence: correction ? 0.9 : 0.7,
    }).catch((error) => logger.warn("improvement follow-up outcome write failed", { event: "work.improvement_follow_up.error", error: String(error) }));
  }
}

async function postAssistantMessages(client: any, channel: string, threadTs: string, messages: string[], workId: string): Promise<AssistantDeliveryReceipt> {
  const planned = (messages.length > 0 ? messages : ["I checked what I could, but I do not have a useful answer yet."])
    .map((message) => message.trim())
    .filter(Boolean);
  let lastTs: string | undefined;
  let postedMessages = 0;
  for (const [partIndex, message] of planned.entries()) {
    let delivered = false;
    let lastError: unknown;
    for (let attempt = 1; attempt <= 3 && !delivered; attempt += 1) {
      try {
        const response = await client.chat.postMessage({
          channel,
          thread_ts: threadTs,
          text: message,
          client_msg_id: deliveryMessageId(workId, partIndex),
          unfurl_links: false,
          unfurl_media: false,
        }) as { ts?: string };
        postedMessages += 1;
        lastTs = response.ts ?? lastTs;
        delivered = true;
      } catch (error) {
        lastError = error;
        if (!isTransientSlackWriteError(error) || attempt === 3) break;
        await delay(attempt * 250);
      }
    }
    if (!delivered) {
      const detail = lastError instanceof Error ? lastError.message : String(lastError);
      throw new AssistantDeliveryError(detail, {
        answerTs: lastTs,
        plannedMessages: planned.length,
        postedMessages,
        complete: false,
      });
    }
  }
  return { answerTs: lastTs, plannedMessages: planned.length, postedMessages, complete: postedMessages === planned.length };
}

function isTransientSlackWriteError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /\b(timeout|timed out|rate.?limit|429|5\d\d|internal_error|service_unavailable|temporar|network|connection|econnreset|socket)\b/i.test(message);
}

function deliveryMessageId(workId: string, partIndex: number): string {
  const hex = createHash("sha256").update(workId).update("\0").update(String(partIndex)).digest("hex").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postAssistantFeedback(
  feedback: Pick<AssistantFeedbackService, "registerAnswer">,
  client: any,
  input: SlackQuestionWorkInput,
  answer: SecurityAssistantAnswer,
  delivery: AssistantDeliveryReceipt,
): Promise<void> {
  if (!delivery.answerTs) return;
  const answerId = `${input.channelId}:${delivery.answerTs}`;
  await feedback.registerAnswer({
    answerId,
    interactionId: input.interactionId,
    channelId: input.channelId,
    threadTs: input.replyThreadTs,
    questionTs: input.ts,
    userId: input.userId,
    question: input.question,
    answer: answer.messages.join("\n\n") || answer.answer,
    executionLane: answer.executionLane,
    objective: answer.teammate?.objective,
    desiredOutcome: answer.teammate?.desiredOutcome,
    resolvedScope: answer.teammate?.resolvedScope ?? [],
    senderKind: input.senderKind ?? "human",
    trafficKind: trafficKind(input),
    source: answer.source,
    toolNames: toolNames(answer.research),
    research: answer.research,
    evidence: answer.evidence,
    actionsTaken: answer.actionsTaken,
    nextActions: answer.nextActions,
    commitments: (answer.teammate?.commitments ?? []).map((commitment) => ({
      id: commitment.id,
      status: commitment.status,
      goalId: commitment.goalId,
      goalStatus: commitment.goalStatus,
      artifactRefs: commitment.artifactRefs,
      verification: commitment.verification,
    })),
    delivery: {
      plannedMessages: delivery.plannedMessages,
      postedMessages: delivery.postedMessages,
      complete: delivery.complete,
    },
    claimEvidence: (answer.claimEvidence ?? []).map((packet) => ({
      claimId: packet.claimId,
      claimText: packet.claimText,
      temporalScope: packet.temporalScope,
      verification: packet.verification,
      evidence: packet.evidence.map((evidence) => ({
        id: evidence.id,
        kind: evidence.kind,
        title: evidence.title,
        access: evidence.access,
        sourceTool: evidence.sourceTool,
        sourceRef: evidence.sourceRef,
        createdAt: evidence.createdAt,
        verifiedAt: evidence.verifiedAt,
        freshness: evidence.freshness,
      })),
    })),
  });
  await client.chat.postMessage({
    channel: input.channelId,
    thread_ts: input.replyThreadTs,
    text: "Rate this Cerebro response",
    blocks: assistantFeedbackBlocks({ answerId, channelId: input.channelId, threadTs: input.replyThreadTs }),
    unfurl_links: false,
    unfurl_media: false,
  });
}

function trafficKind(input: Pick<SlackQuestionWorkInput, "senderKind">): "human_request" | "machine_handoff" {
  return input.senderKind === "bot" ? "machine_handoff" : "human_request";
}

function trafficFields(input: Pick<SlackQuestionWorkInput, "senderKind">): {
  senderKind: "human" | "bot";
  trafficKind: "human_request" | "machine_handoff";
} {
  return { senderKind: input.senderKind ?? "human", trafficKind: trafficKind(input) };
}

function trafficTags(input: Pick<SlackQuestionWorkInput, "senderKind">): string[] {
  const fields = trafficFields(input);
  return [`sender-${fields.senderKind}`, `traffic-${fields.trafficKind}`];
}

function assistantTrafficAttributes(input: Pick<SlackQuestionWorkInput, "senderKind">): Record<string, string> {
  const fields = trafficFields(input);
  return {
    "assistant.sender_kind": fields.senderKind,
    "assistant.traffic_kind": fields.trafficKind,
  };
}

function toolNames(research: string[]): string[] {
  return [...new Set(research.flatMap((entry) => {
    const candidate = entry.split(":", 1)[0]?.trim() ?? "";
    return /^[A-Za-z0-9_.-]{2,160}$/.test(candidate) ? [candidate] : [];
  }))].slice(0, 64);
}

async function addReaction(client: any, channel: string, ts: string, name: string): Promise<void> {
  try {
    await client.reactions.add({ channel, timestamp: ts, name });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/already_reacted|missing_scope|not_in_channel|invalid_name/i.test(message)) {
      logger.warn("slack reaction failed", { error: message, channel, ts, name });
    }
  }
}

async function clearAssistantThreadStatus(client: any, channel: string, threadTs: string): Promise<void> {
  await assistantThreadApiCall(client, "assistant.threads.setStatus", {
    channel_id: channel,
    thread_ts: threadTs,
    status: "",
  });
}

async function setAssistantSuggestedPrompts(client: any, channel: string, threadTs: string, question: string): Promise<void> {
  await assistantThreadApiCall(client, "assistant.threads.setSuggestedPrompts", {
    channel_id: channel,
    thread_ts: threadTs,
    title: "Next checks",
    prompts: suggestedPromptsForQuestion(question),
  });
}

async function assistantThreadApiCall(client: any, method: string, args: Record<string, unknown>): Promise<void> {
  try {
    if (typeof client.apiCall !== "function") return;
    const response = await client.apiCall(method, args) as { ok?: boolean; error?: string; detail?: string };
    if (response?.ok === false) {
      throw new Error(response.detail ? `${response.error ?? "unknown"}: ${response.detail}` : response.error ?? "unknown");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/missing_scope|invalid_thread_ts|channel_not_found|no_permission|not_allowed_token_type|method_not_supported|unknown_method/i.test(message)) {
      logger.info("slack assistant thread api skipped", { method, reason: message.slice(0, 200) });
      return;
    }
    logger.warn("slack assistant thread api failed", { method, error: message.slice(0, 300) });
  }
}

function suggestedPromptsForQuestion(question: string): Array<{ title: string; message: string }> {
  const normalized = question.toLowerCase();
  if (/(false positive|fp|noisy|noise)/.test(normalized)) {
    return [
      { title: "Show evidence", message: "What evidence supports or weakens the false-positive call?" },
      { title: "Check owner", message: "Who owns the resource or identity involved?" },
      { title: "Find changes", message: "What changed around the alert time?" },
      { title: "Next step", message: "What is the safest next check?" },
    ];
  }
  if (/(login|okta|sso|mfa|auth)/.test(normalized)) {
    return [
      { title: "Top risks", message: "What are the top login-security risks right now?" },
      { title: "Open findings", message: "Which open findings affect login security?" },
      { title: "Recent changes", message: "What changed in identity systems today?" },
      { title: "Owners", message: "Who should review the highest-risk item?" },
    ];
  }
  return [
    { title: "Show evidence", message: "What evidence did you check?" },
    { title: "Why risky", message: "Why does this matter?" },
    { title: "Find owner", message: "Who owns the next action?" },
    { title: "Check changes", message: "What changed recently?" },
  ];
}

function stableWorkId(input: SlackQuestionWorkInput): string {
  return [input.channelId, input.ts, input.replyThreadTs].join(":");
}

function stableThreadKey(input: SlackQuestionWorkInput): string {
  return [input.channelId, input.replyThreadTs || input.threadTs || input.ts].join(":");
}

function humanContinuityKey(input: Pick<SlackQuestionWorkInput, "channelId" | "userId">): string {
  return `${input.channelId}:${input.userId ?? "unknown"}`;
}

function questionFingerprint(input: SlackQuestionWorkInput): string {
  return [
    stableThreadKey(input),
    input.question.replace(/\s+/g, " ").trim().toLowerCase(),
  ].join(":");
}

function questionTitle(question: string): string {
  return question.replace(/\s+/g, " ").trim().slice(0, 120) || "Cerebro mention";
}

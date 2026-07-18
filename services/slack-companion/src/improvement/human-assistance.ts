import type { ImprovementRun } from "./types.js";
import type { EnqueueSlackDeliveryInput, SlackDeliveryRecord } from "../slack/delivery-outbox-store.js";

interface SlackDeliveryEnqueuer {
  enqueue(input: EnqueueSlackDeliveryInput): Promise<SlackDeliveryRecord>;
}

export interface ImprovementHumanAssistancePublisher {
  publish(run: ImprovementRun): Promise<SlackDeliveryRecord | undefined>;
}

export const assistanceLifetimeMs = 72 * 60 * 60 * 1_000;

export class SlackImprovementHumanAssistancePublisher implements ImprovementHumanAssistancePublisher {
  private readonly now: () => Date;

  constructor(private readonly outbox: SlackDeliveryEnqueuer, options: { now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
  }

  async publish(run: ImprovementRun): Promise<SlackDeliveryRecord | undefined> {
    const assistance = run.assistance;
    if (!assistance || assistance.deliveryStatus !== "pending") return undefined;
    if (new Date(assistance.expiresAt).getTime() <= this.now().getTime()) return undefined;
    return this.outbox.enqueue(deliveryInput(run));
  }
}

function deliveryInput(run: ImprovementRun): EnqueueSlackDeliveryInput {
  const assistance = run.assistance;
  if (!assistance) throw new Error("Human assistance delivery requires a persisted recipient.");
  const initiativeId = `improvement-assistance:${run.id}`;
  return {
    idempotencyKey: initiativeId,
    channelId: assistance.channelId,
    text: [
      `<@${assistance.intendedUserId}> I recorded ${run.signalCount} ${behaviorName(run.issueKind)} signals in ${behaviorName(run.skillId)} and queued work to author a draft repair.`,
      "What exact outcome should its regression test prove?",
    ].join(" "),
    receiptContext: {
      kind: "assistant_initiative",
      refId: initiativeId,
      assistantInitiative: {
        intendedUserId: assistance.intendedUserId,
        expiresAt: assistance.expiresAt,
        goalId: run.id,
      },
    },
  };
}

function behaviorName(value: string): string {
  return value.replace(/[^a-zA-Z0-9]+/g, " ").replace(/\s+/g, " ").trim().toLowerCase() || "observed gap";
}

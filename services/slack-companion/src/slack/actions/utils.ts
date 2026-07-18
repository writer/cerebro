import type { DailyNoteInput } from "../../learning/daily-notes.js";
import { logger } from "../../logger.js";
import { decodeAction, type ActionPayload } from "../action-codec.js";
import type { ActionDeps } from "./types.js";

export function payloadFromAction(action: any, body: any): ActionPayload {
  return {
    ...decodeAction(action.value),
    channelId: body.channel?.id,
  };
}

export async function postModalResult(client: any, payload: ActionPayload, userId: string, text: string, response?: unknown): Promise<void> {
  if (!payload.channelId) {
    return;
  }
  const suffix = response ? `\n\`${JSON.stringify(response).slice(0, 800)}\`` : "";
  await client.chat.postEphemeral({
    channel: payload.channelId,
    user: userId,
    text: `${text}${suffix}`,
  });
}

export function required(value: string | undefined, label: string): string {
  if (!value?.trim()) {
    throw new Error(`${label} is required`);
  }
  return value.trim();
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function recordDailyNote(deps: ActionDeps, input: DailyNoteInput): Promise<void> {
  await deps.notes.record(input).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: input.kind }));
}

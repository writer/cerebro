export const SLACK_LEARNING_CANDIDATE_REJECTIONS = [
  "machine",
  "subtype",
  "missing_user",
  "missing_timestamp",
  "empty",
  "cerebro_mention",
] as const;

export type SlackLearningCandidateRejection =
  (typeof SLACK_LEARNING_CANDIDATE_REJECTIONS)[number];

/**
 * Minimal host projection needed to decide whether a Slack message may be a
 * learning candidate. Fetching, authorization, and persistence stay outside
 * this portable policy.
 */
export interface SlackLearningCandidateMessage {
  readonly app_id?: string;
  readonly bot_id?: string;
  readonly subtype?: string;
  readonly text?: string;
  readonly ts?: string;
  readonly user?: string;
}

export function slackLearningCandidateRejection(
  message: SlackLearningCandidateMessage,
  cerebroBotUserId: string,
): SlackLearningCandidateRejection | undefined {
  if (message.bot_id || message.app_id) return "machine";
  if (message.subtype) return "subtype";
  if (typeof message.user !== "string" || !message.user.trim()) return "missing_user";
  if (typeof message.ts !== "string" || !message.ts.trim()) return "missing_timestamp";
  if (typeof message.text !== "string" || !message.text.trim()) return "empty";
  if (mentionsUser(message.text, cerebroBotUserId)) return "cerebro_mention";
  return undefined;
}

function mentionsUser(text: string, userId: string): boolean {
  if (!userId.trim()) return false;
  return text.includes(`<@${userId}>`);
}

import { encodeAction } from "../action-codec.js";
import { actionIds } from "./action-ids.js";
import { actions, button, context, type SlackBlock } from "./primitives.js";

export function assistantFeedbackBlocks(input: {
  answerId: string;
  channelId: string;
  threadTs: string;
}): SlackBlock[] {
  return [
    context(["Did this response help complete the task?"]),
    actions([
      button("👍 Helpful", actionIds.assistantFeedbackHelpful, encodeAction({
        kind: "assistant_feedback_helpful",
        answerId: input.answerId,
        channelId: input.channelId,
        threadTs: input.threadTs,
      })),
      button("👎 Needs work", actionIds.assistantFeedbackNeedsWork, encodeAction({
        kind: "assistant_feedback_needs_work",
        answerId: input.answerId,
        channelId: input.channelId,
        threadTs: input.threadTs,
      })),
      button("Evidence receipt", actionIds.assistantFeedbackEvidence, encodeAction({
        kind: "assistant_feedback_evidence",
        answerId: input.answerId,
        channelId: input.channelId,
        threadTs: input.threadTs,
      })),
    ]),
  ];
}

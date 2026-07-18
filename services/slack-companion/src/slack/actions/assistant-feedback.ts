import type { AssistantFeedbackPositiveDetail, AssistantFeedbackReason } from "../../learning/assistant-feedback.js";
import { logger } from "../../logger.js";
import { decodeAction, encodeAction } from "../action-codec.js";
import { actionIds } from "../blocks/index.js";
import { viewValue } from "../modals.js";
import { normalizeSlackUserName } from "../research/utils.js";
import { escapeMrkdwn } from "../blocks/primitives.js";
import { trimForSlack } from "../format.js";
import type { ActionDeps } from "./types.js";
import { errorMessage, payloadFromAction, postModalResult, required } from "./utils.js";

const feedbackModalId = "cerebro_assistant_feedback_submit";
const positiveFeedbackModalId = "cerebro_assistant_feedback_positive_submit";

export function registerAssistantFeedbackActions(app: any, deps: ActionDeps): void {
  app.action(actionIds.assistantFeedbackEvidence, async ({ body, action, ack, respond }: any) => {
    await ack();
    try {
      if (!deps.feedback) throw new Error("Response evidence is not configured.");
      const payload = payloadFromAction(action, body);
      const receipt = await deps.feedback.evidenceReceiptForAnswer(
        required(payload.answerId, "response id"),
        required(payload.channelId ?? body.channel?.id, "channel id"),
      );
      if (!receipt) throw new Error("This evidence receipt is unavailable in this channel.");
      const claims = receipt.claims.slice(0, 6).map((claim) => `• ${escapeMrkdwn(trimForSlack(claim.summary, 240))} — ${claim.status}`).join("\n");
      const sources = receipt.sources.slice(0, 8).map((source) => `• ${escapeMrkdwn(trimForSlack(source.title, 160))} — ${source.status}; checked ${source.observedAt}`).join("\n");
      const receiptText = trimForSlack(`*Evidence receipt*\nStatus: *${receipt.status}*\nReceipt: \`${receipt.receiptId}\`\nValid until: ${receipt.validUntil}\n\n*Claims*\n${claims}\n\n*Sources*\n${sources}`, 2_900);
      await respond({
        response_type: "ephemeral",
        text: `Evidence receipt ${receipt.receiptId}`,
        blocks: [{
          type: "section",
          text: { type: "mrkdwn", text: receiptText },
        }],
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
    }
  });

  app.action(actionIds.assistantFeedbackHelpful, async ({ body, action, ack, client, respond }: any) => {
    await ack();
    try {
      if (!deps.feedback) throw new Error("Response feedback is not configured.");
      const payload = payloadFromAction(action, body);
      const author = await feedbackAuthor(client, body.user);
      await deps.feedback.recordFeedback({
        answerId: required(payload.answerId, "response id"),
        ...author,
        vote: "up",
        reason: "helpful",
      });
      await respond({
        response_type: "ephemeral",
        text: "Helpful recorded. What should Cerebro repeat?",
        blocks: [{
          type: "actions",
          elements: [
            helpfulDetailButton("Correct answer", "correct", payload),
            helpfulDetailButton("Completed the work", "completed_action", payload),
            helpfulDetailButton("Useful evidence", "useful_evidence", payload),
            helpfulDetailButton("Clear explanation", "clear_explanation", payload),
            helpfulDetailButton("Add detail", undefined, payload),
          ],
        }],
      });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
    }
  });

  app.action(actionIds.assistantFeedbackHelpfulDetail, async ({ body, action, ack, client, respond }: any) => {
    await ack();
    try {
      if (!deps.feedback) throw new Error("Response feedback is not configured.");
      const payload = payloadFromAction(action, body);
      const author = await feedbackAuthor(client, body.user);
      const positiveDetail = optionalHelpfulDetail(payload.feedbackDetail);
      if (positiveDetail) {
        await deps.feedback.recordFeedback({
          answerId: required(payload.answerId, "response id"),
          ...author,
          vote: "up",
          reason: "helpful",
          positiveDetail,
        });
      }
      await client.views.open({
        trigger_id: required(body.trigger_id, "trigger id"),
        view: positiveFeedbackModal(action.value, positiveDetail),
      });
      await respond({ replace_original: true, response_type: "ephemeral", text: positiveDetail ? "What worked was recorded. Add the specific behavior in the form." : "Add the specific behavior in the form." });
    } catch (error) {
      await respond({ response_type: "ephemeral", text: errorMessage(error) });
    }
  });

  app.action(actionIds.assistantFeedbackNeedsWork, async ({ body, action, ack, client, respond }: any) => {
    await ack();
    try {
      const payload = payloadFromAction(action, body);
      required(payload.answerId, "response id");
      const sourceOptions = await deps.feedback?.evidenceOptionsForAnswer(
        required(payload.answerId, "response id"),
        required(payload.channelId ?? body.channel?.id, "channel id"),
      ) ?? [];
      await client.views.open({
        trigger_id: required(body.trigger_id, "trigger id"),
        view: {
          type: "modal",
          callback_id: feedbackModalId,
          private_metadata: action.value,
          title: { type: "plain_text", text: "Response feedback" },
          submit: { type: "plain_text", text: "Save feedback" },
          close: { type: "plain_text", text: "Cancel" },
          blocks: [
            {
              type: "input",
              block_id: "reason",
              label: { type: "plain_text", text: "What needs work?" },
              element: {
                type: "static_select",
                action_id: "value",
                options: [
                  option("Wrong answer", "incorrect"),
                  option("Used stale or weak evidence", "weak_evidence"),
                  ...(sourceOptions.length > 0 ? [
                    option("Wrong source", "wrong_source"),
                    option("Source is outdated", "source_outdated"),
                    option("Source cannot be opened", "source_inaccessible"),
                  ] : []),
                  option("Missed part of the request", "missed_request"),
                  option("Did not complete the action", "did_not_act"),
                  option("Too much detail", "too_long"),
                  option("Not enough detail", "too_short"),
                  option("Hard to follow", "unclear"),
                ],
              },
            },
            ...(sourceOptions.length > 0 ? [{
              type: "input",
              optional: true,
              block_id: "source",
              label: { type: "plain_text", text: "Which source needs review?" },
              element: {
                type: "static_select",
                action_id: "value",
                placeholder: { type: "plain_text", text: "Select the source" },
                options: sourceOptions.map((source) => ({
                  text: { type: "plain_text", text: source.title.slice(0, 75) },
                  value: source.evidenceId,
                })),
              },
            }] : []),
            {
              type: "input",
              optional: true,
              block_id: "expected_outcome",
              label: { type: "plain_text", text: "What result did you expect?" },
              element: {
                type: "plain_text_input",
                action_id: "value",
                multiline: true,
                max_length: 1_000,
                placeholder: { type: "plain_text", text: "Name the answer, action, or completed state" },
              },
            },
            {
              type: "input",
              optional: true,
              block_id: "comment",
              label: { type: "plain_text", text: "What was wrong?" },
              element: {
                type: "plain_text_input",
                action_id: "value",
                multiline: true,
                max_length: 1_000,
                placeholder: { type: "plain_text", text: "Add the missing fact or failure detail" },
              },
            },
          ],
        },
      });
    } catch (error) {
      logger.warn("assistant feedback modal failed", { error: String(error), user: body.user?.id });
      await respond?.({ response_type: "ephemeral", text: errorMessage(error) });
    }
  });

  app.view(feedbackModalId, async ({ ack, body, view, client }: any) => {
    const payload = decodeAction(view.private_metadata);
    const reason = feedbackReason(viewValue(view, "reason"));
    const evidenceId = viewValue(view, "source") || undefined;
    if (isSourceFeedbackReason(reason) && !evidenceId) {
      await ack({ response_action: "errors", errors: { source: "Select the source that needs review." } });
      return;
    }
    await ack();
    try {
      if (!deps.feedback) throw new Error("Response feedback is not configured.");
      const author = await feedbackAuthor(client, body.user);
      await deps.feedback.recordFeedback({
        answerId: required(payload.answerId, "response id"),
        ...author,
        vote: "down",
        reason,
        evidenceId,
        expectedOutcome: viewValue(view, "expected_outcome") || undefined,
        comment: viewValue(view, "comment") || undefined,
      });
      await postModalResult(client, payload, body.user.id, "Feedback recorded for this response.");
    } catch (error) {
      logger.warn("assistant feedback write failed", { error: String(error), user: body.user?.id });
      await postModalResult(client, payload, body.user.id, errorMessage(error));
    }
  });

  app.view(positiveFeedbackModalId, async ({ ack, body, view, client }: any) => {
    await ack();
    const payload = decodeAction(view.private_metadata);
    try {
      if (!deps.feedback) throw new Error("Response feedback is not configured.");
      const author = await feedbackAuthor(client, body.user);
      await deps.feedback.recordFeedback({
        answerId: required(payload.answerId, "response id"),
        ...author,
        vote: "up",
        reason: "helpful",
        positiveDetail: helpfulDetail(viewValue(view, "positive_detail")),
        comment: viewValue(view, "positive_note") || undefined,
        positiveOutcome: viewValue(view, "positive_outcome") || undefined,
      });
      await postModalResult(client, payload, body.user.id, "Recorded what Cerebro should repeat.");
    } catch (error) {
      logger.warn("assistant positive feedback write failed", { error: String(error), user: body.user?.id });
      await postModalResult(client, payload, body.user.id, errorMessage(error));
    }
  });
}

function helpfulDetailButton(label: string, detail: AssistantFeedbackPositiveDetail | undefined, payload: ReturnType<typeof decodeAction>): object {
  return {
    type: "button",
    action_id: actionIds.assistantFeedbackHelpfulDetail,
    text: { type: "plain_text", text: label },
    value: encodeAction({ ...payload, kind: "assistant_feedback_helpful_detail", feedbackDetail: detail }),
  };
}

function helpfulDetail(value: unknown): AssistantFeedbackPositiveDetail {
  const detail = optionalHelpfulDetail(value);
  if (detail) return detail;
  throw new Error("Select what worked.");
}

function optionalHelpfulDetail(value: unknown): AssistantFeedbackPositiveDetail | undefined {
  if (value === "correct" || value === "completed_action" || value === "useful_evidence" || value === "right_detail"
    || value === "identified_issue" || value === "initiative" || value === "clear_explanation") return value;
  return undefined;
}

function positiveFeedbackModal(privateMetadata: string, selected?: AssistantFeedbackPositiveDetail): object {
  const options = positiveDetailOptions();
  return {
    type: "modal",
    callback_id: positiveFeedbackModalId,
    private_metadata: privateMetadata,
    title: { type: "plain_text", text: "What worked" },
    submit: { type: "plain_text", text: "Save detail" },
    close: { type: "plain_text", text: "Cancel" },
    blocks: [
      {
        type: "input",
        block_id: "positive_detail",
        label: { type: "plain_text", text: "What did Cerebro do well?" },
        element: {
          type: "static_select",
          action_id: "value",
          options,
          ...(selected ? { initial_option: options.find((item) => item.value === selected) } : {}),
        },
      },
      {
        type: "input",
        optional: true,
        block_id: "positive_note",
        label: { type: "plain_text", text: "What should Cerebro repeat?" },
        element: {
          type: "plain_text_input",
          action_id: "value",
          multiline: true,
          max_length: 1_000,
          placeholder: { type: "plain_text", text: "Name the useful behavior, evidence, action, or explanation" },
        },
      },
      {
        type: "input",
        optional: true,
        block_id: "positive_outcome",
        label: { type: "plain_text", text: "What did this help you complete?" },
        element: {
          type: "plain_text_input",
          action_id: "value",
          multiline: true,
          max_length: 1_000,
          placeholder: { type: "plain_text", text: "Name the decision, action, or finished state" },
        },
      },
    ],
  };
}

function positiveDetailOptions(): Array<{ text: { type: "plain_text"; text: string }; value: AssistantFeedbackPositiveDetail }> {
  return [
    positiveOption("Correct answer", "correct"),
    positiveOption("Completed the work", "completed_action"),
    positiveOption("Useful evidence", "useful_evidence"),
    positiveOption("Found the real issue", "identified_issue"),
    positiveOption("Took the next useful step", "initiative"),
    positiveOption("Clear explanation", "clear_explanation"),
    positiveOption("Right amount of detail", "right_detail"),
  ];
}

function positiveOption(label: string, value: AssistantFeedbackPositiveDetail): { text: { type: "plain_text"; text: string }; value: AssistantFeedbackPositiveDetail } {
  return { text: { type: "plain_text", text: label }, value };
}

async function feedbackAuthor(client: any, user: any): Promise<{ userId: string; userDisplayName?: string }> {
  const userId = required(user?.id, "user id");
  const payloadName = slackName(user?.name) ?? slackName(user?.username);
  try {
    const response = await client.users.info({ user: userId });
    const resolved = normalizeSlackUserName(response?.user, payloadName ?? userId);
    return { userId, userDisplayName: resolved === userId ? undefined : resolved };
  } catch (error) {
    logger.warn("assistant feedback author lookup failed", {
      event: "assistant.feedback.author_lookup_failed",
      error: String(error),
      user: userId,
    });
    return { userId, userDisplayName: payloadName };
  }
}

function slackName(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 160) : undefined;
}

function option(label: string, value: AssistantFeedbackReason): { text: { type: "plain_text"; text: string }; value: string } {
  return { text: { type: "plain_text", text: label }, value };
}

function feedbackReason(value: string): Exclude<AssistantFeedbackReason, "helpful"> {
  if (value === "incorrect" || value === "weak_evidence" || value === "missed_request" || value === "did_not_act" || value === "too_long" || value === "too_short" || value === "unclear"
    || value === "wrong_source" || value === "source_outdated" || value === "source_inaccessible") {
    return value;
  }
  throw new Error("Select what needs work.");
}

function isSourceFeedbackReason(reason: AssistantFeedbackReason): boolean {
  return reason === "wrong_source" || reason === "source_outdated" || reason === "source_inaccessible";
}

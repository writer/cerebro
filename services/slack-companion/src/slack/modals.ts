import type { WebClient } from "@slack/web-api";
import { encodeAction, type ActionPayload } from "./action-codec.js";

export async function openTextModal(client: WebClient, triggerId: string, input: {
  title: string;
  callbackId: string;
  payload: ActionPayload;
  label: string;
  actionId: string;
  placeholder?: string;
  multiline?: boolean;
}): Promise<void> {
  await client.views.open({
    trigger_id: triggerId,
    view: {
      type: "modal",
      callback_id: input.callbackId,
      private_metadata: encodeAction(input.payload),
      title: { type: "plain_text", text: input.title.slice(0, 24) },
      submit: { type: "plain_text", text: "Submit" },
      close: { type: "plain_text", text: "Cancel" },
      blocks: [
        {
          type: "input",
          block_id: "input",
          label: { type: "plain_text", text: input.label },
          element: {
            type: "plain_text_input",
            action_id: input.actionId,
            multiline: input.multiline ?? false,
            placeholder: input.placeholder ? { type: "plain_text", text: input.placeholder } : undefined,
          },
        },
      ],
    },
  });
}

export async function openGraphActionModal(client: WebClient, triggerId: string, payload: ActionPayload): Promise<void> {
  await client.views.open({
    trigger_id: triggerId,
    view: {
      type: "modal",
      callback_id: "cerebro_graph_action_submit",
      private_metadata: encodeAction(payload),
      title: { type: "plain_text", text: "Dry run action" },
      submit: { type: "plain_text", text: "Run" },
      close: { type: "plain_text", text: "Cancel" },
      blocks: [
        {
          type: "input",
          block_id: "action",
          label: { type: "plain_text", text: "Action" },
          element: {
            type: "static_select",
            action_id: "value",
            options: [
              option("Suspend Okta user", "identity.okta.suspend_user"),
              option("Unsuspend Okta user", "identity.okta.unsuspend_user"),
              option("Revoke Cerebro device", "endpoint.cerebro.revoke_device"),
            ],
          },
        },
        {
          type: "input",
          block_id: "reason",
          label: { type: "plain_text", text: "Reason" },
          element: {
            type: "plain_text_input",
            action_id: "value",
            multiline: true,
            placeholder: { type: "plain_text", text: "Why this action is being tested" },
          },
        },
      ],
    },
  });
}

export function viewValue(view: any, blockId: string, actionId = "value"): string {
  const value = view?.state?.values?.[blockId]?.[actionId];
  if (value?.type === "static_select") {
    return value.selected_option?.value ?? "";
  }
  return value?.value ?? "";
}

function option(label: string, value: string): { text: { type: "plain_text"; text: string }; value: string } {
  return { text: { type: "plain_text", text: label }, value };
}

import { trimForSlack } from "../format.js";

export type SlackBlock = Record<string, unknown>;

export function header(textValue: string): SlackBlock {
  return { type: "header", text: { type: "plain_text", text: textValue.slice(0, 150) } };
}

export function section(markdown: string): SlackBlock {
  return { type: "section", text: { type: "mrkdwn", text: markdown } };
}

export function context(lines: string[]): SlackBlock {
  return {
    type: "context",
    elements: lines.map((line) => ({ type: "mrkdwn", text: escapeMrkdwn(line) })),
  };
}

export function actions(elements: SlackBlock[]): SlackBlock {
  return { type: "actions", elements };
}

export function button(label: string, actionId: string, value: string, style?: "primary" | "danger"): SlackBlock {
  const block: SlackBlock = {
    type: "button",
    action_id: actionId,
    text: { type: "plain_text", text: label },
    value,
  };
  if (style) {
    block.style = style;
  }
  return block;
}

export function divider(): SlackBlock {
  return { type: "divider" };
}

export function listSection(title: string, items: string[]): SlackBlock[] {
  if (items.length === 0) return [];
  return [section(`*${title}*\n${items.slice(0, 6).map((item) => `- ${escapeMrkdwn(trimForSlack(item, 500))}`).join("\n")}`)];
}

export function escapeMrkdwn(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

import type { SecuritySkill } from "../../skills/security-skills.js";
import { commandHelpEntries } from "../command-parser.js";
import { trimForSlack } from "../format.js";
import { context, escapeMrkdwn, header, section, type SlackBlock } from "./primitives.js";

export function helpBlocks(): SlackBlock[] {
  return [
    header("Cerebro commands"),
    section(commandHelpEntries().map((entry) => `\`${entry.usage}\` · ${entry.summary}`).join("\n")),
  ];
}

export function skillsBlocks(skills: SecuritySkill[]): SlackBlock[] {
  return [
    header("Cerebro skills"),
    ...skills.map((skill) => section(`*${escapeMrkdwn(skill.id)}* · ${escapeMrkdwn(skill.title)}\n${escapeMrkdwn(skill.summary)}`)),
  ];
}

export function askBlocks(question: string, answer: string): SlackBlock[] {
  return [
    header("Cerebro answer"),
    context([`Question: ${question}`]),
    section(escapeMrkdwn(trimForSlack(answer))),
  ];
}

export function askFailureBlocks(reason: string): SlackBlock[] {
  return [
    header("Cerebro answer"),
    section(`Graph answer did not complete: ${escapeMrkdwn(trimForSlack(reason, 900))}`),
  ];
}

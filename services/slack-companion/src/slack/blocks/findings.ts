import type { Finding, FindingEvidence } from "../../cerebro/types.js";
import type { AppConfig } from "../../config/index.js";
import { encodeAction } from "../action-codec.js";
import { evidenceLine, findingStatusLine, findingTitle, text } from "../format.js";
import { actionIds } from "./action-ids.js";
import { actions, button, divider, escapeMrkdwn, header, section, type SlackBlock } from "./primitives.js";

export function findingBlocks(runtime: string, findings: Finding[], config: AppConfig): SlackBlock[] {
  if (findings.length === 0) {
    return [header("Open findings"), section(`No open findings matched ${escapeMrkdwn(runtime)}.`)];
  }
  return [
    header("Open findings"),
    ...findings.flatMap((finding) => findingCard(runtime, finding, config)),
  ];
}

export function evidenceBlocks(runtime: string, findingId: string, evidence: FindingEvidence[]): SlackBlock[] {
  if (evidence.length === 0) {
    return [header("Finding evidence"), section(`No evidence matched ${escapeMrkdwn(findingId)} in ${escapeMrkdwn(runtime)}.`)];
  }
  return [
    header("Finding evidence"),
    section(`*${escapeMrkdwn(findingId)}* · ${escapeMrkdwn(runtime)}`),
    ...evidence.slice(0, 8).map((item) => section(escapeMrkdwn(evidenceLine(item)))),
  ];
}

export function findingCard(runtime: string, finding: Finding, config: AppConfig): SlackBlock[] {
  const findingId = text(finding.id, "");
  const title = findingTitle(finding);
  const resource = finding.primary_resource_urn ?? finding.resource_urn;
  const link = findingId && config.cerebro.webBaseUrl ? `\n<${config.cerebro.webBaseUrl}/findings/${encodeURIComponent(findingId)}|Open in Cerebro>` : "";
  return [
    section(`*${escapeMrkdwn(title)}*\n${escapeMrkdwn(findingStatusLine(finding))}${resource ? `\n${escapeMrkdwn(resource)}` : ""}${link}`),
    actions([
      button("Evidence", actionIds.findingEvidence, encodeAction({ kind: "finding_evidence", runtimeId: runtime, findingId })),
      button("Note", actionIds.findingNote, encodeAction({ kind: "finding_note", runtimeId: runtime, findingId })),
      button("Assign", actionIds.findingAssign, encodeAction({ kind: "finding_assign", runtimeId: runtime, findingId })),
    ]),
    actions([
      button("Due date", actionIds.findingDue, encodeAction({ kind: "finding_due", runtimeId: runtime, findingId })),
      button("Resolve", actionIds.findingResolve, encodeAction({ kind: "finding_resolve", runtimeId: runtime, findingId }), "primary"),
      button("Suppress", actionIds.findingSuppress, encodeAction({ kind: "finding_suppress", runtimeId: runtime, findingId }), "danger"),
      button("Dry run action", actionIds.graphActionDryRun, encodeAction({ kind: "graph_action_dry_run", runtimeId: runtime, findingId })),
    ]),
    divider(),
  ];
}

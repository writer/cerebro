import { logger } from "../../logger.js";
import { assessDangerousIntent } from "../../security/safety.js";
import {
  askBlocks,
  evidenceBlocks,
  findingBlocks,
  helpBlocks,
  runtimeHealthBlocks,
  securityAnswerBlocks,
  skillsBlocks,
} from "../blocks/index.js";
import { answerFromGraphReason } from "../format.js";
import { publishHome } from "../home.js";
import { recordDailyNote } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandByName, CommandContext } from "./types.js";
import { questionTitle, runtimeIdsFor } from "./utils.js";

export async function handleHelp({ deps, command, respond }: CommandContext<CommandByName<"help">>): Promise<void> {
  await respondEphemeral(respond, helpBlocks());
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro help",
    summary: "Displayed command help.",
    tags: ["slash-command", "help"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleHome({ deps, command, respond, client }: CommandContext<CommandByName<"home">>): Promise<void> {
  await publishHome(client, command.user_id, deps.config, deps.cerebro, deps.a2a);
  await respondEphemeral(respond, [{ type: "section", text: { type: "mrkdwn", text: "Home tab refreshed." } }]);
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro home",
    summary: "Refreshed the Cerebro Slack home tab.",
    tags: ["slash-command", "home"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleHealth({ deps, command, respond, parsed }: CommandContext<CommandByName<"health">>): Promise<void> {
  const runtimes = await deps.cerebro.listRuntimeHealth({
    runtimeId: parsed.runtimeId,
    runtimeIds: parsed.runtimeId ? undefined : deps.config.cerebro.defaultRuntimeIds,
    limit: 20,
  });
  await respondEphemeral(respond, runtimeHealthBlocks(runtimes));
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro health",
    summary: `Returned runtime health for ${runtimes.length} runtime(s).`,
    details: parsed.runtimeId ? `Runtime: ${parsed.runtimeId}` : `Default runtimes: ${deps.config.cerebro.defaultRuntimeIds.join(", ")}`,
    tags: ["slash-command", "runtime-health"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleFindings({ deps, command, respond, parsed }: CommandContext<CommandByName<"findings">>): Promise<void> {
  const runtimeIds = runtimeIdsFor(deps.config, parsed.runtimeId);
  let findingCount = 0;
  for (const runtimeId of runtimeIds) {
    const findings = await deps.cerebro.listFindings(runtimeId, { limit: 5 });
    findingCount += findings.length;
    await respondEphemeral(respond, findingBlocks(runtimeId, findings, deps.config));
  }
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro findings",
    summary: `Returned ${findingCount} open finding(s) across ${runtimeIds.length} runtime(s).`,
    details: `Runtimes: ${runtimeIds.join(", ")}`,
    tags: ["slash-command", "findings"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleAsk({ deps, command, respond, actor, parsed }: CommandContext<CommandByName<"ask">>): Promise<void> {
  const safety = assessDangerousIntent(parsed.question);
  if (!safety.allowed) {
    await respondEphemeral(respond, plainBlocks(safety.refusal ?? "I cannot help with that request."));
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "/cerebro ask refused",
      summary: safety.reason ?? "Cerebro refused an unsafe slash-command question.",
      details: [`Category: ${safety.category ?? "unsafe_request"}`, `Question: ${parsed.question}`].join("\n"),
      tags: ["safety-refusal", safety.category ?? "unsafe-request", "slash-command"],
      channelId: command.channel_id,
      outcome: "refused",
    });
    await deps.cerebro.recordInteraction({
      actor,
      action: "slash.ask",
      channelId: command.channel_id,
      status: "failed",
      details: { safety_category: safety.category ?? "unsafe_request" },
    }).catch((error) => logger.warn("interaction write failed", { error: String(error), status: "refused" }));
    return;
  }

  await deps.cerebro.buildEvidencePacket({
    question: parsed.question,
    capability_ids: ["graph-reasoning"],
  });
  const answer = await deps.cerebro.reasonGraph({ question: parsed.question, scope_urn: parsed.scopeUrn });
  const text = answerFromGraphReason(answer);
  await respondEphemeral(respond, askBlocks(parsed.question, text));
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: questionTitle(parsed.question),
    summary: text,
    details: parsed.scopeUrn ? `Scope URN: ${parsed.scopeUrn}` : undefined,
    tags: ["slash-command", "ask", "graph-reasoning"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleEvidence({ deps, command, respond, parsed }: CommandContext<CommandByName<"evidence">>): Promise<void> {
  const evidence = await deps.cerebro.listFindingEvidence(parsed.runtimeId, parsed.findingId, 8);
  await respondEphemeral(respond, evidenceBlocks(parsed.runtimeId, parsed.findingId, evidence));
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro evidence",
    summary: `Returned ${evidence.length} evidence row(s) for finding ${parsed.findingId}.`,
    details: `Runtime: ${parsed.runtimeId}`,
    tags: ["slash-command", "evidence"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleSkills({ deps, command, respond }: CommandContext<CommandByName<"skills">>): Promise<void> {
  await respondEphemeral(respond, skillsBlocks(deps.skills.list()));
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: "/cerebro skills",
    summary: "Listed reusable Cerebro security skills.",
    tags: ["slash-command", "skills"],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

export async function handleSkill({ deps, command, respond, parsed }: CommandContext<CommandByName<"skill">>): Promise<void> {
  const result = await deps.skills.runSkill({
    skillId: parsed.skillId,
    details: parsed.details,
    channelId: command.channel_id,
    userId: command.user_id,
    ts: command.trigger_id ?? command.event_ts ?? new Date().toISOString(),
  });
  await respondEphemeral(respond, securityAnswerBlocks(result.skill.title, result.answer));
  await recordDailyNote(deps, {
    kind: "assistant_answer",
    title: `/cerebro skill ${result.skill.id}`,
    summary: result.answer.answer,
    details: result.answer.research.join(" | "),
    tags: ["slash-command", "skill", result.skill.id],
    channelId: command.channel_id,
    outcome: "answered",
  });
}

import { createHash } from "node:crypto";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "../agent/security-assistant.js";
import { RuntimeCodeWorkspace, type RuntimeCodePrInput } from "../code/runtime-code.js";
import type { AppConfig } from "../config/index.js";
import type { ImprovementCandidate, ImprovementObserveOptions, ImprovementSignal, ImprovementSignalRecorder } from "../improvement/types.js";
import { trimForSlack } from "../slack/format.js";
import { findSecuritySkill, findSecuritySkillsInText, type SecuritySkill } from "../skills/security-skills.js";
import type { SecurityMemoryRecord } from "./memory-types.js";
import type { SecurityMemoryStore } from "./security-memory/index.js";

interface SelfRepairPrCreator {
  status(): Record<string, unknown>;
  createGithubPullRequest(input: RuntimeCodePrInput): Promise<Record<string, unknown>>;
}

interface SelfImprovementOptions {
  repairPrCreator?: SelfRepairPrCreator;
  improvement?: ImprovementSignalRecorder;
  now?: () => Date;
}

interface RepairSignal {
  skill: SecuritySkill;
  issueKind: string;
  issueLabel: string;
  input: SecurityAssistantInput;
  record?: SecurityMemoryRecord;
  answer?: SecurityAssistantAnswer;
  error?: string;
}

export class SelfImprovementService {
  private readonly repairPrCreator: SelfRepairPrCreator;
  private readonly improvement?: ImprovementSignalRecorder;
  private readonly now: () => Date;

  constructor(
    private readonly config: AppConfig,
    private readonly memory: SecurityMemoryStore,
    options: SelfImprovementOptions = {},
  ) {
    this.repairPrCreator = options.repairPrCreator ?? new RuntimeCodeWorkspace(config);
    this.improvement = options.improvement;
    this.now = options.now ?? (() => new Date());
  }

  async observeSlackAnswer(input: SecurityAssistantInput, answer: SecurityAssistantAnswer): Promise<void> {
    if (input.senderKind === "bot") return;
    const skills = skillsForQuestion(input.question);
    if (!answerNeedsImprovement(answer)) return;
    const issueKind = issueKindForAnswer(answer);
    await Promise.all(skills.map(async (skill) => {
      const record = await this.rememberImprovement({
        skill,
        topic: `${skill.title}: ${issueLabel(issueKind)}`,
        summary: `A Slack question for ${skill.title} did not produce a strong answer. Next time, inspect skill guidance, recall prior context, verify live state, and preserve a reviewable repair when the gap repeats.`,
        details: [
          `Question: ${input.question}`,
          `Execution lane: ${answer.executionLane ?? "unknown"}`,
          `Evidence items: ${answer.evidence.length}`,
          answer.research.length > 0 ? `Research: ${answer.research.join(" | ")}` : "",
          answer.nextActions.length > 0 ? `Next actions returned: ${answer.nextActions.join(" | ")}` : "",
        ].filter(Boolean).join("\n"),
        tags: ["answer-gap", issueKind],
        channelId: input.channelId,
        sourceTs: input.ts,
        confidence: 0.7,
      });
      if (this.improvement) {
        await this.improvement.observe(
          improvementSignal({ skill, issueKind, input, answer, now: this.now() }),
          improvementCandidate(this.config),
          improvementObserveOptions(input),
        );
        return;
      }
      await this.maybeOpenSelfRepairPr({
        skill,
        issueKind,
        issueLabel: issueLabel(issueKind),
        input,
        record,
        answer,
      });
    }));
  }

  async observeSlackFailure(input: SecurityAssistantInput, error: string): Promise<void> {
    if (input.senderKind === "bot") return;
    const skills = skillsForQuestion(input.question);
    const issueKind = issueKindForFailure(error);
    await Promise.all(skills.map(async (skill) => {
      const record = await this.rememberImprovement({
        skill,
        topic: `${skill.title}: ${issueLabel(issueKind)}`,
        summary: `Background work failed for a ${skill.title} question. Future runs should narrow the task, check self-context/tool status, verify live state, and preserve a reviewable code fix when the failure repeats.`,
        details: [
          `Question: ${input.question}`,
          `Failure: ${error}`,
        ].join("\n"),
        tags: ["failure", issueKind],
        channelId: input.channelId,
        sourceTs: input.ts,
        confidence: 0.8,
      });
      if (this.improvement) {
        await this.improvement.observe(
          improvementSignal({ skill, issueKind, input, error, now: this.now() }),
          improvementCandidate(this.config),
          improvementObserveOptions(input),
        );
        return;
      }
      await this.maybeOpenSelfRepairPr({
        skill,
        issueKind,
        issueLabel: issueLabel(issueKind),
        input,
        record,
        error,
      });
    }));
  }

  private async rememberImprovement(input: {
    skill: SecuritySkill;
    topic: string;
    summary: string;
    details?: string;
    tags?: string[];
    channelId?: string;
    sourceTs?: string;
    confidence: number;
  }): Promise<SecurityMemoryRecord | undefined> {
    return await this.memory.remember({
      kind: "skill_improvement",
      topic: input.topic,
      summary: trimForSlack(input.summary, 900),
      details: input.details ? trimForSlack(input.details, 1500) : undefined,
      tags: ["skill-improvement", input.skill.id, ...(input.tags ?? [])],
      channelId: input.channelId,
      sourceTs: input.sourceTs,
      classification: "procedural_learning",
      confidence: input.confidence,
      sourceKind: "tool",
    });
  }

  private async maybeOpenSelfRepairPr(signal: RepairSignal): Promise<void> {
    if (!this.config.selfRepair.enabled || !signal.record) return;
    const signature = repairSignature(signal.skill.id, signal.issueKind);
    const markerTag = repairMarkerTag(signature);
    if (await this.hasRecentRepairMarker(markerTag)) return;

    const matching = await this.recentMatchingImprovements(signal, markerTag);
    if (matching.length < this.config.selfRepair.threshold) return;

    const status = this.repairPrCreator.status();
    if (!this.config.selfRepair.createPr || status.github_pr_enabled !== true) {
      await this.rememberRepairMarker({
        signal,
        signature,
        markerTag,
        outcome: "pending",
        summary: "Self-repair detected a repeated gap, but GitHub PR creation is not configured.",
        details: `Runtime code status: ${JSON.stringify(status).slice(0, 800)}`,
      });
      return;
    }

    const prInput = selfRepairPrInput(signal, matching, signature, this.now());
    const result = await this.repairPrCreator.createGithubPullRequest(prInput);
    if (result.ok === true) {
      const pr = result.pull_request as { url?: string; number?: number } | undefined;
      await this.rememberRepairMarker({
        signal,
        signature,
        markerTag,
        outcome: "opened",
        summary: `Opened a draft self-repair PR for repeated ${signal.issueLabel.toLowerCase()} in ${signal.skill.title}.`,
        details: [
          pr?.url ? `PR: ${pr.url}` : "",
          `Repair packet: ${prInput.files[0]?.path}`,
          `Examples: ${matching.length}`,
        ].filter(Boolean).join("\n"),
      });
      return;
    }

    await this.rememberRepairMarker({
      signal,
      signature,
      markerTag,
      outcome: "failed",
      summary: "Self-repair detected a repeated gap, but draft PR creation failed.",
      details: JSON.stringify(result).slice(0, 1000),
    });
  }

  private async recentMatchingImprovements(signal: RepairSignal, markerTag: string): Promise<SecurityMemoryRecord[]> {
    const since = new Date(this.now().getTime() - this.config.selfRepair.lookbackHours * 3_600_000).toISOString();
    const recent = await this.memory.recall({
      kinds: ["skill_improvement"],
      since,
      limit: Math.max(this.config.selfRepair.threshold + 4, 6),
    });
    const byId = new Map<string, SecurityMemoryRecord>();
    for (const record of [signal.record, ...recent]) {
      if (!record) continue;
      if (record.tags.includes(signal.skill.id) && record.tags.includes(signal.issueKind) && !record.tags.includes(markerTag)) {
        byId.set(record.id, record);
      }
    }
    return [...byId.values()]
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, 6);
  }

  private async hasRecentRepairMarker(markerTag: string): Promise<boolean> {
    const since = new Date(this.now().getTime() - this.config.selfRepair.cooldownHours * 3_600_000).toISOString();
    const markers = await this.memory.recall({
      kinds: ["runbook_note"],
      query: markerTag,
      since,
      limit: 6,
    });
    return markers.some((record) => record.tags.includes("self-repair") && record.tags.includes(markerTag));
  }

  private async rememberRepairMarker(input: {
    signal: RepairSignal;
    signature: string;
    markerTag: string;
    outcome: "opened" | "pending" | "failed";
    summary: string;
    details?: string;
  }): Promise<void> {
    await this.memory.remember({
      kind: "runbook_note",
      topic: `Self-repair ${input.outcome}: ${input.signal.skill.title}`,
      summary: trimForSlack(input.summary, 900),
      details: trimForSlack([
        `Repair signature: ${input.signature}`,
        input.details ?? "",
      ].filter(Boolean).join("\n"), 1500),
      tags: ["self-repair", input.markerTag, input.signal.skill.id, input.signal.issueKind, input.outcome],
      channelId: input.signal.input.channelId,
      sourceTs: input.signal.input.ts,
      classification: "self_repair",
      confidence: 0.85,
      sourceKind: "tool",
      expiresAt: new Date(this.now().getTime() + this.config.selfRepair.cooldownHours * 3_600_000).toISOString(),
    });
  }
}

function skillsForQuestion(question: string): SecuritySkill[] {
  const matches = findSecuritySkillsInText(question);
  if (matches.length > 0) return matches.slice(0, 3);
  return [findSecuritySkill("self-improvement")].filter(Boolean) as SecuritySkill[];
}

function answerNeedsImprovement(answer: SecurityAssistantAnswer): boolean {
  const text = [answer.answer, ...answer.messages, ...answer.evidence, ...answer.actionsTaken].join(" ");
  if (/\bcould not\b|\bdid not return\b|\bnot complete\b|\bfailed\b|\bunavailable\b/i.test(text)) return true;
  if (answer.source === "blocked") return true;
  if (hasUnresolvedPartialToolFailure(answer)) return true;
  return false;
}

function issueKindForAnswer(answer: SecurityAssistantAnswer): string {
  const text = [answer.answer, ...answer.messages, ...answer.evidence, ...answer.actionsTaken, ...answer.research].join(" ");
  if (answer.source === "blocked" || /\bPi assistant is unavailable\b|\bblocked\b/i.test(text)) return "assistant-blocked";
  if (hasUnresolvedPartialToolFailure(answer)) return "partial-tool-failure";
  if (/\bstale\b|\blag\b|\bout of date\b|\blast sync\b|\bold\b/i.test(text)) return "stale-context";
  if (/\btimeout\b|\btimed out\b/i.test(text)) return "timeout";
  if (/\bfailed\b|\bunavailable\b|\bcould not\b|\bnot complete\b|\bdid not return\b/i.test(text)) return "tool-failure";
  if (answer.evidence.length === 0 && answer.research.some((item) => /\bfailed\b/i.test(item))) return "missing-evidence";
  return "answer-gap";
}

function hasUnresolvedPartialToolFailure(answer: SecurityAssistantAnswer): boolean {
  if (failedResearchToolNames(answer).length === 0) return false;
  const visible = [answer.answer, ...answer.messages].join(" ");
  const nextActions = answer.nextActions.join(" ");
  if (/\b(?:is|are|was|were)\s+(?:still\s+)?failing\b|\bno response\b|\brefused\b|\btransient error\b|\btemporarily unavailable\b/i.test(visible)) return true;
  if (/\bdid(?: not|n't|n’t)\s+(?:run|complete|confirm|verify|return|connect)\b/i.test(visible)) return true;
  if (/\b(?:re-?run|retry|try again)\b/i.test(nextActions)) return true;
  return /\b(?:re-?run|retry)\b.{0,120}\b(?:after|once|when)\b/i.test(visible);
}

function failedResearchToolNames(answer: SecurityAssistantAnswer): string[] {
  return [...new Set(answer.research.flatMap((item) => {
    const match = item.trim().match(/^([a-z][a-z0-9_.-]{1,159}):\s*failed$/i);
    return match?.[1] ? [match[1].toLowerCase()] : [];
  }))].sort();
}

function issueKindForFailure(error: string): string {
  if (/\bValidation error\b|\bBedrock\b|\bmodel\b|\bPi assistant\b/i.test(error)) return "pi-runtime";
  if (/\bstale\b|\blag\b|\bout of date\b|\blast sync\b/i.test(error)) return "stale-context";
  if (/\btimeout\b|\btimed out\b/i.test(error)) return "timeout";
  if (/\bunavailable\b|\bnot configured\b|\bmissing\b/i.test(error)) return "tool-unavailable";
  return "background-failure";
}

function issueLabel(issueKind: string): string {
  return issueKind
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function repairSignature(skillId: string, issueKind: string, detail?: string): string {
  const base = `self-repair:${skillId}:${issueKind}`;
  return detail ? `${base}:${shortHash(detail)}` : base;
}

function repairMarkerTag(signature: string): string {
  return `repair-${shortHash(signature)}`;
}

function selfRepairPrInput(signal: RepairSignal, matching: SecurityMemoryRecord[], signature: string, now: Date): RuntimeCodePrInput {
  const path = [
    "docs/self-repair",
    `${dateStamp(now)}-${slug(signal.skill.id)}-${slug(signal.issueKind)}-${shortHash(signature)}.md`,
  ].join("/");
  const title = `Self-repair: ${signal.skill.title} ${signal.issueLabel}`;
  const content = selfRepairPacket(signal, matching, signature, now);
  return {
    title,
    body: [
      "Draft self-repair packet opened from repeated Slack answer gaps.",
      "",
      "This PR is a review surface. It does not merge, deploy, change production config, expose secrets, or mutate the Cerebro graph.",
      "",
      "Operator path:",
      "- Confirm the failure is real.",
      "- Add or adjust a regression eval.",
      "- Patch code, prompt, tool, or runbook behavior.",
      "- Run `npm run typecheck` and `npm test`.",
      "- Merge and deploy through the reviewed path.",
    ].join("\n"),
    files: [{ path, content }],
    draft: true,
  };
}

function improvementSignal(input: {
  skill: SecuritySkill;
  issueKind: string;
  input: SecurityAssistantInput;
  answer?: SecurityAssistantAnswer;
  error?: string;
  now: Date;
}): ImprovementSignal {
  const toolNames = input.answer && input.issueKind === "partial-tool-failure"
    ? failedResearchToolNames(input.answer)
    : [];
  return {
    signature: repairSignature(input.skill.id, input.issueKind, toolNames.join("|") || undefined),
    source: input.error ? "runtime_failure" : "answer_gap",
    issueKind: input.issueKind,
    skillId: input.skill.id,
    occurredAt: input.now.toISOString(),
    channelHash: hashIdentifier(input.input.channelId),
    answerHash: hashIdentifier(input.input.ts),
    question: input.input.question,
    answer: input.answer ? [input.answer.answer, ...input.answer.messages].join("\n") : input.error,
    executionLane: input.answer?.executionLane,
    answerSource: input.answer?.source,
    evidenceCount: input.answer?.evidence.length ?? 0,
    actionCount: input.answer?.actionsTaken.length ?? 0,
    toolNames,
    commitmentStates: input.answer?.teammate?.commitments.map((item) => item.status) ?? [],
  };
}

function improvementCandidate(config: AppConfig): ImprovementCandidate {
  return {
    repo: config.code.defaultRepo,
    baseRef: "main",
  };
}

function improvementObserveOptions(input: SecurityAssistantInput): ImprovementObserveOptions | undefined {
  if (!input.userId) return undefined;
  return {
    humanAssistance: {
      channelId: input.channelId,
      intendedUserId: input.userId,
    },
  };
}

function selfRepairPacket(signal: RepairSignal, matching: SecurityMemoryRecord[], signature: string, now: Date): string {
  const evidence = matching.map((record, index) => [
    `${index + 1}. ${record.createdAt} - ${record.topic}`,
    `   Summary: ${record.summary}`,
    record.details ? `   Details: ${record.details.replace(/\n/g, "\n   ")}` : "",
  ].filter(Boolean).join("\n")).join("\n\n");

  return [
    `# Self-Repair Packet: ${signal.skill.title} ${signal.issueLabel}`,
    "",
    `Created: ${now.toISOString()}`,
    `Repair signature: \`${signature}\``,
    `Source channel: ${signal.input.channelId ?? "unknown"}`,
    `Source message ts: ${signal.input.ts}`,
    "",
    "## Trigger",
    "",
    `Cerebro saw ${matching.length} recent self-improvement records for this same skill and issue type.`,
    "",
    "## Latest Question",
    "",
    signal.input.question,
    "",
    "## Expected Behavior",
    "",
    "- Answer through the Pi assistant work loop for Slack assistant questions.",
    "- Verify live context before making present-tense security or runtime claims.",
    "- Name stale, partial, or blocked context instead of filling gaps.",
    "- Keep self-repair reviewable: PRs and operator approval before merge or deploy.",
    "",
    "## Recent Evidence",
    "",
    evidence || "No matching examples were available.",
    "",
    "## Suggested Repair Plan",
    "",
    "1. Reproduce the behavior with a Slack eval or unit test.",
    "2. Add or update the smallest regression test that catches the bad behavior.",
    "3. Patch the relevant prompt, skill, tool, or code path.",
    "4. Run `npm run typecheck` and `npm test`.",
    "5. Leave merge and deploy to the reviewed operator path.",
    "",
    "## Review Boundary",
    "",
    "This packet is a repair request, not a production change. It must not expose secrets, bypass review, merge itself, deploy itself, mutate graph state, or change AWS/Pulumi state directly.",
    "",
  ].join("\n");
}

function dateStamp(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "repair";
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 8);
}

function hashIdentifier(value: string | undefined): string | undefined {
  return value ? createHash("sha256").update(value).digest("hex").slice(0, 16) : undefined;
}

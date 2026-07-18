import type { ProactiveSlackChannelPolicy } from "../config/index.js";
import { trimForSlack } from "../slack/format.js";
import type { AlertTriageInput, AlertTriageResult } from "./alert-triage-types.js";

export interface ProactiveMonitorSuggestionDraft {
  title: string;
  description: string;
  scheduleText: string;
  dedupKey: string;
}

export function monitorSuggestionFor(
  input: AlertTriageInput,
  result: AlertTriageResult,
  policy: ProactiveSlackChannelPolicy,
): ProactiveMonitorSuggestionDraft | undefined {
  if (policy === "strict") return undefined;
  if (result.classification === "likely_noise") return undefined;
  if (result.confidence < 0.55) return undefined;
  const haystack = [
    input.text,
    result.topic ?? "",
    result.summary,
    ...result.evidence,
    ...result.recommendedActions,
  ].join("\n");
  const kind = monitorKind(haystack);
  if (!kind) return undefined;
  const threadTs = input.threadTs ?? input.ts;
  const subject = subjectFor(haystack, kind);
  const title = kind === "deploy"
    ? `Watch ${subject} rollout`
    : kind === "ci"
      ? `Watch ${subject} checks`
      : kind === "runtime"
        ? `Watch ${subject} runtime`
        : `Watch ${subject} finding`;
  const description = trimForSlack(`Create a short-lived scheduled check for this thread and post only when the status changes or a blocker appears.`, 240);
  const scheduleText = [
    "Every 30 minutes for 4 hours, check this Slack thread and related Cerebro or GitHub status.",
    `Slack channel: ${input.channelId}. Slack thread: ${threadTs}.`,
    `Subject: ${subject}.`,
    `Context: ${trimForSlack(result.summary, 360)}`,
    "Post only if there is a status change, a failed check, a deployment blocker, a runtime health regression, or a finding state change.",
  ].join(" ");
  return {
    title,
    description,
    scheduleText,
    dedupKey: `${kind}:${input.channelId}:${threadTs}:${subject.toLowerCase()}`,
  };
}

function monitorKind(text: string): "deploy" | "ci" | "runtime" | "finding" | undefined {
  if (/\b(deploy|deployment|rollout|rollback|image tag|task definition|release)\b/i.test(text)) return "deploy";
  if (/\b(ci|check run|checks?|job failed|test failed|pull request|pr #?\d+)\b/i.test(text)) return "ci";
  if (/\b(runtime|source runtime|sync failed|ingest|evaluation|health)\b/i.test(text)) return "runtime";
  if (/\b(finding|false positive|suppression|severity|evidence)\b/i.test(text)) return "finding";
  return undefined;
}

function subjectFor(text: string, kind: string): string {
  const pr = text.match(/\b(?:PR|pr|pull request)\s*#?(\d+)\b/);
  if (pr?.[1]) return `PR #${pr[1]}`;
  const version = text.match(/\bv?\d+\.\d+\.\d+(?:[-+][a-z0-9_.-]+)?\b/i);
  if (version) return version[0];
  const finding = text.match(/\bfinding[-_:\s]+([a-z0-9._-]+)\b/i);
  if (finding?.[1]) return `finding ${finding[1]}`;
  const runtime = text.match(/\b(?:runtime|source runtime)[:\s]+([a-z0-9._/-]+)\b/i);
  if (runtime?.[1]) return runtime[1];
  return kind;
}

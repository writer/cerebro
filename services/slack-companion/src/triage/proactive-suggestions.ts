import type { AppConfig, ProactiveSlackChannelPolicy } from "../config/index.js";
import { trimForSlack } from "../slack/format.js";
import { hasSpecificText } from "./alert-triage-signals.js";
import type { AlertTriageInput, AlertTriageResult } from "./alert-triage-types.js";
import { minimumConfidenceForPolicy } from "./channel-policy.js";
import { hasVerifiedTriageBasis } from "./alert-triage-response.js";

export interface ProactiveSuggestionDraft {
  title: string;
  description: string;
  goalText: string;
  dedupKey: string;
}

export function proactiveSuggestionFor(
  config: AppConfig,
  input: AlertTriageInput,
  result: AlertTriageResult,
  policy: ProactiveSlackChannelPolicy,
): ProactiveSuggestionDraft | undefined {
  if (!shouldPostProactiveSuggestion(config, result, policy)) return undefined;
  const haystack = [input.text, result.topic ?? "", result.summary, ...result.evidence, ...result.recommendedActions].join("\n");
  const kind = suggestionKind(haystack);
  const action = firstConcreteAction(result);
  if (!kind || !action) return undefined;
  const threadTs = input.threadTs ?? input.ts;
  const subject = subjectFor(haystack, kind);
  const title = titleFor(kind, subject);
  const description = trimForSlack(action, 240);
  const goalText = [
    `${title}.`,
    `Slack channel: ${input.channelId}. Slack thread: ${threadTs}.`,
    `Context: ${trimForSlack(result.summary, 360)}`,
    `Suggested action: ${trimForSlack(action, 360)}`,
    result.evidence.length > 0 ? `Evidence: ${trimForSlack(result.evidence.slice(0, 3).join(" | "), 500)}` : "",
  ].filter(Boolean).join(" ");
  return {
    title,
    description,
    goalText,
    dedupKey: `${kind}:${input.channelId}:${threadTs}:${subject.toLowerCase()}:${action.toLowerCase()}`,
  };
}

export function shouldPostProactiveSuggestion(
  config: AppConfig,
  result: AlertTriageResult,
  policy: ProactiveSlackChannelPolicy,
): boolean {
  if (!config.slack.triageAutoReply) return false;
  if (!config.autonomy.goalsEnabled) return false;
  if (policy === "strict") return false;
  if (result.classification === "likely_noise") return false;
  if (result.confidence < Math.max(0.65, minimumConfidenceForPolicy(config, policy))) return false;
  if (!hasVerifiedTriageBasis(result)) return false;
  return hasSpecificText(result.evidence) && hasSpecificText(result.recommendedActions);
}

function firstConcreteAction(result: AlertTriageResult): string | undefined {
  return result.recommendedActions.find((item) => hasSpecificText([item]));
}

function suggestionKind(text: string): "release" | "runtime" | "finding" | "source" | "investigation" | undefined {
  if (/\b(deploy|deployment|rollout|rollback|image tag|task definition|release|pull request|pr #?\d+|ci|check run|job failed|test failed)\b/i.test(text)) return "release";
  if (/\b(runtime|source runtime|sync failed|ingest|evaluation|health|regression)\b/i.test(text)) return "runtime";
  if (/\b(finding|false positive|suppression|severity|evidence|exception)\b/i.test(text)) return "finding";
  if (/\b(source|connector|integration|api|kandji|iru|panther|wiz|okta|github)\b/i.test(text)) return "source";
  if (/\b(owner|approval|access|credential|token|secret|admin|permission|policy)\b/i.test(text)) return "investigation";
  return undefined;
}

function titleFor(kind: ReturnType<typeof suggestionKind> & string, subject: string): string {
  if (kind === "release") return `Close the loop on ${subject}`;
  if (kind === "runtime") return `Investigate ${subject} runtime`;
  if (kind === "finding") return `Review ${subject} finding`;
  if (kind === "source") return `Investigate ${subject} source`;
  return `Investigate ${subject}`;
}

function subjectFor(text: string, kind: string): string {
  const pr = text.match(/\b(?:PR|pr|pull request)\s*#?(\d+)\b/);
  if (pr?.[1]) return `PR #${pr[1]}`;
  const finding = text.match(/\bfinding[-_:\s]+([a-z0-9._-]+)\b/i);
  if (finding?.[1]) return `finding ${finding[1]}`;
  const runtime = text.match(/\b(?:runtime|source runtime)[:\s]+([a-z0-9._/-]+)\b/i);
  if (runtime?.[1]) return runtime[1];
  const source = text.match(/\b(?:source|connector|integration)[:\s]+([a-z0-9._/-]+)\b/i);
  if (source?.[1]) return source[1];
  return kind;
}

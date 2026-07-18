import type { AutonomousGoalRecord } from "./goals.js";

export interface GithubMonitorTarget {
  kind: "pull_request" | "ref";
  source: "artifact_url" | "mission_binding" | "objective";
  repo?: string;
  pullNumber?: number;
  ref?: string;
}

export type GithubMonitorDecisionState = "passed" | "pending" | "failed" | "merged" | "unknown";

export interface GithubMonitorDecision {
  state: GithubMonitorDecisionState;
  summary: string;
  passed: number;
  pending: number;
  failed: number;
}

export function githubMonitorTarget(goal: Pick<AutonomousGoalRecord, "objective" | "artifactUrls" | "mission">): GithubMonitorTarget | undefined {
  for (const artifactUrl of goal.artifactUrls) {
    const target = targetFromText(artifactUrl, "artifact_url");
    if (target) return target;
  }
  const pullRequest = goal.mission?.bindings.find((binding) => binding.id === "pull_request")?.value;
  if (pullRequest) {
    const repository = goal.mission?.bindings.find((binding) => binding.id === "repository")?.value;
    const pullNumber = Number(pullRequest.match(/(?:\/pull\/|#)?(\d+)$/)?.[1] ?? pullRequest);
    if (Number.isInteger(pullNumber) && pullNumber > 0) {
      return { kind: "pull_request", source: "mission_binding", repo: repository, pullNumber };
    }
  }
  return targetFromText(goal.objective, "objective");
}

export function githubMonitorDecision(result: Record<string, unknown>): GithubMonitorDecision {
  const pullRequest = objectValue(result.pull_request);
  if (pullRequest && pullRequest.merged === true) {
    return {
      state: "merged",
      summary: `Pull request #${numberValue(pullRequest.number) ?? "unknown"} is merged.`,
      passed: 0,
      pending: 0,
      failed: 0,
    };
  }

  const checks = objectValue(result.checks);
  const summary = objectValue(checks?.summary) ?? objectValue(result.summary);
  const rawState = stringValue(summary?.state);
  const passed = numberValue(summary?.passed) ?? 0;
  const pending = numberValue(summary?.pending) ?? 0;
  const failed = numberValue(summary?.failed) ?? 0;

  if (failed > 0 || rawState === "failed" || rawState === "failure" || rawState === "error") {
    return { state: "failed", summary: `Checks failed: ${failed} failed, ${pending} pending, ${passed} passed.`, passed, pending, failed };
  }
  if (pending > 0 || rawState === "pending") {
    return { state: "pending", summary: `Checks pending: ${pending} pending, ${passed} passed.`, passed, pending, failed };
  }
  if (passed > 0 || rawState === "passed" || rawState === "success") {
    return { state: "passed", summary: `Checks passed: ${passed} passed.`, passed, pending, failed };
  }
  return { state: "unknown", summary: "No completed check state is available yet.", passed, pending, failed };
}

export function githubMonitorTargetLabel(target: GithubMonitorTarget): string {
  if (target.kind === "pull_request") {
    const repo = target.repo ? `${target.repo} ` : "";
    return `${repo}PR #${target.pullNumber ?? "unknown"}`.trim();
  }
  return target.repo ? `${target.repo}@${target.ref}` : String(target.ref ?? "unknown ref");
}

function targetFromText(text: string, source: GithubMonitorTarget["source"]): GithubMonitorTarget | undefined {
  const normalized = text.trim();
  if (!normalized) return undefined;

  const pullUrl = normalized.match(/github\.com\/([^/\s]+\/[^/\s]+)\/pull\/(\d+)/i);
  if (pullUrl) {
    return {
      kind: "pull_request",
      source,
      repo: pullUrl[1],
      pullNumber: Number(pullUrl[2]),
    };
  }

  const prMention = normalized.match(/\b(?:pr|pull request)\s*#?(\d+)\b/i);
  if (prMention) {
    return {
      kind: "pull_request",
      source,
      pullNumber: Number(prMention[1]),
    };
  }

  const refUrl = normalized.match(/github\.com\/([^/\s]+\/[^/\s]+)\/(?:commit|tree)\/([A-Za-z0-9._/-]+)/i);
  if (refUrl) {
    return {
      kind: "ref",
      source,
      repo: refUrl[1],
      ref: refUrl[2],
    };
  }

  const explicitRef = normalized.match(/\b(?:sha|commit|branch|ref)\s+([A-Za-z0-9._/-]{4,80})\b/i);
  if (explicitRef) {
    return {
      kind: "ref",
      source,
      ref: explicitRef[1],
    };
  }

  return undefined;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

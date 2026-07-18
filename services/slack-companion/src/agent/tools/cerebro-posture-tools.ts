import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { Finding } from "../../cerebro/types.js";
import type { AppConfig } from "../../config/index.js";
import { compareScaryFindings, findingSummary } from "./cerebro-finding-summary.js";
import { limit, shortError, unique } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult } from "./tool-result.js";

export function createCerebroPostureTools(deps: SecurityToolDeps): AgentTool[] {
  const postureParams = Type.Object({
    domain: Type.String(),
    question: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    limit: Type.Optional(Type.Number()),
  });
  const recentScaryFindingsParams = Type.Object({
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    since: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });

  return [
    {
      name: "cerebro_security_posture",
      label: "Cerebro security posture",
      description: "Build a compact posture summary for a security domain by checking relevant runtime health, open findings, memory, and graph reasoning.",
      parameters: postureParams,
      execute: async (_toolCallId, params) => {
        const args = params as { domain: string; question?: string; runtime_ids?: string[]; limit?: number };
        return safeToolResult(async () => postureSummary(deps, {
          domain: args.domain,
          question: args.question,
          runtimeIds: args.runtime_ids,
          limit: limit(args.limit, 5),
        }));
      },
    },
    {
      name: "cerebro_recent_scary_findings",
      label: "Cerebro recent scary findings",
      description: "Rank newest high-risk open findings across configured security runtimes. Use for questions about newest findings, scariest findings, top risk today, or what needs attention now.",
      parameters: recentScaryFindingsParams,
      execute: async (_toolCallId, params) => {
        const args = params as { runtime_ids?: string[]; since?: string; limit?: number };
        return safeToolResult(async () => recentScaryFindings(deps, {
          runtimeIds: args.runtime_ids,
          since: args.since,
          limit: limit(args.limit, 5),
        }));
      },
    },
  ];
}

async function postureSummary(deps: SecurityToolDeps, input: {
  domain: string;
  question?: string;
  runtimeIds?: string[];
  limit: number;
}) {
  const runtimeIds = unique(input.runtimeIds?.length ? input.runtimeIds : runtimesForDomain(deps.config, input.domain));
  const memoryQuery = [input.domain, input.question].filter(Boolean).join(" ");
  const [memories, health, findings, graph] = await Promise.all([
    deps.memory.search(memoryQuery, deps.config.learning.maxSearchResults).catch((error) => ({ error: shortError(error) })),
    deps.cerebro.listRuntimeHealth({ runtimeIds, limit: runtimeIds.length || 20 }).catch((error) => ({ error: shortError(error) })),
    Promise.all(runtimeIds.map(async (runtimeId) => ({
      runtime_id: runtimeId,
      findings: await deps.cerebro.listFindings(runtimeId, { limit: input.limit }).catch((error) => ({ error: shortError(error) })),
    }))),
    input.question
      ? deps.cerebro.reasonGraph({ question: input.question }).catch((error) => ({ error: shortError(error) }))
      : Promise.resolve(undefined),
  ]);
  return {
    domain: input.domain,
    question: input.question,
    runtime_ids: runtimeIds,
    memory: memories,
    runtime_health: health,
    open_findings: findings,
    graph_reasoning: graph,
    note: runtimeIds.length > 0
      ? "Use this as a posture packet. Name missing sources and avoid declaring a domain healthy from health checks alone."
      : "No matching runtime IDs were configured for this domain. Use graph reasoning and explain the coverage gap.",
  };
}

export async function recentScaryFindings(deps: SecurityToolDeps, input: {
  runtimeIds?: string[];
  since?: string;
  limit: number;
}) {
  const runtimeIds = unique(input.runtimeIds?.length ? input.runtimeIds : deps.config.cerebro.defaultRuntimeIds);
  const timeZone = deps.config.learning.dailyNotesTimeZone || "America/Los_Angeles";
  const since = parseSince(input.since) ?? startOfTodayInTimeZone(timeZone);
  const perRuntimeLimit = Math.max(5, Math.min(25, input.limit * 3));
  const checked = await Promise.all(runtimeIds.map(async (runtimeId) => {
    try {
      return {
        runtime_id: runtimeId,
        findings: await deps.cerebro.listFindings(runtimeId, {
          status: "open",
          order: "last_observed",
          limit: perRuntimeLimit,
        }),
      };
    } catch (error) {
      return { runtime_id: runtimeId, error: shortError(error), findings: [] as Finding[] };
    }
  }));

  const allFindings = checked.flatMap((runtime) => runtime.findings.map((finding) => findingSummary(deps.config, runtime.runtime_id, finding)));
  const todayFindings = allFindings.filter((finding) => finding.observed_at_ms !== undefined && finding.observed_at_ms >= since.getTime());
  const ranked = (todayFindings.length > 0 ? todayFindings : allFindings)
    .sort(compareScaryFindings)
    .slice(0, input.limit);
  const failures = checked.flatMap((runtime) => runtime.error ? [{ runtime_id: runtime.runtime_id, error: runtime.error }] : []);

  return {
    since: since.toISOString(),
    time_zone: timeZone,
    checked_runtime_ids: runtimeIds,
    returned: ranked.length,
    findings: ranked.map(({ observed_at_ms: _observedAtMs, scare_score: _scareScore, ...finding }) => finding),
    failures,
    note: todayFindings.length > 0
      ? "Findings are open and observed since the start of today in the configured timezone, ranked by severity, risk score, and recency."
      : "No returned finding had a last observed timestamp since the start of today. Showing the newest high-risk open findings returned by Cerebro instead.",
  };
}

function parseSince(value: string | undefined): Date | undefined {
  if (!value?.trim()) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function startOfTodayInTimeZone(timeZone: string): Date {
  const parts = dateTimeParts(new Date(), timeZone);
  const targetUtc = Date.UTC(parts.year, parts.month - 1, parts.day, 0, 0, 0);
  const targetAsZoned = dateTimeParts(new Date(targetUtc), timeZone);
  const zonedUtc = Date.UTC(targetAsZoned.year, targetAsZoned.month - 1, targetAsZoned.day, targetAsZoned.hour, targetAsZoned.minute, targetAsZoned.second);
  return new Date(targetUtc - (zonedUtc - targetUtc));
}

function dateTimeParts(date: Date, timeZone: string) {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const entries = formatter.formatToParts(date).map((part) => [part.type, part.value]);
  const parts = Object.fromEntries(entries);
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second),
  };
}

function runtimesForDomain(config: AppConfig, domain: string): string[] {
  const normalized = domain.toLowerCase();
  const defaults = config.cerebro.defaultRuntimeIds;
  const preferred = defaults.filter((runtimeId) => {
    const runtime = runtimeId.toLowerCase();
    if (/(login|identity|sso|mfa|okta|authn|authz|access)/.test(normalized)) {
      return /(okta|github|slack|identity|iam)/.test(runtime);
    }
    if (/(github|repo|code|supply|dependency)/.test(normalized)) {
      return /(github|repo|code|supply)/.test(runtime);
    }
    if (/(slack|app|linear|workspace|collaboration)/.test(normalized)) {
      return /(slack|tooling|map|cas|github|okta)/.test(runtime);
    }
    return runtime.includes(normalized);
  });
  return preferred.length > 0 ? preferred : defaults;
}

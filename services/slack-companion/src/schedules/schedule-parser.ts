import { findSecuritySkill, skillPrompt, type SecuritySkillStep } from "../skills/security-skills.js";

export type ScheduledJobStatus = "active" | "paused" | "completed" | "blocked";
export type ScheduledContextProviderId = "runtime_health_snapshot" | "open_findings_snapshot" | "companion_self_context";

export interface ScheduledContextProviderDefinition {
  id: ScheduledContextProviderId;
  title: string;
  summary: string;
  aliases: string[];
}

export const SCHEDULE_CONTEXT_PROVIDERS: ScheduledContextProviderDefinition[] = [
  {
    id: "runtime_health_snapshot",
    title: "Runtime health snapshot",
    summary: "Reads source runtime health before a scheduled check starts.",
    aliases: ["runtime-health", "health", "source-health", "sync-status", "ingest-status"],
  },
  {
    id: "open_findings_snapshot",
    title: "Open findings snapshot",
    summary: "Reads a small open-finding sample across configured runtimes before a scheduled check starts.",
    aliases: ["open-findings", "findings", "scary-findings", "risk-backlog", "finding-counts"],
  },
  {
    id: "companion_self_context",
    title: "Companion self context",
    summary: "Reads sanitized Slack companion configuration, commands, skills, storage modes, and debug gaps.",
    aliases: ["self-context", "companion-context", "cerebro-self", "debug-context", "commands"],
  },
];

export type ScheduleCadence =
  | { kind: "once"; runAt: string; timeZone: string }
  | { kind: "interval"; everyMs: number; timeZone: string }
  | { kind: "daily"; timeOfDay: TimeOfDay; timeZone: string }
  | { kind: "weekdays"; timeOfDay: TimeOfDay; timeZone: string }
  | { kind: "weekly"; daysOfWeek: number[]; timeOfDay: TimeOfDay; timeZone: string };

export type ScheduleTrigger =
  | { type: "runtime_health"; runtimeId: string; unhealthyOnly: boolean; cooldownMs: number }
  | { type: "findings_threshold"; runtimeIds: string[]; threshold: number; cooldownMs: number };

export interface TimeOfDay {
  hour: number;
  minute: number;
}

export interface ScheduledJobDraft {
  description: string;
  schedule?: ScheduleCadence;
  trigger?: ScheduleTrigger;
  steps: SecuritySkillStep[];
  contextProviders: ScheduledContextProviderId[];
  channelId?: string;
  nextRunAt?: string;
  warnings: string[];
}

export interface SchedulePlanStep {
  id?: string;
  title?: string;
  skillId?: string;
  prompt?: string;
  dependsOn?: string[];
}

export interface SchedulePlan {
  description: string;
  schedule?: ScheduleCadence;
  trigger?: ScheduleTrigger;
  steps: SchedulePlanStep[];
  contextProviders?: string[];
  channelId?: string;
  warnings?: string[];
}

export interface FinalizeSchedulePlanOptions {
  now?: Date;
  timeZone: string;
  defaultChannelId?: string;
  defaultRuntimeIds: string[];
  sourceText?: string;
}

const DEFAULT_TRIGGER_COOLDOWN_MS = 60 * 60 * 1000;

export function finalizeSchedulePlan(plan: SchedulePlan, options: FinalizeSchedulePlanOptions): ScheduledJobDraft {
  const now = options.now ?? new Date();
  const description = cleanInline(plan.description) ?? cleanInline(options.sourceText) ?? "Scheduled check";
  const schedule = normalizeSchedule(plan.schedule, options.timeZone, now);
  const trigger = normalizeTrigger(plan.trigger, options.defaultRuntimeIds);
  if (!schedule && !trigger) {
    throw new Error("Planner did not return a schedule or trigger.");
  }
  const context = normalizeContextProviders(plan.contextProviders);

  return {
    description: description.slice(0, 180),
    schedule,
    trigger,
    steps: normalizeSteps(plan.steps, options.sourceText ?? description),
    contextProviders: context.providers,
    channelId: cleanChannelId(plan.channelId) ?? options.defaultChannelId,
    nextRunAt: nextRunAtFor(schedule, now),
    warnings: unique([
      ...(plan.warnings ?? []).map((item) => cleanInline(item)).filter(isString),
      ...context.warnings,
    ]),
  };
}

export function nextRunAtFor(schedule: ScheduleCadence | undefined, now = new Date()): string | undefined {
  if (!schedule) return undefined;
  switch (schedule.kind) {
    case "once":
      return schedule.runAt;
    case "interval":
      return new Date(now.getTime() + schedule.everyMs).toISOString();
    case "daily":
      return nextLocalTime(schedule.timeZone, schedule.timeOfDay, now).toISOString();
    case "weekdays":
      return nextLocalTime(schedule.timeZone, schedule.timeOfDay, now, [1, 2, 3, 4, 5]).toISOString();
    case "weekly":
      return nextLocalTime(schedule.timeZone, schedule.timeOfDay, now, schedule.daysOfWeek).toISOString();
  }
}

export function scheduleSummary(schedule: ScheduleCadence | undefined): string {
  if (!schedule) return "No time schedule";
  switch (schedule.kind) {
    case "once":
      return `Once at ${schedule.runAt}`;
    case "interval":
      return `Every ${durationLabel(schedule.everyMs)}`;
    case "daily":
      return `Daily at ${formatTimeOfDay(schedule.timeOfDay)} ${schedule.timeZone}`;
    case "weekdays":
      return `Weekdays at ${formatTimeOfDay(schedule.timeOfDay)} ${schedule.timeZone}`;
    case "weekly":
      return `Weekly on ${schedule.daysOfWeek.map(dayLabel).join(", ")} at ${formatTimeOfDay(schedule.timeOfDay)} ${schedule.timeZone}`;
  }
}

export function triggerSummary(trigger: ScheduleTrigger | undefined): string {
  if (!trigger) return "No trigger";
  if (trigger.type === "runtime_health") {
    return `When ${trigger.runtimeId} is unhealthy`;
  }
  return `When open findings exceed ${trigger.threshold} across ${trigger.runtimeIds.join(", ")}`;
}

export function contextProviderSummary(contextProviders: ScheduledContextProviderId[] | undefined): string {
  const providers = contextProviders ?? [];
  if (providers.length === 0) return "No pre-run context providers";
  return providers.map((id) => SCHEDULE_CONTEXT_PROVIDERS.find((provider) => provider.id === id)?.title ?? id).join(", ");
}

export function normalizeContextProviderIds(values: unknown): ScheduledContextProviderId[] {
  if (!Array.isArray(values)) return [];
  return normalizeContextProviders(values.map(String)).providers;
}

export function isScheduledContextProviderId(value: string): value is ScheduledContextProviderId {
  return SCHEDULE_CONTEXT_PROVIDERS.some((provider) => provider.id === value);
}

function normalizeSchedule(schedule: ScheduleCadence | undefined, defaultTimeZone: string, now: Date): ScheduleCadence | undefined {
  if (!schedule) return undefined;
  const timeZone = cleanInline(schedule.timeZone) ?? defaultTimeZone;
  switch (schedule.kind) {
    case "once": {
      const runAtMs = Date.parse(schedule.runAt);
      if (!Number.isFinite(runAtMs)) {
        throw new Error("Planner returned an invalid one-time run date.");
      }
      if (runAtMs <= now.getTime()) {
        throw new Error("Planner returned a one-time run date in the past.");
      }
      return { kind: "once", runAt: new Date(runAtMs).toISOString(), timeZone };
    }
    case "interval": {
      const everyMs = Math.round(schedule.everyMs);
      if (!Number.isFinite(everyMs) || everyMs <= 0) {
        throw new Error("Planner returned an invalid interval.");
      }
      return { kind: "interval", everyMs, timeZone };
    }
    case "daily":
      return { kind: "daily", timeOfDay: normalizeTimeOfDay(schedule.timeOfDay), timeZone };
    case "weekdays":
      return { kind: "weekdays", timeOfDay: normalizeTimeOfDay(schedule.timeOfDay), timeZone };
    case "weekly": {
      const daysOfWeek = unique(schedule.daysOfWeek.map((day) => Math.trunc(day)).filter((day) => day >= 0 && day <= 6)).sort();
      if (daysOfWeek.length === 0) {
        throw new Error("Planner returned a weekly schedule without valid days.");
      }
      return { kind: "weekly", daysOfWeek, timeOfDay: normalizeTimeOfDay(schedule.timeOfDay), timeZone };
    }
  }
}

function normalizeTrigger(trigger: ScheduleTrigger | undefined, defaultRuntimeIds: string[]): ScheduleTrigger | undefined {
  if (!trigger) return undefined;
  switch (trigger.type) {
    case "runtime_health": {
      const runtimeId = cleanInline(trigger.runtimeId) ?? defaultRuntimeIds[0];
      if (!runtimeId) {
        throw new Error("Planner returned a runtime-health trigger without a runtime id.");
      }
      return {
        type: "runtime_health",
        runtimeId,
        unhealthyOnly: trigger.unhealthyOnly !== false,
        cooldownMs: positiveMs(trigger.cooldownMs, DEFAULT_TRIGGER_COOLDOWN_MS),
      };
    }
    case "findings_threshold": {
      const runtimeIds = unique((trigger.runtimeIds.length > 0 ? trigger.runtimeIds : defaultRuntimeIds).map((item) => cleanInline(item)).filter(isString));
      if (runtimeIds.length === 0) {
        throw new Error("Planner returned a findings trigger without runtime ids.");
      }
      const threshold = Math.trunc(trigger.threshold);
      if (!Number.isFinite(threshold) || threshold < 1) {
        throw new Error("Planner returned an invalid findings threshold.");
      }
      return {
        type: "findings_threshold",
        runtimeIds,
        threshold,
        cooldownMs: positiveMs(trigger.cooldownMs, DEFAULT_TRIGGER_COOLDOWN_MS),
      };
    }
  }
}

function normalizeSteps(rawSteps: SchedulePlanStep[] | undefined, sourceText: string): SecuritySkillStep[] {
  const plannedSteps = rawSteps?.length ? rawSteps : [{ title: "Scheduled check", prompt: sourceText }];
  const usedIds = new Set<string>();
  const idMap = new Map<string, string>();
  const interim = plannedSteps.map((step, index) => {
    const requestedId = cleanStepId(step.id) ?? `step-${index + 1}`;
    const id = uniqueStepId(requestedId, usedIds);
    if (step.id) idMap.set(step.id, id);
    idMap.set(requestedId, id);

    const skill = findSecuritySkill(step.skillId) ?? findSecuritySkill(step.title);
    const details = cleanBlock(step.prompt) ?? cleanInline(step.title) ?? sourceText;
    const title = cleanInline(step.title) ?? skill?.title ?? titleFromText(details);
    return {
      id,
      title,
      skillId: skill?.id,
      prompt: skill ? skillPrompt(skill, details) : customPrompt(details),
      rawDependsOn: step.dependsOn ?? [],
    };
  });

  return interim.map((step) => {
    const dependsOn = unique(step.rawDependsOn
      .map((rawId) => idMap.get(rawId) ?? cleanStepId(rawId))
      .filter((id): id is string => typeof id === "string" && usedIds.has(id) && id !== step.id));
    return {
      id: step.id,
      title: step.title,
      skillId: step.skillId,
      prompt: step.prompt,
      dependsOn,
    };
  });
}

function normalizeContextProviders(values: string[] | undefined): { providers: ScheduledContextProviderId[]; warnings: string[] } {
  const providers: ScheduledContextProviderId[] = [];
  const warnings: string[] = [];
  for (const value of values ?? []) {
    const provider = normalizeContextProvider(value);
    if (!provider) {
      const label = cleanInline(value);
      if (label) warnings.push(`Ignored unknown pre-run context provider: ${label}.`);
      continue;
    }
    if (!providers.includes(provider)) providers.push(provider);
  }
  return { providers, warnings };
}

function normalizeContextProvider(value: string): ScheduledContextProviderId | undefined {
  const key = cleanStepId(value);
  if (!key) return undefined;
  for (const provider of SCHEDULE_CONTEXT_PROVIDERS) {
    if (key === cleanStepId(provider.id) || provider.aliases.some((alias) => key === cleanStepId(alias))) {
      return provider.id;
    }
  }
  return undefined;
}

function normalizeTimeOfDay(value: TimeOfDay): TimeOfDay {
  const hour = Math.trunc(value.hour);
  const minute = Math.trunc(value.minute);
  if (!Number.isFinite(hour) || !Number.isFinite(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error("Planner returned an invalid time of day.");
  }
  return { hour, minute };
}

function positiveMs(value: number | undefined, fallback: number): number {
  const ms = Math.trunc(value ?? fallback);
  return Number.isFinite(ms) && ms > 0 ? ms : fallback;
}

function customPrompt(text: string): string {
  const details = cleanBlock(text) ?? "Review current Cerebro security state.";
  return [
    "Run this scheduled Cerebro security check.",
    "Use memory, Cerebro graph/runtime/finding tools, and Slack research when relevant.",
    `Check request: ${details}`,
    "Return current state, evidence checked, failures, and the next concrete action.",
  ].join("\n");
}

function titleFromText(text: string): string {
  return cleanInline(text)?.split(/\s+/).slice(0, 6).join(" ") || "Scheduled check";
}

function cleanInline(value: string | undefined): string | undefined {
  const trimmed = value?.replace(/\s+/g, " ").trim();
  return trimmed || undefined;
}

function cleanBlock(value: string | undefined): string | undefined {
  const trimmed = value?.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  return trimmed || undefined;
}

function cleanChannelId(value: string | undefined): string | undefined {
  const trimmed = cleanInline(value);
  if (!trimmed) return undefined;
  const mention = /^<#([A-Z0-9]+)(?:\|[^>]+)?>$/.exec(trimmed);
  return mention?.[1] ?? trimmed;
}

function cleanStepId(value: string | undefined): string | undefined {
  const id = value?.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  return id || undefined;
}

function uniqueStepId(base: string, used: Set<string>): string {
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  for (let suffix = 2; suffix < 100; suffix += 1) {
    const candidate = `${base}-${suffix}`;
    if (used.has(candidate)) continue;
    used.add(candidate);
    return candidate;
  }
  throw new Error("Planner returned too many duplicate step ids.");
}

function isString(value: string | undefined): value is string {
  return Boolean(value);
}

function nextLocalTime(timeZone: string, timeOfDay: TimeOfDay, now: Date, allowedDays?: number[]): Date {
  const parts = localParts(now, timeZone);
  for (let offset = 0; offset <= 14; offset += 1) {
    const candidate = localDateTime(timeZone, parts.year, parts.month, parts.day + offset, timeOfDay);
    const candidateDay = localParts(candidate, timeZone).weekday;
    if (allowedDays && !allowedDays.includes(candidateDay)) continue;
    if (candidate.getTime() > now.getTime() + 1000) return candidate;
  }
  return new Date(now.getTime() + 86_400_000);
}

function localDateTime(timeZone: string, year: number, month: number, day: number, timeOfDay: TimeOfDay): Date {
  const targetUtc = Date.UTC(year, month - 1, day, timeOfDay.hour, timeOfDay.minute, 0);
  const asZoned = localParts(new Date(targetUtc), timeZone);
  const zonedUtc = Date.UTC(asZoned.year, asZoned.month - 1, asZoned.day, asZoned.hour, asZoned.minute, asZoned.second);
  return new Date(targetUtc - (zonedUtc - targetUtc));
}

function localParts(date: Date, timeZone: string): { year: number; month: number; day: number; hour: number; minute: number; second: number; weekday: number } {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    weekday: "short",
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
    weekday: weekdayNumber(parts.weekday),
  };
}

function weekdayNumber(value: string | undefined): number {
  switch ((value ?? "").toLowerCase()) {
    case "sun":
      return 0;
    case "mon":
      return 1;
    case "tue":
      return 2;
    case "wed":
      return 3;
    case "thu":
      return 4;
    case "fri":
      return 5;
    case "sat":
      return 6;
    default:
      return 0;
  }
}

function formatTimeOfDay(value: TimeOfDay): string {
  return `${String(value.hour).padStart(2, "0")}:${String(value.minute).padStart(2, "0")}`;
}

function dayLabel(day: number): string {
  return ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][day] ?? String(day);
}

function durationLabel(ms: number): string {
  const minutes = Math.round(ms / 60_000);
  if (minutes % (24 * 60) === 0) return `${minutes / (24 * 60)} day(s)`;
  if (minutes % 60 === 0) return `${minutes / 60} hour(s)`;
  return `${minutes} minute(s)`;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

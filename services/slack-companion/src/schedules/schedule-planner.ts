import { Agent, type ThinkingLevel } from "@earendil-works/pi-agent-core";
import { builtinModels } from "@earendil-works/pi-ai/providers/all";
import { z } from "zod";
import type { SlackActor } from "../auth.js";
import type { AppConfig } from "../config/index.js";
import { listSecuritySkills } from "../skills/security-skills.js";
import {
  finalizeSchedulePlan,
  SCHEDULE_CONTEXT_PROVIDERS,
  type ScheduleCadence,
  type SchedulePlan,
  type ScheduledJobDraft,
  type ScheduleTrigger,
} from "./schedule-parser.js";

export interface SchedulePlannerInput {
  text: string;
  actor?: SlackActor;
  channelId?: string;
  now?: Date;
}

export interface SchedulePlanner {
  plan(input: SchedulePlannerInput): Promise<ScheduledJobDraft>;
}

export interface SchedulePlannerCompletionInput {
  systemPrompt: string;
  userPrompt: string;
  input: SchedulePlannerInput;
}

interface SchedulePlannerServiceOptions {
  complete?: (input: SchedulePlannerCompletionInput) => Promise<string>;
}

const stringArray = z.preprocess((value) => {
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}, z.array(z.string()));

const timeOfDaySchema = z.object({
  hour: z.coerce.number().int().min(0).max(23),
  minute: z.coerce.number().int().min(0).max(59),
});

const scheduleSchema: z.ZodType<ScheduleCadence> = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("once"),
    runAt: z.string().min(1),
    timeZone: z.string().min(1),
  }),
  z.object({
    kind: z.literal("interval"),
    everyMs: z.coerce.number().int().positive(),
    timeZone: z.string().min(1),
  }),
  z.object({
    kind: z.literal("daily"),
    timeOfDay: timeOfDaySchema,
    timeZone: z.string().min(1),
  }),
  z.object({
    kind: z.literal("weekdays"),
    timeOfDay: timeOfDaySchema,
    timeZone: z.string().min(1),
  }),
  z.object({
    kind: z.literal("weekly"),
    daysOfWeek: z.array(z.coerce.number().int().min(0).max(6)).min(1),
    timeOfDay: timeOfDaySchema,
    timeZone: z.string().min(1),
  }),
]);

const triggerSchema: z.ZodType<ScheduleTrigger> = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("runtime_health"),
    runtimeId: z.string().min(1),
    unhealthyOnly: z.boolean().default(true),
    cooldownMs: z.coerce.number().int().positive().default(60 * 60 * 1000),
  }),
  z.object({
    type: z.literal("findings_threshold"),
    runtimeIds: z.array(z.string().min(1)).default([]),
    threshold: z.coerce.number().int().positive(),
    cooldownMs: z.coerce.number().int().positive().default(60 * 60 * 1000),
  }),
]);

const plannerStepSchema = z.object({
  id: z.string().optional(),
  title: z.string().optional(),
  skillId: z.string().optional(),
  skill_id: z.string().optional(),
  prompt: z.string().optional(),
  dependsOn: stringArray.optional(),
  depends_on: stringArray.optional(),
}).transform((step) => ({
  id: step.id,
  title: step.title,
  skillId: step.skillId ?? step.skill_id,
  prompt: step.prompt,
  dependsOn: step.dependsOn ?? step.depends_on ?? [],
}));

const plannerOutputSchema: z.ZodType<SchedulePlan> = z.object({
  description: z.string().min(1),
  schedule: z.preprocess((value) => value === null ? undefined : value, scheduleSchema.optional()),
  trigger: z.preprocess((value) => value === null ? undefined : value, triggerSchema.optional()),
  steps: z.array(plannerStepSchema).min(1),
  contextProviders: stringArray.optional(),
  context_providers: stringArray.optional(),
  channelId: z.string().optional(),
  channel_id: z.string().optional(),
  warnings: stringArray.optional(),
}).transform((plan) => ({
  description: plan.description,
  schedule: plan.schedule,
  trigger: plan.trigger,
  steps: plan.steps,
  contextProviders: plan.contextProviders ?? plan.context_providers ?? [],
  channelId: plan.channelId ?? plan.channel_id,
  warnings: plan.warnings ?? [],
}));

export function parsePlannerOutput(raw: string): SchedulePlan | undefined {
  const jsonText = extractJsonObject(raw);
  if (!jsonText) return undefined;
  let decoded: unknown;
  try {
    decoded = JSON.parse(jsonText);
  } catch {
    return undefined;
  }
  const parsed = plannerOutputSchema.safeParse(decoded);
  return parsed.success ? parsed.data : undefined;
}

export class SchedulePlannerService implements SchedulePlanner {
  private readonly models = builtinModels();

  constructor(
    private readonly config: AppConfig,
    private readonly options: SchedulePlannerServiceOptions = {},
  ) {}

  async plan(input: SchedulePlannerInput): Promise<ScheduledJobDraft> {
    const now = input.now ?? new Date();
    const completeInput = {
      systemPrompt: plannerSystemPrompt(this.config),
      userPrompt: plannerUserPrompt(input, this.config, now),
      input: { ...input, now },
    };
    const raw = this.options.complete
      ? await this.options.complete(completeInput)
      : await this.runPiAgent(completeInput.systemPrompt, completeInput.userPrompt);
    const plan = parsePlannerOutput(raw);
    if (!plan) {
      throw new Error("Pi schedule planner did not return valid schedule JSON.");
    }
    return finalizeSchedulePlan(plan, {
      now,
      timeZone: this.config.schedules.defaultTimeZone,
      defaultChannelId: input.channelId ?? this.config.schedules.defaultChannelId ?? this.config.slack.defaultChannelId,
      defaultRuntimeIds: this.config.cerebro.defaultRuntimeIds,
      sourceText: input.text,
    });
  }

  private async runPiAgent(systemPrompt: string, userPrompt: string): Promise<string> {
    if (!this.config.triage.pi.enabled) {
      throw new Error("Pi schedule planner is disabled by configuration.");
    }
    const model = this.models.getModel(this.config.triage.pi.provider, this.config.triage.pi.model);
    if (!model) {
      throw new Error(`Pi model ${this.config.triage.pi.provider}/${this.config.triage.pi.model} is not available`);
    }

    const agent = new Agent({
      initialState: {
        systemPrompt,
        model,
        thinkingLevel: this.config.triage.pi.thinkingLevel as ThinkingLevel,
        tools: [],
      },
      streamFn: (requestModel, context, options) => this.models.streamSimple(requestModel, context, options),
    });

    const timeout = setTimeout(() => agent.abort(), this.config.triage.timeoutMs);
    timeout.unref?.();
    try {
      await agent.prompt(userPrompt);
    } finally {
      clearTimeout(timeout);
    }

    if (agent.state.errorMessage) {
      throw new Error(agent.state.errorMessage);
    }
    return latestAssistantText(agent.state.messages);
  }
}

function plannerSystemPrompt(config: AppConfig): string {
  return [
    "You plan durable Cerebro scheduled security checks from Slack operator text.",
    "Infer schedule cadence, event triggers, security skills, custom read-side checks, and DAG dependencies from plain language.",
    "Return one JSON object only. Do not include markdown, prose, code fences, comments, or trailing text.",
    "",
    "JSON shape:",
    "{",
    '  "description": "short operator-facing job name",',
    '  "schedule": null | {"kind":"once","runAt":"ISO-8601","timeZone":"IANA"} | {"kind":"interval","everyMs":7200000,"timeZone":"IANA"} | {"kind":"daily","timeOfDay":{"hour":9,"minute":0},"timeZone":"IANA"} | {"kind":"weekdays","timeOfDay":{"hour":9,"minute":0},"timeZone":"IANA"} | {"kind":"weekly","daysOfWeek":[1,3,5],"timeOfDay":{"hour":9,"minute":0},"timeZone":"IANA"},',
    '  "trigger": null | {"type":"runtime_health","runtimeId":"runtime-id","unhealthyOnly":true,"cooldownMs":3600000} | {"type":"findings_threshold","runtimeIds":["runtime-id"],"threshold":10,"cooldownMs":3600000},',
    '  "steps": [{"id":"stable-id","title":"Operator step title","skillId":"known-skill-id","prompt":"extra details for the check","dependsOn":["prior-step-id"]}],',
    '  "contextProviders": ["runtime_health_snapshot"],',
    '  "channelId": "Slack channel id or omitted",',
    '  "warnings": ["short note when a default was inferred"]',
    "}",
    "",
    "Schedule rules:",
    `- Use ${config.schedules.defaultTimeZone} unless the user names another time zone.`,
    "- Use ISO-8601 UTC timestamps for one-time runs.",
    "- daysOfWeek uses 0 for Sunday through 6 for Saturday.",
    "- If no exact time is given for a daily, weekday, or weekly schedule, pick the most likely operator time from the request. Use 09:00 only when the request gives no better clue.",
    "- If no timing or trigger is given, infer a practical cadence for the requested check and add a warning.",
    "",
    "Trigger rules:",
    `- Default runtime ids: ${config.cerebro.defaultRuntimeIds.join(", ") || "none configured"}.`,
    "- Runtime-health triggers fire only when unhealthyOnly is true.",
    "- Finding threshold triggers monitor open findings across the selected runtimes.",
    "- Use a one-hour cooldown unless the user asks for a different cooldown.",
    "",
    "DAG rules:",
    "- Steps joined by then depend on the previous stage.",
    "- Checks joined by and before then can run in parallel unless the user implies order.",
    "- dependsOn values must match step ids exactly.",
    "- Keep prompts read-side: inspect, summarize, rank, verify, recommend, or report. Do not create steps that resolve, suppress, assign, page, deploy, delete, grant access, or mutate infrastructure.",
    "",
    "Pre-run context provider rules:",
    "- Add contextProviders only when the data should be gathered before the first scheduled assistant step.",
    "- Use runtime_health_snapshot for runtime health, source sync, graph ingest, unhealthy, stale, or recovery checks.",
    "- Use open_findings_snapshot for finding counts, high-risk findings, stale findings, risk backlog, or threshold monitors.",
    "- Use companion_self_context for Cerebro, Slack companion, command registry, tool, skill, config, storage, or self-debug checks.",
    "- Context providers are read-only snapshots. Do not invent provider ids.",
    "",
    "Available pre-run context providers:",
    ...SCHEDULE_CONTEXT_PROVIDERS.map((provider) => `- ${provider.id}: ${provider.summary} Aliases: ${provider.aliases.join(", ")}`),
    "",
    "Available skills:",
    ...listSecuritySkills().map((skill) => `- ${skill.id}: ${skill.title}. ${skill.summary} Aliases: ${skill.aliases.join(", ")}`),
  ].join("\n");
}

function plannerUserPrompt(input: SchedulePlannerInput, config: AppConfig, now: Date): string {
  const defaultChannelId = input.channelId ?? config.schedules.defaultChannelId ?? config.slack.defaultChannelId ?? "none";
  return [
    `Current time: ${now.toISOString()}`,
    `Default time zone: ${config.schedules.defaultTimeZone}`,
    `Current Slack channel id: ${defaultChannelId}`,
    `Actor: ${input.actor?.displayName ?? input.actor?.slackUserId ?? input.actor?.actorId ?? "unknown"}`,
    `Default runtime ids: ${config.cerebro.defaultRuntimeIds.join(", ") || "none configured"}`,
    "",
    "Operator text:",
    input.text,
  ].join("\n");
}

function latestAssistantText(messages: unknown[]): string {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index] as { role?: string; content?: unknown };
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    return message.content
      .flatMap((part) => {
        const item = part as { type?: string; text?: unknown };
        return item.type === "text" && typeof item.text === "string" ? [item.text] : [];
      })
      .join("\n")
      .trim();
  }
  return "";
}

function extractJsonObject(raw: string): string | undefined {
  const trimmed = raw.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return undefined;
  return trimmed.slice(start, end + 1);
}

import {
  nextRunAtFor,
  normalizeContextProviderIds,
  type ScheduledJobDraft,
} from "../schedule-parser.js";

export function reviewedScheduleDraft(draft: ScheduledJobDraft, now: Date): ScheduledJobDraft {
  const description = draft.description?.replace(/\s+/g, " ").trim();
  if (!description) throw new Error("Schedule draft needs a description.");
  if (!draft.schedule && !draft.trigger) throw new Error("Schedule draft needs a schedule or trigger.");
  if (!Array.isArray(draft.steps) || draft.steps.length === 0) throw new Error("Schedule draft needs at least one step.");
  return {
    ...draft,
    description: description.slice(0, 180),
    contextProviders: normalizeContextProviderIds(draft.contextProviders),
    nextRunAt: draft.nextRunAt ?? nextRunAtFor(draft.schedule, now),
    warnings: Array.isArray(draft.warnings) ? draft.warnings.map(String) : [],
  };
}

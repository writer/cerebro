const DAY_MS = 86_400_000;
const DEFAULT_MAX_DUE_TIMES = 100;
const MAX_DUE_TIMES = 1_000;
const MAX_WINDOW_MS = 366 * DAY_MS;

export type ScheduleDefinitionState = "active" | "paused" | "retired";

export interface ScheduleTimeOfDayV1 {
  hour: number;
  minute: number;
}

export type ScheduleCadenceV1 =
  | {
      kind: "once";
      run_at: string;
    }
  | {
      anchor_at: string;
      every_ms: number;
      kind: "interval";
    }
  | {
      kind: "daily";
      time_of_day: ScheduleTimeOfDayV1;
      time_zone: string;
    }
  | {
      kind: "weekdays";
      time_of_day: ScheduleTimeOfDayV1;
      time_zone: string;
    }
  | {
      days_of_week: number[];
      kind: "weekly";
      time_of_day: ScheduleTimeOfDayV1;
      time_zone: string;
    };

/** Portable definition of when one opaque unit of work becomes due. */
export interface ScheduleDefinitionV1 {
  cadence: ScheduleCadenceV1;
  created_at: string;
  revision: number;
  schedule_id: string;
  schema_version: "schedule-definition/v1";
  state: ScheduleDefinitionState;
  updated_at: string;
  work_digest: string;
  work_ref: string;
}

export interface ScheduleDueTimePlanRequest {
  definition: ScheduleDefinitionV1;
  end_inclusive: string;
  max_due_times?: number;
  start_exclusive: string;
}

export interface ScheduleDueTimePlan {
  due_at: string[];
  truncated: boolean;
}

export class ScheduleDefinitionInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScheduleDefinitionInputError";
  }
}

/** Validate and canonicalize a definition before a host stores or evaluates it. */
export function normalizeScheduleDefinition(
  definition: ScheduleDefinitionV1,
): ScheduleDefinitionV1 {
  if (definition.schema_version !== "schedule-definition/v1") {
    throw new ScheduleDefinitionInputError("schema_version is unsupported");
  }
  const scheduleId = normalizedRef(definition.schedule_id, "schedule_id", 200);
  const workRef = normalizedRef(definition.work_ref, "work_ref", 500);
  if (!/^sha256:[0-9a-f]{64}$/.test(definition.work_digest)) {
    throw new ScheduleDefinitionInputError(
      "work_digest must be a lowercase SHA-256 digest",
    );
  }
  requirePositiveInteger(definition.revision, "revision");
  if (
    definition.state !== "active" &&
    definition.state !== "paused" &&
    definition.state !== "retired"
  ) {
    throw new ScheduleDefinitionInputError("state is invalid");
  }

  const createdAt = normalizeTime(definition.created_at, "created_at");
  const updatedAt = normalizeTime(definition.updated_at, "updated_at");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new ScheduleDefinitionInputError(
      "updated_at must not predate created_at",
    );
  }

  return {
    cadence: normalizeCadence(definition.cadence),
    created_at: createdAt,
    revision: definition.revision,
    schedule_id: scheduleId,
    schema_version: "schedule-definition/v1",
    state: definition.state,
    updated_at: updatedAt,
    work_digest: definition.work_digest,
    work_ref: workRef,
  };
}

/** Return deterministic due times for one bounded planning window. */
export function planScheduleDueTimes(
  request: ScheduleDueTimePlanRequest,
): ScheduleDueTimePlan {
  const definition = normalizeScheduleDefinition(request.definition);
  const startExclusive = normalizeTime(
    request.start_exclusive,
    "start_exclusive",
  );
  const endInclusive = normalizeTime(request.end_inclusive, "end_inclusive");
  const startMs = Date.parse(startExclusive);
  const endMs = Date.parse(endInclusive);
  if (endMs <= startMs) {
    throw new ScheduleDefinitionInputError(
      "end_inclusive must be later than start_exclusive",
    );
  }
  if (endMs - startMs > MAX_WINDOW_MS) {
    throw new ScheduleDefinitionInputError(
      "schedule planning window exceeds 366 days",
    );
  }

  const limit = request.max_due_times ?? DEFAULT_MAX_DUE_TIMES;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_DUE_TIMES) {
    throw new ScheduleDefinitionInputError(
      `max_due_times must be between 1 and ${MAX_DUE_TIMES}`,
    );
  }
  if (definition.state !== "active") {
    return { due_at: [], truncated: false };
  }

  const candidates = dueTimes(
    definition.cadence,
    startMs,
    endMs,
    limit + 1,
  );
  return {
    due_at: candidates.slice(0, limit),
    truncated: candidates.length > limit,
  };
}

function normalizeCadence(cadence: ScheduleCadenceV1): ScheduleCadenceV1 {
  switch (cadence.kind) {
    case "once":
      return { kind: "once", run_at: normalizeTime(cadence.run_at, "run_at") };
    case "interval":
      requirePositiveInteger(cadence.every_ms, "every_ms");
      return {
        anchor_at: normalizeTime(cadence.anchor_at, "anchor_at"),
        every_ms: cadence.every_ms,
        kind: "interval",
      };
    case "daily":
    case "weekdays":
      return {
        kind: cadence.kind,
        time_of_day: normalizeTimeOfDay(cadence.time_of_day),
        time_zone: normalizeTimeZone(cadence.time_zone),
      };
    case "weekly": {
      const days = [...new Set(cadence.days_of_week)].sort(
        (left, right) => left - right,
      );
      if (
        days.length === 0 ||
        days.some((day) => !Number.isInteger(day) || day < 0 || day > 6)
      ) {
        throw new ScheduleDefinitionInputError(
          "days_of_week must contain weekdays from 0 through 6",
        );
      }
      return {
        days_of_week: days,
        kind: "weekly",
        time_of_day: normalizeTimeOfDay(cadence.time_of_day),
        time_zone: normalizeTimeZone(cadence.time_zone),
      };
    }
  }
}

function dueTimes(
  cadence: ScheduleCadenceV1,
  startMs: number,
  endMs: number,
  limit: number,
): string[] {
  switch (cadence.kind) {
    case "once": {
      const runAt = Date.parse(cadence.run_at);
      return runAt > startMs && runAt <= endMs ? [cadence.run_at] : [];
    }
    case "interval":
      return intervalDueTimes(cadence, startMs, endMs, limit);
    case "daily":
      return calendarDueTimes(
        cadence.time_zone,
        cadence.time_of_day,
        undefined,
        startMs,
        endMs,
        limit,
      );
    case "weekdays":
      return calendarDueTimes(
        cadence.time_zone,
        cadence.time_of_day,
        new Set([1, 2, 3, 4, 5]),
        startMs,
        endMs,
        limit,
      );
    case "weekly":
      return calendarDueTimes(
        cadence.time_zone,
        cadence.time_of_day,
        new Set(cadence.days_of_week),
        startMs,
        endMs,
        limit,
      );
  }
}

function intervalDueTimes(
  cadence: Extract<ScheduleCadenceV1, { kind: "interval" }>,
  startMs: number,
  endMs: number,
  limit: number,
): string[] {
  const anchorMs = Date.parse(cadence.anchor_at);
  const elapsed = startMs - anchorMs;
  const firstOrdinal = Math.max(0, Math.floor(elapsed / cadence.every_ms) + 1);
  const result: string[] = [];
  for (let ordinal = firstOrdinal; result.length < limit; ordinal += 1) {
    const due = anchorMs + ordinal * cadence.every_ms;
    if (!Number.isSafeInteger(due) || due > endMs) break;
    result.push(new Date(due).toISOString());
  }
  return result;
}

function calendarDueTimes(
  timeZone: string,
  timeOfDay: ScheduleTimeOfDayV1,
  allowedDays: ReadonlySet<number> | undefined,
  startMs: number,
  endMs: number,
  limit: number,
): string[] {
  const startLocal = zonedParts(new Date(startMs), timeZone);
  const result: string[] = [];
  for (let offset = 0; offset <= 367 && result.length < limit; offset += 1) {
    const date = addCalendarDays(startLocal, offset);
    const day = new Date(Date.UTC(date.year, date.month - 1, date.day)).getUTCDay();
    if (allowedDays !== undefined && !allowedDays.has(day)) continue;
    const due = earliestInstantForLocalTime(timeZone, date, timeOfDay);
    if (due === undefined || due <= startMs) continue;
    if (due > endMs) break;
    result.push(new Date(due).toISOString());
  }
  return result;
}

function earliestInstantForLocalTime(
  timeZone: string,
  date: LocalDate,
  timeOfDay: ScheduleTimeOfDayV1,
): number | undefined {
  const localAsUtc = Date.UTC(
    date.year,
    date.month - 1,
    date.day,
    timeOfDay.hour,
    timeOfDay.minute,
  );
  const offsets = new Set(
    [-DAY_MS, 0, DAY_MS].map((delta) =>
      timeZoneOffsetMs(new Date(localAsUtc + delta), timeZone),
    ),
  );
  const matches = [...offsets]
    .map((offset) => localAsUtc - offset)
    .filter((candidate) =>
      matchesLocalTime(new Date(candidate), timeZone, date, timeOfDay),
    )
    .sort((left, right) => left - right);
  return matches[0];
}

interface LocalDate {
  day: number;
  month: number;
  year: number;
}

interface ZonedParts extends LocalDate {
  hour: number;
  minute: number;
  second: number;
}

function addCalendarDays(date: LocalDate, offset: number): LocalDate {
  const next = new Date(Date.UTC(date.year, date.month - 1, date.day + offset));
  return {
    day: next.getUTCDate(),
    month: next.getUTCMonth() + 1,
    year: next.getUTCFullYear(),
  };
}

function matchesLocalTime(
  instant: Date,
  timeZone: string,
  date: LocalDate,
  timeOfDay: ScheduleTimeOfDayV1,
): boolean {
  const parts = zonedParts(instant, timeZone);
  return (
    parts.year === date.year &&
    parts.month === date.month &&
    parts.day === date.day &&
    parts.hour === timeOfDay.hour &&
    parts.minute === timeOfDay.minute &&
    parts.second === 0
  );
}

function timeZoneOffsetMs(instant: Date, timeZone: string): number {
  const parts = zonedParts(instant, timeZone);
  const localAsUtc = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
  );
  return localAsUtc - Math.floor(instant.getTime() / 1_000) * 1_000;
}

function zonedParts(instant: Date, timeZone: string): ZonedParts {
  const entries = new Intl.DateTimeFormat("en-US-u-ca-iso8601", {
    day: "2-digit",
    hour: "2-digit",
    hourCycle: "h23",
    minute: "2-digit",
    month: "2-digit",
    second: "2-digit",
    timeZone,
    year: "numeric",
  }).formatToParts(instant);
  const parts = Object.fromEntries(
    entries.map((entry) => [entry.type, entry.value]),
  );
  return {
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    month: Number(parts.month),
    second: Number(parts.second),
    year: Number(parts.year),
  };
}

function normalizeTimeOfDay(value: ScheduleTimeOfDayV1): ScheduleTimeOfDayV1 {
  if (
    !Number.isInteger(value.hour) ||
    value.hour < 0 ||
    value.hour > 23 ||
    !Number.isInteger(value.minute) ||
    value.minute < 0 ||
    value.minute > 59
  ) {
    throw new ScheduleDefinitionInputError("time_of_day is invalid");
  }
  return { hour: value.hour, minute: value.minute };
}

function normalizeTimeZone(value: string): string {
  const normalized = normalizedRef(value, "time_zone", 100);
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: normalized }).format();
  } catch {
    throw new ScheduleDefinitionInputError("time_zone is invalid");
  }
  return normalized;
}

function normalizeTime(value: string, field: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new ScheduleDefinitionInputError(
      `${field} must be an ISO-8601 timestamp`,
    );
  }
  return new Date(timestamp).toISOString();
}

function normalizedRef(value: string, field: string, maximum: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximum) {
    throw new ScheduleDefinitionInputError(
      `${field} must contain between 1 and ${maximum} characters`,
    );
  }
  return normalized;
}

function requirePositiveInteger(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new ScheduleDefinitionInputError(
      `${field} must be a positive integer`,
    );
  }
}

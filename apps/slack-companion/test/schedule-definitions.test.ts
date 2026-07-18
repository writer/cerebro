import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  normalizeScheduleDefinition,
  planScheduleDueTimes,
  ScheduleDefinitionInputError,
  type ScheduleDefinitionV1,
} from "../src/operations/schedule-definitions.js";

const digest = `sha256:${"a".repeat(64)}`;
const createdAt = "2026-01-01T00:00:00.000Z";

function definition(
  overrides: Partial<ScheduleDefinitionV1> = {},
): ScheduleDefinitionV1 {
  return {
    cadence: {
      anchor_at: "2026-01-01T00:00:00.000Z",
      every_ms: 60 * 60 * 1_000,
      kind: "interval",
    },
    created_at: createdAt,
    revision: 1,
    schedule_id: "hourly-summary",
    schema_version: "schedule-definition/v1",
    state: "active",
    updated_at: createdAt,
    work_digest: digest,
    work_ref: "work/hourly-summary",
    ...overrides,
  };
}

describe("portable schedule cadence", () => {
  test("keeps interval due times anchored across planner restarts", () => {
    const request = {
      definition: definition(),
      end_inclusive: "2026-01-01T05:00:00.000Z",
      start_exclusive: "2026-01-01T01:30:00.000Z",
    };

    const first = planScheduleDueTimes(request);
    const restarted = planScheduleDueTimes(structuredClone(request));

    assert.deepEqual(first, restarted);
    assert.deepEqual(first, {
      due_at: [
        "2026-01-01T02:00:00.000Z",
        "2026-01-01T03:00:00.000Z",
        "2026-01-01T04:00:00.000Z",
        "2026-01-01T05:00:00.000Z",
      ],
      truncated: false,
    });
  });

  test("normalizes portable identity without execution generation", () => {
    const normalized = normalizeScheduleDefinition(
      definition({
        created_at: "2026-01-01T00:00:00Z",
        revision: 7,
        schedule_id: "  daily-review  ",
        updated_at: "2026-01-02T00:00:00Z",
        work_ref: "  work/daily-review  ",
      }),
    );

    assert.equal(normalized.revision, 7);
    assert.equal(normalized.schedule_id, "daily-review");
    assert.equal(normalized.work_ref, "work/daily-review");
    assert.equal(normalized.created_at, "2026-01-01T00:00:00.000Z");
    assert.equal(normalized.updated_at, "2026-01-02T00:00:00.000Z");
    assert.equal("generation" in normalized, false);
  });

  test("suppresses paused and retired definitions", () => {
    for (const state of ["paused", "retired"] as const) {
      assert.deepEqual(
        planScheduleDueTimes({
          definition: definition({ state }),
          end_inclusive: "2026-01-01T03:00:00.000Z",
          start_exclusive: "2026-01-01T00:00:00.000Z",
        }),
        { due_at: [], truncated: false },
      );
    }
  });

  test("skips a nonexistent local time during daylight-saving change", () => {
    const plan = planScheduleDueTimes({
      definition: definition({
        cadence: {
          kind: "daily",
          time_of_day: { hour: 2, minute: 30 },
          time_zone: "America/Los_Angeles",
        },
      }),
      end_inclusive: "2026-03-10T00:00:00.000Z",
      start_exclusive: "2026-03-07T00:00:00.000Z",
    });

    assert.deepEqual(plan.due_at, [
      "2026-03-07T10:30:00.000Z",
      "2026-03-09T09:30:00.000Z",
    ]);
  });

  test("uses the earliest instant when a local time repeats", () => {
    const plan = planScheduleDueTimes({
      definition: definition({
        cadence: {
          kind: "daily",
          time_of_day: { hour: 1, minute: 30 },
          time_zone: "America/Los_Angeles",
        },
      }),
      end_inclusive: "2026-11-02T00:00:00.000Z",
      start_exclusive: "2026-11-01T00:00:00.000Z",
    });

    assert.deepEqual(plan.due_at, ["2026-11-01T08:30:00.000Z"]);
  });

  test("plans one-time schedules once and bounds interval output", () => {
    assert.deepEqual(
      planScheduleDueTimes({
        definition: definition({
          cadence: { kind: "once", run_at: "2026-01-01T01:00:00Z" },
        }),
        end_inclusive: "2026-01-01T02:00:00Z",
        start_exclusive: "2026-01-01T00:00:00Z",
      }),
      { due_at: ["2026-01-01T01:00:00.000Z"], truncated: false },
    );

    assert.deepEqual(
      planScheduleDueTimes({
        definition: definition(),
        end_inclusive: "2026-01-01T04:00:00Z",
        max_due_times: 2,
        start_exclusive: "2026-01-01T00:00:00Z",
      }),
      {
        due_at: [
          "2026-01-01T01:00:00.000Z",
          "2026-01-01T02:00:00.000Z",
        ],
        truncated: true,
      },
    );
  });

  test("rejects malformed definitions and unbounded windows", () => {
    assert.throws(
      () => normalizeScheduleDefinition(definition({ revision: 0 })),
      ScheduleDefinitionInputError,
    );
    assert.throws(
      () =>
        normalizeScheduleDefinition(
          definition({
            cadence: {
              kind: "daily",
              time_of_day: { hour: 24, minute: 0 },
              time_zone: "UTC",
            },
          }),
        ),
      ScheduleDefinitionInputError,
    );
    assert.throws(
      () =>
        normalizeScheduleDefinition(
          definition({
            cadence: {
              kind: "weekly",
              days_of_week: [],
              time_of_day: { hour: 9, minute: 0 },
              time_zone: "UTC",
            },
          }),
        ),
      ScheduleDefinitionInputError,
    );
    assert.throws(
      () =>
        planScheduleDueTimes({
          definition: definition(),
          end_inclusive: "2027-01-03T00:00:00Z",
          start_exclusive: "2026-01-01T00:00:00Z",
        }),
      /exceeds 366 days/,
    );
    assert.throws(
      () =>
        planScheduleDueTimes({
          definition: definition(),
          end_inclusive: "2026-01-01T01:00:00Z",
          max_due_times: 0,
          start_exclusive: "2026-01-01T00:00:00Z",
        }),
      /max_due_times/,
    );
  });
});

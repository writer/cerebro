import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  normalizeScheduleDefinition,
  planScheduleOccurrences,
  type ScheduleDefinitionV1,
} from "../src/operations/schedule-definitions.js";

const digest = `sha256:${"a".repeat(64)}`;

describe("durable schedule definitions", () => {
  test("keeps anchored interval due times stable across planner restarts", () => {
    const definition = schedule({
      cadence: {
        anchor_at: "2026-07-18T10:00:00Z",
        every_ms: 60 * 60 * 1_000,
        kind: "interval",
      },
    });

    const first = planScheduleOccurrences({
      created_at: "2026-07-18T12:20:00Z",
      definition,
      end_inclusive: "2026-07-18T15:00:00Z",
      start_exclusive: "2026-07-18T12:20:00Z",
    });
    const restarted = planScheduleOccurrences({
      created_at: "2026-07-18T12:45:00Z",
      definition,
      end_inclusive: "2026-07-18T15:00:00Z",
      start_exclusive: "2026-07-18T12:20:00Z",
    });

    assert.deepEqual(first.due_at, [
      "2026-07-18T13:00:00.000Z",
      "2026-07-18T14:00:00.000Z",
      "2026-07-18T15:00:00.000Z",
    ]);
    assert.deepEqual(restarted.due_at, first.due_at);
    assert.deepEqual(
      restarted.occurrences.map((occurrence) => occurrence.occurrence_id),
      first.occurrences.map((occurrence) => occurrence.occurrence_id),
    );
  });

  test("fences occurrence identity by schedule revision", () => {
    const request = {
      created_at: "2026-07-18T12:00:00Z",
      end_inclusive: "2026-07-18T13:00:00Z",
      start_exclusive: "2026-07-18T12:00:00Z",
    };
    const first = planScheduleOccurrences({
      ...request,
      definition: schedule({ revision: 4 }),
    });
    const revised = planScheduleOccurrences({
      ...request,
      definition: schedule({ revision: 5 }),
    });

    assert.equal(first.occurrences.length, 1);
    assert.equal(revised.occurrences.length, 1);
    assert.notEqual(
      first.occurrences[0]?.occurrence_id,
      revised.occurrences[0]?.occurrence_id,
    );
  });

  test("does not create new work for paused or retired definitions", () => {
    for (const state of ["paused", "retired"] as const) {
      const plan = planScheduleOccurrences({
        created_at: "2026-07-18T12:00:00Z",
        definition: schedule({ state }),
        end_inclusive: "2026-07-18T14:00:00Z",
        start_exclusive: "2026-07-18T12:00:00Z",
      });
      assert.deepEqual(plan, {
        due_at: [],
        occurrences: [],
        truncated: false,
      });
    }
  });

  test("plans local daily times across a daylight-saving transition", () => {
    const plan = planScheduleOccurrences({
      created_at: "2026-03-07T00:00:00Z",
      definition: schedule({
        cadence: {
          kind: "daily",
          time_of_day: { hour: 9, minute: 0 },
          time_zone: "America/Los_Angeles",
        },
      }),
      end_inclusive: "2026-03-10T20:00:00Z",
      start_exclusive: "2026-03-07T00:00:00Z",
    });

    assert.deepEqual(plan.due_at, [
      "2026-03-07T17:00:00.000Z",
      "2026-03-08T16:00:00.000Z",
      "2026-03-09T16:00:00.000Z",
      "2026-03-10T16:00:00.000Z",
    ]);
  });

  test("skips a nonexistent local time and uses the earliest repeated time", () => {
    const nonexistent = planScheduleOccurrences({
      created_at: "2026-03-08T00:00:00Z",
      definition: schedule({
        cadence: {
          kind: "daily",
          time_of_day: { hour: 2, minute: 30 },
          time_zone: "America/Los_Angeles",
        },
      }),
      end_inclusive: "2026-03-09T12:00:00Z",
      start_exclusive: "2026-03-08T00:00:00Z",
    });
    assert.deepEqual(nonexistent.due_at, ["2026-03-09T09:30:00.000Z"]);

    const repeated = planScheduleOccurrences({
      created_at: "2026-11-01T00:00:00Z",
      definition: schedule({
        cadence: {
          days_of_week: [0],
          kind: "weekly",
          time_of_day: { hour: 1, minute: 30 },
          time_zone: "America/Los_Angeles",
        },
      }),
      end_inclusive: "2026-11-01T12:00:00Z",
      start_exclusive: "2026-11-01T00:00:00Z",
    });
    assert.deepEqual(repeated.due_at, ["2026-11-01T08:30:00.000Z"]);
  });

  test("runs a one-time definition once and bounds catch-up output", () => {
    const once = schedule({
      cadence: { kind: "once", run_at: "2026-07-18T13:00:00Z" },
    });
    assert.equal(planScheduleOccurrences({
      created_at: "2026-07-18T12:00:00Z",
      definition: once,
      end_inclusive: "2026-07-18T14:00:00Z",
      start_exclusive: "2026-07-18T12:00:00Z",
    }).occurrences.length, 1);
    assert.equal(planScheduleOccurrences({
      created_at: "2026-07-18T14:00:00Z",
      definition: once,
      end_inclusive: "2026-07-18T15:00:00Z",
      start_exclusive: "2026-07-18T14:00:00Z",
    }).occurrences.length, 0);

    const bounded = planScheduleOccurrences({
      created_at: "2026-07-18T10:00:00Z",
      definition: schedule(),
      end_inclusive: "2026-07-18T15:00:00Z",
      max_occurrences: 2,
      start_exclusive: "2026-07-18T10:00:00Z",
    });
    assert.equal(bounded.occurrences.length, 2);
    assert.equal(bounded.truncated, true);
  });

  test("rejects malformed or unbounded definitions and windows", () => {
    assert.throws(
      () => normalizeScheduleDefinition(schedule({
        schema_version: "unsupported" as "schedule-definition/v1",
      })),
      /schema_version/,
    );
    assert.throws(
      () => normalizeScheduleDefinition(schedule({ work_digest: "sha256:no" })),
      /work_digest/,
    );
    assert.throws(
      () => normalizeScheduleDefinition(schedule({
        cadence: {
          kind: "daily",
          time_of_day: { hour: 9, minute: 0 },
          time_zone: "not/a-zone",
        },
      })),
      /time_zone/,
    );
    assert.throws(
      () => planScheduleOccurrences({
        created_at: "2026-01-01T00:00:00Z",
        definition: schedule(),
        end_inclusive: "2027-01-03T00:00:00Z",
        start_exclusive: "2026-01-01T00:00:00Z",
      }),
      /exceeds 366 days/,
    );
  });
});

function schedule(
  overrides: Partial<ScheduleDefinitionV1> = {},
): ScheduleDefinitionV1 {
  return {
    cadence: {
      anchor_at: "2026-07-18T10:00:00Z",
      every_ms: 60 * 60 * 1_000,
      kind: "interval",
    },
    created_at: "2026-07-18T09:00:00Z",
    generation: 3,
    misfire_policy: "run_all_bounded",
    revision: 4,
    schedule_id: "schedule-summary",
    schema_version: "schedule-definition/v1",
    state: "active",
    updated_at: "2026-07-18T09:30:00Z",
    work_digest: digest,
    work_ref: "work-template-summary",
    ...overrides,
  };
}

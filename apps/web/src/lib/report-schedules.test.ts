import { describe, expect, it } from "vitest";

import {
  describeInterval,
  intervalToSeconds,
  missingRequiredParameters,
  reportNameForID,
  reportRunIntent,
  sanitizeScheduleParameters,
  scheduleParameterFields,
  type ReportDefinition,
} from "@/lib/report-schedules";

const findingSummary: ReportDefinition = {
  id: "finding-summary",
  name: "Finding Summary",
  parameters: [
    { id: "tenant_id", required: true },
    { id: "runtime_ids", required: true },
    { id: "resource_limit" },
  ],
};

describe("intervalToSeconds", () => {
  it("converts each supported unit to seconds", () => {
    expect(intervalToSeconds(5, "minutes")).toBe(300);
    expect(intervalToSeconds(2, "hours")).toBe(7200);
    expect(intervalToSeconds(1, "days")).toBe(86400);
  });
});

describe("describeInterval", () => {
  it("renders whole-unit cadences with pluralization", () => {
    expect(describeInterval(60)).toBe("Every 1 minute");
    expect(describeInterval(120)).toBe("Every 2 minutes");
    expect(describeInterval(3600)).toBe("Every 1 hour");
    expect(describeInterval(7200)).toBe("Every 2 hours");
    expect(describeInterval(86400)).toBe("Every 1 day");
    expect(describeInterval(172800)).toBe("Every 2 days");
  });

  it("falls back to minutes for non-whole-unit values", () => {
    expect(describeInterval(3660)).toBe("Every 61 minutes");
  });

  it("returns a placeholder for non-positive values", () => {
    expect(describeInterval(0)).toBe("—");
    expect(describeInterval(-10)).toBe("—");
  });
});

describe("scheduleParameterFields", () => {
  it("excludes the server-injected tenant parameter", () => {
    expect(scheduleParameterFields(findingSummary).map((field) => field.id)).toEqual([
      "runtime_ids",
      "resource_limit",
    ]);
  });

  it("returns an empty list for an unknown definition", () => {
    expect(scheduleParameterFields(undefined)).toEqual([]);
  });
});

describe("missingRequiredParameters", () => {
  it("reports required fields that are blank, ignoring tenant", () => {
    expect(missingRequiredParameters(findingSummary, {})).toEqual(["runtime_ids"]);
    expect(missingRequiredParameters(findingSummary, { runtime_ids: "   " })).toEqual(["runtime_ids"]);
  });

  it("returns nothing once required fields are supplied", () => {
    expect(missingRequiredParameters(findingSummary, { runtime_ids: "rt-1" })).toEqual([]);
  });
});

describe("sanitizeScheduleParameters", () => {
  it("trims values and drops empty entries", () => {
    expect(sanitizeScheduleParameters({ runtime_ids: " rt-1 ", note: "", graph_limit: "5" })).toEqual({
      runtime_ids: "rt-1",
      graph_limit: "5",
    });
  });
});

describe("reportNameForID", () => {
  it("resolves a definition name and falls back to the id", () => {
    expect(reportNameForID([findingSummary], "finding-summary")).toBe("Finding Summary");
    expect(reportNameForID([findingSummary], "risk-delta")).toBe("risk-delta");
    expect(reportNameForID(undefined, "risk-delta")).toBe("risk-delta");
  });
});

describe("reportRunIntent", () => {
  it("maps run status strings to intents", () => {
    expect(reportRunIntent("completed")).toBe("success");
    expect(reportRunIntent("failed")).toBe("danger");
    expect(reportRunIntent("running")).toBe("info");
    expect(reportRunIntent("unknown-status")).toBe("warning");
    expect(reportRunIntent(undefined)).toBe("warning");
  });
});

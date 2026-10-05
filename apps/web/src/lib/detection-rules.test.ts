import { describe, expect, it } from "vitest";

import { awaitsExternalVerdict } from "./detection-rules";

describe("awaitsExternalVerdict", () => {
  it("flags a rule that only listens for a verdict decided elsewhere", () => {
    expect(awaitsExternalVerdict({ id: "a", input_stream_ids: ["policy.evidence"] })).toBe(true);
    expect(awaitsExternalVerdict({ id: "b", input_stream_ids: ["policy.result"] })).toBe(true);
    expect(awaitsExternalVerdict({ id: "c", input_stream_ids: ["policy.evidence", "policy.result"] })).toBe(true);
  });

  it("does not flag a rule a connector can trigger", () => {
    expect(awaitsExternalVerdict({ id: "d", input_stream_ids: ["aws.s3_bucket"] })).toBe(false);
  });

  it("does not flag a rule that has any collected stream alongside a verdict", () => {
    expect(awaitsExternalVerdict({ id: "e", input_stream_ids: ["policy.evidence", "okta.user"] })).toBe(false);
  });

  it("treats an unbound rule as unknown rather than external", () => {
    expect(awaitsExternalVerdict({ id: "f" })).toBe(false);
    expect(awaitsExternalVerdict({ id: "g", input_stream_ids: [] })).toBe(false);
  });
});

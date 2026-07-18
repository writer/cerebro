import { describe, expect, it } from "vitest";

import {
  aperioProposalActionForCandidate,
  aperioResponseCandidateHint,
  aperioResponseCandidateHintForCandidate,
} from "./aperio-response-candidate-hints";
import type { SecurityProducer } from "./security-producers";

const producers: SecurityProducer[] = [{
  id: "aperio",
  label: "Response producer",
  repo: "",
  runtimeIds: [],
  sourceIds: [],
  mcpTools: ["producer.propose"],
  resourceTemplates: [],
  contextKeys: [],
  responseActions: [{
    id: "REMOVE_APP",
    label: "Remove app",
    providers: ["GENERIC_SAAS"],
    targetTypes: ["application"],
    requiredContextKeys: ["application_id"],
    mode: "proposal",
    mcpTool: "producer.propose",
    runtimeAction: "QUARANTINE_APP",
    dryRun: true,
    requiresApproval: true,
  }],
}];

describe("response candidate compatibility hints", () => {
  it("derives proposal actions and tools from registry metadata", () => {
    expect(aperioProposalActionForCandidate("REMOVE_APP", producers)).toBe("QUARANTINE_APP");
    expect(aperioResponseCandidateHintForCandidate("REMOVE_APP", producers)).toBe(
      "REMOVE_APP (call producer.propose with action=QUARANTINE_APP and provider=GENERIC_SAAS)",
    );
  });

  it("passes through unknown candidates and keeps the empty fallback concise", () => {
    expect(aperioResponseCandidateHintForCandidate("CUSTOM_ACTION", producers)).toBe("CUSTOM_ACTION");
    expect(aperioResponseCandidateHint([], producers)).toBe("Response proposal");
  });
});

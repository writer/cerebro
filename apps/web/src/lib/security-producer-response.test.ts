import { describe, expect, it } from "vitest";

import {
  securityProducerForFinding,
  securityProducerResponseActionCandidates,
  securityProducerResponseCandidateHint,
} from "./security-producer-response";
import type { SecurityProducer } from "./security-producers";

const producers: SecurityProducer[] = [
  {
    id: "producer-one",
    label: "Producer One",
    repo: "example/security-producer",
    runtimeIds: ["runtime-one"],
    sourceIds: ["source-one"],
    mcpTools: ["producer.propose"],
    resourceTemplates: [],
    contextKeys: [],
    responseActions: [
      {
        id: "QUARANTINE_APP",
        label: "Quarantine app",
        providers: ["GENERIC_SAAS"],
        targetTypes: ["application"],
        requiredContextKeys: ["application_id"],
        mode: "proposal",
        mcpTool: "producer.propose",
        dryRun: true,
        requiresApproval: true,
      },
      {
        id: "OPEN_TICKET",
        label: "Open ticket",
        providers: ["ALL"],
        targetTypes: ["finding"],
        requiredContextKeys: ["finding_id"],
        mode: "proposal",
        dryRun: false,
        requiresApproval: false,
      },
    ],
  },
];

describe("security producer response context", () => {
  it("matches a configured producer without built-in repository knowledge", () => {
    const finding = {
      source_id: "source-one",
      runtime_id: "",
      attributes: { provider: "GENERIC_SAAS" },
      external_refs: [],
    };
    expect(securityProducerForFinding(finding, producers)?.id).toBe("producer-one");
    expect(securityProducerResponseActionCandidates(finding, producers)).toEqual([
      "QUARANTINE_APP",
      "OPEN_TICKET",
    ]);
  });

  it("keeps provider-specific actions out when the finding lacks that provider", () => {
    expect(securityProducerResponseActionCandidates({
      source_id: "source-one",
      runtime_id: "",
      attributes: {},
      external_refs: [],
    }, producers)).toEqual(["OPEN_TICKET"]);
  });

  it("renders approval and dry-run requirements from configured action metadata", () => {
    expect(securityProducerResponseCandidateHint(["QUARANTINE_APP"], producers)).toBe(
      "QUARANTINE_APP via producer.propose for provider=GENERIC_SAAS; approval required; dry run",
    );
  });
});

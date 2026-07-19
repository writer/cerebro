/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecurityProducerCatalogProvider } from "@/components/SecurityProducerCatalogProvider";
import type { GRCFinding } from "@/lib/grc";

const mocks = vi.hoisted(() => ({
  fetchSecurityProducers: vi.fn(),
  openAgent: vi.fn(),
}));

vi.mock("@/lib/security-producers-client", () => ({
  fetchSecurityProducers: mocks.fetchSecurityProducers,
}));
vi.mock("@/components/agent/CerebroAgentProvider", () => ({
  useCerebroAgent: () => ({ openAgent: mocks.openAgent }),
}));

import FindingTable from "./FindingTable";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushUpdates = () => new Promise((resolve) => setTimeout(resolve, 0));

const finding: GRCFinding = {
  id: "finding-one",
  title: "Configured producer finding",
  severity: "HIGH",
  status: "open",
  evidence_count: 1,
  owner: "Security",
  risk_score: 80,
  sla_status: "due",
  source_id: "source-one",
  attributes: { provider: "GENERIC_SAAS" },
};

describe("FindingTable runtime producer context", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    mocks.openAgent.mockReset();
    mocks.fetchSecurityProducers.mockReset().mockResolvedValue({
      state: "ready",
      producers: [{
        id: "producer-one",
        label: "Producer One",
        repo: "",
        runtimeIds: [],
        sourceIds: ["source-one"],
        mcpTools: ["producer.propose"],
        resourceTemplates: [],
        contextKeys: [],
        responseActions: [{
          id: "OPEN_TICKET",
          label: "Open ticket",
          providers: ["ALL"],
          targetTypes: ["finding"],
          requiredContextKeys: ["finding_id"],
          mode: "proposal",
          mcpTool: "producer.propose",
          dryRun: true,
          requiresApproval: true,
        }],
      }],
    });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("passes the fetched producer and action candidates into Ask context", async () => {
    await act(async () => {
      root.render(
        <SecurityProducerCatalogProvider>
          <FindingTable findings={[finding]} />
        </SecurityProducerCatalogProvider>,
      );
      await flushUpdates();
    });

    await act(async () => {
      container.querySelector<HTMLButtonElement>("button[title='Ask about this finding']")?.click();
    });

    expect(mocks.openAgent).toHaveBeenCalledWith(expect.objectContaining({
      context: expect.objectContaining({
        security_producer_id: "producer-one",
        response_action_candidates: ["OPEN_TICKET"],
      }),
    }));
  });
});

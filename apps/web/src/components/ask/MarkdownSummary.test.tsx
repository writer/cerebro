import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/agent/CerebroAgentProvider", () => ({
  useCerebroAgent: () => ({ openAgent: vi.fn() }),
}));

import MarkdownSummary from "./MarkdownSummary";

describe("MarkdownSummary", () => {
  it("renders citation spans using offsets from the full markdown document", () => {
    const markdown = "First paragraph.\n\nSecond paragraph cites repo.";
    const start = markdown.indexOf("repo");
    const html = renderToStaticMarkup(
      <MarkdownSummary
        markdown={markdown}
        citations={[
          {
            urn: "urn:cerebro:writer:repo:security-agent-platform",
            span: [start, start + "repo".length],
          },
        ]}
      />,
    );

    expect(html).toContain("Second paragraph cites");
    expect(html).toContain('data-urn="urn:cerebro:writer:repo:security-agent-platform"');
    expect(html).toContain(">repo</button>");
  });

  it("renders cited bullet lines without shifting offsets", () => {
    const markdown = "- Finding touches repo\n- Connector is healthy";
    const start = markdown.indexOf("Connector");
    const html = renderToStaticMarkup(
      <MarkdownSummary
        markdown={markdown}
        citations={[
          {
            urn: "urn:cerebro:writer:connector:local-github",
            span: [start, start + "Connector".length],
          },
        ]}
      />,
    );

    expect(html).toContain('data-urn="urn:cerebro:writer:connector:local-github"');
    expect(html).toContain(">Connector</button>");
  });
});

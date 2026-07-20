import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

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
    expect(html).toContain("/impact?root_urn=urn%3Acerebro%3Awriter%3Arepo%3Asecurity-agent-platform");
    expect(html).toContain(">repo</a>");
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

    expect(html).toContain(">Connector</a>");
  });
});

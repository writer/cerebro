import { describe, expect, it } from "vitest";

import { graphHiddenScopeCopy } from "./GraphViewer";

describe("graphHiddenScopeCopy", () => {
  it("describes nodes and edges hidden by scale caps and filters", () => {
    expect(graphHiddenScopeCopy({ filteredEdges: 2, filteredNodes: 1, hiddenEdges: 4, hiddenNodes: 3 })).toEqual([
      "3 nodes hidden by cap",
      "4 edges hidden by cap",
      "1 node and 2 edges hidden by filters",
    ]);
  });

  it("keeps singular count labels precise", () => {
    expect(graphHiddenScopeCopy({ filteredEdges: 1, filteredNodes: 1, hiddenEdges: 1, hiddenNodes: 1 })).toEqual([
      "1 node hidden by cap",
      "1 edge hidden by cap",
      "1 node and 1 edge hidden by filters",
    ]);
  });

  it("omits empty hidden-scope copy", () => {
    expect(graphHiddenScopeCopy({ filteredEdges: 0, filteredNodes: 0, hiddenEdges: 0, hiddenNodes: 0 })).toEqual([]);
  });
});

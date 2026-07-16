import { describe, expect, it } from "vitest";

import { connectorLibraryPagePath, mergeConnectorLibraryPages } from "./connector-library-query";

describe("connector library pagination", () => {
  it("builds bounded connector library page paths", () => {
    expect(connectorLibraryPagePath({ tenantID: " tenant-a ", view: "full" })).toBe(
      "/connectors?tenant_id=tenant-a&view=full&limit=200",
    );
    expect(connectorLibraryPagePath({ view: "summary", limit: 500, cursor: "page-two" })).toBe(
      "/connectors?view=summary&limit=200&cursor=page-two",
    );
    expect(connectorLibraryPagePath({ limit: 0 })).toBe("/connectors?view=full&limit=1");
  });

  it("merges connector library pages into the existing response shape", () => {
    const merged = mergeConnectorLibraryPages([
      {
        tenant_id: "tenant-a",
        view: "full",
        credential_stores: [{ id: "cerebro_vault", available: true }],
        connectors: [{ source_id: "github", name: "GitHub" }],
        page: { total: 3, returned: 1, limit: 1, has_more: true, next_cursor: "one" },
      },
      {
        tenant_id: "tenant-a",
        view: "full",
        connectors: [
          { source_id: "aws", name: "AWS" },
          { source_id: "okta", name: "Okta" },
        ],
        page: { total: 3, returned: 2, limit: 2, has_more: false },
      },
    ]);

    expect(merged?.tenant_id).toBe("tenant-a");
    expect(merged?.credential_stores).toEqual([{ id: "cerebro_vault", available: true }]);
    expect(merged?.connectors?.map((connector) => connector.source_id)).toEqual(["github", "aws", "okta"]);
    expect(merged?.page).toMatchObject({
      total: 3,
      returned: 3,
      limit: 1,
      has_more: false,
    });
  });
});

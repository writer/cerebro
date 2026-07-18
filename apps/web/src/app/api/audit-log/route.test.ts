import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { GET } from "./route";

describe("audit log compatibility route", () => {
  it("forwards portable filters through the authenticated Cerebro proxy", () => {
    const response = GET(new NextRequest("http://localhost/api/audit-log?minutes=60&status=failed"));

    expect(response.status).toBe(307);
    expect(response.headers.get("location")).toBe(
      "http://localhost/api/cerebro/grc/audit-log?minutes=60&status=failed",
    );
  });
});

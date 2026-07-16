import { describe, expect, it } from "vitest";

import { currentUserServerAuditFields } from "./identity-server";
import type { CurrentUser } from "./identity";

const testUser: CurrentUser = {
  actorId: "user-123",
  actorLabel: "test@example.com",
  confidence: "trusted-proxy",
  displayName: "Test User",
  initials: "TU",
  email: "test@example.com",
  provider: "okta",
  source: "headers",
  entitlements: {
    groups: ["engineering"],
    roles: ["cerebro.viewer"],
    scopes: [],
  },
};

describe("currentUserServerAuditFields", () => {
  it("includes a truncated actor key hash", () => {
    const fields = currentUserServerAuditFields(testUser);
    expect(fields.actorKey).toHaveLength(16);
    expect(fields.actorKey).toMatch(/^[0-9a-f]{16}$/);
  });

  it("produces stable hashes for the same user", () => {
    const a = currentUserServerAuditFields(testUser);
    const b = currentUserServerAuditFields(testUser);
    expect(a.actorKey).toBe(b.actorKey);
  });

  it("produces different hashes for different actors", () => {
    const other = { ...testUser, actorId: "user-456", actorLabel: "other@example.com" };
    expect(currentUserServerAuditFields(testUser).actorKey).not.toBe(
      currentUserServerAuditFields(other).actorKey,
    );
  });

  it("returns empty actor key for null user", () => {
    const fields = currentUserServerAuditFields(null);
    expect(fields.actorKey).toBe("");
    expect(fields.actorIdPresent).toBe(false);
    expect(fields.actorLabelPresent).toBe(false);
  });

  it("includes presence flags and base audit fields", () => {
    const fields = currentUserServerAuditFields(testUser);
    expect(fields.actorIdPresent).toBe(true);
    expect(fields.actorLabelPresent).toBe(true);
    expect(fields.authenticated).toBe(true);
    expect(fields.confidence).toBe("trusted-proxy");
  });
});

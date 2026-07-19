import { describe, expect, it } from "vitest";

import {
  identityOrganizationsPath,
  identityProviderLabel,
  identitySourceLabel,
  identityUsersPath,
  normalizeIdentityOrganizationSort,
  normalizeIdentityOrganizationsResponse,
  normalizeIdentityUserSort,
  normalizeIdentityUsersResponse,
  sortIdentityOrganizations,
  sortIdentityUsers,
} from "./identity-directory";

describe("identity directory", () => {
  it("normalizes organization responses and drops unusable rows", () => {
    const response = normalizeIdentityOrganizationsResponse({
      tenant_id: " tenant-a ",
      organizations: [
        {
          org_id: " tenant-a ",
          tenant_id: " tenant-a ",
          name: " Tenant A ",
          provider: " okta ",
          source: "mcp_oauth",
          user_count: "4",
          last_synced_at: "2026-06-28T12:00:00Z",
        },
        { org_id: "", tenant_id: "tenant-a", name: "missing id" },
      ],
      meta: { limit: "200", loaded: 2, configured: 1, persisted: 1 },
    });

    expect(response.tenant_id).toBe("tenant-a");
    expect(response.organizations).toEqual([
      expect.objectContaining({
        org_id: "tenant-a",
        tenant_id: "tenant-a",
        name: "Tenant A",
        provider: "okta",
        source: "mcp_oauth",
        user_count: 4,
      }),
    ]);
    expect(response.meta).toEqual({ limit: 200, loaded: 2, configured: 1, persisted: 1 });
  });

  it("normalizes users with roles, groups, and fallback display names", () => {
    const response = normalizeIdentityUsersResponse({
      users: [
        {
          user_id: "00u123",
          tenant_id: "tenant-a",
          org_id: "tenant-a",
          email: "person@example.com",
          provider: "okta",
          source: "mcp_oauth",
          roles: ["cerebro.viewer", "cerebro.viewer", ""],
          groups: ["security-team", " security-team "],
        },
      ],
    });

    expect(response.users).toEqual([
      expect.objectContaining({
        user_id: "00u123",
        display_name: "person@example.com",
        roles: ["cerebro.viewer"],
        groups: ["security-team"],
        status: "active",
      }),
    ]);
    expect(response.meta.limit).toBe(100);
  });

  it("builds backend paths and labels auth sources", () => {
    expect(identityOrganizationsPath({ tenantID: "tenant-a", provider: "okta", source: "mcp_oauth_client", status: "active", query: "okta", limit: 50 })).toBe("/identity/orgs?tenant_id=tenant-a&provider=okta&source=mcp_oauth_client&q=okta&limit=50");
    expect(identityUsersPath({ tenantID: "tenant-a", orgID: "tenant-a", provider: "okta", source: "mcp_oauth", status: "active", query: "person" })).toBe("/identity/users?tenant_id=tenant-a&org_id=tenant-a&provider=okta&source=mcp_oauth&status=active&q=person");
    expect(identitySourceLabel("mcp_oauth_client")).toBe("OAuth client");
    expect(identityProviderLabel("okta")).toBe("Okta");
  });

  it("sorts organizations for table views", () => {
    const organizations = normalizeIdentityOrganizationsResponse({
      organizations: [
        { org_id: "beta", tenant_id: "tenant-a", name: "Beta", source: "identity_directory", user_count: 2, last_synced_at: "2026-06-01T00:00:00Z" },
        { org_id: "alpha", tenant_id: "tenant-a", name: "Alpha", provider: "okta", source: "mcp_oauth_client", user_count: 5, last_synced_at: "2026-06-03T00:00:00Z" },
        { org_id: "gamma", tenant_id: "tenant-a", name: "Gamma", source: "api_key", user_count: 5 },
      ],
    }).organizations;

    expect(sortIdentityOrganizations(organizations, "name").map((org) => org.org_id)).toEqual(["alpha", "beta", "gamma"]);
    expect(sortIdentityOrganizations(organizations, "users").map((org) => org.org_id)).toEqual(["alpha", "gamma", "beta"]);
    expect(sortIdentityOrganizations(organizations, "last_synced").map((org) => org.org_id)).toEqual(["alpha", "beta", "gamma"]);
    expect(normalizeIdentityOrganizationSort("unknown")).toBe("name");
  });

  it("sorts users for table views", () => {
    const users = normalizeIdentityUsersResponse({
      users: [
        { user_id: "u2", tenant_id: "tenant-a", display_name: "Bailey", status: "inactive", source: "api_key", roles: [], groups: [], last_seen_at: "2026-06-01T00:00:00Z" },
        { user_id: "u1", tenant_id: "tenant-a", display_name: "Avery", status: "active", provider: "okta", source: "mcp_oauth", roles: [], groups: [], last_seen_at: "2026-06-03T00:00:00Z" },
        { user_id: "u3", tenant_id: "tenant-a", display_name: "Casey", status: "active", source: "identity_directory", roles: [], groups: [] },
      ],
    }).users;

    expect(sortIdentityUsers(users, "last_seen").map((user) => user.user_id)).toEqual(["u1", "u2", "u3"]);
    expect(sortIdentityUsers(users, "name").map((user) => user.user_id)).toEqual(["u1", "u2", "u3"]);
    expect(sortIdentityUsers(users, "status").map((user) => user.user_id)).toEqual(["u1", "u3", "u2"]);
    expect(normalizeIdentityUserSort("unknown")).toBe("last_seen");
  });
});

import { describe, expect, it } from "vitest";

import {
  authorizationRoleLabelsForUser,
  effectiveAuthorizationPermissionsForUser,
  hasExplicitCerebroRoleOrScope,
  authorizationRoleCatalog,
  parseRoleClaimMappings,
  permissionForCerebroProxyRequest,
  rolesFromClaimMappings,
} from "./rbac";
import type { CurrentUser } from "./identity";

const user = (roles: string[] = [], scopes: string[] = []): CurrentUser => ({
  actorId: "subject-1",
  actorLabel: "person@example.com",
  confidence: "signature-verified",
  displayName: "Person Example",
  entitlements: { roles, scopes },
  initials: "PE",
  provider: "okta",
  source: "jwt",
  subject: "subject-1",
});

describe("RBAC permissions", () => {
  it("expands Cerebro roles into effective permissions", () => {
    expect(effectiveAuthorizationPermissionsForUser(user(["cerebro.connector_manager"]))).toEqual([
      "identity:read",
      "agent:ask",
      "cerebro:read",
      "preferences:write",
      "connector-credentials:read",
      "connector-credentials:write",
      "connector-definitions:write",
      "connectors:write",
    ]);
    expect(authorizationRoleLabelsForUser(user(["viewer", "cerebro.viewer", "owner"]))).toEqual([
      "cerebro.viewer",
      "cerebro.admin",
    ]);
  });

  it("expands backend scopes into web permissions", () => {
    expect(effectiveAuthorizationPermissionsForUser(user([], [
      "cerebro.cosmo.security.read",
      "cerebro.user_preferences.write",
      "cerebro.dashboards.write",
      "cerebro.grc.policy_lifecycle.write",
      "cerebro.runtime_response.write",
      "cerebro.source_runtimes.write",
    ]))).toEqual([
      "identity:read",
      "agent:ask",
      "cerebro:read",
      "preferences:write",
      "grc:policies:write",
      "dashboards:write",
      "runtime-response:write",
      "source-runtimes:write",
    ]);
  });

  it.each(["constructor", "__proto__"])("ignores inherited entitlement bundle name %s", (name) => {
    const currentUser = user([name], [name]);

    expect(effectiveAuthorizationPermissionsForUser(currentUser)).toEqual([]);
    expect(hasExplicitCerebroRoleOrScope(currentUser)).toBe(false);
  });
});

describe("Cerebro proxy route permissions", () => {
  it("rejects paths whose dot segments would change the forwarded target", () => {
    expect(() => permissionForCerebroProxyRequest("GET", "other/../sources/preview")).toThrow(/dot segments/);
  });

  it("keeps read and ask routes read-scoped", () => {
    expect(permissionForCerebroProxyRequest("GET", "findings/finding-1")).toBe("cerebro:read");
    expect(permissionForCerebroProxyRequest("GET", "user/preferences")).toBe("cerebro:read");
    expect(permissionForCerebroProxyRequest("POST", "grc/ask")).toBe("agent:ask");
    expect(permissionForCerebroProxyRequest("POST", "grc/control-packs/aws")).toBe("cerebro:read");
  });

  it("maps sensitive write families to dedicated permissions", () => {
    expect(permissionForCerebroProxyRequest("GET", "connectors/github/credentials")).toBe("connector-credentials:read");
    expect(permissionForCerebroProxyRequest("POST", "connectors/github/credentials")).toBe("connector-credentials:write");
    expect(permissionForCerebroProxyRequest("POST", "connectors/custom/deposits")).toBe("connectors:write");
    expect(permissionForCerebroProxyRequest("POST", "connector-definitions/plan")).toBe("connector-definitions:write");
    expect(permissionForCerebroProxyRequest("POST", "connector-definitions/preview")).toBe("connector-definitions:write");
    expect(permissionForCerebroProxyRequest("POST", "connector-definitions/github/promote")).toBe("connector-definitions:write");
    expect(permissionForCerebroProxyRequest("POST", "source-runtimes/runtime-1/sync")).toBe("source-runtimes:write");
    expect(permissionForCerebroProxyRequest("PUT", "source-runtimes/runtime-1")).toBe("source-runtimes:write");
    expect(permissionForCerebroProxyRequest("POST", "platform/jobs/job-1/cancel")).toBe("jobs:write");
    expect(permissionForCerebroProxyRequest("POST", "platform/workflow/replay")).toBe("workflow:replay");
  });

  it("maps finding, report, GRC, and response writes", () => {
    expect(permissionForCerebroProxyRequest("POST", "finding-candidates/candidate-1/promote")).toBe("findings:write");
    expect(permissionForCerebroProxyRequest("PUT", "findings/finding-1/assign")).toBe("findings:write");
    expect(permissionForCerebroProxyRequest("POST", "reports/aws-soc2/runs")).toBe("reports:run");
    expect(permissionForCerebroProxyRequest("PATCH", "grc/inventory/asset-reports/report-1/triage")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendors")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/process")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/assignments")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/questions")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/vendor-link")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/decisions")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/questionnaire-runs/run-1/comments")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendors/urn%3Acerebro%3Ademo%3Avendor%3Aone/actions")).toBe("cerebro:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendor-discoveries/discovery-1/decision")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/policy-lifecycle/actions")).toBe("grc:policies:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/policy-lifecycle/uploads")).toBe("grc:policies:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/policy-lifecycle/uploads/upload-1/replay")).toBe("grc:policies:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendors/uploads")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendors/uploads/upload-1/replay")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/dashboards")).toBe("dashboards:write");
    expect(permissionForCerebroProxyRequest("PATCH", "grc/dashboards/dashboard-1")).toBe("dashboards:write");
    expect(permissionForCerebroProxyRequest("DELETE", "grc/dashboards/dashboard-1")).toBe("dashboards:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/dashboards/dashboard-1/clone")).toBe("dashboards:write");
    expect(permissionForCerebroProxyRequest("POST", "platform/runtime-response/actions")).toBe("runtime-response:write");
    expect(permissionForCerebroProxyRequest("PUT", "user/preferences")).toBe("preferences:write");
  });
});

describe("claim to role mappings", () => {
  const groupUser = (groups: string[]): CurrentUser => ({
    actorId: "subject-2",
    actorLabel: "person@example.com",
    confidence: "trusted-proxy",
    displayName: "Person Example",
    entitlements: { groups },
    initials: "PE",
    provider: "alb-oidc",
    source: "headers",
    subject: "subject-2",
  });

  it("grants no roles when nothing is configured", () => {
    expect(parseRoleClaimMappings(undefined)).toEqual([]);
    expect(rolesFromClaimMappings(groupUser(["Security Team"]), [])).toEqual([]);
  });

  it("maps a group claim onto a role and its permissions", () => {
    const mappings = parseRoleClaimMappings(
      JSON.stringify({ groups: { "Security Team": ["cerebro.viewer"] } }),
    );
    expect(rolesFromClaimMappings(groupUser(["Security Team"]), mappings)).toEqual(["cerebro.viewer"]);
  });

  it("matches group values case insensitively", () => {
    const mappings = parseRoleClaimMappings(
      JSON.stringify({ groups: { "security team": ["cerebro.analyst"] } }),
    );
    expect(rolesFromClaimMappings(groupUser(["Security Team"]), mappings)).toEqual(["cerebro.analyst"]);
  });

  it("grants nothing for an unmatched group", () => {
    const mappings = parseRoleClaimMappings(
      JSON.stringify({ groups: { "CEREBRO Admins": ["cerebro.admin"] } }),
    );
    expect(rolesFromClaimMappings(groupUser(["Security Team"]), mappings)).toEqual([]);
  });

  it("ignores roles that are not real bundles so a typo grants nothing", () => {
    const mappings = parseRoleClaimMappings(
      JSON.stringify({ groups: { "Security Team": ["cerebro.superuser"] } }),
    );
    expect(mappings).toEqual([]);
  });

  it("returns no mappings for unparseable configuration", () => {
    expect(parseRoleClaimMappings("{not json")).toEqual([]);
    expect(parseRoleClaimMappings("[]")).toEqual([]);
  });

  it("resolves permissions from a mapped group claim", () => {
    process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS = JSON.stringify({
      groups: { "Security Team": ["cerebro.viewer"] },
    });
    try {
      expect(effectiveAuthorizationPermissionsForUser(groupUser(["Security Team"]))).toEqual([
        "identity:read",
        "agent:ask",
        "cerebro:read",
        "preferences:write",
      ]);
    } finally {
      delete process.env.CEREBRO_AUTHZ_ROLE_CLAIM_MAPPINGS;
    }
  });

  it("resolves no permissions from a group claim when mappings are absent", () => {
    expect(effectiveAuthorizationPermissionsForUser(groupUser(["Security Team"]))).toEqual([]);
  });

  it("gives the admin role every permission including admin:read", () => {
    const admin = authorizationRoleCatalog().find((entry) => entry.role === "cerebro.admin");
    expect(admin?.permissions).toContain("admin:read");
    const viewer = authorizationRoleCatalog().find((entry) => entry.role === "cerebro.viewer");
    expect(viewer?.permissions).not.toContain("admin:read");
  });
});

describe("role catalog descriptions", () => {
  it("describes every role so an opaque name is explained in the console", () => {
    const undescribed = authorizationRoleCatalog().filter((entry) => !entry.description.trim());
    expect(undescribed.map((entry) => entry.role)).toEqual([]);
  });

  it("says what the responder role actually does", () => {
    const responder = authorizationRoleCatalog().find((entry) => entry.role === "cerebro.responder");
    expect(responder?.description).toContain("runtime response");
    expect(responder?.permissions).toContain("runtime-response:write");
    expect(responder?.permissions).not.toContain("findings:write");
  });
});

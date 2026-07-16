import { describe, expect, it } from "vitest";

import {
  authorizationRoleLabelsForUser,
  effectiveAuthorizationPermissionsForUser,
  permissionForCerebroProxyRequest,
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
});

describe("Cerebro proxy route permissions", () => {
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
    expect(permissionForCerebroProxyRequest("POST", "grc/vendors/urn%3Acerebro%3Ademo%3Avendor%3Aone/actions")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendor-discoveries/discovery-1/decision")).toBe("grc:inventory:write");
    expect(permissionForCerebroProxyRequest("POST", "grc/vendor-discoveries/sync")).toBe("grc:inventory:write");
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

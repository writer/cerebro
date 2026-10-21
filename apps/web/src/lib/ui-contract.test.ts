import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import { describe, expect, it } from "vitest";

import { BANNED_PRODUCT_UI_PATTERNS, PRODUCT_UI_CONTRACT_VERSION, REQUIRED_DEVELOPER_UTILITY_LABELS } from "./product-ui-contract";

const projectPath = (...parts: string[]) => join(process.cwd(), ...parts);
const sourceRoot = projectPath("src");

const sourceFiles = (directory: string): string[] =>
  readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(fullPath);
    if (!/\.(ts|tsx)$/.test(entry.name) || entry.name.includes(".test.")) return [];
    return [fullPath];
  });

const readProjectFile = (...parts: string[]) => readFileSync(projectPath(...parts), "utf8");

describe("product UI contract", () => {
  it("keeps repository process metadata out of product source", () => {
    const offenders = sourceFiles(sourceRoot).flatMap((file) => {
      const source = readFileSync(file, "utf8");
      return BANNED_PRODUCT_UI_PATTERNS
        .filter((pattern) => pattern.test(source))
        .map((pattern) => `${relative(process.cwd(), file)}: ${pattern}`);
    });

    expect(offenders).toEqual([]);
  });

  it("keeps removed topology explainer routes and data modules absent", () => {
    expect(existsSync(projectPath("src/app/developer/repository-split/page.tsx"))).toBe(false);
    expect(existsSync(projectPath("src/lib/repository-split.ts"))).toBe(false);
  });

  it("keeps developer utilities focused on supported tools", () => {
    const source = readProjectFile("src/app/developer/page.tsx");

    expect(PRODUCT_UI_CONTRACT_VERSION).toBe("2026-06-16.agent-platform");
    expect(source).toContain("Developer Utilities");
    for (const label of REQUIRED_DEVELOPER_UTILITY_LABELS) {
      expect(source).toContain(label);
    }
    expect(source).not.toMatch(/repository[\s_-]+split/i);
  });

  it("keeps the topbar avatar bound to current user identity", () => {
    const source = readProjectFile("src/components/Topbar.tsx");
    const dismissalSource = readProjectFile("src/lib/use-popover-dismissal.ts");

    expect(source).toContain("useCurrentUser");
    expect(source).toContain("topbarRef");
    expect(source).toContain("usePopoverDismissal");
    expect(dismissalSource).toContain('event.key === "Escape"');
    expect(dismissalSource).toContain('document.addEventListener("pointerdown"');
    expect(source).toContain("identityPosture");
    expect(source).toContain("identity.initials");
    expect(source).toContain("View identity contract");
    expect(source).toContain("currentUserWriteFieldForPath");
    expect(source).not.toMatch(/>\s*(CB|JH)\s*</);
    expect(source).not.toMatch(/const\s+userInitials\s*=\s*["'`](CB|JH)["'`]/);
  });

  it("keeps global startup work bounded until the operator requests it", () => {
    const developerSource = readProjectFile("src/app/developer/page.tsx");
    const providersSource = readProjectFile("src/components/providers.tsx");
    const sidebarSource = readProjectFile("src/components/Sidebar.tsx");
    const statusSource = readProjectFile("src/components/StatusPanel.tsx");
    const topbarSource = readProjectFile("src/components/Topbar.tsx");

    expect(topbarSource).toContain("notificationsRequested && !invalidNotificationScope");
    expect(topbarSource).toContain("grcDashboardPath({");
    expect(topbarSource).toContain('grcPath("/report-runs"');
    expect(topbarSource).toContain("onFocus={() => setNotificationsRequested(true)}");
    expect(topbarSource).toContain("onMouseEnter={() => setNotificationsRequested(true)}");
    expect(topbarSource).not.toContain("showNotifications ? grcDashboardPath");
    expect(topbarSource).not.toContain("showNotifications ? grcPath");
    expect(topbarSource).not.toContain('fetch("/api/config"');
    expect(statusSource).not.toContain('fetch("/api/config"');
    expect(providersSource.match(/fetch\("\/api\/config"/g)).toHaveLength(1);
    expect(sidebarSource).toContain("prefetch={false}");
    expect(developerSource.match(/prefetch=\{false\}/g)).toHaveLength(2);
  });

  it("keeps identity and API recovery diagnostics in developer-owned surfaces", () => {
    expect(existsSync(projectPath("src/app/developer/identity/page.tsx"))).toBe(true);
    expect(existsSync(projectPath("src/lib/identity.ts"))).toBe(true);
    expect(existsSync(projectPath("src/lib/runtime-state.ts"))).toBe(true);

    const developerSource = readProjectFile("src/app/developer/page.tsx");
    const identityPanelSource = readProjectFile("src/components/identity/IdentityContractPanel.tsx");
    const primitivesSource = readProjectFile("src/components/grc/Primitives.tsx");
    const runtimeStateSource = readProjectFile("src/lib/runtime-state.ts");
    const statusSource = readProjectFile("src/components/StatusPanel.tsx");

    expect(developerSource).toContain("IdentityContractPanel");
    expect(identityPanelSource).toContain("Write Stamps");
    expect(identityPanelSource).toContain("currentUserWriteFieldForPath");
    expect(statusSource).toContain("Runtime Health");
    expect(statusSource).toContain("API liveness");
    expect(statusSource).toContain("API readiness");
    expect(statusSource).toContain("Rust source runtime");
    expect(statusSource).not.toContain('withGRCScope("/api/cerebro/v1/actions?limit=1"');
    expect(statusSource).toContain("Inventory");
    expect(statusSource).toContain("Vendor register");
    expect(statusSource).toContain("Policy lifecycle");
    expect(statusSource).toContain("LIVENESS_TIMEOUT_MS");
    expect(statusSource).toContain("PRODUCT_READ_TIMEOUT_MS");
    expect(statusSource).toContain("GRC_QUERY_TIMEOUT_MS");
    expect(statusSource).not.toContain("/api/cerebro/grc/dashboard");
    expect(primitivesSource).toContain("DataStateBanner");
    expect(primitivesSource).toContain("data-grc-data-state");
    expect(primitivesSource).toContain("RuntimeRecoveryBlock");
    expect(primitivesSource).toContain("/developer#quick-status");
    expect(runtimeStateSource).toContain("API unavailable");
    expect(runtimeStateSource).toContain("runtimeStateForQuery");
    expect(runtimeStateSource).toContain("metricDetailForState");
  });

  it("keeps data-page metrics and filters tied to runtime state", () => {
    const dataTableSource = readProjectFile("src/components/grc/DataTable.tsx");
    const layoutSource = readProjectFile("src/app/layout.tsx");
    const queryParamSource = readProjectFile("src/lib/query-params.ts");
    const primitivesSource = readProjectFile("src/components/grc/Primitives.tsx");
    const bannerPages = [
      "src/app/risks/page.tsx",
    ];

    expect(layoutSource).toContain("NuqsAdapter");
    expect(queryParamSource).toContain("useQueryState");
    expect(queryParamSource).toContain("parseAsString.withDefault");
    expect(queryParamSource).not.toContain("window.history.replaceState");
    expect(dataTableSource).toContain("useReactTable");
    expect(dataTableSource).toContain("useVirtualizer");
    expect(primitivesSource).toContain("AppliedFilterChips");
    expect(primitivesSource).toContain("state?: RuntimeState");

    for (const page of bannerPages) {
      const source = readProjectFile(page);
      expect(source).toContain("AppliedFilterChips");
      expect(source).toContain("DataStateBanner");
      expect(source).toContain("queryState");
      expect(source).toContain("lastSuccessfulAt");
      expect(source).toMatch(/state(?:=\{|:)\s*metricState/);
    }

    for (const page of ["src/app/page.tsx", "src/app/explore/page.tsx", "src/app/findings/[id]/page.tsx"]) {
      expect(readProjectFile(page)).toContain("DataStateBanner");
    }

    const inventorySource = readProjectFile("src/components/inventory/InventoryWorkspace.tsx");
    expect(inventorySource).toContain("AppliedFilterChips");
    expect(inventorySource).toContain("metricValueForState");
    expect(inventorySource).toContain("metricDetailForState");
    expect(inventorySource).toContain('data-testid="inventory-results"');
    // Inventory is a search surface: the query reaches the catalog and the page says what it covers.
    expect(inventorySource).toContain("q: debouncedQuery");
    expect(inventorySource).toContain("every attribute collected from the source");
    expect(inventorySource).toContain("inventoryMetadataMatch");
    // Review disposition, owner accountability and compliance scope belong to the risk and compliance pages.
    expect(inventorySource).not.toContain("Needs review");
    expect(inventorySource).not.toContain('data-label="Accountability"');
    expect(inventorySource).not.toContain("review_state");

    const inventoryDetailSource = readProjectFile("src/app/inventory/[urn]/page.tsx");
    expect(inventoryDetailSource).toContain('role="tablist"');
    expect(inventoryDetailSource).toContain("min-w-max");
    expect(inventoryDetailSource).toContain("Load relationships");

    const reportsSource = readProjectFile("src/app/reports/page.tsx");
    expect(reportsSource).toContain("AppliedFilterChips");
    expect(reportsSource).not.toContain("applyScope");
  });

  it("keeps integration tiles ahead of operator diagnostics", () => {
    const source = readProjectFile("src/app/integrations/page.tsx");
    const page = source.slice(source.indexOf("export default function IntegrationsPage"));
    const advancedTools = page.indexOf("Advanced integration tools");

    expect(page).toContain("Add Integration");
    expect(page).toContain("Search integrations");
    expect(page).toContain("runtimeStateForError");
    expect(page.indexOf("IntegrationTile")).toBeGreaterThan(0);
    expect(page.indexOf("IntegrationTile")).toBeLessThan(advancedTools);
    expect(page.indexOf("ProviderAPIProofPanel")).toBeGreaterThan(advancedTools);
    expect(page.indexOf("CustomIntegrationsPanel")).toBeGreaterThan(advancedTools);
    // A single-team console: no tenant filter, no request-access path, and the
    // product word is "integration", not "source".
    expect(source).not.toContain("tenant_id");
    expect(source).not.toMatch(/Request access|request_access_url/i);
    expect(source).not.toMatch(/>[^<{]*\bsources?\b[^<{]*</i);
  });

  it("uses the Rust source-runtime readiness contract for the integration presentation", () => {
    const page = readProjectFile("src/app/integrations/page.tsx");
    const runtime = readProjectFile("src/lib/connector-runtime.ts");

    expect(page).toContain('withQuery("/v1/source-runtimes/health"');
    expect(page).toContain("normalizeSourceRuntimeSummary");
    expect(page).not.toContain("sourceHealthBreakdown");
    expect(runtime).toContain('stringField(runtime, ["readiness"])');
    expect(runtime).toContain('stringField(summary, ["readiness"])');
    expect(runtime).not.toContain("const sourceReadiness =");
  });

  it("guards Explore expansion responses against a changed scope", () => {
    const page = readProjectFile("src/app/explore/page.tsx");

    expect(page).toContain("const requestScopeKey = activeScopeKey");
    expect(page).toContain("activeScopeKeyRef.current !== requestScopeKey");
    expect(page).toContain("activeScopeKeyRef.current === requestScopeKey");
    expect(page).toContain("setExpandingURN(null);");
  });

  it("opens the graph on named viewpoints instead of an empty seed box", () => {
    const page = readProjectFile("src/app/explore/page.tsx");

    expect(page).toContain("graphViewpointList");
    expect(page).toContain("graphPathRowsToGraph");
    expect(page).toContain('aria-pressed={active}');
    // A path set is only evidence if the page says which revision it was read at and what proved each hop.
    expect(page).toContain("Read at graph revision");
    expect(page).toContain("proof edge");
    expect(page).toContain("No proof edges returned");
    // The viewpoints must stay server-side reads; the page must not re-derive paths from a neighbourhood crawl.
    expect(page).not.toContain("attack path heuristic");

    const viewpoints = readProjectFile("src/lib/graph-viewpoints.ts");
    expect(viewpoints).toContain("cerebro.graph.v1.OrganizationalGraphService");
    expect(viewpoints).toContain("ListEffectiveAccessPaths");
    expect(viewpoints).toContain("ListCloudAttackPaths");

    // Connect unary reads arrive as POST and must not be charged write permission.
    const rbac = readProjectFile("src/lib/rbac.ts");
    expect(rbac).toContain("ListCloudAttackPaths");
    expect(rbac).toMatch(/readOnlyPostPaths[\s\S]{0,600}ListPersonAccessPaths/);
  });

  it("carries the findings join on the graph page rather than a separate affected-assets page", () => {
    const page = readProjectFile("src/app/explore/page.tsx");

    // The impact read is what joins findings and evidence counts to one entity.
    expect(page).toContain("grcEntityImpactPath");
    expect(page).toContain("Findings on This Entity");
    expect(page).toContain("<FindingTable");
    // Findings come from the Go impact read and must not wait on the Rust neighbourhood graph.
    expect(page).toMatch(/\{selectedSeed && \([\s\S]{0,400}Findings on This Entity/);
    // The backend canonicalizes the requested URN, so the page must name the URN it actually read.
    expect(page).toContain("Read against the canonical URN");

    // The retired page must not come back as a second destination for the same question.
    expect(() => readProjectFile("src/app/impact/page.tsx")).toThrow();
    for (const file of [
      "src/lib/routes.ts",
      "src/lib/entity-chip.ts",
      "src/lib/information-areas.ts",
      "src/components/Sidebar.tsx",
      "src/components/CommandPalette.tsx",
      "src/components/grc/GraphViewer.tsx",
    ]) {
      expect(readProjectFile(file), `${file} still links the retired page`).not.toMatch(/["'`]\/impact\b/);
    }
  });

  it("keeps compliance limited to framework mapping", () => {
    for (const page of [
      "src/app/controls/builder/page.tsx",
      "src/app/controls/detail/page.tsx",
      "src/app/evidence/page.tsx",
      "src/app/policies/page.tsx",
      "src/app/questionnaires/page.tsx",
      "src/app/reports/packages/page.tsx",
      "src/app/vendors/page.tsx",
      "src/app/vendors/[urn]/page.tsx",
    ]) {
      expect(existsSync(projectPath(page)), page).toBe(false);
    }
  });

  it("keeps Ask readiness public-safe and visible before a question runs", () => {
    const routeSource = readProjectFile("src/app/api/agent/ask/status/route.ts");
    const providerSource = readProjectFile("src/components/agent/CerebroAgentProvider.tsx");
    const panelSource = readProjectFile("src/components/agent/CerebroAgentPanel.tsx");

    expect(routeSource).toContain("askAgentReadiness");
    expect(routeSource).toContain("NextResponse.json");
    expect(providerSource).toContain("/api/agent/ask/status");
    expect(panelSource).toContain("readinessLoading");
    expect(panelSource).toContain("Ask path unavailable");
    expect(panelSource).not.toMatch(/env|token|credential|not configured/i);
  });

  it("keeps command palette page actions ahead of unavailable live search", () => {
    const source = readProjectFile("src/components/CommandPalette.tsx");

    expect(source).toContain("return [...generated, ...orderedNavigation, ...liveSearch.commands]");
    expect(source).toContain("Page actions are ready. Searching live data...");
  });

  // Pass/fail posture needs per-control evaluation the API does not expose yet,
  // so compliance pages must only claim violations they can see in open findings.
  it("keeps compliance pages scoped to enabled frameworks and finding violations", () => {
    const complianceSource = readProjectFile("src/app/grc/page.tsx");
    const frameworkSource = readProjectFile("src/app/frameworks/[frameworkID]/page.tsx");

    expect(complianceSource).toContain("FRAMEWORK_SETTINGS_PATH");
    expect(complianceSource).toContain("enabledFrameworks(");
    for (const source of [complianceSource, frameworkSource]) {
      expect(source).toContain("controlViolations(");
      expect(source).not.toContain("passing_controls");
      expect(source).not.toContain("deriveFrameworkReadiness");
    }
  });

  // Compliance reporting is owned by a dedicated tool, so the operator home
  // must not grow an audit-readiness surface again.
  it("keeps the security overview on risk rather than audit readiness", () => {
    const overviewSource = readProjectFile("src/app/page.tsx");

    expect(overviewSource).toContain("data?.coverage_blind_spots");
    expect(overviewSource).toContain("data?.coverage_summaries");
    expect(overviewSource).toContain('coverage_view: "page"');
    expect(overviewSource).toContain("coverageSummaries.reduce");
    expect(overviewSource).toContain("/grc/trends");
    expect(overviewSource).not.toContain("passing_controls");
    expect(overviewSource).not.toContain("Export audit packet");
    expect(overviewSource).not.toContain("audit-packages");
    expect(overviewSource).not.toContain("sampled dashboard values");
    expect(overviewSource).not.toContain("sampled total");
  });

  it("keeps graph zoom on the Cytoscape default wheel behavior", () => {
    const graphSource = readProjectFile("src/components/grc/GraphViewer.tsx");

    expect(graphSource).not.toContain("wheelSensitivity");
  });
});

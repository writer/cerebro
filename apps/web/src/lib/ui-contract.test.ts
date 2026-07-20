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
      "src/app/evidence/page.tsx",
      "src/app/controls/page.tsx",
      "src/app/risk-inbox/page.tsx",
    ];
    const runtimePages = [
      "src/app/connectors/page.tsx",
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

    for (const page of runtimePages) {
      const source = readProjectFile(page);
      expect(source).toContain("AppliedFilterChips");
      expect(source).toContain("runtimeStateForError");
      expect(source).toMatch(/state(?:=\{|:)\s*metricState/);
    }

    for (const page of ["src/app/page.tsx", "src/app/explore/page.tsx", "src/app/findings/[id]/page.tsx"]) {
      expect(readProjectFile(page)).toContain("DataStateBanner");
    }

    const inventorySource = readProjectFile("src/app/inventory/page.tsx");
    expect(inventorySource).toContain("AppliedFilterChips");
    expect(inventorySource).toContain("metricValueForState");
    expect(inventorySource).toContain("metricDetailForState");

    const reportsSource = readProjectFile("src/app/reports/page.tsx");
    expect(reportsSource).toContain("AppliedFilterChips");
    expect(reportsSource).not.toContain("applyScope");
  });

  it("keeps Ask readiness public-safe and visible before a question runs", () => {
    const routeSource = readProjectFile("src/app/api/agent/ask/status/route.ts");
    const pageSource = readProjectFile("src/app/ask/page.tsx");
    const inputSource = readProjectFile("src/components/ask/AskInput.tsx");

    expect(routeSource).toContain("askAgentReadiness");
    expect(routeSource).toContain("NextResponse.json");
    expect(pageSource).toContain("/api/agent/ask/status");
    expect(inputSource).toContain("useForm");
    expect(inputSource).toContain("Checking Ask path");
    expect(inputSource).not.toMatch(/env|token|credential|not configured/i);
  });

  it("keeps command palette page actions ahead of unavailable live search", () => {
    const source = readProjectFile("src/components/CommandPalette.tsx");

    expect(source).toContain("return [...generated, ...orderedNavigation, ...liveSearch.commands]");
    expect(source).toContain("Page actions are ready. Searching live data...");
  });

  it("keeps overview audit readiness fallbacks dashboard-backed instead of sample-labeled", () => {
    const overviewSource = readProjectFile("src/app/page.tsx");

    expect(overviewSource).toContain("data?.coverage_blind_spots");
    expect(overviewSource).toContain("data?.coverage_summaries");
    expect(overviewSource).toContain('coverage_view: "page"');
    expect(overviewSource).toContain("coverageSummaries.reduce");
    expect(overviewSource).toContain("dashboardBackedReadiness");
    expect(overviewSource).not.toContain("sampled dashboard values");
    expect(overviewSource).not.toContain("sampled total");
  });

  it("keeps graph zoom on the Cytoscape default wheel behavior", () => {
    const graphSource = readProjectFile("src/components/grc/GraphViewer.tsx");

    expect(graphSource).not.toContain("wheelSensitivity");
  });
});

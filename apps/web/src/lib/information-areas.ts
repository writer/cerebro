import { navigationEntries } from "@/lib/routes";

export type InformationAreaID = "risks" | "controls" | "sources" | "reports";

export type InformationAreaRoute = {
  href: string;
  label: string;
  detail: string;
};

export type InformationSignalKey =
  | "activeRisk"
  | "auditReadiness"
  | "controlFailures"
  | "coverageGaps"
  | "evidenceIssues"
  | "highImpact"
  | "ownerGaps"
  | "sourceTrust";

export type InformationAreaSignal = {
  key: InformationSignalKey;
  label: string;
  href: string;
};

export type InformationAreaWorkQueue = {
  title: string;
  description: string;
  actionLabel: string;
  actionHref: string;
  empty: string;
};

export type InformationArea = {
  id: InformationAreaID;
  label: string;
  shortLabel: string;
  tagline: string;
  description: string;
  searchPlaceholder: string;
  priorities: string[];
  headline: string;
  summaryFocus: string[];
  signals: InformationAreaSignal[];
  workQueue: InformationAreaWorkQueue;
  primaryRoutes: InformationAreaRoute[];
  secondaryRoutes: InformationAreaRoute[];
};

export const DEFAULT_INFORMATION_AREA_ID: InformationAreaID = "risks";

export const informationAreas: InformationArea[] = [
  {
    id: "risks",
    label: "Risks",
    shortLabel: "Risks",
    tagline: "Risks, owners, evidence, and affected assets.",
    description: "Open risks, evidence, affected assets, owners, due dates, and source freshness.",
    searchPlaceholder: "Search risks, owners, evidence, assets...",
    priorities: ["Critical/high risks", "Affected assets", "Owners and due dates", "Evidence"],
    headline: "active risks need attention",
    summaryFocus: ["critical and high risk", "owners and due dates", "evidence"],
    signals: [
      { key: "activeRisk", label: "Active risks", href: "/risk-inbox" },
      { key: "highImpact", label: "Critical/high", href: "/risk-inbox?severity=CRITICAL" },
      { key: "ownerGaps", label: "No owner", href: "/risk-inbox?owner=unassigned" },
      { key: "evidenceIssues", label: "Evidence issues", href: "/evidence" },
      { key: "sourceTrust", label: "Stale sources", href: "/connectors" },
      { key: "coverageGaps", label: "Coverage gaps", href: "/connectors" },
    ],
    workQueue: {
      title: "Risks",
      description: "Highest-risk findings by score, owner, due date, evidence, and source freshness.",
      actionLabel: "View all risks",
      actionHref: "/risk-inbox",
      empty: "No open findings.",
    },
    primaryRoutes: [
      { href: "/", label: "Home", detail: "Active risk, owners, evidence, and source attention." },
      { href: "/risk-inbox", label: "Issues", detail: "Findings by severity, owner, evidence, SLA, and status." },
      { href: "/impact", label: "Affected assets", detail: "Impacted entities and risk paths." },
      { href: "/ask", label: "Ask", detail: "Ask investigation questions and review cited answers." },
      { href: "/inventory", label: "Inventory", detail: "Assets, owners, scope, vulnerabilities, and graph context." },
      { href: "/vendors", label: "Vendors", detail: "Vendor discoveries, owners, reviews, contracts, assurance records, and open risk." },
    ],
    secondaryRoutes: [
      { href: "/trends", label: "Trends", detail: "Opened, closed, aged, and breached finding flow." },
      { href: "/explore", label: "Graph", detail: "Trace relationships around entities and findings." },
      { href: "/connectors", label: "Sources", detail: "Source freshness and ingestion health." },
    ],
  },
  {
    id: "controls",
    label: "Controls",
    shortLabel: "Controls",
    tagline: "Control blockers, evidence gaps, and packet exports.",
    description: "Failing controls, policy owners, evidence gaps, source gaps, and packet exports.",
    searchPlaceholder: "Search controls, policies, evidence, frameworks...",
    priorities: ["Packet blockers", "Policy approvals", "Evidence gaps", "Failing controls"],
    headline: "evidence gaps block packet export",
    summaryFocus: ["missing or stale evidence", "failing controls", "packet blockers"],
    signals: [
      { key: "auditReadiness", label: "Packet score", href: "/reports?report_type=control&profile=soc2-security-core" },
      { key: "evidenceIssues", label: "Evidence gaps", href: "/evidence" },
      { key: "controlFailures", label: "Failing controls", href: "/controls" },
      { key: "coverageGaps", label: "Scope gaps", href: "/connectors" },
      { key: "sourceTrust", label: "Stale sources", href: "/connectors" },
      { key: "activeRisk", label: "Mapped risks", href: "/risk-inbox" },
    ],
    workQueue: {
      title: "Controls",
      description: "Policy approvals, controls, and evidence items that block packet export.",
      actionLabel: "Review controls",
      actionHref: "/controls",
      empty: "No failing controls or missing evidence. Export the packet or schedule the next run.",
    },
    primaryRoutes: [
      { href: "/", label: "Home", detail: "Packet status, control issues, evidence gaps, and source health." },
      { href: "/grc", label: "Compliance", detail: "Packet blockers, control issues, evidence gaps, and framework status." },
      { href: "/controls", label: "Controls", detail: "Control status, mapped findings, and evidence gaps." },
      { href: "/policies", label: "Policies", detail: "Policy versions, approvals, attestations, exceptions, and mappings." },
      { href: "/frameworks", label: "Frameworks", detail: "Framework status, failing controls, evidence gaps, and exports." },
      { href: "/evidence", label: "Evidence", detail: "Evidence register linked to findings, rules, and graph roots." },
      { href: "/questionnaires", label: "Questionnaires", detail: "Customer and vendor answer queues, blockers, owners, approvals, and evidence gaps." },
      { href: "/reports", label: "Reports", detail: "Control evidence packets with mapped evidence and affected assets." },
      { href: "/reports/audit-packages", label: "Packet review", detail: "Packet blockers, evidence review, shared snapshots, and scope exclusions." },
    ],
    secondaryRoutes: [
      { href: "/trends/dashboards", label: "Dashboards", detail: "Saved compliance and trend widgets." },
      { href: "/reports/schedules", label: "Report schedules", detail: "Recurring packet runs and recent scheduled outputs." },
      { href: "/controls/builder", label: "Control Builder", detail: "Custom control packs, coverage preview, and YAML export." },
      { href: "/connectors", label: "Sources", detail: "Source coverage and freshness for evidence." },
      { href: "/risk-inbox", label: "Issues", detail: "Findings that affect controls and framework posture." },
    ],
  },
  {
    id: "sources",
    label: "Sources",
    shortLabel: "Sources",
    tagline: "Source health, coverage, and inventory.",
    description: "Source freshness, coverage gaps, inventory owners, and runtime diagnostics.",
    searchPlaceholder: "Search sources, runtimes, assets...",
    priorities: ["Source freshness", "Coverage gaps", "Owner gaps", "High-risk assets"],
    headline: "source issues need repair",
    summaryFocus: ["source sync", "coverage", "ownership"],
    signals: [
      { key: "sourceTrust", label: "Runtime freshness", href: "/connectors" },
      { key: "coverageGaps", label: "Coverage gaps", href: "/connectors" },
      { key: "ownerGaps", label: "No owner", href: "/inventory?owner=unassigned" },
      { key: "highImpact", label: "High-risk assets", href: "/inventory?risk=high" },
      { key: "controlFailures", label: "Failing controls", href: "/controls" },
      { key: "activeRisk", label: "Runtime risks", href: "/risk-inbox" },
    ],
    workQueue: {
      title: "Sources",
      description: "Stale sources, coverage gaps, missing owners, and runtime status.",
      actionLabel: "Review sources",
      actionHref: "/connectors",
      empty: "All sources synced and in scope.",
    },
    primaryRoutes: [
      { href: "/", label: "Home", detail: "Connector health, source coverage, and ownership." },
      { href: "/connectors", label: "Sources", detail: "Source library, freshness, scope, and ingestion health." },
      { href: "/inventory", label: "Inventory", detail: "Assets, owners, scope, tests, and graph context." },
      { href: "/explore", label: "Graph", detail: "Trace relationships around entities and sources." },
      { href: "/trends", label: "Trends", detail: "Runtime-backed risk and backlog movement." },
    ],
    secondaryRoutes: [
      { href: "/ask", label: "Ask", detail: "Ask runtime and coverage questions." },
      { href: "/impact", label: "Affected assets", detail: "Entity impact and affected paths." },
      { href: "/connectors/activation", label: "Source activation", detail: "Source collection scope, access, and trust posture." },
      { href: "/credential-stores", label: "Credential stores", detail: "Credential store defaults, accepted reference formats, and setup status." },
      { href: "/developer", label: "Developer Tools", detail: "API status, OpenAPI resources, and diagnostics." },
    ],
  },
  {
    id: "reports",
    label: "Review",
    shortLabel: "Review",
    tagline: "Top risks, owners, trends, and reports.",
    description: "Top risks, control blockers, trend direction, owner follow-up, source freshness, and reports.",
    searchPlaceholder: "Search status, trends, reports...",
    priorities: ["Top risks", "Owner follow-up", "Trend direction", "Reports"],
    headline: "items need follow-up",
    summaryFocus: ["top risks", "owner follow-up", "packet blockers"],
    signals: [
      { key: "highImpact", label: "High-risk assets", href: "/impact" },
      { key: "auditReadiness", label: "Review packet", href: "/reports?report_type=control&profile=soc2-security-core" },
      { key: "ownerGaps", label: "Owner follow-up", href: "/risk-inbox?owner=unassigned" },
      { key: "controlFailures", label: "Failing controls", href: "/controls" },
      { key: "sourceTrust", label: "Stale sources", href: "/connectors" },
      { key: "activeRisk", label: "Open risks", href: "/risk-inbox" },
    ],
    workQueue: {
      title: "Follow up",
      description: "High risks, failing controls, stale evidence, and owner gaps that need review.",
      actionLabel: "Open scorecards",
      actionHref: "/trends/dashboards",
      empty: "No high-risk follow-up right now. Keep controls, owners, and sources current.",
    },
    primaryRoutes: [
      { href: "/", label: "Home", detail: "Top risks, controls, reports, and source health." },
      { href: "/trends", label: "Trends", detail: "Finding flow, backlog movement, and SLA pressure." },
      { href: "/trends/dashboards", label: "Dashboards", detail: "Saved scorecards and reusable widgets." },
      { href: "/reports", label: "Reports", detail: "Control evidence packets and finding packets for review." },
      { href: "/reports/audit-packages", label: "Packet review", detail: "Packet blockers, approved evidence, scope exclusions, and shared snapshots." },
      { href: "/impact", label: "Affected assets", detail: "High-risk entity impact and affected paths." },
    ],
    secondaryRoutes: [
      { href: "/frameworks", label: "Frameworks", detail: "Framework status, control gaps, and planning." },
      { href: "/risk-inbox", label: "Issues", detail: "Priority findings behind the summary." },
      { href: "/ask", label: "Ask", detail: "Ask follow-up questions against the graph." },
    ],
  },
];

const informationAreaIDs = new Set<InformationAreaID>(informationAreas.map((area) => area.id));
const navigationHrefs = new Set(navigationEntries.map((entry) => entry.href));

export const informationAreaByID = Object.fromEntries(
  informationAreas.map((area) => [area.id, area]),
) as Record<InformationAreaID, InformationArea>;

export function isInformationAreaID(value: string | null | undefined): value is InformationAreaID {
  return Boolean(value && informationAreaIDs.has(value as InformationAreaID));
}

export function routeHrefsForArea(area: InformationArea) {
  return [...area.primaryRoutes, ...area.secondaryRoutes].map((route) => route.href);
}

export function routeRankForArea(area: InformationArea, href: string) {
  const index = routeHrefsForArea(area).indexOf(href);
  return index === -1 ? Number.POSITIVE_INFINITY : index;
}

export function routeIsAvailable(href: string) {
  return navigationHrefs.has(href);
}

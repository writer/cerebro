import { supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { INVENTORY_GROUPS } from "@/lib/inventory-groups";

export type NavigationEntry = {
  label: string;
  href: string;
  description: string;
  section: "Operator" | "Advanced";
  keywords: string[];
};

export const operatorNavLinks: NavigationEntry[] = [
  {
    label: "Home",
    href: "/",
    description: "Open work, evidence gaps, and audit readiness.",
    section: "Operator",
    keywords: ["dashboard", "overview", "metrics", "home"],
  },
  {
    label: "Risks",
    href: "/risks",
    description: "Prioritized findings by owner and due date.",
    section: "Operator",
    keywords: ["issues", "findings", "risk", "sla", "triage", "owner", "framework", ...supportedGRCFrameworkNames],
  },
  {
    label: "Verified Findings",
    href: "/verified",
    description: "Agent-confirmed findings and their fixes.",
    section: "Operator",
    keywords: ["verified", "validated", "findings", "evidence", "agent", "remediation", "actions", "approval", "execution", "verification", "rollback"],
  },
  {
    label: "Compliance",
    href: "/grc",
    description: "Framework controls violated by open findings.",
    section: "Operator",
    keywords: ["grc", "compliance", "framework", "frameworks", "control", "controls", "violations", "benchmark", "cspm", "sspm", ...supportedGRCFrameworkNames],
  },
  {
    label: "Trends",
    href: "/trends",
    description: "New vs. resolved findings over time.",
    section: "Operator",
    keywords: ["trends", "history", "over time", "burndown", "opened", "closed", "backlog", "chart"],
  },
  {
    label: "Dashboards",
    href: "/trends/dashboards",
    description: "Saved, shareable trend views.",
    section: "Operator",
    keywords: ["custom dashboard", "dashboards", "trends", "widgets", "workspace", "saved views"],
  },
  {
    label: "Rules",
    href: "/rules",
    description: "CSPM, SSPM, ISPM, and correlation rules, plus custom rules in YAML or JSON.",
    section: "Operator",
    keywords: ["rules", "finding rules", "checks", "catalog", "policy rules", "signatures", "cspm", "sspm", "ispm", "correlation", "custom rule", "yaml"],
  },
  {
    label: "Inventory",
    href: "/inventory",
    description: "Assets, owners, and graph context.",
    section: "Operator",
    keywords: ["assets", "inventory", "resources", "scope", "tests", "vulnerabilities", "framework", ...supportedGRCFrameworkNames],
  },
  // The inventory groups are preset searches over the same catalog, so their
  // labels and copy come from the one module the service ids are checked against.
  ...INVENTORY_GROUPS.map((group) => ({
    label: group.label,
    href: group.href,
    description: group.description,
    section: "Operator" as const,
    keywords: group.keywords,
  })),
  {
    label: "Attack Graphs",
    href: "/explore",
    description: "Trace attack paths and simulate fixes.",
    section: "Operator",
    keywords: ["attack graphs", "attack paths", "graph", "relationships", "expand", "neighbors", "pivot", "entity", "impact", "affected assets", "blast radius", "simulate", "simulation", "what if"],
  },
  {
    label: "Reports",
    href: "/reports",
    description: "Evidence packets for controls and findings.",
    section: "Operator",
    keywords: ["audit packet", "export", "report", "evidence"],
  },
  {
    label: "Integrations",
    href: "/integrations",
    description: "Connected tools, their health, and credentials.",
    section: "Operator",
    keywords: ["runtimes", "sources", "integrations", "connectors", "freshness", "scope", "credentials", "secrets", "credential stores", "vault"],
  },
];

const commandOnlyNavLinks: NavigationEntry[] = [
  {
    label: "Members",
    href: "/identity",
    description: "Who can sign in, and their roles.",
    section: "Advanced",
    keywords: ["members", "identity", "users", "organizations", "orgs", "okta", "oauth", "roles", "groups", "settings"],
  },
  {
    label: "Report Schedules",
    href: "/reports/schedules",
    description: "Recurring reports and recent runs.",
    section: "Operator",
    keywords: ["schedule", "scheduled", "recurring", "interval", "report", "delivery", "runs", "cron"],
  },
  {
    label: "Risk Model",
    href: "/developer/scoring",
    description: "How assets and attack paths are scored.",
    section: "Advanced",
    keywords: ["risk", "scoring", "model", "attack path", "asset value", "classification", "countermeasure", "exposure", "cvss", "epss", "kev"],
  },
  {
    label: "Integration Activation",
    href: "/integrations/activation",
    description: "Preview what an integration collects before you rely on it.",
    section: "Operator",
    keywords: ["integration", "source", "activation", "connector", "coverage", "access", "trust", "onboarding"],
  },
];

export const adminNavLinks: NavigationEntry[] = [
  {
    label: "Access Control",
    href: "/admin/access",
    description: "Verification, roles, and permissions.",
    section: "Advanced",
    keywords: ["rbac", "roles", "permissions", "claims", "groups", "entitlements", "authorization", "authentication", "identity", "oidc", "sso", "jwks", "issuer", "login"],
  },
  {
    label: "Audit Events",
    href: "/developer/audit",
    description: "Who changed what, and when.",
    section: "Advanced",
    keywords: ["audit", "log", "history", "who", "changed", "events", "trail"],
  },
];

export const utilityLinks: NavigationEntry[] = [
  {
    label: "Admin",
    href: "/admin",
    description: "Access, secrets, and audit history.",
    section: "Advanced",
    keywords: ["admin", "settings", "access control", "rbac", "roles", "permissions", "claims", "oidc", "groups", "sso", "integrations"],
  },
  ...adminNavLinks,
  {
    label: "Developer Tools",
    href: "/developer",
    description: "API status and developer tools.",
    section: "Advanced",
    keywords: ["openapi", "status", "developer", "api"],
  },
];

export const navigationEntries = [
  ...operatorNavLinks,
  ...commandOnlyNavLinks,
  ...utilityLinks,
];

const routeLabels: Record<string, string> = Object.fromEntries(
  navigationEntries.map((entry) => [entry.href, entry.label]),
);

routeLabels["/"] = "Home";
routeLabels["/findings"] = "Finding detail";
routeLabels["/identity"] = "Members";
routeLabels["/integrations/builder"] = "Integration builder";
routeLabels["/developer/agents"] = "Agent platform";
routeLabels["/developer/audit"] = "Audit Events";
routeLabels["/developer/evals"] = "Ask evals";
routeLabels["/developer/producers"] = "Security producers";
routeLabels["/frameworks"] = "Frameworks";
routeLabels["/reports/shared"] = "Shared Snapshot";

const matchesRoute = (pathname: string, route: string) =>
  pathname === route || (route !== "/" && pathname.startsWith(`${route}/`));

export function routeLabelForPath(pathname: string) {
  const match = Object.keys(routeLabels)
    .filter((route) => matchesRoute(pathname, route))
    .sort((left, right) => right.length - left.length)[0];
  if (match) return routeLabels[match];
  return pathname.split("/").filter(Boolean).at(-1)?.replace(/-/g, " ") ?? "Cerebro";
}

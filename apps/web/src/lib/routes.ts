import { supportedGRCFrameworkNames } from "@/lib/grc-frameworks";

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
    label: "Work",
    href: "/risk-inbox",
    description: "Prioritized findings and control work by owner, due date, and evidence state.",
    section: "Operator",
    keywords: ["issues", "findings", "risk", "sla", "triage", "owner", "framework", ...supportedGRCFrameworkNames],
  },
  {
    label: "Actions",
    href: "/actions",
    description: "Remediation proposals, approvals, execution receipts, and independent verification.",
    section: "Operator",
    keywords: ["actions", "remediation", "approval", "execution", "verification", "rollback"],
  },
  {
    label: "Credentials",
    href: "/security/lifecycle",
    description: "Credential and certificate expiry, ownership, findings, and approved rotation routes.",
    section: "Operator",
    keywords: ["credential", "certificate", "expiry", "rotation", "revocation", "owner"],
  },
  {
    label: "Compliance",
    href: "/grc",
    description: "Packet blockers, control issues, evidence gaps, source freshness, and framework status.",
    section: "Operator",
    keywords: ["grc", "compliance", "packet", "audit", "framework", "control", "test", "evidence", "policy", "questionnaire", "report", ...supportedGRCFrameworkNames],
  },
  {
    label: "Trends",
    href: "/trends",
    description: "Finding flow over time: opened versus closed and the running open backlog.",
    section: "Operator",
    keywords: ["trends", "history", "over time", "burndown", "opened", "closed", "backlog", "chart"],
  },
  {
    label: "Dashboards",
    href: "/trends/dashboards",
    description: "Saved custom trend dashboards with reusable filters, widgets, and sharing scope.",
    section: "Operator",
    keywords: ["custom dashboard", "dashboards", "trends", "widgets", "workspace", "saved views"],
  },
  {
    label: "Ask",
    href: "/ask",
    description: "Ask questions about risks, owners, evidence, affected assets, and what changed.",
    section: "Operator",
    keywords: ["ask", "question", "owner", "evidence", "query", "search"],
  },
  {
    label: "Controls",
    href: "/controls",
    description: "Control status, custom framework packs, mapped findings, and evidence gaps.",
    section: "Operator",
    keywords: ["soc2", "iso", "framework", "control", "audit", "builder", "custom", ...supportedGRCFrameworkNames],
  },
  {
    label: "Policies",
    href: "/policies",
    description: "Policy versions, approvals, attestations, exceptions, reminders, and mappings.",
    section: "Operator",
    keywords: ["policy", "policies", "templates", "approvals", "attestations", "exceptions", "reminders", "review", "owner", ...supportedGRCFrameworkNames],
  },
  {
    label: "Frameworks",
    href: "/frameworks",
    description: "Framework status, failing controls, evidence gaps, and packet exports.",
    section: "Operator",
    keywords: ["soc2", "iso", "framework", "catalog", "coverage", "gap", "planning", "export", ...supportedGRCFrameworkNames],
  },
  {
    label: "Evidence",
    href: "/evidence",
    description: "Evidence linked to findings, rules, runs, and affected assets.",
    section: "Operator",
    keywords: ["claims", "events", "evidence", "audit"],
  },
  {
    label: "Questionnaires",
    href: "/questionnaires",
    description: "Customer questionnaires, vendor reviews, answer blockers, owners, approvals, and evidence gaps.",
    section: "Operator",
    keywords: ["questionnaires", "security review", "customer review", "vendor review", "answers", "evidence gaps", "approvals", "owners"],
  },
  {
    label: "Inventory",
    href: "/inventory",
    description: "Browse assets, owners, scope, tests, vulnerabilities, and graph context.",
    section: "Operator",
    keywords: ["assets", "inventory", "resources", "scope", "tests", "vulnerabilities", "framework", ...supportedGRCFrameworkNames],
  },
  {
    label: "Vendors",
    href: "/vendors",
    description: "Vendors, discoveries, owners, reviews, contracts, assurance records, and open risk.",
    section: "Operator",
    keywords: ["vendors", "third party", "vendor risk", "vendor discoveries", "contracts", "security review", "questionnaire", "assurance", "owner"],
  },
  {
    label: "Affected assets",
    href: "/impact",
    description: "Assets and relationships touched by a finding or entity.",
    section: "Operator",
    keywords: ["graph", "entity", "impact", "affected entities"],
  },
  {
    label: "Graph",
    href: "/explore",
    description: "Trace relationships around an asset, finding, owner, or source.",
    section: "Operator",
    keywords: ["graph", "relationships", "expand", "neighbors", "pivot", "entity"],
  },
  {
    label: "Reports",
    href: "/reports",
    description: "Create control evidence packets and finding packets with mapped evidence, scope exclusions, and source records.",
    section: "Operator",
    keywords: ["audit packet", "export", "report", "evidence"],
  },
  {
    label: "Audit workspace",
    href: "/reports/audit-packages",
    description: "Review packet blockers, evidence, source freshness, reviewer questions, and shared snapshots.",
    section: "Operator",
    keywords: ["audit package", "packet review", "evidence review", "control owners", "snapshot", "scope", "exceptions"],
  },
  {
    label: "Integrations",
    href: "/connectors",
    description: "Source setup, freshness, scope, and ingestion health.",
    section: "Operator",
    keywords: ["runtimes", "sources", "connectors", "freshness", "scope"],
  },
  {
    label: "Credential stores",
    href: "/credential-stores",
    description: "Credential store defaults, accepted reference formats, and setup status.",
    section: "Operator",
    keywords: ["credential stores", "credentials", "secret stores", "vault", "secrets", "resolver"],
  },
];

const commandOnlyNavLinks: NavigationEntry[] = [
  {
    label: "Members",
    href: "/identity",
    description: "Organizations, users, auth providers, roles, and login history.",
    section: "Advanced",
    keywords: ["members", "identity", "users", "organizations", "orgs", "okta", "oauth", "roles", "groups", "settings"],
  },
  {
    label: "Report schedules",
    href: "/reports/schedules",
    description: "Schedule reports on a fixed interval and review recent scheduled runs.",
    section: "Operator",
    keywords: ["schedule", "scheduled", "recurring", "interval", "report", "delivery", "runs", "cron"],
  },
  {
    label: "Risk scoring",
    href: "/developer/risk-scoring",
    description: "Tune tenant risk thresholds, signal cutoffs, relation weights, and factor weights.",
    section: "Advanced",
    keywords: ["risk", "scoring", "threshold", "cvss", "epss", "weights", "configuration"],
  },
  {
    label: "Control Builder",
    href: "/controls/builder",
    description: "Build custom control packs, preview coverage, and export YAML.",
    section: "Operator",
    keywords: ["builder", "custom framework", "control pack", "yaml", "audit", ...supportedGRCFrameworkNames],
  },
  {
    label: "Source activation",
    href: "/connectors/activation",
    description: "See what a source collects, the access it needs, and whether you can trust it yet for your program.",
    section: "Operator",
    keywords: ["source", "activation", "connector", "coverage", "access", "trust", "onboarding"],
  },
];

export const utilityLinks: NavigationEntry[] = [
  {
    label: "Developer Tools",
    href: "/developer",
    description: "API status, OpenAPI resources, and developer utilities.",
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
routeLabels["/ask"] = "Ask";
routeLabels["/evidence"] = "Evidence";
routeLabels["/findings"] = "Finding detail";
routeLabels["/identity"] = "Members";
routeLabels["/connectors/builder"] = "Connector builder";
routeLabels["/developer/agent-platform"] = "Agent platform";
routeLabels["/developer/audit-log"] = "Audit events";
routeLabels["/developer/evals"] = "Ask evals";
routeLabels["/developer/security-producers"] = "Security producers";
routeLabels["/controls/builder"] = "Control builder";
routeLabels["/reports/shared"] = "Shared snapshot";

const matchesRoute = (pathname: string, route: string) =>
  pathname === route || (route !== "/" && pathname.startsWith(`${route}/`));

export function routeLabelForPath(pathname: string) {
  const match = Object.keys(routeLabels)
    .filter((route) => matchesRoute(pathname, route))
    .sort((left, right) => right.length - left.length)[0];
  if (match) return routeLabels[match];
  return pathname.split("/").filter(Boolean).at(-1)?.replace(/-/g, " ") ?? "Cerebro";
}

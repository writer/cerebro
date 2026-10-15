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
    label: "Credential Health",
    href: "/security/lifecycle",
    description: "Key and certificate rotation.",
    section: "Operator",
    keywords: ["credential", "certificate", "expiry", "rotation", "revocation", "owner"],
  },
  {
    label: "Compliance",
    href: "/grc",
    description: "Control gaps, evidence, and packets.",
    section: "Operator",
    keywords: ["grc", "compliance", "packet", "audit", "framework", "control", "test", "evidence", "policy", "questionnaire", "report", ...supportedGRCFrameworkNames],
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
    label: "Controls",
    href: "/controls",
    description: "Control status and mapped findings.",
    section: "Operator",
    keywords: ["soc2", "iso", "framework", "control", "audit", "builder", "custom", ...supportedGRCFrameworkNames],
  },
  {
    // "Policies" alone reads as detection rules to a cloud security engineer;
    // this page is written governance documents.
    label: "Policy Documents",
    href: "/policies",
    description: "Policy versions, approvals, and attestations.",
    section: "Operator",
    keywords: ["policy", "policies", "policy documents", "templates", "approvals", "attestations", "exceptions", "reminders", "review", "owner", ...supportedGRCFrameworkNames],
  },
  {
    label: "Frameworks",
    href: "/frameworks",
    description: "Framework status and gaps.",
    section: "Operator",
    keywords: ["soc2", "iso", "framework", "catalog", "coverage", "gap", "planning", "export", ...supportedGRCFrameworkNames],
  },
  {
    label: "Evidence",
    href: "/evidence",
    description: "Proof linked to findings and assets.",
    section: "Operator",
    keywords: ["claims", "events", "evidence", "audit"],
  },
  {
    label: "Questionnaires",
    href: "/questionnaires",
    description: "Customer and vendor questionnaires.",
    section: "Operator",
    keywords: ["questionnaires", "security review", "customer review", "vendor review", "answers", "evidence gaps", "approvals", "owners"],
  },
  {
    label: "Rules",
    href: "/rules",
    description: "Rules that turn evidence into findings.",
    section: "Operator",
    keywords: ["rules", "finding rules", "checks", "catalog", "policy rules", "signatures", "streams"],
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
    label: "Vendors",
    href: "/vendors",
    description: "Vendors, reviews, and assurance.",
    section: "Operator",
    keywords: ["vendors", "third party", "vendor risk", "vendor discoveries", "contracts", "security review", "questionnaire", "assurance", "owner"],
  },
  {
    label: "Graph",
    href: "/explore",
    description: "Trace paths around any entity.",
    section: "Operator",
    keywords: ["graph", "relationships", "expand", "neighbors", "pivot", "entity", "impact", "affected assets", "blast radius"],
  },
  {
    label: "Reports",
    href: "/reports",
    description: "Evidence packets for controls and findings.",
    section: "Operator",
    keywords: ["audit packet", "export", "report", "evidence"],
  },
  {
    label: "Audit Workspace",
    href: "/reports/packages",
    description: "Clear blockers before sharing a packet.",
    section: "Operator",
    keywords: ["audit package", "packet review", "evidence review", "control owners", "snapshot", "scope", "exceptions"],
  },
  {
    label: "Integrations",
    href: "/connectors",
    description: "Source setup and health.",
    section: "Operator",
    keywords: ["runtimes", "sources", "connectors", "freshness", "scope"],
  },
  {
    label: "Credential Stores",
    href: "/credentials",
    description: "Secret store setup and status.",
    section: "Operator",
    keywords: ["credential stores", "credentials", "secret stores", "vault", "secrets", "resolver"],
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
    label: "Risk Scoring",
    href: "/developer/scoring",
    description: "How findings are ranked.",
    section: "Advanced",
    keywords: ["risk", "scoring", "threshold", "cvss", "epss", "weights", "configuration"],
  },
  {
    label: "Control Builder",
    href: "/controls/builder",
    description: "Compose custom control packs.",
    section: "Operator",
    keywords: ["builder", "custom framework", "control pack", "yaml", "audit", ...supportedGRCFrameworkNames],
  },
  {
    label: "Source Activation",
    href: "/connectors/activation",
    description: "Preview what a source collects before you rely on it.",
    section: "Operator",
    keywords: ["source", "activation", "connector", "coverage", "access", "trust", "onboarding"],
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
routeLabels["/evidence"] = "Evidence";
routeLabels["/findings"] = "Finding detail";
routeLabels["/identity"] = "Members";
routeLabels["/connectors/builder"] = "Connector builder";
routeLabels["/developer/agents"] = "Agent platform";
routeLabels["/developer/audit"] = "Audit Events";
routeLabels["/developer/evals"] = "Ask evals";
routeLabels["/developer/producers"] = "Security producers";
routeLabels["/controls/builder"] = "Control Builder";
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

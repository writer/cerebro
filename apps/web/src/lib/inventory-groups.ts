// Inventory groups are the console's top-level inventory sub-menus. The
// membership rules live in the Go service; this module only mirrors the ids and
// the copy, and inventory-groups.test.ts fails if the two drift apart.
export type InventoryGroupID = "iam" | "cloud" | "saas" | "code" | "devices" | "secrets";

export type InventoryGroup = {
  description: string;
  href: string;
  id: InventoryGroupID;
  keywords: string[];
  label: string;
  summary: string;
};

export const INVENTORY_GROUPS: InventoryGroup[] = [
  {
    id: "iam",
    label: "IAM",
    href: "/inventory/iam",
    keywords: ["identities", "iam", "users", "people", "accounts", "service accounts", "groups", "roles", "permissions", "principals", "okta", "entra", "rbac"],
    summary: "People, service accounts, groups, and roles",
    description: "Every principal Cerebro has collected, with the groups and roles they hold, across identity providers, clouds, and clusters.",
  },
  {
    id: "cloud",
    label: "Cloud",
    href: "/inventory/cloud",
    keywords: ["cloud", "aws", "gcp", "azure", "accounts", "compute", "instances", "clusters", "kubernetes", "storage", "buckets", "databases", "networking"],
    summary: "Accounts, compute, clusters, and storage",
    description: "Cloud accounts and the resources inside them, including compute, clusters, storage, and networking.",
  },
  {
    id: "saas",
    label: "SaaS",
    href: "/inventory/saas",
    keywords: ["saas", "applications", "apps", "integrations", "vendors", "third party", "oauth apps", "tenants"],
    summary: "Applications, integrations, and vendors",
    description: "Connected business applications, the integrations installed into them, and the vendors behind them.",
  },
  {
    id: "code",
    label: "Code",
    href: "/inventory/code",
    keywords: ["code", "repositories", "repos", "github", "registries", "containers", "images", "runners", "pipelines", "build"],
    summary: "Repositories, registries, and runners",
    description: "Source repositories, container registries, build runners, and the images they produce.",
  },
  {
    id: "devices",
    label: "Devices",
    href: "/inventory/devices",
    keywords: ["devices", "endpoints", "laptops", "workstations", "mdm", "agents", "edr", "kandji", "kolide", "jamf"],
    summary: "Managed endpoints and their agents",
    description: "Endpoints reported by device management and endpoint protection, with the agents covering them.",
  },
  {
    id: "secrets",
    label: "Secrets",
    href: "/inventory/secrets",
    keywords: ["secrets", "credentials", "keys", "api keys", "tokens", "certificates", "expiry", "rotation"],
    summary: "Credentials, keys, and certificates",
    description: "Stored credentials, keys, and certificates collected from connected sources.",
  },
];

type InventoryGroupRule = {
  exact: string[];
  id: InventoryGroupID;
  prefixes: string[];
  suffixes: string[];
};

// A mirror of inventoryGroupRules() in internal/graphquery/inventory_groups.go,
// held in step by the parity assertion in inventory-groups.test.ts. Order is
// load-bearing: the first rule that matches wins.
export const INVENTORY_GROUP_RULES: InventoryGroupRule[] = [
  { id: "secrets", exact: ["secret", "certificate"], prefixes: [], suffixes: [".secret", ".credential", ".certificate"] },
  {
    id: "devices",
    exact: ["device"],
    prefixes: ["trusted_endpoint.", "kandji.", "kolide.", "jamf.", "intune.", "sentinelone."],
    suffixes: [".device", ".endpoint"],
  },
  {
    id: "iam",
    exact: ["user", "person", "group", "identity_application", "cerebro.principal", "privileged.capability"],
    prefixes: ["aws.sso.", "kubernetes.rbac_"],
    suffixes: [".user", ".person", ".group", ".role", ".service_account", ".service_principal", ".principal"],
  },
  {
    id: "code",
    exact: ["repository", "deployment"],
    prefixes: ["github.", "gitlab.", "bitbucket.", "container.", "aws.ecr."],
    suffixes: [".repository", ".runner", ".pipeline", ".workflow"],
  },
  {
    id: "cloud",
    exact: [],
    prefixes: ["aws.", "gcp.", "azure.", "kubernetes.", "linode.", "oci.", "cloud."],
    suffixes: [".cluster", ".instance", ".bucket", ".volume"],
  },
  {
    id: "saas",
    exact: ["vendor", "saas.application", "sdk.integration", "grc.integration"],
    prefixes: ["okta.", "google_workspace.", "auth0."],
    suffixes: [".application", ".integration", ".tenant", ".workspace"],
  },
];

// Projectors join the parts of an entity type with either a dot or an
// underscore for the same concept, so both sides are compared in one form.
const normalizeEntityType = (value: string) => value.trim().toLowerCase().replaceAll("_", ".");

export const inventoryGroupForEntityType = (entityType: string | undefined): InventoryGroupID | undefined => {
  const value = normalizeEntityType(entityType ?? "");
  if (!value) return undefined;
  for (const rule of INVENTORY_GROUP_RULES) {
    if (rule.exact.some((candidate) => value === normalizeEntityType(candidate))) return rule.id;
    if (rule.prefixes.some((prefix) => value.startsWith(normalizeEntityType(prefix)))) return rule.id;
    if (rule.suffixes.some((suffix) => value.endsWith(normalizeEntityType(suffix)))) return rule.id;
  }
  return undefined;
};

export const inventoryGroupFor = (id: string | undefined): InventoryGroup | undefined =>
  INVENTORY_GROUPS.find((group) => group.id === id);

export const isInventoryGroupID = (value: string): value is InventoryGroupID =>
  INVENTORY_GROUPS.some((group) => group.id === value);

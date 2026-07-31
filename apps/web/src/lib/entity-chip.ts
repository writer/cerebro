import { shortUrn } from "@/lib/ask";
import { type GRCGraph, type GRCGraphNode, riskLevelFromScore } from "@/lib/grc";

export type EntityUrnParts = {
  tenant: string;
  entityType: string;
  id: string;
};

const URN_PREFIX = "urn:cerebro:";

export const parseEntityUrn = (urn: string): EntityUrnParts | null => {
  if (!urn.startsWith(URN_PREFIX)) return null;
  const rest = urn.slice(URN_PREFIX.length);
  const separator = rest.indexOf(":");
  if (separator <= 0) return null;
  const remainder = rest.slice(separator + 1);
  const nextSeparator = remainder.indexOf(":");
  if (nextSeparator <= 0) return null;
  const tenant = rest.slice(0, separator);
  const entityType = remainder.slice(0, nextSeparator);
  const id = remainder.slice(nextSeparator + 1);
  if (!tenant || !entityType || !id) return null;
  return { tenant, entityType, id };
};

export type EntityTypeKey =
  | "finding"
  | "identity"
  | "asset"
  | "package"
  | "threat"
  | "default";

export const entityTypeKey = (entityType: string): EntityTypeKey => {
  const normalized = entityType.toLowerCase();
  if (normalized.includes("finding")) return "finding";
  if (
    normalized.includes("user") ||
    normalized.includes("identity") ||
    normalized.includes("account") ||
    normalized.includes("group")
  ) {
    return "identity";
  }
  if (
    normalized.includes("asset") ||
    normalized.includes("agent") ||
    normalized.includes("endpoint") ||
    normalized.includes("device") ||
    normalized.includes("repository")
  ) {
    return "asset";
  }
  if (
    normalized.includes("package") ||
    normalized.includes("vuln") ||
    normalized.includes("cve")
  ) {
    return "package";
  }
  if (
    normalized.includes("threat") ||
    normalized.includes("malware") ||
    normalized.includes("infection")
  ) {
    return "threat";
  }
  return "default";
};

export const entityTypeLabel = (key: EntityTypeKey): string =>
  key === "default" ? "entity" : key;

export const entityDetailHref = (urn: string): string =>
  `/inventory/${encodeURIComponent(urn)}`;

export const entityImpactHref = (urn: string): string =>
  `/impact?root_urn=${encodeURIComponent(urn)}`;

export const entityExploreHref = (urn: string): string =>
  `/explore?root_urn=${encodeURIComponent(urn)}`;

export const entityPivotQuestion = (urn: string): string =>
  `Explore what connects to ${shortUrn(urn)}`;

const findGraphNode = (
  graph: GRCGraph | null | undefined,
  urn: string,
): GRCGraphNode | null => {
  if (!graph) return null;
  if (graph.root?.urn === urn) return graph.root;
  return graph.neighbors?.find((node) => node.urn === urn) ?? null;
};

const parseRiskScore = (attributes?: Record<string, string>): number | undefined => {
  const raw = attributes?.risk_score;
  if (!raw) return undefined;
  const value = Number(raw);
  return Number.isFinite(value) ? value : undefined;
};

export type EntityPeekData = {
  urn: string;
  label: string;
  entityType: string;
  typeKey: EntityTypeKey;
  risk?: number;
  riskLevel: ReturnType<typeof riskLevelFromScore>;
  /** "graph" when label/type/risk came from a graph node, "urn" when derived from the URN alone. */
  source: "graph" | "urn";
};

export const resolveEntityPeek = (
  urn: string,
  options?: { graph?: GRCGraph | null; label?: string },
): EntityPeekData => {
  const node = findGraphNode(options?.graph, urn);
  const parsed = parseEntityUrn(urn);
  const entityType = node?.entity_type || parsed?.entityType || "entity";
  const risk = parseRiskScore(node?.attributes);
  return {
    urn,
    label: options?.label || node?.label || parsed?.id || shortUrn(urn),
    entityType,
    typeKey: entityTypeKey(entityType),
    risk,
    riskLevel: riskLevelFromScore(risk),
    source: node ? "graph" : "urn",
  };
};

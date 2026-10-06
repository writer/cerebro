import { GRCGraph, GRCGraphNode, GRCGraphRelation } from "@/lib/grc";

export const GRAPH_VIEWPOINT_IDS = [
  "connections",
  "effective-access",
  "human-access",
  "attack-paths",
  "sensitive-assets",
] as const;

export type GraphViewpointID = (typeof GRAPH_VIEWPOINT_IDS)[number];

export type GraphViewpoint = {
  id: GraphViewpointID;
  label: string;
  question: string;
  /** Connect unary method path, or null for the entity neighborhood read. */
  method: string | null;
  /** True when the viewpoint needs a seed entity before it can run. */
  needsSeed: boolean;
  /** Request field for a free-text narrowing query, where the RPC defines one. */
  queryField?: string;
  queryLabel?: string;
};

const CONNECT_SERVICE = "cerebro.graph.v1.OrganizationalGraphService";

export const GRAPH_VIEWPOINTS: Record<GraphViewpointID, GraphViewpoint> = {
  connections: {
    id: "connections",
    label: "Connections",
    question: "What does one asset or identity connect to, hop by hop?",
    method: null,
    needsSeed: true,
  },
  "effective-access": {
    id: "effective-access",
    label: "Effective Access",
    question: "Which identities reach which permission once groups and roles resolve?",
    method: `${CONNECT_SERVICE}/ListEffectiveAccessPaths`,
    needsSeed: false,
    queryField: "identity_query",
    queryLabel: "Identity",
  },
  "human-access": {
    id: "human-access",
    label: "Human Access",
    question: "What does one person reach across every account they hold?",
    method: `${CONNECT_SERVICE}/ListPersonAccessPaths`,
    needsSeed: false,
    queryField: "person_query",
    queryLabel: "Person",
  },
  "attack-paths": {
    id: "attack-paths",
    label: "Attack Paths",
    question: "Where does internet exposure reach a privileged cloud permission?",
    method: `${CONNECT_SERVICE}/ListCloudAttackPaths`,
    needsSeed: false,
  },
  "sensitive-assets": {
    id: "sensitive-assets",
    label: "Sensitive Assets",
    question: "What can reach an asset classified as sensitive?",
    method: `${CONNECT_SERVICE}/ListCrownJewelPaths`,
    needsSeed: false,
  },
};

export const graphViewpointList = (): GraphViewpoint[] =>
  GRAPH_VIEWPOINT_IDS.map((id) => GRAPH_VIEWPOINTS[id]);

export const isGraphViewpointID = (value: string | null | undefined): value is GraphViewpointID =>
  Boolean(value) && (GRAPH_VIEWPOINT_IDS as readonly string[]).includes(value as string);

export const graphViewpointFor = (value: string | null | undefined): GraphViewpoint =>
  isGraphViewpointID(value) ? GRAPH_VIEWPOINTS[value] : GRAPH_VIEWPOINTS.connections;

export type GraphPathNode = {
  urn: string;
  kind: string;
  label: string;
  /** Role the node plays in its path, for example "exposed_resource". */
  role?: string;
};

export type GraphPathEvidence = {
  relation: string;
  sourceID: string;
  runtimeID: string;
};

export type GraphPathRow = {
  id: string;
  nodes: GraphPathNode[];
  relations: string[];
  evidence: GraphPathEvidence[];
  owners: GraphPathNode[];
  detail: string;
};

type RawRecord = Record<string, unknown>;

const asRecord = (value: unknown): RawRecord | null =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as RawRecord) : null;

const asString = (value: unknown): string => (typeof value === "string" ? value.trim() : "");

const asStringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(asString).filter(Boolean) : [];

const asList = (value: unknown): RawRecord[] =>
  Array.isArray(value) ? value.map(asRecord).filter((entry): entry is RawRecord => entry !== null) : [];

// CloudAttackPathNode carries a top-level urn; ContextEntity keeps it in properties.entity_urn.
export const graphPathNode = (value: unknown, role?: string): GraphPathNode | null => {
  const raw = asRecord(value);
  if (!raw) return null;
  const properties = asRecord(raw.properties) ?? {};
  const urn = asString(raw.urn) || asString(properties.entity_urn) || asString(raw.agent_key);
  if (!urn) return null;
  const kind = asString(raw.entity_kind) || asString(raw.entity_type);
  return { urn, kind, label: asString(raw.label) || urn, ...(role ? { role } : {}) };
};

const nodeChain = (entries: Array<[unknown, string]>): GraphPathNode[] =>
  entries
    .map(([value, role]) => graphPathNode(value, role))
    .filter((node): node is GraphPathNode => node !== null);

const edgeEvidence = (value: unknown): GraphPathEvidence | null => {
  const raw = asRecord(value);
  if (!raw) return null;
  const relation = asString(raw.relation);
  const sourceID = asString(raw.source_id);
  const runtimeID = asString(raw.source_runtime_id) || asString(raw.runtime_id);
  if (!relation && !sourceID && !runtimeID) return null;
  return { relation, sourceID, runtimeID };
};

const collectEvidence = (values: unknown[]): GraphPathEvidence[] =>
  values
    .flatMap((value) => (Array.isArray(value) ? value : [value]))
    .map(edgeEvidence)
    .filter((entry): entry is GraphPathEvidence => entry !== null);

const pathID = (prefix: string, nodes: GraphPathNode[], index: number) =>
  nodes.length > 0 ? `${prefix}:${nodes[0].urn}:${nodes[nodes.length - 1].urn}:${index}` : `${prefix}:${index}`;

export const cloudAttackPathRows = (payload: unknown): GraphPathRow[] =>
  asList(asRecord(payload)?.paths).flatMap((path, index) => {
    const nodes = nodeChain([
      [path.public_principal, "public_principal"],
      [path.exposed_resource, "exposed_resource"],
      [path.principal, "principal"],
      [path.permission, "permission"],
    ]);
    if (nodes.length < 2) return [];
    const account = graphPathNode(path.cloud_account, "cloud_account");
    const relations = asStringList(path.relation_chain);
    return [{
      id: pathID("cloud-attack", nodes, index),
      nodes,
      relations: relations.length > 0 ? relations : [asString(path.reach_relation), asString(path.access_relation)].filter(Boolean),
      evidence: collectEvidence([path.exposure_edge, path.traversal_edges, path.privilege_edge, path.resource_account_edge, path.permission_account_edge]),
      owners: asList(path.ownerships)
        .map((ownership) => graphPathNode(ownership.owner, "owner"))
        .filter((node): node is GraphPathNode => node !== null),
      detail: account ? `In ${account.label}` : "",
    }];
  });

export const effectiveAccessPathRows = (payload: unknown): GraphPathRow[] =>
  asList(asRecord(payload)?.paths).flatMap((path, index) => {
    const nodes = nodeChain([
      [path.identity, "identity"],
      [path.principal, "principal"],
      [path.mediator, "mediator"],
      [path.access_target, "access_target"],
      [path.entitlement, "entitlement"],
      [path.capability, "capability"],
    ]);
    if (nodes.length < 2) return [];
    return [{
      id: pathID("effective-access", nodes, index),
      nodes,
      relations: [...asStringList(path.identity_relation_chain), ...asStringList(path.relation_chain)],
      evidence: collectEvidence([path.identity_edges, path.edges]),
      owners: [],
      detail: asString(path.assignment_kind) ? `Granted by ${asString(path.assignment_kind)}` : "",
    }];
  });

export const personAccessPathRows = (payload: unknown): GraphPathRow[] =>
  asList(asRecord(payload)?.paths).flatMap((path, index) => {
    const nodes = nodeChain([
      [path.person, "person"],
      [path.identity, "identity"],
      [path.principal, "principal"],
      [path.access_target, "access_target"],
    ]);
    if (nodes.length < 2) return [];
    return [{
      id: pathID("person-access", nodes, index),
      nodes,
      relations: asStringList(path.relation_chain),
      evidence: [],
      owners: [],
      detail: "",
    }];
  });

export const crownJewelPathRows = (payload: unknown): GraphPathRow[] =>
  asList(asRecord(payload)?.paths).flatMap((path, index) => {
    const seed = graphPathNode(path.seed, "crown_jewel");
    const chain = asList(path.nodes)
      .map((node) => graphPathNode(node))
      .filter((node): node is GraphPathNode => node !== null);
    // The seed is already the first element of nodes, so only prepend when it is absent.
    const nodes = chain.length > 0 && seed && chain[0].urn === seed.urn
      ? [{ ...chain[0], role: "crown_jewel" }, ...chain.slice(1)]
      : [...(seed ? [seed] : []), ...chain];
    if (nodes.length < 2) return [];
    return [{
      id: pathID("crown-jewel", nodes, index),
      nodes,
      relations: asStringList(path.relations),
      evidence: [],
      owners: [],
      detail: "",
    }];
  });

const ROW_ADAPTERS: Record<GraphViewpointID, (payload: unknown) => GraphPathRow[]> = {
  connections: () => [],
  "effective-access": effectiveAccessPathRows,
  "human-access": personAccessPathRows,
  "attack-paths": cloudAttackPathRows,
  "sensitive-assets": crownJewelPathRows,
};

export const graphPathRows = (viewpoint: GraphViewpointID, payload: unknown): GraphPathRow[] =>
  ROW_ADAPTERS[viewpoint](payload);

export const graphRevisionOf = (payload: unknown): number | undefined => {
  const revision = asRecord(payload)?.graph_revision;
  return typeof revision === "number" && Number.isFinite(revision) ? revision : undefined;
};

export const graphPathsTruncated = (payload: unknown): boolean => asRecord(payload)?.truncated === true;

export type GraphPathCounts = {
  paths: number;
  nodes: number;
  relations: number;
  owners: number;
};

export const graphPathCounts = (rows: GraphPathRow[]): GraphPathCounts => {
  const nodes = new Set<string>();
  const relations = new Set<string>();
  const owners = new Set<string>();
  rows.forEach((row) => {
    row.nodes.forEach((node) => nodes.add(node.urn));
    row.relations.forEach((relation) => relations.add(relation));
    row.owners.forEach((owner) => owners.add(owner.urn));
  });
  return { paths: rows.length, nodes: nodes.size, relations: relations.size, owners: owners.size };
};

export const graphPathRowsToGraph = (rows: GraphPathRow[], rootURN?: string): GRCGraph | undefined => {
  if (rows.length === 0) return undefined;
  const nodes = new Map<string, GraphPathNode>();
  const relations: GRCGraphRelation[] = [];
  const seenRelations = new Set<string>();
  rows.forEach((row) => {
    [...row.nodes, ...row.owners].forEach((node) => {
      if (!nodes.has(node.urn)) nodes.set(node.urn, node);
    });
    row.nodes.forEach((node, index) => {
      const next = row.nodes[index + 1];
      if (!next) return;
      const relation = row.relations[index] || "reaches";
      const key = `${node.urn}|${relation}|${next.urn}`;
      if (seenRelations.has(key)) return;
      seenRelations.add(key);
      relations.push({ from_urn: node.urn, relation, to_urn: next.urn });
    });
    row.owners.forEach((owner) => {
      const target = row.nodes[1] ?? row.nodes[0];
      const key = `${owner.urn}|owns|${target.urn}`;
      if (seenRelations.has(key)) return;
      seenRelations.add(key);
      relations.push({ from_urn: owner.urn, relation: "owns", to_urn: target.urn });
    });
  });

  const toGraphNode = (node: GraphPathNode): GRCGraphNode => ({
    urn: node.urn,
    entity_type: node.kind,
    label: node.label,
    ...(node.role ? { attributes: { role: node.role } } : {}),
  });

  const preferredRoot = (rootURN && nodes.get(rootURN)) || nodes.get(rows[0].nodes[0].urn);
  const neighbors = [...nodes.values()].filter((node) => node.urn !== preferredRoot?.urn);
  return {
    ...(preferredRoot ? { root: toGraphNode(preferredRoot) } : {}),
    neighbors: neighbors.map(toGraphNode),
    relations,
  };
};

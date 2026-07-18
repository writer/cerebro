import type {
  SecurityMemoryDagEdge,
  SecurityMemoryDagNode,
  SecurityMemoryGraphEdge,
  SecurityMemoryGraphNode,
  SecurityMemoryGraphProjection,
  SecurityMemoryLineageDag,
  SecurityMemoryRecallConflict,
  SecurityMemoryRecord,
} from "../memory-types.js";
import { roundScore } from "./hygiene.js";
import { normalizeSearchText, stableId, unique } from "./normalization.js";

export interface MemoryGraphMatch {
  record: SecurityMemoryRecord;
  score: number;
  trustScore: number;
  matchedEntities: string[];
}

export function emptyMemoryGraph(query = ""): SecurityMemoryGraphProjection {
  const rootId = queryNodeId(query);
  return {
    rootId,
    nodes: [{ id: rootId, kind: "query", label: query.trim() || "memory recall" }],
    edges: [],
    focusMemoryIds: [],
    entityCount: 0,
    sourceArtifactCount: 0,
    conflictCount: 0,
  };
}

export function emptyLineageDag(query = ""): SecurityMemoryLineageDag {
  const rootId = queryNodeId(query);
  return {
    rootId,
    nodes: [{ id: rootId, kind: "query", label: query.trim() || "memory recall" }],
    edges: [],
    topologicalOrder: [rootId],
  };
}

export function buildMemoryGraph(input: {
  query: string;
  queryEntities: string[];
  matches: MemoryGraphMatch[];
  conflicts: SecurityMemoryRecallConflict[];
  warnings: string[];
}): SecurityMemoryGraphProjection {
  const nodes = new Map<string, SecurityMemoryGraphNode>();
  const edges = new Map<string, SecurityMemoryGraphEdge>();
  const rootId = queryNodeId(input.query);
  addNode(nodes, { id: rootId, kind: "query", label: input.query.trim() || "memory recall" });
  for (const entity of input.queryEntities.slice(0, 12)) {
    const entityId = entityNodeId(entity);
    addNode(nodes, { id: entityId, kind: "entity", label: entity });
    addEdge(edges, { from: rootId, to: entityId, kind: "mentions", reason: "query entity" });
  }

  for (const item of input.matches.slice(0, 12)) {
    const record = item.record;
    const memoryId = memoryNodeId(record.id);
    addNode(nodes, {
      id: memoryId,
      kind: "memory",
      label: record.topic,
      recordId: record.id,
      weight: item.trustScore,
    });
    addEdge(edges, {
      from: rootId,
      to: memoryId,
      kind: "matches",
      weight: roundScore(item.score),
      reason: "recall match",
    });
    for (const entity of unique([...(record.entities ?? []), ...item.matchedEntities]).slice(0, 10)) {
      const entityId = entityNodeId(entity);
      addNode(nodes, { id: entityId, kind: "entity", label: entity });
      addEdge(edges, { from: memoryId, to: entityId, kind: "mentions" });
    }
    if (record.scope) {
      const scopeId = scopeNodeId(record.scope);
      addNode(nodes, { id: scopeId, kind: "scope", label: record.scope });
      addEdge(edges, { from: memoryId, to: scopeId, kind: "scoped_to" });
    }
    for (const artifact of (record.sourceArtifacts ?? []).slice(0, 6)) {
      const artifactId = artifactNodeId(artifact);
      addNode(nodes, { id: artifactId, kind: "source_artifact", label: artifact });
      addEdge(edges, { from: memoryId, to: artifactId, kind: "supported_by" });
    }
    for (const verifier of (record.verifiedBy ?? []).slice(0, 6)) {
      const verifierId = verifierNodeId(verifier);
      addNode(nodes, { id: verifierId, kind: "verifier", label: verifier });
      addEdge(edges, { from: memoryId, to: verifierId, kind: "verified_by" });
    }
  }

  for (const conflict of input.conflicts.slice(0, 5)) {
    const conflictId = conflictNodeId(conflict.recordIds);
    addNode(nodes, { id: conflictId, kind: "conflict", label: conflict.topic });
    for (const recordId of conflict.recordIds.slice(0, 8)) {
      const memoryId = memoryNodeId(recordId);
      if (nodes.has(memoryId)) {
        addEdge(edges, { from: conflictId, to: memoryId, kind: "conflicts_with", reason: conflict.reason });
      }
    }
  }
  for (const warning of input.warnings.slice(0, 5)) {
    const warningId = warningNodeId(warning);
    addNode(nodes, { id: warningId, kind: "warning", label: warning });
    addEdge(edges, { from: rootId, to: warningId, kind: "warns" });
  }

  const graphNodes = [...nodes.values()].slice(0, 80);
  const nodeIds = new Set(graphNodes.map((node) => node.id));
  const graphEdges = [...edges.values()].filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to)).slice(0, 140);
  return {
    rootId,
    nodes: graphNodes,
    edges: graphEdges,
    focusMemoryIds: input.matches.map((item) => item.record.id),
    entityCount: graphNodes.filter((node) => node.kind === "entity").length,
    sourceArtifactCount: graphNodes.filter((node) => node.kind === "source_artifact").length,
    conflictCount: input.conflicts.length,
  };
}

export function buildLineageDag(input: {
  query: string;
  matches: MemoryGraphMatch[];
  conflicts: SecurityMemoryRecallConflict[];
  warnings: string[];
}): SecurityMemoryLineageDag {
  const nodes = new Map<string, SecurityMemoryDagNode>();
  const edges = new Map<string, SecurityMemoryDagEdge>();
  const rootId = queryNodeId(input.query);
  const constraintId = `constraint:${stableId([rootId])}`;
  addDagNode(nodes, { id: rootId, kind: "query", label: input.query.trim() || "memory recall" });
  addDagNode(nodes, { id: constraintId, kind: "answer_constraint", label: "Verify current state before using memory as proof." });
  addDagEdge(edges, { from: constraintId, to: rootId, relation: "constrains_answer" });

  for (const item of input.matches.slice(0, 12)) {
    const record = item.record;
    const memoryId = memoryNodeId(record.id);
    addDagNode(nodes, {
      id: memoryId,
      kind: "memory",
      label: record.topic,
      recordId: record.id,
      weight: item.trustScore,
    });
    addDagEdge(edges, { from: memoryId, to: rootId, relation: "recalled_for", reason: "recall match" });
    if ((record.sourceArtifacts ?? []).length === 0 && (record.verifiedBy ?? []).length === 0) {
      addDagEdge(edges, { from: memoryId, to: constraintId, relation: "requires_verification" });
    }
    for (const artifact of (record.sourceArtifacts ?? []).slice(0, 6)) {
      const artifactId = artifactNodeId(artifact);
      addDagNode(nodes, { id: artifactId, kind: "source_artifact", label: artifact });
      addDagEdge(edges, { from: artifactId, to: memoryId, relation: "supports_memory" });
    }
    for (const verifier of (record.verifiedBy ?? []).slice(0, 6)) {
      const verifierId = verifierNodeId(verifier);
      addDagNode(nodes, { id: verifierId, kind: "verifier", label: verifier });
      addDagEdge(edges, { from: verifierId, to: memoryId, relation: "verified_memory" });
    }
  }

  for (const conflict of input.conflicts.slice(0, 5)) {
    const conflictId = conflictNodeId(conflict.recordIds);
    addDagNode(nodes, { id: conflictId, kind: "conflict", label: conflict.topic });
    addDagEdge(edges, { from: conflictId, to: constraintId, relation: "requires_reconciliation", reason: conflict.reason });
  }
  for (const warning of input.warnings.slice(0, 5)) {
    const warningId = warningNodeId(warning);
    addDagNode(nodes, { id: warningId, kind: "warning", label: warning });
    addDagEdge(edges, { from: warningId, to: constraintId, relation: "limits_answer" });
  }

  const dagNodes = [...nodes.values()].slice(0, 80);
  const nodeIds = new Set(dagNodes.map((node) => node.id));
  const dagEdges = [...edges.values()].filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to)).slice(0, 140);
  return {
    rootId,
    nodes: dagNodes,
    edges: dagEdges,
    topologicalOrder: dagNodes
      .slice()
      .sort((left, right) => dagRank(left.kind) - dagRank(right.kind) || left.label.localeCompare(right.label))
      .map((node) => node.id),
  };
}

function addNode(nodes: Map<string, SecurityMemoryGraphNode>, node: SecurityMemoryGraphNode): void {
  if (!nodes.has(node.id)) nodes.set(node.id, node);
}

function addEdge(edges: Map<string, SecurityMemoryGraphEdge>, edge: SecurityMemoryGraphEdge): void {
  edges.set(`${edge.from}:${edge.kind}:${edge.to}`, edge);
}

function addDagNode(nodes: Map<string, SecurityMemoryDagNode>, node: SecurityMemoryDagNode): void {
  if (!nodes.has(node.id)) nodes.set(node.id, node);
}

function addDagEdge(edges: Map<string, SecurityMemoryDagEdge>, edge: SecurityMemoryDagEdge): void {
  edges.set(`${edge.from}:${edge.relation}:${edge.to}`, edge);
}

function queryNodeId(query: string): string {
  return `query:${stableId([normalizeSearchText(query) || "memory recall"])}`;
}

function memoryNodeId(recordId: string): string {
  return `memory:${recordId}`;
}

function entityNodeId(entity: string): string {
  return `entity:${stableId([normalizeSearchText(entity)])}`;
}

function scopeNodeId(scope: string): string {
  return `scope:${stableId([normalizeSearchText(scope)])}`;
}

function artifactNodeId(artifact: string): string {
  return `artifact:${stableId([normalizeSearchText(artifact)])}`;
}

function verifierNodeId(verifier: string): string {
  return `verifier:${stableId([normalizeSearchText(verifier)])}`;
}

function warningNodeId(warning: string): string {
  return `warning:${stableId([warning])}`;
}

function conflictNodeId(recordIds: string[]): string {
  return `conflict:${stableId(recordIds.slice().sort())}`;
}

function dagRank(kind: SecurityMemoryDagNode["kind"]): number {
  switch (kind) {
    case "source_artifact":
    case "verifier":
      return 0;
    case "memory":
      return 1;
    case "conflict":
    case "warning":
      return 2;
    case "answer_constraint":
      return 3;
    case "query":
      return 4;
  }
}

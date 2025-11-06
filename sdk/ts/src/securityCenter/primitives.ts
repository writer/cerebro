import { parseDate } from "../serialization.js";

export type EntityKind = "vendor" | "customer";

export interface EntityProfile {
  kind: EntityKind;
  id: string;
  name: string;
  category?: string;
  tags: string[];
  metadata: Record<string, unknown>;
}

export interface EvidenceArtifact {
  id: string;
  entityId: string;
  source: string;
  collectedAt: Date | null;
  expiresAt: Date | null;
  contentType?: string;
  labels: string[];
  metadata: Record<string, unknown>;
}

export type EvidenceLifecycleStatus = "fresh" | "stale" | "expired";

export interface EvidenceLifecycle {
  status: EvidenceLifecycleStatus;
  ageDays: number | null;
  ttlDays: number | null;
  nextRefreshAt: Date | null;
  requiresAction: boolean;
}

export interface LifecyclePolicy {
  maxAgeDays?: number;
  refreshWindowDays?: number;
  hardExpiryDays?: number;
}

const MS_PER_DAY = 1000 * 60 * 60 * 24;

export function evaluateEvidenceLifecycle(
  artifact: EvidenceArtifact,
  policy: LifecyclePolicy,
  now: Date = new Date(),
): EvidenceLifecycle {
  const collectedAt = artifact.collectedAt;
  const expiresAt = artifact.expiresAt ?? (policy.hardExpiryDays ? new Date((collectedAt ?? now).getTime() + policy.hardExpiryDays * MS_PER_DAY) : null);
  const ageDays = collectedAt ? Math.floor((now.getTime() - collectedAt.getTime()) / MS_PER_DAY) : null;
  const ttlDays = expiresAt && collectedAt ? Math.ceil((expiresAt.getTime() - collectedAt.getTime()) / MS_PER_DAY) : policy.hardExpiryDays ?? null;

  const maxAge = policy.maxAgeDays ?? null;
  const refreshWindow = policy.refreshWindowDays ?? null;

  let status: EvidenceLifecycleStatus = "fresh";
  let requiresAction = false;

  if (expiresAt && now.getTime() >= expiresAt.getTime()) {
    status = "expired";
    requiresAction = true;
  } else if (ageDays !== null && maxAge !== null && ageDays > maxAge) {
    status = "stale";
    requiresAction = true;
  } else if (refreshWindow !== null && expiresAt) {
    const refreshThreshold = new Date(expiresAt.getTime() - refreshWindow * MS_PER_DAY);
    if (now.getTime() >= refreshThreshold.getTime()) {
      status = "stale";
      requiresAction = true;
    }
  }

  return {
    status,
    ageDays,
    ttlDays,
    nextRefreshAt: expiresAt,
    requiresAction,
  } satisfies EvidenceLifecycle;
}

export interface EvidenceSetSummary {
  status: EvidenceLifecycleStatus;
  lifecycle: EvidenceLifecycle[];
  staleArtifacts: EvidenceArtifact[];
  expiredArtifacts: EvidenceArtifact[];
  nextRefreshAt: Date | null;
}

export function summarizeEvidenceSet(
  artifacts: EvidenceArtifact[],
  policy: LifecyclePolicy,
  now: Date = new Date(),
): EvidenceSetSummary {
  if (artifacts.length === 0) {
    return {
      status: "fresh",
      lifecycle: [],
      staleArtifacts: [],
      expiredArtifacts: [],
      nextRefreshAt: null,
    } satisfies EvidenceSetSummary;
  }

  const deduped = dedupeArtifacts(artifacts);
  const lifecycle = deduped.map((artifact) => evaluateEvidenceLifecycle(artifact, policy, now));
  const staleArtifacts: EvidenceArtifact[] = [];
  const expiredArtifacts: EvidenceArtifact[] = [];

  let nextRefreshAt: Date | null = null;
  let status: EvidenceLifecycleStatus = "fresh";

  for (let idx = 0; idx < deduped.length; idx += 1) {
    const life = lifecycle[idx];
    const artifact = deduped[idx];

    if (life.status === "expired") {
      expiredArtifacts.push(artifact);
      status = "expired";
    } else if (life.status === "stale") {
      staleArtifacts.push(artifact);
      if (status !== "expired") status = "stale";
    }

    if (life.nextRefreshAt) {
      if (!nextRefreshAt || life.nextRefreshAt.getTime() < nextRefreshAt.getTime()) {
        nextRefreshAt = life.nextRefreshAt;
      }
    }
  }

  return {
    status,
    lifecycle,
    staleArtifacts,
    expiredArtifacts,
    nextRefreshAt,
  } satisfies EvidenceSetSummary;
}

export interface EvidenceExtractionOptions {
  kind: EntityKind;
  entityId: string;
  metadata: Record<string, unknown> | undefined;
  defaultSource?: string;
}

export function extractEvidenceArtifacts(options: EvidenceExtractionOptions): EvidenceArtifact[] {
  if (!options.metadata) return [];
  const artifacts: EvidenceArtifact[] = [];
  const evidence = options.metadata.evidence;

  if (isRecord(evidence)) {
    artifacts.push(
      toArtifact({
        kind: options.kind,
        entityId: options.entityId,
        source: options.defaultSource ?? "metadata",
        payload: evidence,
      }),
    );
  }

  const attachments = options.metadata.attachments ?? options.metadata.evidenceArtifacts;
  if (Array.isArray(attachments)) {
    for (const attachment of attachments) {
      if (!isRecord(attachment)) continue;
      const source = typeof attachment.source === "string" ? attachment.source : "attachment";
      artifacts.push(
        toArtifact({
          kind: options.kind,
          entityId: options.entityId,
          source,
          payload: attachment,
        }),
      );
    }
  }

  return artifacts;
}

interface ArtifactParams {
  kind: EntityKind;
  entityId: string;
  source: string;
  payload: Record<string, unknown>;
}

function toArtifact(params: ArtifactParams): EvidenceArtifact {
  const collectedAt = coerceDate(params.payload.collectedAt ?? params.payload.collected_at ?? params.payload.createdAt ?? params.payload.created_at ?? null);
  const expiresAt = coerceDate(params.payload.expiresAt ?? params.payload.expires_at ?? params.payload.validUntil ?? params.payload.valid_until ?? null);
  const labels = collectLabels(params.payload.labels ?? params.payload.tags);
  const id = String(params.payload.id ?? `${params.kind}-${params.entityId}-${params.source}-${collectedAt?.toISOString() ?? "unknown"}`);

  return {
    id,
    entityId: params.entityId,
    source: params.source,
    collectedAt,
    expiresAt,
    contentType: typeof params.payload.contentType === "string" ? params.payload.contentType : undefined,
    labels,
    metadata: params.payload,
  } satisfies EvidenceArtifact;
}

function collectLabels(input: unknown): string[] {
  if (Array.isArray(input)) return input.filter((value): value is string => typeof value === "string");
  if (isRecord(input)) return Object.values(input).filter((value): value is string => typeof value === "string");
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function dedupeArtifacts(artifacts: EvidenceArtifact[]): EvidenceArtifact[] {
  const seen = new Map<string, EvidenceArtifact>();
  for (const artifact of artifacts) {
    if (!seen.has(artifact.id)) {
      seen.set(artifact.id, artifact);
    }
  }
  return Array.from(seen.values());
}

function coerceDate(value: unknown): Date | null {
  if (value == null) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") {
    const fromNumber = new Date(value);
    return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
  }
  if (typeof value === "string") return parseDate(value);
  return parseDate(value as string | Date | null | undefined);
}

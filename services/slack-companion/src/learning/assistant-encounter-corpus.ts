import { createHash } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";
import { redactSecurityText } from "../security/redaction.js";

const MAX_SCAN_PAGES = 32;
const MAX_SEEDS = 1_000;

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface EncounterRecord {
  id?: unknown;
  details?: unknown;
  tags?: unknown;
  createdAt?: unknown;
  outcome?: unknown;
  senderKind?: unknown;
  trafficKind?: unknown;
}

export interface EncounterRequestSeed {
  id: string;
  question: string;
  occurredAt?: string;
  tags: string[];
}

export async function loadEncounterRequestSeeds(input: {
  tableName: string;
  limit?: number;
  lookbackDays?: number;
  now?: Date;
  client?: CommandSender;
}): Promise<EncounterRequestSeed[]> {
  const limit = boundedInteger(input.limit ?? 500, 1, MAX_SEEDS);
  const lookbackDays = boundedInteger(input.lookbackDays ?? 30, 1, 365);
  const cutoff = (input.now ?? new Date()).getTime() - lookbackDays * 86_400_000;
  const client = input.client ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
    marshallOptions: { removeUndefinedValues: true },
  });
  const records: EncounterRecord[] = [];
  let exclusiveStartKey: Record<string, unknown> | undefined;
  for (let page = 0; page < MAX_SCAN_PAGES && records.length < limit * 3; page += 1) {
    const response = await client.send(new ScanCommand({
      TableName: input.tableName,
      FilterExpression: "#kind = :kind AND #outcome = :answered",
      ExpressionAttributeNames: {
        "#kind": "kind",
        "#outcome": "outcome",
        "#id": "id",
        "#details": "details",
        "#tags": "tags",
        "#created": "createdAt",
        "#sender": "senderKind",
        "#traffic": "trafficKind",
      },
      ExpressionAttributeValues: { ":kind": "encounter_story", ":answered": "answered" },
      ProjectionExpression: "#id, #details, #tags, #created, #outcome, #sender, #traffic",
      ExclusiveStartKey: exclusiveStartKey,
      Limit: 250,
    })) as { Items?: EncounterRecord[]; LastEvaluatedKey?: Record<string, unknown> };
    records.push(...(response.Items ?? []));
    exclusiveStartKey = response.LastEvaluatedKey;
    if (!exclusiveStartKey) break;
  }
  return encounterRecordsToSeeds(records, { limit, cutoff });
}

export function encounterRecordsToSeeds(
  records: EncounterRecord[],
  options: { limit: number; cutoff?: number },
): EncounterRequestSeed[] {
  const seeds = records.flatMap((record) => {
    if (record.outcome !== "answered" || record.senderKind === "bot" || record.trafficKind === "machine_handoff") return [];
    const tags = stringArray(record.tags);
    if (tags.some((tag) => /machine[-_ ]handoff|automated[-_ ]handoff/i.test(tag))) return [];
    const occurredAt = typeof record.createdAt === "string" ? record.createdAt : undefined;
    if (options.cutoff !== undefined && occurredAt) {
      const parsed = Date.parse(occurredAt);
      if (Number.isFinite(parsed) && parsed < options.cutoff) return [];
    }
    const question = extractEncounterQuestion(record.details);
    if (!question) return [];
    const sourceId = typeof record.id === "string" ? record.id : question;
    return [{
      id: `encounter-${createHash("sha256").update(sourceId).update("\0").update(question).digest("hex").slice(0, 20)}`,
      question,
      occurredAt,
      tags: tags.map((tag) => sanitizeCorpusText(tag, 80)).filter(Boolean).slice(0, 12),
    }];
  }).sort((left, right) => (right.occurredAt ?? "").localeCompare(left.occurredAt ?? ""));
  const unique = new Map<string, EncounterRequestSeed>();
  for (const seed of seeds) {
    const normalized = seed.question.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    if (!normalized || unique.has(normalized)) continue;
    unique.set(normalized, seed);
    if (unique.size >= options.limit) break;
  }
  return [...unique.values()];
}

export function extractEncounterQuestion(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const match = value.trim().match(/^Question:\s*([\s\S]*?)(?:\n|\s+)Answer:/i);
  if (!match?.[1]) return undefined;
  const question = sanitizeCorpusText(match[1], 4_000);
  return question.length > 0 ? question : undefined;
}

export function sanitizeCorpusText(value: string, max: number): string {
  return redactSecurityText(value)
    .replace(/<@[A-Z0-9]+>/gi, "[person]")
    .replace(/<#[A-Z0-9]+(?:\|[^>]+)?>/gi, "[channel]")
    .replace(/https:\/\/[A-Za-z0-9.-]+\.slack\.com\/archives\/[A-Z0-9]+\/p\d+(?:\?[^\s)]*)?/gi, "[slack_message]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Expected an integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

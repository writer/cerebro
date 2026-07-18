import { createHash } from "node:crypto";
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import type { ImprovementArtifact } from "./types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface ImprovementArtifactStore {
  putJson(runId: string, kind: ImprovementArtifact["kind"], value: unknown, now?: Date): Promise<ImprovementArtifact>;
  getJson(artifact: ImprovementArtifact): Promise<unknown>;
}

export class S3ImprovementArtifactStore implements ImprovementArtifactStore {
  private readonly client: CommandSender;

  constructor(private readonly bucket: string, client?: CommandSender) {
    this.client = client ?? new S3Client({});
  }

  async putJson(runId: string, kind: ImprovementArtifact["kind"], value: unknown, now = new Date()): Promise<ImprovementArtifact> {
    const body = Buffer.from(stableJson(value), "utf8");
    const sha256 = createHash("sha256").update(body).digest("hex");
    const key = `runs/${boundedSegment(runId)}/${kind}/${now.toISOString().replace(/[:.]/g, "-")}-${sha256.slice(0, 12)}.json`;
    await this.client.send(new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: body,
      ContentType: "application/json",
      ServerSideEncryption: "aws:kms",
      IfNoneMatch: "*",
      Metadata: { sha256, schema: "recursive-improvement-v1" },
    }));
    return { kind, uri: `s3://${this.bucket}/${key}`, sha256, createdAt: now.toISOString() };
  }

  async getJson(artifact: ImprovementArtifact): Promise<unknown> {
    const location = parseS3Uri(artifact.uri);
    if (location.bucket !== this.bucket) throw new Error("Improvement artifact bucket does not match the configured bucket.");
    const response = await this.client.send(new GetObjectCommand({ Bucket: location.bucket, Key: location.key })) as {
      Body?: { transformToString(): Promise<string> };
    };
    if (!response.Body) throw new Error("Improvement artifact did not include a response body.");
    const body = await response.Body.transformToString();
    const sha256 = createHash("sha256").update(body, "utf8").digest("hex");
    if (sha256 !== artifact.sha256) throw new Error("Improvement artifact checksum did not match its receipt.");
    return JSON.parse(body) as unknown;
  }
}

export class InMemoryImprovementArtifactStore implements ImprovementArtifactStore {
  readonly values = new Map<string, unknown>();

  async putJson(runId: string, kind: ImprovementArtifact["kind"], value: unknown, now = new Date()): Promise<ImprovementArtifact> {
    const body = stableJson(value);
    const sha256 = createHash("sha256").update(body).digest("hex");
    const uri = `s3://test-improvement/runs/${boundedSegment(runId)}/${kind}/${sha256}.json`;
    this.values.set(uri, structuredClone(value));
    return { kind, uri, sha256, createdAt: now.toISOString() };
  }

  async getJson(artifact: ImprovementArtifact): Promise<unknown> {
    if (!this.values.has(artifact.uri)) throw new Error("Improvement artifact was not found.");
    return structuredClone(this.values.get(artifact.uri));
  }
}

export function stableJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => [key, sortJson(item)]));
}

function parseS3Uri(uri: string): { bucket: string; key: string } {
  const matched = uri.match(/^s3:\/\/([^/]+)\/(.+)$/);
  if (!matched?.[1] || !matched[2]) throw new Error("Improvement artifact URI is invalid.");
  return { bucket: matched[1], key: matched[2] };
}

function boundedSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 160);
}

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";
import { improvementEventSchema, improvementRunSchema, type ImprovementEvent, type ImprovementRun, type ImprovementRunStatus } from "./types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface ImprovementRunStore {
  create(run: ImprovementRun, event: ImprovementEvent): Promise<void>;
  get(runId: string): Promise<ImprovementRun | undefined>;
  commit(previousVersion: number, run: ImprovementRun, event: ImprovementEvent): Promise<void>;
  listByStatus(status: ImprovementRunStatus, limit: number): Promise<ImprovementRun[]>;
}

export class DynamoImprovementRunStore implements ImprovementRunStore {
  private readonly client: CommandSender;

  constructor(private readonly tableName: string, client?: CommandSender) {
    this.client = client ?? DynamoDBDocumentClient.from(new DynamoDBClient({}), {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async create(run: ImprovementRun, event: ImprovementEvent): Promise<void> {
    const parsedRun = improvementRunSchema.parse(run);
    const parsedEvent = improvementEventSchema.parse(event);
    await this.client.send(new TransactWriteCommand({
      TransactItems: [
        {
          Put: {
            TableName: this.tableName,
            Item: runItem(parsedRun),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
        {
          Put: {
            TableName: this.tableName,
            Item: eventItem(parsedEvent),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
      ],
    }));
  }

  async get(runId: string): Promise<ImprovementRun | undefined> {
    const response = await this.client.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: runPartition(runId), sk: "RUN" },
      ConsistentRead: true,
    })) as { Item?: unknown };
    return parseRunItem(response.Item);
  }

  async commit(previousVersion: number, run: ImprovementRun, event: ImprovementEvent): Promise<void> {
    const parsedRun = improvementRunSchema.parse(run);
    const parsedEvent = improvementEventSchema.parse(event);
    await this.client.send(new TransactWriteCommand({
      TransactItems: [
        {
          Put: {
            TableName: this.tableName,
            Item: runItem(parsedRun),
            ConditionExpression: "#version = :previousVersion",
            ExpressionAttributeNames: { "#version": "version" },
            ExpressionAttributeValues: { ":previousVersion": previousVersion },
          },
        },
        {
          Put: {
            TableName: this.tableName,
            Item: eventItem(parsedEvent),
            ConditionExpression: "attribute_not_exists(pk)",
          },
        },
      ],
    }));
  }

  async listByStatus(status: ImprovementRunStatus, limit: number): Promise<ImprovementRun[]> {
    const response = await this.client.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: "status-updated-at-index",
      KeyConditionExpression: "#status = :status",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: { ":status": status },
      ScanIndexForward: true,
      Limit: Math.max(1, Math.min(limit, 100)),
    })) as { Items?: unknown[] };
    return (response.Items ?? []).flatMap((item) => {
      const parsed = parseRunItem(item);
      return parsed ? [parsed] : [];
    });
  }
}

export class InMemoryImprovementRunStore implements ImprovementRunStore {
  readonly runs = new Map<string, ImprovementRun>();
  readonly events: ImprovementEvent[] = [];

  async create(run: ImprovementRun, event: ImprovementEvent): Promise<void> {
    if (this.runs.has(run.id)) throw conditionalFailure("Improvement run already exists.");
    this.runs.set(run.id, structuredClone(improvementRunSchema.parse(run)));
    this.events.push(structuredClone(improvementEventSchema.parse(event)));
  }

  async get(runId: string): Promise<ImprovementRun | undefined> {
    const run = this.runs.get(runId);
    return run ? structuredClone(run) : undefined;
  }

  async commit(previousVersion: number, run: ImprovementRun, event: ImprovementEvent): Promise<void> {
    const current = this.runs.get(run.id);
    if (!current || current.version !== previousVersion) throw conditionalFailure("Improvement run version changed.");
    this.runs.set(run.id, structuredClone(improvementRunSchema.parse(run)));
    this.events.push(structuredClone(improvementEventSchema.parse(event)));
  }

  async listByStatus(status: ImprovementRunStatus, limit: number): Promise<ImprovementRun[]> {
    return [...this.runs.values()]
      .filter((run) => run.status === status)
      .sort((left, right) => left.updatedAt.localeCompare(right.updatedAt))
      .slice(0, Math.max(1, Math.min(limit, 100)))
      .map((run) => structuredClone(run));
  }
}

export function isImprovementStoreConflict(error: unknown): boolean {
  const name = error && typeof error === "object" && "name" in error ? String((error as { name?: unknown }).name) : "";
  return name === "TransactionCanceledException" || name === "ConditionalCheckFailedException";
}

function runItem(run: ImprovementRun): Record<string, unknown> {
  return {
    pk: runPartition(run.id),
    sk: "RUN",
    recordType: "improvement_run",
    updated_at: run.updatedAt,
    ...run,
  };
}

function eventItem(event: ImprovementEvent): Record<string, unknown> {
  return {
    pk: runPartition(event.runId),
    sk: `EVENT#${event.id}`,
    recordType: "improvement_event",
    ...event,
  };
}

function parseRunItem(value: unknown): ImprovementRun | undefined {
  if (!value || typeof value !== "object") return undefined;
  const { pk: _pk, sk: _sk, recordType: _recordType, updated_at: _updatedAt, ...candidate } = value as Record<string, unknown>;
  const parsed = improvementRunSchema.safeParse(candidate);
  return parsed.success ? parsed.data : undefined;
}

function runPartition(runId: string): string {
  return `RUN#${runId}`;
}

function conditionalFailure(message: string): Error {
  const error = new Error(message);
  error.name = "ConditionalCheckFailedException";
  return error;
}

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import type { A2AInstance, A2AMessage } from "./types.js";

export interface A2AFleetStore {
  putInstance(instance: A2AInstance): Promise<void>;
  listInstances(nowEpochSeconds: number): Promise<A2AInstance[]>;
  putMessage(message: A2AMessage): Promise<void>;
  listInbox(instanceId: string, nowEpochSeconds: number): Promise<A2AMessage[]>;
  claimMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<boolean>;
  releaseMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<void>;
  acknowledgeMessage(instanceId: string, message: A2AMessage, acknowledgedAt: string): Promise<void>;
  getMessage(instanceId: string, message: A2AMessage): Promise<A2AMessage | undefined>;
}

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export class DynamoA2AFleetStore implements A2AFleetStore {
  private readonly dynamo: CommandSender;
  private readonly fleetPk: string;
  private readonly mailboxPrefix: string;

  constructor(
    private readonly tableName: string,
    tenantId: string,
    dynamo?: CommandSender,
  ) {
    this.dynamo = dynamo ?? DynamoDBDocumentClient.from(new DynamoDBClient({}));
    this.fleetPk = `tenant#${tenantId}#a2a-fleet`;
    this.mailboxPrefix = `tenant#${tenantId}#a2a-mailbox#`;
  }

  async putInstance(instance: A2AInstance): Promise<void> {
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: { pk: this.fleetPk, sk: `instance#${instance.instanceId}`, ...instance, expires_at: instance.expiresAt },
    }));
  }

  async listInstances(nowEpochSeconds: number): Promise<A2AInstance[]> {
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.fleetPk, ":prefix": "instance#" },
      ConsistentRead: true,
    })) as { Items?: Array<Record<string, unknown>> };
    return (response.Items ?? [])
      .flatMap((item) => {
        const instance = instanceFromItem(item);
        return instance && instance.expiresAt >= nowEpochSeconds ? [instance] : [];
      });
  }

  async putMessage(message: A2AMessage): Promise<void> {
    await this.dynamo.send(new PutCommand({
      TableName: this.tableName,
      Item: {
        pk: this.mailboxPk(message.to),
        sk: messageKey(message),
        ...message,
        expires_at: message.expiresAt,
      },
      ConditionExpression: "attribute_not_exists(pk) AND attribute_not_exists(sk)",
    }));
  }

  async listInbox(instanceId: string, nowEpochSeconds: number): Promise<A2AMessage[]> {
    const response = await this.dynamo.send(new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: "pk = :pk AND begins_with(sk, :prefix)",
      ExpressionAttributeValues: { ":pk": this.mailboxPk(instanceId), ":prefix": "message#" },
      ScanIndexForward: true,
      Limit: 25,
      ConsistentRead: true,
    })) as { Items?: Array<Record<string, unknown>> };
    return (response.Items ?? [])
      .flatMap((item) => {
        const message = messageFromItem(item);
        return message && !message.processedAt && message.expiresAt >= nowEpochSeconds ? [message] : [];
      });
  }

  async claimMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<boolean> {
    try {
      await this.dynamo.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: this.mailboxPk(instanceId), sk: messageKey(message) },
        UpdateExpression: "SET processedAt = :processedAt",
        ConditionExpression: "attribute_not_exists(processedAt)",
        ExpressionAttributeValues: { ":processedAt": processedAt },
      }));
      return true;
    } catch (error) {
      if ((error as { name?: string }).name === "ConditionalCheckFailedException") return false;
      throw error;
    }
  }

  async acknowledgeMessage(instanceId: string, message: A2AMessage, acknowledgedAt: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: this.mailboxPk(instanceId), sk: messageKey(message) },
      UpdateExpression: "SET acknowledgedAt = :at, acknowledgedBy = :by",
      ExpressionAttributeValues: { ":at": acknowledgedAt, ":by": instanceId },
    }));
  }

  async releaseMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<void> {
    await this.dynamo.send(new UpdateCommand({
      TableName: this.tableName,
      Key: { pk: this.mailboxPk(instanceId), sk: messageKey(message) },
      UpdateExpression: "REMOVE processedAt",
      ConditionExpression: "processedAt = :processedAt AND attribute_not_exists(acknowledgedAt)",
      ExpressionAttributeValues: { ":processedAt": processedAt },
    })).catch((error) => {
      if ((error as { name?: string }).name !== "ConditionalCheckFailedException") throw error;
    });
  }

  async getMessage(instanceId: string, message: A2AMessage): Promise<A2AMessage | undefined> {
    const response = await this.dynamo.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk: this.mailboxPk(instanceId), sk: messageKey(message) },
      ConsistentRead: true,
    })) as { Item?: Record<string, unknown> };
    return response.Item ? messageFromItem(response.Item) : undefined;
  }

  private mailboxPk(instanceId: string): string {
    return `${this.mailboxPrefix}${instanceId}`;
  }
}

export class InMemoryA2AFleetStore implements A2AFleetStore {
  private readonly instances = new Map<string, A2AInstance>();
  private readonly messages = new Map<string, A2AMessage>();

  async putInstance(instance: A2AInstance): Promise<void> {
    this.instances.set(instance.instanceId, structuredClone(instance));
  }
  async listInstances(nowEpochSeconds: number): Promise<A2AInstance[]> {
    return [...this.instances.values()].filter((item) => item.expiresAt >= nowEpochSeconds).map((item) => structuredClone(item));
  }
  async putMessage(message: A2AMessage): Promise<void> {
    this.messages.set(this.key(message.to, message), structuredClone(message));
  }
  async listInbox(instanceId: string, nowEpochSeconds: number): Promise<A2AMessage[]> {
    return [...this.messages.values()]
      .filter((item) => item.to === instanceId && !item.processedAt && item.expiresAt >= nowEpochSeconds)
      .map((item) => structuredClone(item));
  }
  async claimMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<boolean> {
    const key = this.key(instanceId, message);
    const found = this.messages.get(key);
    if (!found || found.processedAt) return false;
    found.processedAt = processedAt;
    return true;
  }
  async acknowledgeMessage(instanceId: string, message: A2AMessage, acknowledgedAt: string): Promise<void> {
    const found = this.messages.get(this.key(instanceId, message));
    if (!found) return;
    found.acknowledgedAt = acknowledgedAt;
    found.acknowledgedBy = instanceId;
  }
  async releaseMessage(instanceId: string, message: A2AMessage, processedAt: string): Promise<void> {
    const found = this.messages.get(this.key(instanceId, message));
    if (found?.processedAt === processedAt && !found.acknowledgedAt) delete found.processedAt;
  }
  async getMessage(instanceId: string, message: A2AMessage): Promise<A2AMessage | undefined> {
    const found = this.messages.get(this.key(instanceId, message));
    return found ? structuredClone(found) : undefined;
  }
  private key(instanceId: string, message: A2AMessage): string {
    return `${instanceId}#${message.createdAt}#${message.messageId}`;
  }
}

function messageKey(message: A2AMessage): string {
  return `message#${message.createdAt}#${message.messageId}`;
}

function instanceFromItem(item: Record<string, unknown>): A2AInstance | undefined {
  if (typeof item.instanceId !== "string" || typeof item.heartbeatAt !== "string" || typeof item.expiresAt !== "number") return undefined;
  return {
    instanceId: item.instanceId,
    label: String(item.label ?? "unknown"),
    role: String(item.role ?? "unknown"),
    commit: String(item.commit ?? "unknown"),
    commitSubject: typeof item.commitSubject === "string" ? item.commitSubject : undefined,
    capabilities: Array.isArray(item.capabilities) ? item.capabilities.map(String) : [],
    state: item.state === "draining" || item.state === "stopped" ? item.state : "active",
    startedAt: String(item.startedAt ?? item.heartbeatAt),
    heartbeatAt: item.heartbeatAt,
    expiresAt: item.expiresAt,
  };
}

function messageFromItem(item: Record<string, unknown>): A2AMessage | undefined {
  if (typeof item.messageId !== "string" || typeof item.from !== "string" || typeof item.to !== "string" || typeof item.createdAt !== "string" || typeof item.expiresAt !== "number") return undefined;
  if (item.kind !== "task" && item.kind !== "handoff" && item.kind !== "status") return undefined;
  return {
    messageId: item.messageId,
    contextId: String(item.contextId ?? item.messageId),
    taskId: typeof item.taskId === "string" ? item.taskId : undefined,
    kind: item.kind,
    from: item.from,
    to: item.to,
    parts: Array.isArray(item.parts) ? item.parts as A2AMessage["parts"] : [],
    createdAt: item.createdAt,
    expiresAt: item.expiresAt,
    acknowledgedAt: typeof item.acknowledgedAt === "string" ? item.acknowledgedAt : undefined,
    acknowledgedBy: typeof item.acknowledgedBy === "string" ? item.acknowledgedBy : undefined,
    processedAt: typeof item.processedAt === "string" ? item.processedAt : undefined,
  };
}

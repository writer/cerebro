import { SendMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
import { improvementJobSchema, type ImprovementJob } from "./types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface ImprovementJobQueue {
  send(job: ImprovementJob, delaySeconds?: number): Promise<void>;
}

export class SqsImprovementJobQueue implements ImprovementJobQueue {
  private readonly client: CommandSender;

  constructor(private readonly queueUrl: string, client?: CommandSender) {
    this.client = client ?? new SQSClient({});
  }

  async send(job: ImprovementJob, delaySeconds = 0): Promise<void> {
    const parsed = improvementJobSchema.parse(job);
    await this.client.send(new SendMessageCommand({
      QueueUrl: this.queueUrl,
      MessageBody: JSON.stringify(parsed),
      DelaySeconds: Math.max(0, Math.min(Math.floor(delaySeconds), 900)),
    }));
  }
}

export class InMemoryImprovementJobQueue implements ImprovementJobQueue {
  readonly jobs: Array<{ job: ImprovementJob; delaySeconds: number }> = [];

  async send(job: ImprovementJob, delaySeconds = 0): Promise<void> {
    this.jobs.push({ job: structuredClone(improvementJobSchema.parse(job)), delaySeconds });
  }
}

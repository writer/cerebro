import HttpClient from "../httpClient.js";

export interface TaskSubmission {
  taskId: string;
  status: string;
}

export interface TaskStatusRecord {
  taskId: string;
  status: string;
  successful: boolean;
  failed: boolean;
  result: unknown;
  traceback: string | null;
  dateDone: Date | null;
}

export interface EnqueueTaskOptions {
  queue?: string;
  kwargs?: Record<string, unknown>;
  countdown?: number;
  eta?: Date | string;
  priority?: number;
}

export interface TasksAdapter {
  enqueue(taskName: string, args?: unknown[], options?: EnqueueTaskOptions): Promise<TaskSubmission>;
  sendTask(taskName: string, args?: unknown[], options?: Record<string, unknown>): Promise<TaskSubmission>;
  getStatus(taskId: string): Promise<TaskStatusRecord>;
  revoke(taskId: string, options?: { terminate?: boolean; signal?: string }): Promise<void>;
}

export interface HttpTasksAdapterOptions {
  enqueueEndpoint?: string;
  sendTaskEndpoint?: string;
  statusEndpoint?: (taskId: string) => string;
  revokeEndpoint?: (taskId: string) => string;
}

interface TaskStatusPayload {
  task_id: string;
  status: string;
  successful?: boolean;
  failed?: boolean;
  result?: unknown;
  traceback?: string | null;
  date_done?: string | null;
}

class HttpTasksAdapter implements TasksAdapter {
  private readonly enqueueEndpoint: string;
  private readonly sendEndpoint: string;

  constructor(
    private readonly http: HttpClient,
    private readonly options: HttpTasksAdapterOptions = {},
  ) {
    this.enqueueEndpoint = options.enqueueEndpoint ?? "/api/v1/tasks/enqueue";
    this.sendEndpoint = options.sendTaskEndpoint ?? "/api/v1/tasks/send";
  }

  async enqueue(taskName: string, args: unknown[] = [], options: EnqueueTaskOptions = {}): Promise<TaskSubmission> {
    const payload: Record<string, unknown> = {
      task_name: taskName,
      args,
      kwargs: options.kwargs ?? {},
    };

    if (options.queue !== undefined) payload.queue = options.queue;
    if (options.countdown !== undefined) payload.countdown = options.countdown;
    if (options.eta) payload.eta = normaliseDate(options.eta);
    if (options.priority !== undefined) payload.priority = options.priority;

    const response = await this.http.post<TaskStatusPayload | TaskSubmission>(this.enqueueEndpoint, {
      body: payload,
    });

    return mapSubmission(response);
  }

  async sendTask(taskName: string, args: unknown[] = [], options: Record<string, unknown> = {}): Promise<TaskSubmission> {
    const response = await this.http.post<TaskStatusPayload | TaskSubmission>(this.sendEndpoint, {
      body: {
        task_name: taskName,
        args,
        options,
      },
    });

    return mapSubmission(response);
  }

  async getStatus(taskId: string): Promise<TaskStatusRecord> {
    if (!this.options.statusEndpoint) {
      throw new Error("statusEndpoint is not configured for HttpTasksAdapter");
    }

    const payload = await this.http.get<TaskStatusPayload>(this.options.statusEndpoint(taskId));
    return mapStatus(payload);
  }

  async revoke(taskId: string, options: { terminate?: boolean; signal?: string } = {}): Promise<void> {
    if (!this.options.revokeEndpoint) {
      throw new Error("revokeEndpoint is not configured for HttpTasksAdapter");
    }

    await this.http.post(this.options.revokeEndpoint(taskId), {
      body: {
        terminate: options.terminate ?? false,
        signal: options.signal ?? null,
      },
    });
  }
}

export class InMemoryTasksAdapter implements TasksAdapter {
  private readonly store = new Map<string, TaskStatusRecord>();

  async enqueue(taskName: string, args: unknown[] = [], _options: EnqueueTaskOptions = {}): Promise<TaskSubmission> {
    const id = generateId();
    const record: TaskStatusRecord = {
      taskId: id,
      status: "PENDING",
      successful: false,
      failed: false,
      result: { taskName, args },
      traceback: null,
      dateDone: null,
    };
    this.store.set(id, record);
    return { taskId: id, status: record.status };
  }

  async sendTask(taskName: string, args: unknown[] = [], _options: Record<string, unknown> = {}): Promise<TaskSubmission> {
    return this.enqueue(taskName, args, {});
  }

  async getStatus(taskId: string): Promise<TaskStatusRecord> {
    const record = this.store.get(taskId);
    if (!record) {
      throw new Error(`Task '${taskId}' not found`);
    }
    return record;
  }

  async revoke(taskId: string): Promise<void> {
    const record = this.store.get(taskId);
    if (record) {
      record.status = "REVOKED";
      record.failed = true;
      record.successful = false;
      record.dateDone = new Date();
    }
  }
}

export class TasksClient {
  constructor(private readonly adapter: TasksAdapter) {}

  static fromHttpClient(http: HttpClient, options?: HttpTasksAdapterOptions): TasksClient {
    return new TasksClient(new HttpTasksAdapter(http, options));
  }

  async enqueue(taskName: string, args?: unknown[], options?: EnqueueTaskOptions): Promise<TaskSubmission> {
    return this.adapter.enqueue(taskName, args, options);
  }

  async sendTask(taskName: string, args?: unknown[], options?: Record<string, unknown>): Promise<TaskSubmission> {
    return this.adapter.sendTask(taskName, args, options);
  }

  async getStatus(taskId: string): Promise<TaskStatusRecord> {
    return this.adapter.getStatus(taskId);
  }

  async revoke(taskId: string, options?: { terminate?: boolean; signal?: string }): Promise<void> {
    return this.adapter.revoke(taskId, options);
  }
}

function mapSubmission(payload: TaskStatusPayload | TaskSubmission): TaskSubmission {
  if ((payload as TaskSubmission).taskId) {
    return payload as TaskSubmission;
  }
  const statusPayload = payload as TaskStatusPayload;
  return {
    taskId: String(statusPayload.task_id),
    status: statusPayload.status,
  };
}

function mapStatus(payload: TaskStatusPayload): TaskStatusRecord {
  return {
    taskId: String(payload.task_id),
    status: payload.status,
    successful: Boolean(payload.successful),
    failed: Boolean(payload.failed),
    result: payload.result,
    traceback: payload.traceback ?? null,
    dateDone: payload.date_done ? new Date(payload.date_done) : null,
  };
}

function normaliseDate(input: Date | string): string {
  if (input instanceof Date) {
    return input.toISOString();
  }
  return new Date(input).toISOString();
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

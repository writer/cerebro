import HttpClient from "../httpClient";
import { AgentNotificationRecord, AgentTicketRecord } from "../types";

export interface EnqueueNotificationRequest {
  orgId: string;
  taskId: string;
  channel: string;
  payload?: Record<string, unknown>;
}

export interface NotificationsAdapter {
  enqueue(request: EnqueueNotificationRequest): Promise<AgentNotificationRecord>;
  list(options?: { status?: string; limit?: number }): Promise<AgentNotificationRecord[]>;
  markDelivered(notificationId: string): Promise<AgentNotificationRecord | null>;
}

export interface TicketsAdapter {
  createTicket(request: {
    orgId: string;
    taskId: string;
    system: string;
    summary: string;
    metadata?: Record<string, unknown>;
  }): Promise<AgentTicketRecord>;
  closeTicket(ticketId: string, options?: { externalId?: string }): Promise<AgentTicketRecord | null>;
  listTickets(taskId: string): Promise<AgentTicketRecord[]>;
}

export interface HttpNotificationsAdapterOptions {
  notificationsPath?: string;
  ticketsPath?: string;
}

interface NotificationPayload {
  id: string;
  task_id: string;
  org_id: string;
  channel: string;
  status: string;
  payload?: Record<string, unknown> | null;
  created_at: string;
  delivered_at?: string | null;
}

interface TicketPayload {
  id: string;
  task_id: string;
  org_id: string;
  system: string;
  status: string;
  details?: Record<string, unknown> | null;
  external_id?: string | null;
  created_at: string;
  updated_at?: string | null;
}

class HttpNotificationsAdapter implements NotificationsAdapter {
  constructor(
    private readonly http: HttpClient,
    private readonly options: HttpNotificationsAdapterOptions = {},
  ) {}

  private get basePath(): string {
    return this.options.notificationsPath ?? "/api/v1/agents/notifications";
  }

  async enqueue(request: EnqueueNotificationRequest): Promise<AgentNotificationRecord> {
    const payload = await this.http.post<NotificationPayload>(this.basePath, {
      body: {
        org_id: request.orgId,
        task_id: request.taskId,
        channel: request.channel,
        payload: request.payload ?? {},
      },
    });
    return mapNotification(payload);
  }

  async list(options: { status?: string; limit?: number } = {}): Promise<AgentNotificationRecord[]> {
    const params: Record<string, string | number> = {};
    if (options.status) params.status = options.status;
    if (options.limit !== undefined) params.limit = options.limit;

    const payload = await this.http.get<NotificationPayload[]>(this.basePath, {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    return payload.map(mapNotification);
  }

  async markDelivered(notificationId: string): Promise<AgentNotificationRecord | null> {
    const payload = await this.http.post<NotificationPayload | null>(`${this.basePath}/${notificationId}/deliver`, {});
    return payload ? mapNotification(payload) : null;
  }
}

class HttpTicketsAdapter implements TicketsAdapter {
  constructor(
    private readonly http: HttpClient,
    private readonly options: HttpNotificationsAdapterOptions = {},
  ) {}

  private get basePath(): string {
    return this.options.ticketsPath ?? "/api/v1/agents/tickets";
  }

  async createTicket(request: {
    orgId: string;
    taskId: string;
    system: string;
    summary: string;
    metadata?: Record<string, unknown>;
  }): Promise<AgentTicketRecord> {
    const payload = await this.http.post<TicketPayload>(this.basePath, {
      body: {
        org_id: request.orgId,
        task_id: request.taskId,
        system: request.system,
        summary: request.summary,
        metadata: request.metadata ?? {},
      },
    });

    return mapTicket(payload);
  }

  async closeTicket(ticketId: string, options: { externalId?: string } = {}): Promise<AgentTicketRecord | null> {
    const payload = await this.http.post<TicketPayload | null>(`${this.basePath}/${ticketId}/close`, {
      body: {
        external_id: options.externalId ?? null,
      },
    });
    return payload ? mapTicket(payload) : null;
  }

  async listTickets(taskId: string): Promise<AgentTicketRecord[]> {
    const payload = await this.http.get<TicketPayload[]>(`${this.basePath}`, {
      searchParams: { task_id: taskId },
    });
    return payload.map(mapTicket);
  }
}

export class InMemoryNotificationsAdapter implements NotificationsAdapter {
  private readonly notifications = new Map<string, AgentNotificationRecord>();

  constructor(initial: AgentNotificationRecord[] = []) {
    initial.forEach((notification) => this.notifications.set(notification.notificationId, notification));
  }

  async enqueue(request: EnqueueNotificationRequest): Promise<AgentNotificationRecord> {
    const record: AgentNotificationRecord = {
      notificationId: generateId(),
      taskId: request.taskId,
      orgId: request.orgId,
      channel: request.channel,
      status: "PENDING",
      payload: request.payload ?? {},
      createdAt: new Date(),
      deliveredAt: null,
    };
    this.notifications.set(record.notificationId, record);
    return record;
  }

  async list(): Promise<AgentNotificationRecord[]> {
    return Array.from(this.notifications.values());
  }

  async markDelivered(notificationId: string): Promise<AgentNotificationRecord | null> {
    const record = this.notifications.get(notificationId);
    if (!record) {
      return null;
    }
    record.status = "DELIVERED";
    record.deliveredAt = new Date();
    return record;
  }
}

export class InMemoryTicketsAdapter implements TicketsAdapter {
  private readonly tickets = new Map<string, AgentTicketRecord>();

  async createTicket(request: {
    orgId: string;
    taskId: string;
    system: string;
    summary: string;
    metadata?: Record<string, unknown>;
  }): Promise<AgentTicketRecord> {
    const record: AgentTicketRecord = {
      ticketId: generateId(),
      taskId: request.taskId,
      orgId: request.orgId,
      system: request.system,
      status: "OPEN",
      details: { summary: request.summary, ...(request.metadata ?? {}) },
      externalId: null,
      createdAt: new Date(),
      updatedAt: null,
    };
    this.tickets.set(record.ticketId, record);
    return record;
  }

  async closeTicket(ticketId: string, options: { externalId?: string } = {}): Promise<AgentTicketRecord | null> {
    const record = this.tickets.get(ticketId);
    if (!record) {
      return null;
    }
    record.status = "CLOSED";
    record.updatedAt = new Date();
    if (options.externalId) {
      record.externalId = options.externalId;
    }
    return record;
  }

  async listTickets(taskId: string): Promise<AgentTicketRecord[]> {
    return Array.from(this.tickets.values()).filter((ticket) => ticket.taskId === taskId);
  }
}

export class AgentNotificationsClient {
  constructor(private readonly adapter: NotificationsAdapter) {}

  static fromHttpClient(http: HttpClient, options?: HttpNotificationsAdapterOptions): AgentNotificationsClient {
    return new AgentNotificationsClient(new HttpNotificationsAdapter(http, options));
  }

  async enqueue(request: EnqueueNotificationRequest): Promise<AgentNotificationRecord> {
    return this.adapter.enqueue(request);
  }

  async list(options?: { status?: string; limit?: number }): Promise<AgentNotificationRecord[]> {
    return this.adapter.list(options);
  }

  async markDelivered(notificationId: string): Promise<AgentNotificationRecord | null> {
    return this.adapter.markDelivered(notificationId);
  }
}

export class AgentTicketsClient {
  constructor(private readonly adapter: TicketsAdapter) {}

  static fromHttpClient(http: HttpClient, options?: HttpNotificationsAdapterOptions): AgentTicketsClient {
    return new AgentTicketsClient(new HttpTicketsAdapter(http, options));
  }

  async createTicket(request: {
    orgId: string;
    taskId: string;
    system: string;
    summary: string;
    metadata?: Record<string, unknown>;
  }): Promise<AgentTicketRecord> {
    return this.adapter.createTicket(request);
  }

  async closeTicket(ticketId: string, options?: { externalId?: string }): Promise<AgentTicketRecord | null> {
    return this.adapter.closeTicket(ticketId, options);
  }

  async listTickets(taskId: string): Promise<AgentTicketRecord[]> {
    return this.adapter.listTickets(taskId);
  }
}

function mapNotification(payload: NotificationPayload): AgentNotificationRecord {
  return {
    notificationId: payload.id,
    taskId: payload.task_id,
    orgId: payload.org_id,
    channel: payload.channel,
    status: payload.status,
    payload: payload.payload ?? {},
    createdAt: new Date(payload.created_at),
    deliveredAt: payload.delivered_at ? new Date(payload.delivered_at) : null,
  };
}

function mapTicket(payload: TicketPayload): AgentTicketRecord {
  return {
    ticketId: payload.id,
    taskId: payload.task_id,
    orgId: payload.org_id,
    system: payload.system,
    status: payload.status,
    details: payload.details ?? {},
    externalId: payload.external_id ?? null,
    createdAt: new Date(payload.created_at),
    updatedAt: payload.updated_at ? new Date(payload.updated_at) : null,
  };
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

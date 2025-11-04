import HttpClient from "../httpClient.js";
import { UserProfile } from "../types.js";

export interface ListUsersOptions {
  provider?: string;
  status?: string;
  mfaEnabled?: boolean;
  limit?: number;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  scopes?: string[];
  isAdmin?: boolean;
}

export interface UsersAdapter {
  list(options?: ListUsersOptions): Promise<UserProfile[]>;
  get(username: string, options?: ListUsersOptions): Promise<UserProfile | null>;
  create?(request: CreateUserRequest): Promise<UserProfile>;
  addScopes?(userId: string, scopes: string[]): Promise<void>;
  removeScopes?(userId: string, scopes: string[]): Promise<void>;
}

export interface HttpUsersAdapterOptions {
  basePath?: string;
  createEndpoint?: string;
  scopesEndpoint?: (userId: string) => string;
}

interface UserPayload {
  user_id?: string;
  username?: string;
  email?: string | null;
  is_admin?: boolean;
  scopes?: string[] | null;
  [key: string]: unknown;
}

class HttpUsersAdapter implements UsersAdapter {
  private readonly basePath: string;

  constructor(
    private readonly http: HttpClient,
    private readonly options: HttpUsersAdapterOptions = {},
  ) {
    this.basePath = options.basePath ?? "/api/v1/query/users";
  }

  async list(options: ListUsersOptions = {}): Promise<UserProfile[]> {
    const params: Record<string, string | number | boolean> = {};
    if (options.provider) params.provider = options.provider;
    if (options.status) params.status = options.status;
    if (options.mfaEnabled !== undefined) params.mfa_enabled = options.mfaEnabled;
    if (options.limit !== undefined) params.limit = options.limit;

    const payload = await this.http.get<UserPayload[] | UserPayload | null>(this.basePath, {
      searchParams: Object.keys(params).length ? params : undefined,
    });

    const records = Array.isArray(payload) ? payload : payload ? [payload] : [];
    return records.map(mapUserPayload);
  }

  async get(username: string, options: ListUsersOptions = {}): Promise<UserProfile | null> {
    const candidates = await this.list(options);
    return candidates.find((record) => record.username === username) ?? null;
  }

  async create(request: CreateUserRequest): Promise<UserProfile> {
    if (!this.options.createEndpoint) {
      throw new Error("createEndpoint is not configured for HttpUsersAdapter");
    }

    const payload = await this.http.post<UserPayload>(this.options.createEndpoint, {
      body: {
        username: request.username,
        email: request.email,
        password: request.password,
        scopes: request.scopes ?? [],
        is_admin: request.isAdmin ?? false,
      },
    });

    return mapUserPayload(payload);
  }

  async addScopes(userId: string, scopes: string[]): Promise<void> {
    const endpoint = this.options.scopesEndpoint?.(userId);
    if (!endpoint) {
      throw new Error("scopesEndpoint is not configured for HttpUsersAdapter");
    }

    await this.http.post(endpoint, {
      body: {
        action: "add",
        scopes,
      },
    });
  }

  async removeScopes(userId: string, scopes: string[]): Promise<void> {
    const endpoint = this.options.scopesEndpoint?.(userId);
    if (!endpoint) {
      throw new Error("scopesEndpoint is not configured for HttpUsersAdapter");
    }

    await this.http.post(endpoint, {
      body: {
        action: "remove",
        scopes,
      },
    });
  }
}

export class InMemoryUsersAdapter implements UsersAdapter {
  constructor(private readonly records: UserProfile[] = []) {}

  async list(): Promise<UserProfile[]> {
    return [...this.records];
  }

  async get(username: string): Promise<UserProfile | null> {
    return this.records.find((record) => record.username === username) ?? null;
  }

  async create(request: CreateUserRequest): Promise<UserProfile> {
    const record: UserProfile = {
      userId: generateId(),
      username: request.username,
      email: request.email,
      isAdmin: request.isAdmin ?? false,
      orgId: null,
      scopes: request.scopes ?? [],
    };
    this.records.push(record);
    return record;
  }

  async addScopes(userId: string, scopes: string[]): Promise<void> {
    const target = this.records.find((record) => record.userId === userId);
    if (!target) {
      throw new Error(`User '${userId}' not found`);
    }
    const next = new Set(target.scopes);
    scopes.forEach((scope) => next.add(scope));
    target.scopes = Array.from(next);
  }

  async removeScopes(userId: string, scopes: string[]): Promise<void> {
    const target = this.records.find((record) => record.userId === userId);
    if (!target) {
      throw new Error(`User '${userId}' not found`);
    }
    const banned = new Set(scopes);
    target.scopes = target.scopes.filter((scope) => !banned.has(scope));
  }
}

export class UsersClient {
  constructor(private readonly adapter: UsersAdapter) {}

  static fromHttpClient(http: HttpClient, options?: HttpUsersAdapterOptions): UsersClient {
    return new UsersClient(new HttpUsersAdapter(http, options));
  }

  async list(options?: ListUsersOptions): Promise<UserProfile[]> {
    return this.adapter.list(options);
  }

  async get(username: string, options?: ListUsersOptions): Promise<UserProfile | null> {
    return this.adapter.get(username, options);
  }

  async create(request: CreateUserRequest): Promise<UserProfile> {
    if (!this.adapter.create) {
      throw new Error("create operation is not supported by the configured adapter");
    }
    return this.adapter.create(request);
  }

  async addScopes(userId: string, scopes: string[]): Promise<void> {
    if (!this.adapter.addScopes) {
      throw new Error("addScopes operation is not supported by the configured adapter");
    }
    await this.adapter.addScopes(userId, scopes);
  }

  async removeScopes(userId: string, scopes: string[]): Promise<void> {
    if (!this.adapter.removeScopes) {
      throw new Error("removeScopes operation is not supported by the configured adapter");
    }
    await this.adapter.removeScopes(userId, scopes);
  }
}

function mapUserPayload(source: UserPayload): UserProfile {
  return {
    userId: String(source.user_id ?? source["id"] ?? source["userId"] ?? ""),
    username: String(source.username ?? source["name"] ?? ""),
    email: source.email === undefined ? null : (source.email as string | null),
    isAdmin: Boolean(source.is_admin ?? source["isAdmin"] ?? false),
    orgId: (source["org_id"] ?? source["orgId"] ?? null) as string | null,
    scopes: Array.isArray(source.scopes) ? source.scopes.filter((item): item is string => typeof item === "string") : [],
  };
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

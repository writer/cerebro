import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const ROUTE_SCHEMA_VERSION = "private-slack-thread-route/v1";

export interface SlackThreadRoute {
  appRef: string;
  botUserId: string;
  boundAt: string;
  channelId: string;
  schemaVersion: typeof ROUTE_SCHEMA_VERSION;
  teamId: string;
  threadRef: string;
  threadTs: string;
}

export class FileSlackThreadRouteStore {
  private databaseInstance?: DatabaseSync;
  private initializeTask?: Promise<void>;

  constructor(
    private readonly root: string,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async bind(
    input: Omit<SlackThreadRoute, "boundAt" | "schemaVersion">,
  ): Promise<SlackThreadRoute> {
    await this.initialize();
    return this.bindRoute(validateRoute({
      ...input,
      boundAt: this.clock().toISOString(),
      schemaVersion: ROUTE_SCHEMA_VERSION,
    }));
  }

  async read(threadRef: string): Promise<SlackThreadRoute | undefined> {
    await this.initialize();
    const row = this.database().prepare(`
      SELECT route_json
      FROM slack_thread_routes
      WHERE thread_ref = ?
    `).get(threadRef) as { route_json: string } | undefined;
    return row ? validateRoute(JSON.parse(row.route_json)) : undefined;
  }

  private bindRoute(route: SlackThreadRoute): SlackThreadRoute {
    return this.transaction((database) => {
      database.prepare(`
        INSERT OR IGNORE INTO slack_thread_routes (
          thread_ref,
          app_ref,
          bot_user_id,
          channel_id,
          team_id,
          thread_ts,
          bound_at_ms,
          route_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        route.threadRef,
        route.appRef,
        route.botUserId,
        route.channelId,
        route.teamId,
        route.threadTs,
        Date.parse(route.boundAt),
        JSON.stringify(route),
      );
      const row = database.prepare(`
        SELECT route_json
        FROM slack_thread_routes
        WHERE thread_ref = ?
      `).get(route.threadRef) as { route_json: string } | undefined;
      if (!row) throw new Error("The Slack thread route did not commit.");
      const current = validateRoute(JSON.parse(row.route_json));
      if (JSON.stringify(routeIdentity(current)) !== JSON.stringify(routeIdentity(route))) {
        throw new Error("The Slack thread route changed for an existing opaque reference.");
      }
      return current;
    });
  }

  private async initialize(): Promise<void> {
    this.initializeTask ??= this.initializeOnce();
    await this.initializeTask;
  }

  private async initializeOnce(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const database = this.database();
    database.exec(`
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = DELETE;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS slack_thread_routes (
        thread_ref TEXT PRIMARY KEY,
        app_ref TEXT NOT NULL,
        bot_user_id TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        team_id TEXT NOT NULL,
        thread_ts TEXT NOT NULL,
        bound_at_ms INTEGER NOT NULL,
        route_json TEXT NOT NULL
      ) STRICT;
    `);
    await chmod(this.databasePath(), 0o600);
    await this.importLegacyRoutes();
  }

  private async importLegacyRoutes(): Promise<void> {
    let files: string[];
    try {
      files = (await readdir(this.legacyDirectory()))
        .filter((file) => file.endsWith(".json"))
        .sort();
    } catch (error) {
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    for (const file of files) {
      const route = validateRoute(JSON.parse(
        await readFile(join(this.legacyDirectory(), file), "utf8"),
      ));
      if (file !== `${digest(route.threadRef)}.json`) {
        throw new Error("The legacy Slack thread route filename is invalid.");
      }
      this.bindRoute(route);
    }
  }

  private database(): DatabaseSync {
    this.databaseInstance ??= new DatabaseSync(this.databasePath());
    return this.databaseInstance;
  }

  private databasePath(): string {
    return join(this.root, "slack-ingress.sqlite3");
  }

  private legacyDirectory(): string {
    return join(this.root, "slack-thread-routes");
  }

  private transaction<T>(operation: (database: DatabaseSync) => T): T {
    const database = this.database();
    database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation(database);
      database.exec("COMMIT");
      return result;
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  }
}

function routeIdentity(route: SlackThreadRoute): Omit<SlackThreadRoute, "boundAt"> {
  return {
    appRef: route.appRef,
    botUserId: route.botUserId,
    channelId: route.channelId,
    schemaVersion: route.schemaVersion,
    teamId: route.teamId,
    threadRef: route.threadRef,
    threadTs: route.threadTs,
  };
}

function validateRoute(value: unknown): SlackThreadRoute {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Slack thread route is invalid.");
  }
  const route = value as Record<string, unknown>;
  if (
    JSON.stringify(Object.keys(route).sort()) !== JSON.stringify([
      "appRef",
      "botUserId",
      "boundAt",
      "channelId",
      "schemaVersion",
      "teamId",
      "threadRef",
      "threadTs",
    ])
    || route.schemaVersion !== ROUTE_SCHEMA_VERSION
    || !requiredText(route.appRef)
    || !requiredText(route.botUserId)
    || !requiredText(route.channelId)
    || !requiredText(route.teamId)
    || !/^slack-scratchpad:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(route.threadRef))
    || !/^\d+(?:\.\d+)?$/u.test(requiredText(route.threadTs))
    || !canonicalTimestamp(route.boundAt)
  ) {
    throw new Error("The Slack thread route is invalid.");
  }
  return Object.freeze(route as unknown as SlackThreadRoute);
}

function requiredText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function canonicalTimestamp(value: unknown): boolean {
  return typeof value === "string"
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const ROUTE_SCHEMA_VERSION = "private-slack-thread-route/v1";

export interface SlackThreadRoute {
  appRef: string;
  boundAt: string;
  channelId: string;
  schemaVersion: typeof ROUTE_SCHEMA_VERSION;
  teamId: string;
  threadRef: string;
  threadTs: string;
}

export class FileSlackThreadRouteStore {
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly root: string,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async bind(
    input: Omit<SlackThreadRoute, "boundAt" | "schemaVersion">,
  ): Promise<SlackThreadRoute> {
    return this.serialize(async () => {
      const route = validateRoute({
        ...input,
        boundAt: this.clock().toISOString(),
        schemaVersion: ROUTE_SCHEMA_VERSION,
      });
      const current = await this.read(route.threadRef);
      if (current) {
        const expected = { ...route, boundAt: current.boundAt };
        if (JSON.stringify(current) !== JSON.stringify(expected)) {
          throw new Error("The Slack thread route changed for an existing opaque reference.");
        }
        return current;
      }
      await atomicWrite(this.path(route.threadRef), route);
      return route;
    });
  }

  async read(threadRef: string): Promise<SlackThreadRoute | undefined> {
    try {
      return validateRoute(JSON.parse(await readFile(this.path(threadRef), "utf8")));
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
  }

  private path(threadRef: string): string {
    return join(this.root, "slack-thread-routes", `${digest(threadRef)}.json`);
  }

  private async serialize<T>(operation: () => Promise<T>): Promise<T> {
    const prior = this.mutationQueue;
    let release!: () => void;
    this.mutationQueue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function validateRoute(value: unknown): SlackThreadRoute {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Slack thread route is invalid.");
  }
  const route = value as Record<string, unknown>;
  if (
    JSON.stringify(Object.keys(route).sort()) !== JSON.stringify([
      "appRef",
      "boundAt",
      "channelId",
      "schemaVersion",
      "teamId",
      "threadRef",
      "threadTs",
    ])
    || route.schemaVersion !== ROUTE_SCHEMA_VERSION
    || !requiredText(route.appRef)
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

async function atomicWrite(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await rename(temporary, path);
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

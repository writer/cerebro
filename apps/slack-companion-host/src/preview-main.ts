import { createServer, type Server } from "node:http";

import { CerebroAskClient } from "./runtime/cerebro-ask-client.js";

const port = boundedPort(process.env.PORT);
let ready = false;

const server = createServer((request, response) => {
  if (request.method !== "GET" || (request.url !== "/healthz" && request.url !== "/readyz")) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(ready ? 200 : 503, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ mode: "pull-request-preview", ready }));
});

async function main(): Promise<void> {
  await listen(server, port);
  const client = new CerebroAskClient({
    apiKey: required(process.env.CEREBRO_READ_API_KEY),
    baseUrl: validatedBaseUrl(required(process.env.CEREBRO_BASE_URL)),
    tenantId: required(process.env.CEREBRO_TENANT_ID),
  });
  const result = await client.ask(
    "Which security sources are configured and healthy? Use read-only evidence and state any evidence gaps.",
    AbortSignal.timeout(120_000),
  );
  ready = true;
  process.stdout.write(`${JSON.stringify({
    citation_validation: result.citationValidationPassed,
    component: "pull-request-preview",
    operation: "read-only-canary",
    state: "ready",
    trace_id: result.traceId ?? null,
  })}\n`);

  let stopping = false;
  const stop = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    ready = false;
    await close(server);
    process.stdout.write(`${JSON.stringify({ component: "pull-request-preview", operation: "stop", signal, state: "complete" })}\n`);
  };
  process.once("SIGTERM", () => void stop("SIGTERM"));
  process.once("SIGINT", () => void stop("SIGINT"));
}

function required(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized) throw new Error("A required preview binding is missing.");
  return normalized;
}

function validatedBaseUrl(value: string): string {
  const parsed = new URL(value);
  const localHttp = parsed.protocol === "http:"
    && (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost");
  if ((parsed.protocol !== "https:" && !localHttp) || parsed.username || parsed.password) {
    throw new Error("The preview service binding is invalid.");
  }
  parsed.pathname = parsed.pathname.replace(/\/$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
}

function boundedPort(value: string | undefined): number {
  const parsed = Number(value ?? "3000");
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new Error("The preview port is invalid.");
  }
  return parsed;
}

function listen(target: Server, targetPort: number): Promise<void> {
  return new Promise((resolve, reject) => {
    target.once("error", reject);
    target.listen(targetPort, "0.0.0.0", resolve);
  });
}

function close(target: Server): Promise<void> {
  return new Promise((resolve, reject) => target.close((error) => error ? reject(error) : resolve()));
}

main().catch(async (error: unknown) => {
  ready = false;
  if (server.listening) await close(server).catch(() => undefined);
  process.stderr.write(`${JSON.stringify({
    component: "pull-request-preview",
    error_kind: error instanceof Error ? error.name : "unknown",
    operation: "read-only-canary",
    state: "failed",
  })}\n`);
  process.exitCode = 1;
});

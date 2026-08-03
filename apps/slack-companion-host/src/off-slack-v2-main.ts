import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { loadSlackRuntimeConfig } from "./runtime/config.js";
import { createProductionOffSlackRuntime } from "./runtime/production-off-slack-adapter.js";
import { SlackTransportV2Bridge } from "./runtime/slack-transport-v2-bridge.js";
import {
  BoundRustWakePortV2,
  ChallengedAuthorityTelemetryPortV2,
  loadEd25519TransportSigner,
  loadPrivateCandidateAttestation,
  loadPrivateTransportBindings,
} from "./runtime/slack-transport-v2-runtime.js";

const MAX_REQUEST_BYTES = 64 * 1024;

async function main(): Promise<void> {
  const config = loadSlackRuntimeConfig();
  const candidate = await loadPrivateCandidateAttestation(required(
    process.env.CEREBRO_SLACK_V2_CANDIDATE_ATTESTATION_FILE,
  ));
  const bindings = await loadPrivateTransportBindings(required(
    process.env.CEREBRO_SLACK_V2_BINDINGS_FILE,
  ));
  const signer = await loadEd25519TransportSigner({
    candidatePrincipalRef: candidate.principal_ref,
    keyPath: required(process.env.CEREBRO_SLACK_V2_SIGNING_KEY_FILE),
    keyRef: required(process.env.CEREBRO_SLACK_V2_SIGNER_KEY_REF),
    principalRef: required(process.env.CEREBRO_SLACK_V2_SIGNER_PRINCIPAL_REF),
  });
  const botUserId = slackId(required(process.env.CEREBRO_SLACK_V2_BOT_USER_ID));
  const production = createProductionOffSlackRuntime(config);
  const telemetry = new ChallengedAuthorityTelemetryPortV2(
    config.slackAnswerAuthorityUrl,
    candidate,
  );
  await telemetry.challenge();
  const wakePort = new BoundRustWakePortV2(
    production.agentClient,
    production.adapter,
    production.threadRoutes,
    bindings.wakeBindings,
    required(process.env.CEREBRO_SLACK_V2_WAKE_WORKER_REF),
    botUserId,
  );
  const bridge = new SlackTransportV2Bridge({
    adapter: production.adapter,
    botUserId,
    phaseBudgetMs: positiveInteger(
      process.env.CEREBRO_SLACK_V2_PHASE_BUDGET_MS,
      120_000,
      1_000_000,
    ),
    sequencePort: bindings.sequencePort,
    signer,
    telemetryPort: telemetry,
    wakePort,
  });
  const server = createServer((request, response) => {
    void handleHttp(request, response, bridge);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(
      positiveInteger(process.env.CEREBRO_SLACK_V2_PORT, 58110, 65_535),
      loopbackHost(process.env.CEREBRO_SLACK_V2_BIND),
      resolve,
    );
  });
  process.stdout.write(`${JSON.stringify({
    component: "off-slack-transport-v2",
    operation: "listen",
    promotion_interface: "signed-v2-only",
    schema_version: "slack-agent-transport-v2-runtime/v1",
    state: "ready",
  })}\n`);

  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    server.close((error) => {
      if (error) process.exitCode = 1;
    });
    process.stdout.write(`${JSON.stringify({
      component: "off-slack-transport-v2",
      operation: "stop",
      signal,
      state: "started",
    })}\n`);
  };
  process.once("SIGTERM", () => stop("SIGTERM"));
  process.once("SIGINT", () => stop("SIGINT"));
}

async function handleHttp(
  request: IncomingMessage,
  response: ServerResponse,
  bridge: SlackTransportV2Bridge,
): Promise<void> {
  try {
    const path = new URL(request.url ?? "/", "http://transport.invalid").pathname;
    if (request.method === "GET" && (path === "/healthz" || path === "/readyz")) {
      writeJson(response, 200, {
        ready: true,
        schema_version: "slack-agent-transport-v2-runtime/v1",
      });
      return;
    }
    if (path !== "/v2/dispatch") {
      writeJson(response, 404, { error: "route_not_found" });
      return;
    }
    const body = await readBody(request);
    const result = await bridge.handle(new Request("http://transport.invalid/v2/dispatch", {
      body: Buffer.from(body),
      method: request.method,
    }));
    response.statusCode = result.status;
    result.headers.forEach((value, name) => response.setHeader(name, value));
    response.end(Buffer.from(await result.arrayBuffer()));
  } catch (error) {
    const tooLarge = error instanceof Error && error.message === "request_too_large";
    writeJson(response, tooLarge ? 413 : 500, {
      error: tooLarge ? "dispatch_size_invalid" : "transport_runtime_failed",
    });
  }
}

async function readBody(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > MAX_REQUEST_BYTES) throw new Error("request_too_large");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function writeJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function required(value: string | undefined): string {
  const normalized = value?.trim();
  if (!normalized) throw new Error("A required V2 supervisor binding is missing.");
  return normalized;
}

function positiveInteger(value: string | undefined, fallback: number, maximum: number): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error("A V2 supervisor integer binding is invalid.");
  }
  return parsed;
}

function loopbackHost(value: string | undefined): string {
  const host = value?.trim() || "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new Error("The V2 supervisor transport must bind to loopback.");
  }
  return host;
}

function slackId(value: string): string {
  if (!/^[A-Z][A-Z0-9]{1,31}$/u.test(value)) {
    throw new Error("The V2 transport bot identity is invalid.");
  }
  return value;
}

main().catch((error: unknown) => {
  process.stderr.write(`${JSON.stringify({
    component: "off-slack-transport-v2",
    error_kind: error instanceof Error ? error.name : "unknown",
    operation: "start",
    state: "failed",
  })}\n`);
  process.exitCode = 1;
});

#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  createSign,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDir, "..");
const repositoryRoot = path.resolve(webRoot, "..", "..");
const defaultTimeoutMs = 10 * 60_000;
const audience = "cerebro-local-web";
const tenantID = "tenant-demo";
const keyID = "local-e2e-key";
const postgresImage = "postgres:16-alpine";

const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const base64UrlJSON = (value) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

export function signedBearerToken(privateKey, issuer, now = Date.now(), claims = {}) {
  const issuedAt = Math.floor(now / 1000);
  const input = [
    base64UrlJSON({ alg: "RS256", kid: keyID, typ: "JWT" }),
    base64UrlJSON({
      aud: audience,
      email: "rust.e2e@example.com",
      exp: issuedAt + 300,
      iat: issuedAt,
      iss: issuer,
      name: "Rust E2E",
      scope: "cerebro:read cerebro:actions:read identity:read",
      sub: "rust-e2e-user",
      tenant_id: tenantID,
      ...claims,
    }),
  ].join(".");
  const signature = createSign("RSA-SHA256")
    .update(input)
    .end()
    .sign(privateKey, "base64url");
  return `${input}.${signature}`;
}

export function parseArgs(argv) {
  const options = {
    artifactRoot: undefined,
    timeoutMs: defaultTimeoutMs,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--artifact-dir") {
      options.artifactRoot = requireValue(argument, argv[++index]);
    } else if (argument.startsWith("--artifact-dir=")) {
      options.artifactRoot = requireValue(
        "--artifact-dir",
        argument.slice("--artifact-dir=".length),
      );
    } else if (argument === "--timeout-ms") {
      options.timeoutMs = positiveInteger(argument, argv[++index]);
    } else if (argument.startsWith("--timeout-ms=")) {
      options.timeoutMs = positiveInteger(
        "--timeout-ms",
        argument.slice("--timeout-ms=".length),
      );
    } else {
      throw new Error(`Unknown option: ${argument}`);
    }
  }
  return options;
}

function requireValue(name, value) {
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function positiveInteger(name, value) {
  if (!/^\d+$/.test(value ?? "")) {
    throw new Error(`${name} requires a positive integer`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} requires a positive integer`);
  }
  return parsed;
}

export function portableEnvironment(source = process.env, additions = {}) {
  const allowed = [
    "PATH",
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
    "COMSPEC",
    "LOCALAPPDATA",
    "APPDATA",
    "CI",
    "NO_COLOR",
    "TERM",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
  ];
  return {
    ...Object.fromEntries(
      allowed.flatMap((key) =>
        source[key] === undefined ? [] : [[key, source[key]]],
      ),
    ),
    ...additions,
  };
}

async function reserveLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  expect(Number.isSafeInteger(port) && port > 0, "Unable to reserve a loopback port");
  return port;
}

function remaining(deadlineAt, label) {
  const milliseconds = deadlineAt - Date.now();
  if (milliseconds <= 0) throw new Error(`Timed out during ${label}`);
  return milliseconds;
}

async function withDeadline(promise, deadlineAt, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Timed out during ${label}`)),
          remaining(deadlineAt, label),
        );
        timer.unref?.();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function run(command, args, options, deadlineAt) {
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env ?? portableEnvironment(),
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = [];
  child.stdout.on("data", (chunk) => output.push(chunk));
  child.stderr.on("data", (chunk) => output.push(chunk));
  try {
    return await withDeadline(
      new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => {
          if (code === 0) {
            resolve(Buffer.concat(output).toString("utf8"));
          } else {
            reject(
              new Error(
                `${command} exited with ${code ?? signal}\n${Buffer.concat(output).toString("utf8").slice(-4000)}`,
              ),
            );
          }
        });
      }),
      deadlineAt,
      `${command} ${args.join(" ")}`,
    );
  } catch (error) {
    await stopProcessTree(child);
    throw error;
  }
}

function startLogged(name, command, args, options, logDir) {
  const log = createWriteStream(path.join(logDir, `${name}.log`), { flags: "a" });
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    detached: process.platform !== "win32",
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(log);
  child.stderr.pipe(log);
  child.log = log;
  return child;
}

async function stopChild(child) {
  if (!child?.pid) return;
  await stopProcessTree(child);
  await new Promise((resolve) => child.log?.end(resolve));
}

async function stopProcessTree(child) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  try {
    if (process.platform === "win32") {
      child.kill("SIGTERM");
    } else {
      process.kill(-child.pid, "SIGTERM");
    }
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  await Promise.race([
    exited,
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    try {
      if (process.platform === "win32") {
        child.kill("SIGKILL");
      } else {
        process.kill(-child.pid, "SIGKILL");
      }
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
    await Promise.race([
      exited,
      new Promise((resolve) => setTimeout(resolve, 5_000)),
    ]);
  }
}

async function waitFor(label, probe, child, deadlineAt) {
  let lastError;
  while (Date.now() < deadlineAt) {
    if (child && child.exitCode !== null) {
      throw new Error(`${label} process exited with ${child.exitCode}`);
    }
    try {
      if (await probe()) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(
    `Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ""}`,
  );
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.text();
  return { body, headers: response.headers, status: response.status };
}

function lifecycleSuccesses(metrics) {
  const match =
    /cerebro_rust_http_requests_total\{operation="security_lifecycle",status_class="success"\} (\d+)/.exec(
      metrics,
    );
  return match ? Number.parseInt(match[1], 10) : 0;
}

async function startJwksServer(publicJwk) {
  const server = http.createServer((request, response) => {
    if (request.url !== "/jwks") {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-type": "application/json",
    });
    response.end(
      JSON.stringify({
        keys: [{ ...publicJwk, alg: "RS256", kid: keyID, use: "sig" }],
      }),
    );
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  expect(port > 0, "JWKS server did not bind a loopback port");
  return {
    issuer: `http://127.0.0.1:${port}`,
    stop: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

function dockerLoopbackPort(output) {
  const lines = output.trim().split(/\r?\n/).filter(Boolean);
  expect(lines.length === 1, "Docker returned an unexpected Postgres port mapping");
  const match = /^127\.0\.0\.1:(\d+)$/.exec(lines[0]);
  expect(match, "Docker did not publish Postgres on loopback");
  const port = Number.parseInt(match[1], 10);
  expect(
    Number.isSafeInteger(port) && port > 0 && port <= 65_535,
    "Docker returned an invalid Postgres port",
  );
  return port;
}

async function startPostgres(containerName, deadlineAt) {
  await run(
    "docker",
    [
      "run",
      "--rm",
      "--name",
      containerName,
      "-e",
      "POSTGRES_HOST_AUTH_METHOD=trust",
      "-e",
      "POSTGRES_DB=cerebro",
      "-p",
      "127.0.0.1::5432",
      "-d",
      postgresImage,
    ],
    { cwd: repositoryRoot, env: portableEnvironment() },
    deadlineAt,
  );
  const port = dockerLoopbackPort(
    await run(
      "docker",
      ["port", containerName, "5432/tcp"],
      { cwd: repositoryRoot, env: portableEnvironment() },
      deadlineAt,
    ),
  );
  await waitFor(
    "Postgres",
    async () => {
      await run(
        "docker",
        ["exec", containerName, "pg_isready", "-U", "postgres", "-d", "cerebro"],
        { cwd: repositoryRoot, env: portableEnvironment() },
        deadlineAt,
      );
      return true;
    },
    undefined,
    deadlineAt,
  );
  const postgresDSN =
    `postgres://postgres@127.0.0.1:${port}/cerebro?sslmode=disable`;
  await waitFor(
    "Postgres host connection",
    async () => {
      await run(
        "cargo",
        [
          "run",
          "--quiet",
          "--locked",
          "-p",
          "cerebro-platform",
          "--example",
          "action_authority_e2e_fixture",
          "--",
          "--probe-postgres",
        ],
        {
          cwd: repositoryRoot,
          env: portableEnvironment(process.env, {
            CEREBRO_POSTGRES_DSN: postgresDSN,
          }),
        },
        deadlineAt,
      );
      return true;
    },
    undefined,
    deadlineAt,
  );
  return postgresDSN;
}

async function startAccessApprovalsProvider(bearerToken) {
  let providerStatus = "queued";
  let observationCount = 0;
  const requests = [];
  const server = http.createServer((request, response) => {
    const reject = (status, message) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: message }));
    };
    if (request.headers.authorization !== `Bearer ${bearerToken}`) {
      reject(401, "missing provider identity");
      return;
    }
    if (request.method === "POST" && request.url === "/admin/okta-jail/suspend") {
      const chunks = [];
      let size = 0;
      request.on("data", (chunk) => {
        size += chunk.length;
        if (size <= 64 * 1_024) chunks.push(chunk);
      });
      request.on("end", () => {
        if (size > 64 * 1_024) {
          reject(413, "request too large");
          return;
        }
        let payload;
        try {
          payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          reject(400, "invalid JSON");
          return;
        }
        requests.push(payload);
        response.writeHead(201, { "content-type": "application/json" });
        response.end(JSON.stringify(providerReceipt(payload, providerStatus)));
      });
      return;
    }
    if (
      request.method === "GET" &&
      request.url === "/admin/okta-jail/actions/provider-action:rust-e2e"
    ) {
      observationCount += 1;
      const payload = requests[0];
      if (!payload) {
        reject(404, "provider action not found");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(providerReceipt(payload, providerStatus)));
      return;
    }
    reject(404, "route not found");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  expect(port > 0, "Access-approvals provider did not bind a loopback port");
  return {
    baseURL: `http://127.0.0.1:${port}`,
    dispatchCount: () => requests.length,
    observationCount: () => observationCount,
    requests,
    markSucceeded: () => {
      providerStatus = "succeeded";
    },
    stop: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

function providerReceipt(request, status) {
  const timestamp = Math.floor(Date.now() / 1_000);
  return {
    id: "provider-action:rust-e2e",
    action: "suspend",
    status,
    target: request.email_or_user_id,
    idempotency_key: request.idempotency_key,
    tenant_id: request.tenant_id,
    finding_id: request.finding_id,
    updated_at_unix: timestamp,
    ...(status === "succeeded" ? { completed_at_unix: timestamp } : {}),
  };
}

async function postJSON(url, bearer, payload) {
  return request(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bearer}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

function parsedJSON(response, label) {
  try {
    return JSON.parse(response.body);
  } catch {
    throw new Error(`${label} returned non-JSON status ${response.status}: ${response.body.slice(0, 500)}`);
  }
}

async function executeSignedActionLifecycle({
  webBase,
  privateKey,
  issuer,
  readBearer,
  fixture,
  provider,
}) {
  const token = (subject, scope) =>
    signedBearerToken(privateKey, issuer, Date.now(), { scope, sub: subject });
  const validatorBearer = token(
    fixture.finding_validation.validated_by,
    "cerebro:write cerebro:findings:validate",
  );
  const proposerBearer = token(
    fixture.proposal.proposed_by,
    "cerebro:actions:write cerebro:actions:propose",
  );
  const simulatorBearer = token(
    "simulator:rust-e2e",
    "cerebro:actions:write cerebro:actions:simulate",
  );
  const approverBearer = token(
    fixture.approver_id,
    "cerebro:actions:write cerebro:actions:approve",
  );
  const workerBearer = token(
    fixture.worker_id,
    "cerebro:read cerebro:actions:write identity:read cerebro:actions:execute",
  );
  const reconcilerBearer = token(
    "reconciler:rust-e2e",
    "cerebro:actions:write cerebro:actions:reconcile",
  );
  const actionURL = `${webBase}/api/cerebro/v1/actions/${encodeURIComponent(fixture.operation_id)}`;
  const commandURL = `${actionURL}/commands`;

  let response = await postJSON(
    `${webBase}/api/cerebro/v1/finding-validations`,
    validatorBearer,
    fixture.finding_validation,
  );
  expect(response.status === 200, `Finding validation returned ${response.status}: ${response.body}`);

  response = await postJSON(`${webBase}/api/cerebro/v1/actions`, proposerBearer, fixture.proposal);
  expect(response.status === 200, `Action proposal returned ${response.status}: ${response.body}`);
  let operation = parsedJSON(response, "Action proposal");
  expect(operation.state === "proposed" && operation.version === 1, "Rust did not persist the proposed Action");

  const transition = async (bearer, command) => {
    const result = await postJSON(commandURL, bearer, {
      expected_version: operation.version,
      command,
    });
    expect(result.status === 200, `Action ${command.command} returned ${result.status}: ${result.body}`);
    operation = parsedJSON(result, `Action ${command.command}`);
    return operation;
  };

  await transition(simulatorBearer, { command: "record_simulation" });
  await transition(proposerBearer, { command: "request_approval" });
  await transition(approverBearer, {
    command: "record_approval",
    receipt: {
      decision_id: fixture.decision_id,
      proposal_digest: fixture.proposal.proposal_digest,
      approved: true,
      decided_by: fixture.approver_id,
      decided_at_unix_ms: Date.now(),
    },
  });
  const claimedAt = Date.now();
  await transition(workerBearer, {
    command: "claim",
    worker_id: fixture.worker_id,
    claimed_at_unix_ms: claimedAt,
    claim_expires_at_unix_ms: Math.min(
      claimedAt + fixture.max_claim_lease_ms,
      fixture.proposal.proposal_expires_at_unix_ms,
    ),
  });
  expect(operation.state === "claimed" && operation.version === 5, "Rust did not persist the Action claim");

  response = await request(commandURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      expected_version: operation.version,
      command: { command: "start_execution", started_at_unix_ms: Date.now() },
    }),
  });
  expect(response.status === 401, `Next/Rust accepted an unauthenticated Action mutation (${response.status})`);

  response = await postJSON(commandURL, readBearer, {
    expected_version: operation.version,
    command: { command: "start_execution", started_at_unix_ms: Date.now() },
  });
  expect(response.status === 403, `Rust accepted Action execution without cerebro:actions:execute (${response.status})`);

  response = await postJSON(commandURL, workerBearer, {
    expected_version: operation.version,
    command: {
      command: "record_provider_receipt",
      external_receipt_ref: "forged",
      provider_status: "succeeded",
    },
  });
  expect(
    response.status >= 400 && response.status < 500,
    `Rust accepted a caller-supplied provider receipt (${response.status})`,
  );
  expect(provider.dispatchCount() === 0, "Rejected Action commands reached the provider");

  await transition(workerBearer, {
    command: "start_execution",
    started_at_unix_ms: Date.now(),
  });
  expect(operation.state === "dispatched", `Provider acceptance produced ${operation.state}`);
  expect(operation.version === 7, `Provider dispatch committed version ${operation.version}`);
  expect(operation.provider_status === "queued", "Rust did not persist the queued provider status");
  expect(
    operation.external_receipt_ref === "provider-action:rust-e2e",
    "Rust did not persist the bound provider receipt",
  );
  expect(provider.dispatchCount() === 1, `Rust submitted ${provider.dispatchCount()} provider mutations`);
  expect(
    provider.requests[0]?.tenant_id === tenantID &&
      provider.requests[0]?.finding_id === fixture.proposal.finding_id &&
      provider.requests[0]?.email_or_user_id === fixture.proposal.target_id &&
      provider.requests[0]?.idempotency_key === fixture.proposal.idempotency_key,
    "Rust provider submission was not bound to the durable dispatch",
  );

  provider.markSucceeded();
  response = await postJSON(`${actionURL}/provider-observation`, workerBearer, {});
  expect(
    response.status === 403,
    `Rust accepted provider reconciliation from the executor (${response.status})`,
  );
  expect(
    provider.observationCount() === 0,
    "Rejected executor reconciliation reached the provider",
  );
  response = await postJSON(
    `${actionURL}/provider-observation`,
    reconcilerBearer,
    {},
  );
  expect(response.status === 200, `Provider observation returned ${response.status}: ${response.body}`);
  operation = parsedJSON(response, "Provider observation");
  expect(operation.state === "dispatched", "Provider success completed the Action without effect evidence");
  expect(operation.provider_status === "succeeded", "Rust did not persist the provider observation");
  expect(operation.version === 8, `Provider observation committed version ${operation.version}`);
  expect(operation.observed_effect_digest === null, "Provider status manufactured an observed effect");
  expect(operation.executed_at_unix_ms === null, "Provider status manufactured execution completion");
  expect(provider.dispatchCount() === 1, "Provider observation retried the mutation");
  expect(
    provider.observationCount() === 1,
    "Rust performed an unexpected number of provider observations",
  );

  response = await request(actionURL, {
    headers: { authorization: `Bearer ${workerBearer}` },
  });
  expect(
    response.status === 403,
    `Rust accepted an Action read from the executor (${response.status})`,
  );
  response = await request(actionURL, {
    headers: { authorization: `Bearer ${readBearer}` },
  });
  expect(response.status === 200, `Durable Action read returned ${response.status}`);
  expect(parsedJSON(response, "Durable Action read").version === 8, "Rust did not return the latest durable Action version");

  response = await request(`${actionURL}/history`, {
    headers: { authorization: `Bearer ${readBearer}` },
  });
  expect(response.status === 200, `Durable Action history returned ${response.status}`);
  const history = parsedJSON(response, "Durable Action history");
  expect(history.length === 8, `Rust returned ${history.length} committed Action versions`);
  expect(
    history.at(-1)?.event_kind === "observe_provider_receipt",
    "Rust history did not end at the provider observation",
  );

  return { operation, workerBearer };
}

export async function runAuthenticatedRustE2E(options = {}) {
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  const deadlineAt = Date.now() + timeoutMs;
  const artifactRoot = path.resolve(options.artifactRoot ?? os.tmpdir());
  await mkdir(artifactRoot, { recursive: true });
  const workDir = await mkdtemp(path.join(artifactRoot, "cerebro-rust-auth-e2e-"));
  const logDir = path.join(workDir, "logs");
  await mkdir(logDir);

  const processes = [];
  let browser;
  let jwks;
  let provider;
  const postgresContainer = `cerebro-rust-action-e2e-${process.pid}-${randomUUID()}`;
  let postgresStarted = false;
  let failed = true;
  try {
    const [rustPort, webPort] = await Promise.all([
      reserveLoopbackPort(),
      reserveLoopbackPort(),
    ]);
    expect(rustPort !== webPort, "Reserved ports collided");

    await run(
      "cargo",
      ["build", "--locked", "-p", "cerebro-platform"],
      { cwd: repositoryRoot },
      deadlineAt,
    );
    const fixture = JSON.parse(
      await run(
        "cargo",
        [
          "run",
          "--quiet",
          "--locked",
          "-p",
          "cerebro-platform",
          "--example",
          "action_authority_e2e_fixture",
        ],
        { cwd: repositoryRoot, env: portableEnvironment() },
        deadlineAt,
      ),
    );
    await run(
      "docker",
      ["--version"],
      { cwd: repositoryRoot, env: portableEnvironment() },
      deadlineAt,
    );
    postgresStarted = true;
    const postgresDSN = await startPostgres(postgresContainer, deadlineAt);

    const sharedSecret = `rust-e2e-${randomBytes(32).toString("base64url")}`;
    const providerBearer = `provider-e2e-${randomBytes(32).toString("base64url")}`;
    provider = await startAccessApprovalsProvider(providerBearer);
    const rustBinary = path.join(
      repositoryRoot,
      "target",
      "debug",
      process.platform === "win32" ? "cerebro-platform.exe" : "cerebro-platform",
    );
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    jwks = await startJwksServer(publicKey.export({ format: "jwk" }));
    const bearer = signedBearerToken(privateKey, jwks.issuer);

    const rust = startLogged(
      "rust-platform",
      rustBinary,
      ["serve-demo"],
      {
        cwd: repositoryRoot,
        env: portableEnvironment(process.env, {
          CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET: sharedSecret,
          CEREBRO_IDENTITY_AUDIENCE: audience,
          CEREBRO_IDENTITY_ISSUER: jwks.issuer,
          CEREBRO_IDENTITY_JWKS_URL: `${jwks.issuer}/jwks`,
          CEREBRO_POSTGRES_DSN: postgresDSN,
          CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL: provider.baseURL,
          CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN: providerBearer,
          CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT: "5s",
          CEREBRO_RUST_BIND: `127.0.0.1:${rustPort}`,
        }),
      },
      logDir,
    );
    processes.push(rust);
    await waitFor(
      "Rust platform",
      async () => (await request(`http://127.0.0.1:${rustPort}/readyz`)).status === 200,
      rust,
      deadlineAt,
    );

    const unauthorized = await request(
      `http://127.0.0.1:${rustPort}/v1/security/lifecycle?limit=100`,
    );
    expect(unauthorized.status === 401, `Rust accepted an unauthenticated read (${unauthorized.status})`);
    const directLifecycle = await request(
      `http://127.0.0.1:${rustPort}/v1/security/lifecycle?limit=100`,
      { headers: { authorization: `Bearer ${bearer}` } },
    );
    expect(directLifecycle.status === 200, `Rust lifecycle read returned ${directLifecycle.status}`);
    const directPayload = JSON.parse(directLifecycle.body);
    expect(typeof directPayload.as_of === "string", "Lifecycle response did not come from the Rust contract");

    const directIdentity = await request(`http://127.0.0.1:${rustPort}/v1/me`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(directIdentity.status === 200, `Rust identity read returned ${directIdentity.status}`);
    expect(
      JSON.parse(directIdentity.body).user?.actorId === "rust-e2e-user",
      "Rust did not derive the actor from the signed subject",
    );

    const missingScope = signedBearerToken(privateKey, jwks.issuer, Date.now(), {
      scope: "identity:read",
    });
    expect(
      (
        await request(
          `http://127.0.0.1:${rustPort}/v1/security/lifecycle?limit=100`,
          { headers: { authorization: `Bearer ${missingScope}` } },
        )
      ).status === 403,
      "Rust accepted a lifecycle read without cerebro:read",
    );
    const wrongAudience = signedBearerToken(privateKey, jwks.issuer, Date.now(), {
      aud: "not-cerebro",
    });
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${wrongAudience}` },
        })
      ).status === 401,
      "Rust accepted a token for another audience",
    );
    const expired = signedBearerToken(privateKey, jwks.issuer, Date.now(), {
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${expired}` },
        })
      ).status === 401,
      "Rust accepted an expired token",
    );
    const wrongIssuer = signedBearerToken(privateKey, "https://wrong-issuer.example");
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${wrongIssuer}` },
        })
      ).status === 401,
      "Rust accepted a token from another issuer",
    );
    const missingTenant = signedBearerToken(privateKey, jwks.issuer, Date.now(), {
      tenant_id: undefined,
    });
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${missingTenant}` },
        })
      ).status === 401,
      "Rust accepted a token without a tenant",
    );
    const missingIdentityScope = signedBearerToken(privateKey, jwks.issuer, Date.now(), {
      scope: "cerebro:read",
    });
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${missingIdentityScope}` },
        })
      ).status === 403,
      "Rust accepted an identity read without identity:read",
    );
    const { privateKey: untrustedPrivateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const invalidSignature = signedBearerToken(untrustedPrivateKey, jwks.issuer);
    expect(
      (
        await request(`http://127.0.0.1:${rustPort}/v1/me`, {
          headers: { authorization: `Bearer ${invalidSignature}` },
        })
      ).status === 401,
      "Rust accepted a bearer signed by an untrusted key",
    );

    const web = startLogged(
      "web",
      "npm",
      ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(webPort)],
      {
        cwd: webRoot,
        env: portableEnvironment(process.env, {
          CEREBRO_API_BASE: `http://127.0.0.1:${rustPort}`,
          CEREBRO_AUTHORITY_MODE: "rust",
          CEREBRO_FORWARD_AUTH_HEADERS: "true",
          CEREBRO_PROXY_CACHE_TTL_MS: "0",
          NEXT_PUBLIC_CEREBRO_API_BASE: "/api/cerebro",
        }),
      },
      logDir,
    );
    processes.push(web);
    const authorization = { authorization: `Bearer ${bearer}` };
    await waitFor(
      "web",
      async () =>
        (await request(`http://127.0.0.1:${webPort}/api/me`, { headers: authorization }))
          .status === 200,
      web,
      deadlineAt,
    );

    const unauthenticatedWeb = await request(`http://127.0.0.1:${webPort}/api/me`);
    expect(
      unauthenticatedWeb.status === 401,
      `Web accepted a missing browser identity (${unauthenticatedWeb.status})`,
    );
    const currentUser = await request(`http://127.0.0.1:${webPort}/api/me`, {
      headers: authorization,
    });
    const identity = JSON.parse(currentUser.body);
    expect(identity.authenticated === true, "Browser identity was not authenticated");
    expect(identity.fallback === false, "Browser identity used local fallback");
    expect(identity.user?.actorId === "rust-e2e-user", "Browser identity subject changed");
    expect(
      identity.user?.confidence === "signature-verified",
      `Browser identity confidence was ${identity.user?.confidence}`,
    );
    const actionResult = await executeSignedActionLifecycle({
      webBase: `http://127.0.0.1:${webPort}`,
      privateKey,
      issuer: jwks.issuer,
      readBearer: bearer,
      fixture,
      provider,
    });

    const metricsBefore = await request(`http://127.0.0.1:${rustPort}/metrics`);
    const beforeCount = lifecycleSuccesses(metricsBefore.body);
    expect(beforeCount >= 1, "Direct Rust lifecycle read was not recorded");

    const { chromium } = await import("@playwright/test");
    browser = await withDeadline(chromium.launch({ headless: true }), deadlineAt, "Chromium launch");
    const context = await browser.newContext({
      extraHTTPHeaders: { Authorization: `Bearer ${bearer}` },
      viewport: { height: 900, width: 1440 },
    });
    const page = await context.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    const lifecycleResponse = page.waitForResponse(
      (candidate) =>
        new URL(candidate.url()).pathname === "/api/cerebro/v1/security/lifecycle",
      { timeout: Math.min(30_000, remaining(deadlineAt, "lifecycle browser request")) },
    );
    const navigation = await page.goto(
      `http://127.0.0.1:${webPort}/security/lifecycle`,
      {
        timeout: Math.min(30_000, remaining(deadlineAt, "lifecycle navigation")),
        waitUntil: "domcontentloaded",
      },
    );
    expect(navigation?.status() === 200, `Lifecycle page returned ${navigation?.status()}`);
    const dataResponse = await lifecycleResponse;
    expect(dataResponse.status() === 200, `Lifecycle browser query returned ${dataResponse.status()}`);
    await page
      .getByText("No credential or certificate records match these filters.", {
        exact: true,
      })
      .waitFor({
        state: "visible",
        timeout: Math.min(30_000, remaining(deadlineAt, "lifecycle empty state")),
      });
    expect(pageErrors.length === 0, `Lifecycle page raised ${pageErrors[0]?.message}`);
    await page.screenshot({
      fullPage: true,
      path: path.join(workDir, "authenticated-rust-lifecycle.png"),
    });
    await context.setExtraHTTPHeaders({
      Authorization: `Bearer ${bearer}`,
    });
    const actionResponse = page.waitForResponse(
      (candidate) =>
        new URL(candidate.url()).pathname ===
        `/api/cerebro/v1/actions/${encodeURIComponent(fixture.operation_id)}`,
      { timeout: Math.min(30_000, remaining(deadlineAt, "Action browser request")) },
    );
    const actionNavigation = await page.goto(
      `http://127.0.0.1:${webPort}/actions/${encodeURIComponent(fixture.operation_id)}`,
      {
        timeout: Math.min(30_000, remaining(deadlineAt, "Action navigation")),
        waitUntil: "domcontentloaded",
      },
    );
    expect(actionNavigation?.status() === 200, `Action page returned ${actionNavigation?.status()}`);
    expect((await actionResponse).status() === 200, "Action browser query did not reach Rust");
    await page.getByText("Provider Succeeded", { exact: true }).waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "provider status rendering")),
    });
    await page.getByText("Not verified", { exact: true }).first().waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "verification state rendering")),
    });
    expect(pageErrors.length === 0, `Action page raised ${pageErrors.at(-1)?.message}`);
    await page.screenshot({
      fullPage: true,
      path: path.join(workDir, "authenticated-rust-action.png"),
    });

    const metricsAfter = await request(`http://127.0.0.1:${rustPort}/metrics`);
    const afterCount = lifecycleSuccesses(metricsAfter.body);
    expect(
      afterCount > beforeCount,
      `Browser lifecycle read did not reach Rust (${beforeCount} -> ${afterCount})`,
    );
    failed = false;
    return {
      identityConfidence: identity.user.confidence,
      lifecycleRequests: afterCount,
      actionVersion: actionResult.operation.version,
    };
  } finally {
    await browser?.close().catch(() => undefined);
    await Promise.allSettled([...processes].reverse().map(stopChild));
    await provider?.stop().catch(() => undefined);
    await jwks?.stop().catch(() => undefined);
    if (postgresStarted) {
      if (failed) {
        const postgresLog = await run(
          "docker",
          ["logs", postgresContainer],
          { cwd: repositoryRoot, env: portableEnvironment() },
          Date.now() + 30_000,
        ).catch((error) => `Unable to capture PostgreSQL logs: ${error.message}\n`);
        await writeFile(
          path.join(logDir, "postgres.log"),
          postgresLog,
          "utf8",
        ).catch(() => undefined);
      }
      await run(
        "docker",
        ["rm", "-f", postgresContainer],
        { cwd: repositoryRoot, env: portableEnvironment() },
        Date.now() + 30_000,
      ).catch(() => undefined);
    }
    if (failed) {
      console.error(`[e2e:rust-auth:local] retained artifacts: ${workDir}`);
    } else {
      await rm(workDir, { force: true, recursive: true });
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runAuthenticatedRustE2E(parseArgs(process.argv.slice(2)))
    .then((result) => {
      console.log(
        `[e2e:rust-auth:local] passed signed browser identity and Action lifecycle -> Next relay -> Rust/Postgres/provider authority (${result.identityConfidence}, Action version ${result.actionVersion}, ${result.lifecycleRequests} Rust reads)`,
      );
    })
    .catch((error) => {
      console.error(`[e2e:rust-auth:local] failed: ${error.stack || error.message}`);
      process.exitCode = 1;
    });
}

#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  createSign,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
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
      scope: "cerebro:read identity:read",
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
            resolve();
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

    const sharedSecret = `rust-e2e-${randomBytes(32).toString("base64url")}`;
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
    };
  } finally {
    await browser?.close().catch(() => undefined);
    await Promise.allSettled([...processes].reverse().map(stopChild));
    await jwks?.stop().catch(() => undefined);
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
        `[e2e:rust-auth:local] passed signed browser identity -> Next relay -> Rust auth and lifecycle (${result.identityConfidence}, ${result.lifecycleRequests} Rust reads)`,
      );
    })
    .catch((error) => {
      console.error(`[e2e:rust-auth:local] failed: ${error.stack || error.message}`);
      process.exitCode = 1;
    });
}

#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

export const fixtureReadyPrefix = "CEREBRO_FIXTURE_READY ";

const portableEnvironmentNames = new Set([
  "CI",
  "COLORTERM",
  "COMSPEC",
  "FORCE_COLOR",
  "HOME",
  "LANG",
  "NO_COLOR",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TERM",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "WINDIR",
]);

export function createFixtureEnvironment(source = process.env, runNonce = source.CEREBRO_E2E_RUN_NONCE) {
  const environment = {};
  for (const [name, value] of Object.entries(source)) {
    const normalizedName = name.toUpperCase();
    if (value !== undefined && (portableEnvironmentNames.has(normalizedName) || normalizedName.startsWith("LC_"))) {
      environment[name] = value;
    }
  }
  return {
    ...environment,
    CEREBRO_API_BASE: "fixture://local",
    CEREBRO_E2E_RUN_NONCE: runNonce ?? randomUUID(),
    CEREBRO_IDENTITY_PROFILE: "local",
    CEREBRO_IDENTITY_REQUIRED: "false",
    CEREBRO_LOCAL_IDENTITY_FALLBACK: "1",
    CEREBRO_PROXY_CACHE_TTL_MS: "0",
    CEREBRO_TRUSTED_IDENTITY_HEADERS: "x-user-email",
    CEREBRO_WEB_FIXTURE_MODE: "1",
    NEXT_PUBLIC_CEREBRO_API_BASE: "fixture://local",
    NEXT_TELEMETRY_DISABLED: "1",
  };
}

function parsePort(value) {
  if (!/^\d+$/.test(value ?? "")) throw new Error("--port requires an integer");
  const port = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new Error("--port must be between 0 and 65535");
  }
  return String(port);
}

export function normalizeFixtureDevArgs(argv) {
  const forwarded = [];
  let port;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--hostname" || arg.startsWith("--hostname=") || arg.startsWith("-H")) {
      throw new Error("Fixture development is restricted to 127.0.0.1");
    }
    if (arg === "--port" || arg === "-p") {
      port = parsePort(argv[index + 1]);
      index += 1;
    } else if (arg.startsWith("--port=")) {
      port = parsePort(arg.slice("--port=".length));
    } else if (arg.startsWith("-p") && arg.length > 2) {
      port = parsePort(arg.slice(2));
    } else {
      forwarded.push(arg);
    }
  }
  return ["dev", "--hostname", "127.0.0.1", "--port", port ?? "0", ...forwarded];
}

export function extractLoopbackPort(output) {
  const plain = output.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "");
  const match = plain.match(/Local:\s+http:\/\/127\.0\.0\.1:(\d+)/);
  if (!match) return null;
  const port = Number.parseInt(match[1], 10);
  return port > 0 && port <= 65_535 ? port : null;
}

export async function runFixtureDev(options = {}) {
  const require = createRequire(import.meta.url);
  const nextCli = require.resolve("next/dist/bin/next");
  const environment = createFixtureEnvironment(options.environment, options.runNonce);
  const child = spawn(process.execPath, [nextCli, ...normalizeFixtureDevArgs(options.argv ?? process.argv.slice(2))], {
    cwd: options.cwd ?? process.cwd(),
    env: environment,
    stdio: ["inherit", "pipe", "pipe"],
  });
  let bufferedOutput = "";
  let announced = false;
  const forward = (source, destination) => {
    source.on("data", (chunk) => {
      destination.write(chunk);
      if (announced) return;
      bufferedOutput = `${bufferedOutput}${chunk}`.slice(-8_192);
      const port = extractLoopbackPort(bufferedOutput);
      if (port !== null) {
        announced = true;
        process.stdout.write(`\n${fixtureReadyPrefix}${JSON.stringify({ nonce: environment.CEREBRO_E2E_RUN_NONCE, port })}\n`);
      }
    });
  };
  forward(child.stdout, process.stdout);
  forward(child.stderr, process.stderr);
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

async function runCli() {
  const result = await runFixtureDev();
  if (result.signal) {
    process.exitCode = 1;
  } else {
    process.exitCode = result.code ?? 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[dev:fixtures] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

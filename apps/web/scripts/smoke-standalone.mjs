#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import { access, mkdir, mkdtemp } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { smokeBaseUrl, waitForHttp } from "./smoke-http.mjs";
import { resolveStandaloneAppRoot } from "./prepare-standalone.mjs";

const parseArgs = (argv) => {
  const options = { build: true, port: 0 };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--skip-build") {
      options.build = false;
    } else if (arg === "--port") {
      options.port = Number.parseInt(argv[index + 1] ?? "", 10);
      index += 1;
    } else if (arg.startsWith("--port=")) {
      options.port = Number.parseInt(arg.slice("--port=".length), 10);
    }
  }
  return options;
};

async function findFreePort(requestedPort = 0) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : requestedPort;
      server.close(() => resolve(port));
    });
    server.listen(requestedPort, "127.0.0.1");
  });
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: options.quiet ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited ${code}: ${stderr || stdout}`.trim()));
      }
    });
  });
}

async function stopChild(child) {
  if (!child || child.killed) {
    return;
  }
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 5_000)).then(() => child.kill("SIGKILL")),
  ]);
}

export async function smokeStandalone(options = {}) {
  const root = options.root ?? process.cwd();
  if (options.build !== false) {
    await run("npm", ["run", "build"], { cwd: root });
  }
  const standaloneAppRoot = await resolveStandaloneAppRoot(root);
  const standaloneServer = path.join(standaloneAppRoot, "server.js");
  try {
    await access(standaloneServer);
  } catch {
    throw new Error(`${standaloneServer} is missing. Run npm run build before --skip-build standalone smoke.`);
  }

  const port = await findFreePort(options.port ?? 0);
  const workDir = await mkdtemp(path.join(os.tmpdir(), "cerebro-web-standalone-smoke-"));
  const logDir = path.join(workDir, "logs");
  await mkdir(logDir, { recursive: true });
  const logPath = path.join(logDir, "standalone.log");
  const logStream = createWriteStream(logPath, { flags: "a" });
  const child = spawn(process.execPath, [standaloneServer], {
    cwd: standaloneAppRoot,
    env: {
      ...process.env,
      CEREBRO_API_BASE: "fixture://local",
      CEREBRO_IDENTITY_PROFILE: "local",
      CEREBRO_IDENTITY_REQUIRED: "false",
      CEREBRO_LOCAL_IDENTITY_FALLBACK: "1",
      CEREBRO_PROXY_CACHE_TTL_MS: "0",
      CEREBRO_WEB_FIXTURE_MODE: "1",
      HOSTNAME: "127.0.0.1",
      NEXT_PUBLIC_CEREBRO_API_BASE: "fixture://local",
      NODE_ENV: "production",
      PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(logStream);
  child.stderr.pipe(logStream);

  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForHttp(`${baseUrl}/api/health`, { timeoutMs: options.readyTimeoutMs ?? 90_000 });
    const result = await smokeBaseUrl(baseUrl, { chunkLimit: options.chunkLimit ?? 5 });
    return { ...result, baseUrl, logPath };
  } catch (error) {
    error.message = `${error.message}\nStandalone log: ${logPath}`;
    throw error;
  } finally {
    await stopChild(child);
    logStream.end();
  }
}

async function runCli() {
  const options = parseArgs(process.argv.slice(2));
  const result = await smokeStandalone(options);
  console.log(`[smoke:standalone] ${result.baseUrl}`);
  console.log(`[smoke:standalone] checked ${result.chunkResponses.length}/${result.scriptCount} script chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[smoke:standalone] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

#!/usr/bin/env node

import { spawn } from "node:child_process";
import net from "node:net";
import { pathToFileURL } from "node:url";

import { smokeBaseUrl, waitForHttp } from "./smoke-http.mjs";

export const parseSmokeDockerArgs = (argv) => {
  const options = { image: "cerebro-web:ci", port: 0 };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--port") {
      options.port = Number.parseInt(argv[index + 1] ?? "", 10);
      index += 1;
    } else if (arg.startsWith("--port=")) {
      options.port = Number.parseInt(arg.slice("--port=".length), 10);
    } else if (!arg.startsWith("--") && options.image === "cerebro-web:ci") {
      options.image = arg;
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

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
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

export async function smokeDocker(options = {}) {
  const image = options.image ?? "cerebro-web:ci";
  const port = await findFreePort(options.port ?? 0);
  const name = `cerebro-web-smoke-${process.pid}-${Date.now()}`;
  try {
    const { stdout } = await run("docker", [
      "run",
      "--rm",
      "-d",
      "--name",
      name,
      "-p",
      `127.0.0.1:${port}:3000`,
      "-e",
      "CEREBRO_API_BASE=fixture://local",
      "-e",
      "NEXT_PUBLIC_CEREBRO_API_BASE=fixture://local",
      "-e",
      "CEREBRO_WEB_FIXTURE_MODE=1",
      "-e",
      "CEREBRO_IDENTITY_PROFILE=local",
      "-e",
      "CEREBRO_IDENTITY_REQUIRED=false",
      "-e",
      "CEREBRO_LOCAL_IDENTITY_FALLBACK=1",
      image,
    ]);
    const containerID = stdout.trim();
    const baseUrl = `http://127.0.0.1:${port}`;
    await waitForHttp(`${baseUrl}/api/health`, { timeoutMs: options.readyTimeoutMs ?? 90_000 });
    const result = await smokeBaseUrl(baseUrl, { chunkLimit: options.chunkLimit ?? 5 });
    return { ...result, baseUrl, containerID, image };
  } finally {
    await run("docker", ["stop", name]).catch(() => undefined);
  }
}

async function runCli() {
  const options = parseSmokeDockerArgs(process.argv.slice(2));
  const result = await smokeDocker(options);
  console.log(`[smoke:docker] ${result.image} at ${result.baseUrl}`);
  console.log(`[smoke:docker] checked ${result.chunkResponses.length}/${result.scriptCount} script chunks`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli().catch((error) => {
    console.error(`[smoke:docker] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

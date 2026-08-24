#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { access, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const webRoot = path.resolve(scriptDir, "..");
const repositoryRoot = path.resolve(webRoot, "..", "..");
const defaultTimeoutMs = 20 * 60_000;
const tenantID = "tenant-demo";
const tenantAuthContext = Buffer.from(
  "cerebro-organizational-graph/tenant/v1\0",
  "utf8",
);

const expect = (condition, message) => {
  if (!condition) throw new Error(message);
};

const repositoryPath = (value) =>
  path.isAbsolute(value) ? value : path.resolve(repositoryRoot, value);

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

export function parseArgs(argv) {
  const options = {
    artifactRoot: undefined,
    check: false,
    receiptPath: path.join(repositoryRoot, "tmp", "rust-product-demo", "receipt.json"),
    timeoutMs: defaultTimeoutMs,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--check") {
      options.check = true;
    } else if (argument === "--artifact-dir") {
      options.artifactRoot = repositoryPath(requireValue(argument, argv[++index]));
    } else if (argument.startsWith("--artifact-dir=")) {
      options.artifactRoot = repositoryPath(
        requireValue("--artifact-dir", argument.slice("--artifact-dir=".length)),
      );
    } else if (argument === "--receipt") {
      options.receiptPath = repositoryPath(requireValue(argument, argv[++index]));
    } else if (argument.startsWith("--receipt=")) {
      options.receiptPath = repositoryPath(
        requireValue("--receipt", argument.slice("--receipt=".length)),
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
    "DDESK_CARGO_EMERGENCY_FREE_BYTES",
    "DDESK_CARGO_RESERVATION_BYTES",
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

export function tenantBearer(secret, requestedTenantID) {
  const tenant = Buffer.from(requestedTenantID, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(tenant.length));
  return createHmac("sha256", secret)
    .update(tenantAuthContext)
    .update(length)
    .update(tenant)
    .digest("hex");
}

export function parseDemoNeighborhood(output) {
  const neighborhood = JSON.parse(output);
  const rootURN = neighborhood?.root?.agent_key;
  expect(
    typeof rootURN === "string" && rootURN.startsWith(`urn:cerebro:${tenantID}:`),
    "Rust demo output did not contain a tenant-scoped product root",
  );
  return { neighborhood, rootURN };
}

export function expectedNeighborhoodProof(neighborhood) {
  const rootEntityID = neighborhood?.root?.entity_id;
  const rootLabel = neighborhood?.root?.label;
  expect(typeof rootEntityID === "string" && rootEntityID, "Rust demo root has no entity ID");
  expect(typeof rootLabel === "string" && rootLabel, "Rust demo root has no label");

  const neighborIDs = new Set();
  let relationCount = 0;
  for (const edge of neighborhood?.edges ?? []) {
    if (edge?.from === rootEntityID && typeof edge.to === "string") {
      neighborIDs.add(edge.to);
      relationCount += 1;
    } else if (edge?.to === rootEntityID && typeof edge.from === "string") {
      neighborIDs.add(edge.from);
      relationCount += 1;
    }
  }
  expect(relationCount > 0, "Rust demo root has no product graph relations");
  return {
    node_count: 1 + neighborIDs.size,
    relation_count: relationCount,
    root_label: rootLabel,
  };
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
  const stdout = [];
  child.stdout.on("data", (chunk) => {
    stdout.push(chunk);
    output.push(chunk);
  });
  child.stderr.on("data", (chunk) => output.push(chunk));
  try {
    return await withDeadline(
      new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => {
          if (code === 0) {
            resolve(
              Buffer.concat(options.capture === "stdout" ? stdout : output).toString("utf8"),
            );
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
  child.startError = undefined;
  child.once("error", (error) => {
    child.startError = error;
  });
  return child;
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
  await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5_000))]);
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
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5_000))]);
  }
}

async function stopChild(child) {
  if (!child) return;
  await stopProcessTree(child);
  await new Promise((resolve) => child.log?.end(resolve));
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

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.text();
  return { body, headers: response.headers, status: response.status };
}

function parsedJSON(response, label) {
  try {
    return JSON.parse(response.body);
  } catch {
    throw new Error(
      `${label} returned non-JSON status ${response.status}: ${response.body.slice(0, 500)}`,
    );
  }
}

async function waitFor(label, probe, child, deadlineAt) {
  let lastError;
  while (Date.now() < deadlineAt) {
    if (child?.startError) {
      throw new Error(`${label} process failed to start: ${child.startError.message}`);
    }
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

async function cargoBinary(deadlineAt) {
  const metadata = JSON.parse(
    await run(
      "cargo",
      ["metadata", "--locked", "--no-deps", "--format-version", "1"],
      { capture: "stdout", cwd: repositoryRoot },
      deadlineAt,
    ),
  );
  expect(typeof metadata.target_directory === "string", "Cargo did not report a target directory");
  return path.join(
    metadata.target_directory,
    "debug",
    process.platform === "win32" ? "cerebro-platform.exe" : "cerebro-platform",
  );
}

async function browserProof(webBase, rootURN, expectedProof, workDir, deadlineAt) {
  const { chromium } = await import("@playwright/test");
  let browser;
  try {
    browser = await withDeadline(
      chromium.launch({ headless: true }),
      deadlineAt,
      "Chromium launch",
    );
  } catch (error) {
    if (!String(error?.message).includes("Executable doesn't exist")) throw error;
    browser = await withDeadline(
      chromium.launch({ channel: "chrome", headless: true }),
      deadlineAt,
      "installed Chrome launch",
    );
  }
  try {
    const page = await browser.newPage({ viewport: { height: 900, width: 1440 } });
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    const graphResponse = page.waitForResponse(
      (candidate) =>
        new URL(candidate.url()).pathname ===
        "/api/cerebro/platform/graph/neighborhood",
      { timeout: Math.min(30_000, remaining(deadlineAt, "graph browser request")) },
    );
    const navigation = await page.goto(
      `${webBase}/explore?root_urn=${encodeURIComponent(rootURN)}`,
      {
        timeout: Math.min(30_000, remaining(deadlineAt, "graph navigation")),
        waitUntil: "domcontentloaded",
      },
    );
    expect(navigation?.status() === 200, `Graph page returned ${navigation?.status()}`);
    const response = await graphResponse;
    expect(response.status() === 200, `Graph browser query returned ${response.status()}`);
    const graph = await response.json();
    const nodeCount = 1 + (graph.neighbors?.length ?? 0);
    const relationCount = graph.relations?.length ?? 0;
    expect(
      nodeCount === expectedProof.node_count,
      `Graph browser query returned ${nodeCount} nodes; expected ${expectedProof.node_count}`,
    );
    expect(
      relationCount === expectedProof.relation_count,
      `Graph browser query returned ${relationCount} relations; expected ${expectedProof.relation_count}`,
    );
    expect(
      graph.root?.label === expectedProof.root_label,
      "Graph browser query returned another root label",
    );
    await page.getByRole("img", {
      name: `Impact graph with ${expectedProof.node_count} nodes and ${expectedProof.relation_count} edges`,
    }).waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "graph rendering")),
    });
    await page.getByText(expectedProof.root_label, { exact: true }).first().waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "graph root rendering")),
    });
    await page.getByRole("button", { name: "Fit", exact: true }).click();
    await page.waitForTimeout(250);
    expect(
      (await page.locator("label").filter({ hasText: "Tenant" }).count()) === 0,
      "Graph explorer exposed a client-selected tenant field",
    );
    expect(pageErrors.length === 0, `Graph page raised ${pageErrors[0]?.message}`);
    const screenshot = path.join(workDir, "rust-product-graph.png");
    await page.screenshot({ fullPage: true, path: screenshot });
    return {
      endpoint_status: 200,
      browser_version: browser.version(),
      ...expectedProof,
      screenshot: path.basename(screenshot),
    };
  } finally {
    await browser.close();
  }
}

async function vendorBrowserProof(webBase, workDir, deadlineAt) {
  const { chromium } = await import("@playwright/test");
  let browser;
  try {
    browser = await withDeadline(
      chromium.launch({ headless: true }),
      deadlineAt,
      "Chromium launch",
    );
  } catch (error) {
    if (!String(error?.message).includes("Executable doesn't exist")) throw error;
    browser = await withDeadline(
      chromium.launch({ channel: "chrome", headless: true }),
      deadlineAt,
      "installed Chrome launch",
    );
  }
  try {
    const page = await browser.newPage({ viewport: { height: 900, width: 1440 } });
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error));
    const vendorsResponse = page.waitForResponse(
      (candidate) => new URL(candidate.url()).pathname === "/api/cerebro/grc/vendors",
      { timeout: Math.min(30_000, remaining(deadlineAt, "vendor browser request")) },
    );
    const navigation = await page.goto(`${webBase}/vendors?tenant_id=${tenantID}`, {
      timeout: Math.min(30_000, remaining(deadlineAt, "vendor navigation")),
      waitUntil: "domcontentloaded",
    });
    expect(navigation?.status() === 200, `Vendor page returned ${navigation?.status()}`);
    const response = await vendorsResponse;
    expect(response.status() === 200, `Vendor browser query returned ${response.status()}`);
    expect(response.headers()["x-cerebro-fixture"] !== "true", "Vendor browser query used fixture data");
    const payload = await response.json();
    expect(payload.data_authority === "rust_graph", "Vendor response did not report Rust graph authority");
    expect(
      Number.isSafeInteger(payload.graph_revision) && payload.graph_revision > 0,
      "Vendor response did not report a positive graph revision",
    );
    expect(payload.vendors?.length === 2, `Vendor response returned ${payload.vendors?.length ?? 0} rows; expected 2`);
    await page.getByText("Identity Platform", { exact: true }).first().waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "vendor row rendering")),
    });
    await page.getByText(`Rust graph revision ${payload.graph_revision}`, { exact: false }).waitFor({
      state: "visible",
      timeout: Math.min(30_000, remaining(deadlineAt, "vendor authority rendering")),
    });
    expect(pageErrors.length === 0, `Vendor page raised ${pageErrors[0]?.message}`);
    const screenshot = path.join(workDir, "rust-product-vendors.png");
    await page.screenshot({ fullPage: true, path: screenshot });
    return {
      endpoint_status: 200,
      data_authority: payload.data_authority,
      graph_revision: payload.graph_revision,
      vendor_count: payload.vendors.length,
      fixture_header: response.headers()["x-cerebro-fixture"] ?? "absent",
      screenshot: path.basename(screenshot),
    };
  } finally {
    await browser.close();
  }
}

function waitForOperatorShutdown(children) {
  return new Promise((resolve, reject) => {
    const childListeners = new Map();
    const cleanup = () => {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      childListeners.forEach((listener, child) => child.off("exit", listener));
    };
    const finish = (fn, value) => {
      cleanup();
      fn(value);
    };
    const onSignal = () => finish(resolve);
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    children.forEach((child) => {
      const listener = (code, signal) =>
        finish(
          reject,
          new Error(`Demo process exited before shutdown (${code ?? signal})`),
        );
      childListeners.set(child, listener);
      child.once("exit", listener);
    });
  });
}

export async function runRustProductDemo(options = {}) {
  const startedAt = new Date().toISOString();
  const timeoutMs = options.timeoutMs ?? defaultTimeoutMs;
  const deadlineAt = Date.now() + timeoutMs;
  const artifactRoot = path.resolve(
    options.artifactRoot ?? path.join(repositoryRoot, "tmp", "rust-product-demo"),
  );
  const receiptPath = path.resolve(
    options.receiptPath ?? path.join(artifactRoot, "receipt.json"),
  );
  await mkdir(artifactRoot, { recursive: true });
  const workDir = await mkdtemp(path.join(artifactRoot, "run-"));
  const logDir = path.join(workDir, "logs");
  await mkdir(logDir);

  const processes = [];
  let failed = true;
  try {
    const [rustPort, apiPort, webPort] = await Promise.all([
      reserveLoopbackPort(),
      reserveLoopbackPort(),
      reserveLoopbackPort(),
    ]);
    expect(new Set([rustPort, apiPort, webPort]).size === 3, "Reserved ports collided");

    const rustBinary = await cargoBinary(deadlineAt);
    const eventAdmissionBinary = path.join(
      path.dirname(rustBinary),
      process.platform === "win32"
        ? "cerebro-event-admission-worker.exe"
        : "cerebro-event-admission-worker",
    );
    await run(
      "cargo",
      [
        "build", "--locked",
        "-p", "cerebro-platform",
        "-p", "cerebro-sourceruntime-eventadmission",
        "--bin", "cerebro-platform",
        "--bin", "cerebro-event-admission-worker",
      ],
      { cwd: repositoryRoot },
      deadlineAt,
    );
    await access(rustBinary).catch(() => {
      throw new Error(`Cargo did not produce the Rust platform binary at ${rustBinary}`);
    });
    await access(eventAdmissionBinary).catch(() => {
      throw new Error(`Cargo did not produce the event admission binary at ${eventAdmissionBinary}`);
    });
    const { neighborhood, rootURN } = parseDemoNeighborhood(
      await run(
        rustBinary,
        ["demo"],
        { capture: "stdout", cwd: repositoryRoot, env: portableEnvironment() },
        deadlineAt,
      ),
    );
    const expectedProof = expectedNeighborhoodProof(neighborhood);

    const sharedSecret = randomBytes(32).toString("hex");
    const bearer = tenantBearer(sharedSecret, tenantID);
    const rust = startLogged(
      "rust-platform",
      rustBinary,
      ["serve-demo"],
      {
        cwd: repositoryRoot,
        env: portableEnvironment(process.env, {
          CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET: sharedSecret,
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

    const apiBinary = path.join(
      workDir,
      process.platform === "win32" ? "cerebro-demo-api.exe" : "cerebro-demo-api",
    );
    await run(
      "go",
      ["build", "-o", apiBinary, "./cmd/cerebro"],
      { cwd: repositoryRoot },
      deadlineAt,
    );
    const api = startLogged(
      "go-api-adapter",
      apiBinary,
      ["serve"],
      {
        cwd: repositoryRoot,
        env: portableEnvironment(process.env, {
          CEREBRO_DEV_MODE: "1",
          CEREBRO_DEV_MODE_ACK: "1",
          CEREBRO_EVENT_ADMISSION_WORKER: eventAdmissionBinary,
          CEREBRO_HTTP_ADDR: `127.0.0.1:${apiPort}`,
          CEREBRO_ORGANIZATIONAL_GRAPH_READ_MODE: "authority",
          CEREBRO_ORGANIZATIONAL_GRAPH_READ_URL: `http://127.0.0.1:${rustPort}`,
          CEREBRO_ORGANIZATIONAL_GRAPH_SHARED_SECRET: sharedSecret,
          CEREBRO_ORGANIZATIONAL_GRAPH_TIMEOUT: "30s",
        }),
      },
      logDir,
    );
    processes.push(api);
    await waitFor(
      "Go product adapter",
      async () => (await request(`http://127.0.0.1:${apiPort}/healthz`)).status === 200,
      api,
      deadlineAt,
    );

    const graphQuery = `/platform/graph/neighborhood?root_urn=${encodeURIComponent(rootURN)}&limit=50`;
    const directGraphResponse = await request(
      `http://127.0.0.1:${rustPort}${graphQuery}`,
      {
        headers: {
          authorization: `Bearer ${bearer}`,
          "x-cerebro-tenant": tenantID,
        },
      },
    );
    expect(
      directGraphResponse.status === 200,
      `Rust graph query returned ${directGraphResponse.status}: ${directGraphResponse.body}`,
    );
    const directGraph = parsedJSON(directGraphResponse, "Rust graph query");
    expect(directGraph.root?.urn === rootURN, "Rust graph query returned another root");

    const web = startLogged(
      "web",
      "npm",
      ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(webPort)],
      {
        cwd: webRoot,
        env: portableEnvironment(process.env, {
          CEREBRO_API_BASE: `http://127.0.0.1:${apiPort}`,
          CEREBRO_FORWARD_AUTH_HEADERS: "false",
          CEREBRO_IDENTITY_REQUIRED: "false",
          CEREBRO_LOCAL_IDENTITY_FALLBACK: "true",
          CEREBRO_ORGANIZATIONAL_GRAPH_TENANT_ID: tenantID,
          CEREBRO_PROXY_CACHE_TTL_MS: "0",
          NEXT_PUBLIC_CEREBRO_API_BASE: "/api/cerebro",
        }),
      },
      logDir,
    );
    processes.push(web);
    const webBase = `http://127.0.0.1:${webPort}`;
    const proxiedGraphURL = `${webBase}/api/cerebro${graphQuery}`;
    let proxiedGraphResponse;
    await waitFor(
      "web graph proxy",
      async () => {
        proxiedGraphResponse = await request(proxiedGraphURL);
        return proxiedGraphResponse.status === 200;
      },
      web,
      deadlineAt,
    );
    const proxiedGraph = parsedJSON(proxiedGraphResponse, "Web graph proxy");
    expect(proxiedGraph.root?.urn === rootURN, "Web proxy returned another graph root");

    const graphURL = `${webBase}/explore?root_urn=${encodeURIComponent(rootURN)}`;
    const vendorsURL = `${webBase}/vendors?tenant_id=${tenantID}`;
    if (!options.check) {
      console.log(`[demo:rust] Graph explorer: ${graphURL}`);
      console.log(`[demo:rust] Vendor register: ${vendorsURL}`);
      console.log("[demo:rust] Authority: Rust in-memory organizational graph");
      console.log("[demo:rust] Provider credentials: not required");
      console.log("[demo:rust] Press Ctrl-C to stop the Rust and web processes.");
      await waitForOperatorShutdown(processes);
      failed = false;
      return { graphURL, vendorsURL, workDir };
    }

    const browser = await browserProof(
      webBase,
      rootURN,
      expectedProof,
      workDir,
      deadlineAt,
    );
    const vendors = await vendorBrowserProof(webBase, workDir, deadlineAt);
    const revision = (
      process.env.GITHUB_SHA?.trim() ||
      (
        await run(
          "git",
          ["rev-parse", "HEAD"],
          { capture: "stdout", cwd: repositoryRoot },
          deadlineAt,
        )
      ).trim()
    );
    const receipt = {
      schema_version: "cerebro.rust-product-demo.receipt.v1",
      result: "passed",
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      source: { revision },
      runtime: {
        command: "cerebro-platform serve-demo",
        graph_authority: "rust",
        persistence: "memory",
        product_adapter: "go_http",
      },
      authentication: {
        kind: "ephemeral_hmac",
        tenant_id: tenantID,
        user_credentials_supplied: false,
        secret_recorded: false,
      },
      contract: {
        path: "/platform/graph/neighborhood",
        vendor_path: "/grc/vendors",
        root_urn: rootURN,
        tenant_selected_by_browser: false,
      },
      proof: {
        direct_rust_status: 200,
        web_proxy_status: 200,
        browser,
        vendors,
      },
    };
    await mkdir(path.dirname(receiptPath), { recursive: true });
    await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
    console.log(`[demo:rust] passed; receipt: ${receiptPath}`);
    failed = false;
    return receipt;
  } finally {
    await Promise.allSettled([...processes].reverse().map(stopChild));
    if (failed) {
      console.error(`[demo:rust] retained failure artifacts: ${workDir}`);
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runRustProductDemo(parseArgs(process.argv.slice(2))).catch((error) => {
    console.error(`[demo:rust] failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });
}

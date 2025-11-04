#!/usr/bin/env node

import { execSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const cwd = process.cwd();
let createdTarballPath = null;

function run(command, options = {}) {
  return execSync(command, {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
    ...options,
  });
}

function runIn(command, directory, options = {}) {
  return execSync(command, {
    cwd: directory,
    stdio: "inherit",
    ...options,
  });
}

function fail(message) {
  console.error(message);
  if (createdTarballPath) {
    try {
      rmSync(createdTarballPath, { force: true });
    } catch {
      // ignore cleanup errors
    }
  }
  process.exit(1);
}

let packInfo;
try {
  const output = run("npm pack --json");
  const entries = JSON.parse(output);
  if (!Array.isArray(entries) || entries.length !== 1) {
    fail("Unexpected npm pack output format");
  }
  packInfo = entries[0];
} catch (error) {
  console.error(error.stdout?.toString() ?? error.message);
  process.exit(1);
}

const tarballPath = path.join(cwd, packInfo.filename);
createdTarballPath = tarballPath;
const sizeLimit = 200 * 1024; // 200 KB upper bound for the SDK bundle

if (typeof packInfo.size !== "number") {
  fail("npm pack output missing size field");
}

if (packInfo.size > sizeLimit) {
  fail(
    `Packaged tarball is too large (${packInfo.size} bytes). Limit is ${sizeLimit} bytes. Please reduce bundled assets.`
  );
}

const packagedPaths = (packInfo.files ?? []).map((file) => file.path);

const requiredPaths = [
  "package.json",
  "dist/index.js",
  "dist/index.js.map",
  "dist/index.d.ts",
  "dist/index.d.ts.map",
];

for (const required of requiredPaths) {
  if (!packagedPaths.includes(required)) {
    fail(`Missing required file in package: ${required}`);
  }
}

const disallowedPrefixes = ["src/", "test/", "scripts/", "tmp/", "node_modules/"];
const strayFiles = packagedPaths.filter((item) =>
  disallowedPrefixes.some((prefix) => item.startsWith(prefix))
);

if (strayFiles.length > 0) {
  fail(`Package includes disallowed files: ${strayFiles.join(", ")}`);
}

const tempDir = mkdtempSync(path.join(tmpdir(), "cerebro-sdk-"));

try {
  runIn("npm init -y", tempDir, { stdio: "ignore" });
  runIn(`npm install ${tarballPath}`, tempDir);
  const smokeTest = `
    const mod = await import('@cerebro/sdk');
    if (typeof mod.SecurityCenterClient !== 'function') {
      throw new Error('SecurityCenterClient export missing');
    }
    if (typeof mod.CerebroSDK !== 'function') {
      throw new Error('CerebroSDK export missing');
    }
    if (typeof mod.default !== 'function') {
      throw new Error('Default export missing');
    }
    const client = new mod.CerebroSDK({ baseUrl: 'https://example.com', token: 'test' });
    if (!client || typeof client.securityCenter !== 'object') {
      throw new Error('CerebroSDK instance misconfigured');
    }
  `;

  runIn(`node --input-type=module -e "${smokeTest.replace(/"/g, '\\"').replace(/\n/g, ';')}"`, tempDir);
} finally {
  try {
    rmSync(tarballPath, { force: true });
  } catch (error) {
    console.warn(`Failed to remove tarball: ${error.message}`);
  }
  rmSync(tempDir, { recursive: true, force: true });
}

console.log(`Package validation succeeded (size: ${packInfo.size} bytes).`);

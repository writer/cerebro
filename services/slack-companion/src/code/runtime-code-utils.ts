import { createHash } from "node:crypto";
import { readdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function walk(root: string, onFile: (file: string) => void): void {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === ".git") continue;
      walk(path, onFile);
    } else if (entry.isFile()) {
      onFile(path);
    }
  }
}

export function atomicWrite(path: string, content: string): void {
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, content, "utf8");
  renameSync(tmp, path);
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function occurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let index = 0;
  while ((index = haystack.indexOf(needle, index)) !== -1) {
    count += 1;
    index += needle.length;
  }
  return count;
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export function bounded(value: number | undefined, min: number, max: number, fallback: number): number {
  const numeric = Number.isFinite(value) ? Number(value) : fallback;
  return Math.max(min, Math.min(max, Math.trunc(numeric)));
}

export function unifiedDiff(path: string, before: string, after: string): string {
  if (before === after) return "";
  return [
    `--- a/${path}`,
    `+++ b/${path}`,
    "@@",
    ...before.split("\n").slice(0, 80).map((line) => `-${line}`),
    ...after.split("\n").slice(0, 80).map((line) => `+${line}`),
  ].join("\n").slice(0, 6000);
}

export function normalizeRelativePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/\/+/g, "/").replace(/\/$/, "");
}

export function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

export function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "change";
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

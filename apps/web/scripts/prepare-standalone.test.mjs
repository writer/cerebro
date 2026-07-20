import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { prepareStandalonePackage } from "./prepare-standalone.mjs";

const withFixture = async (fn) => {
  const root = await mkdtemp(path.join(tmpdir(), "cerebro-web-standalone-"));
  try {
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

describe("prepareStandalonePackage", () => {
  it("copies static chunks and public assets into the standalone output", async () => {
    await withFixture(async (root) => {
      await mkdir(path.join(root, ".next", "standalone"), { recursive: true });
      await mkdir(path.join(root, ".next", "static", "chunks"), { recursive: true });
      await mkdir(path.join(root, "public"), { recursive: true });
      await writeFile(path.join(root, ".next", "standalone", "server.js"), "server");
      await writeFile(path.join(root, ".next", "static", "chunks", "app.js"), "chunk");
      await writeFile(path.join(root, "public", "robots.txt"), "User-agent: *\n");

      await prepareStandalonePackage(root);

      await expect(
        statPath(path.join(root, ".next", "standalone", ".next", "static", "chunks", "app.js")),
      ).resolves.toBe("file");
      await expect(
        statPath(path.join(root, ".next", "standalone", "public", "robots.txt")),
      ).resolves.toBe("file");
    });
  });

  it("fails fast when the build has no JavaScript chunks to package", async () => {
    await withFixture(async (root) => {
      await mkdir(path.join(root, ".next", "standalone"), { recursive: true });
      await mkdir(path.join(root, ".next", "static", "chunks"), { recursive: true });
      await writeFile(path.join(root, ".next", "standalone", "server.js"), "server");

      await expect(prepareStandalonePackage(root)).rejects.toThrow("no JavaScript chunks");
    });
  });

  it("packages a workspace-scoped standalone server", async () => {
    await withFixture(async (root) => {
      const appRoot = path.join(root, ".next", "standalone", "apps", "web");
      await mkdir(appRoot, { recursive: true });
      await mkdir(path.join(root, ".next", "static", "chunks"), { recursive: true });
      await writeFile(path.join(appRoot, "server.js"), "server");
      await writeFile(path.join(root, ".next", "static", "chunks", "app.js"), "chunk");

      await prepareStandalonePackage(root);

      await expect(
        statPath(path.join(appRoot, ".next", "static", "chunks", "app.js")),
      ).resolves.toBe("file");
    });
  });
});

const statPath = async (target) => {
  const info = await import("node:fs/promises").then(({ stat }) => stat(target));
  if (info.isFile()) return "file";
  if (info.isDirectory()) return "directory";
  return "other";
};

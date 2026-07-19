import { cp, mkdir, readdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const defaultProjectRoot = path.resolve(scriptDir, "..");

const exists = async (target) => {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
};

const assertDirectory = async (target, label) => {
  let info;
  try {
    info = await stat(target);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error(`${label} is missing at ${target}`);
    }
    throw error;
  }

  if (!info.isDirectory()) {
    throw new Error(`${label} is not a directory at ${target}`);
  }
};

const assertFile = async (target, label) => {
  let info;
  try {
    info = await stat(target);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error(`${label} is missing at ${target}`);
    }
    throw error;
  }

  if (!info.isFile()) {
    throw new Error(`${label} is not a file at ${target}`);
  }
};

const jsChunkNames = async (chunksDir) => {
  const entries = await readdir(chunksDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".js"))
    .map((entry) => entry.name);
};

const copyFresh = async (source, destination) => {
  await rm(destination, { recursive: true, force: true });
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true });
};

export async function resolveStandaloneAppRoot(projectRoot = defaultProjectRoot) {
  const standaloneDir = path.join(projectRoot, ".next", "standalone");
  const candidates = [
    standaloneDir,
    path.join(standaloneDir, "apps", "web"),
  ];

  for (const candidate of candidates) {
    if (await exists(path.join(candidate, "server.js"))) {
      return candidate;
    }
  }

  return candidates[1];
}

export async function prepareStandalonePackage(projectRoot = defaultProjectRoot) {
  const nextDir = path.join(projectRoot, ".next");
  const standaloneAppRoot = await resolveStandaloneAppRoot(projectRoot);
  const sourceStaticDir = path.join(nextDir, "static");
  const sourceChunksDir = path.join(sourceStaticDir, "chunks");
  const packagedStaticDir = path.join(standaloneAppRoot, ".next", "static");
  const packagedChunksDir = path.join(packagedStaticDir, "chunks");
  const publicDir = path.join(projectRoot, "public");
  const packagedPublicDir = path.join(standaloneAppRoot, "public");

  await assertFile(path.join(standaloneAppRoot, "server.js"), "Next standalone server");
  await assertDirectory(sourceStaticDir, "Next static assets");
  await assertDirectory(sourceChunksDir, "Next static chunk directory");

  const chunks = await jsChunkNames(sourceChunksDir);
  if (chunks.length === 0) {
    throw new Error(`Next static chunk directory has no JavaScript chunks at ${sourceChunksDir}`);
  }

  await copyFresh(sourceStaticDir, packagedStaticDir);

  if (await exists(publicDir)) {
    await copyFresh(publicDir, packagedPublicDir);
  }

  const packagedChunks = await jsChunkNames(packagedChunksDir);
  if (packagedChunks.length === 0) {
    throw new Error(`Packaged standalone chunk directory has no JavaScript chunks at ${packagedChunksDir}`);
  }

  console.log(`Packaged standalone Next assets (${packagedChunks.length} chunks).`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  prepareStandalonePackage().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}

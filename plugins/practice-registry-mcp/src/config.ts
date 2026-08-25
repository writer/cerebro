import path from "node:path";
import type { RegistryOptions } from "./registry.js";
import { defaultPracticesRoot, defaultSemgrepRulesPath } from "./paths.js";

export function registryOptionsFromEnv(): RegistryOptions {
  return {
    practicesRoot: path.resolve(process.env.PRACTICE_REGISTRY_ROOT ?? defaultPracticesRoot()),
    dbPath: path.resolve(process.env.PRACTICE_REGISTRY_DB ?? ".practice-registry/practices.db"),
    semgrepBin: process.env.PRACTICE_SEMGREP_BIN ?? "semgrep",
    semgrepRulesPath: path.resolve(process.env.PRACTICE_SEMGREP_RULES ?? defaultSemgrepRulesPath()),
  };
}

export function semgrepBinFromEnv(): string {
  return process.env.PRACTICE_SEMGREP_BIN ?? "semgrep";
}

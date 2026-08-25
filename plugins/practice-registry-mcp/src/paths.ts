import path from "node:path";
import { fileURLToPath } from "node:url";

export function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function defaultPracticesRoot(): string {
  return path.join(packageRoot(), "practices");
}

export function defaultSemgrepRulesPath(): string {
  return path.join(packageRoot(), "semgrep", "practice-rules.yml");
}

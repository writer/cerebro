import fs from "node:fs";
import path from "node:path";
import { parse, stringify } from "yaml";
import type { PracticeRecord } from "./schema.js";

type SemgrepRule = {
  id: string;
  languages: string[];
  message: string;
  severity: "ERROR" | "WARNING" | "INFO";
  metadata: {
    practice_id: string;
    status: string;
    enforcement: string;
    owner: string;
    source_file: string;
  };
  paths?: {
    include?: string[];
    exclude?: string[];
  };
  pattern?: string;
  "pattern-regex"?: string;
};

export type SemgrepConfig = {
  rules: SemgrepRule[];
};

export function buildSemgrepConfig(records: PracticeRecord[]): SemgrepConfig {
  const rules = records
    .filter((record) => record.semgrep)
    .map((record) => {
      const semgrep = record.semgrep;
      if (!semgrep) {
        throw new Error(`Missing Semgrep config for ${record.id}`);
      }

      const rule: SemgrepRule = {
        id: semgrep.rule_id ?? record.id,
        languages: semgrep.languages ?? record.scope.languages,
        message: `${record.title}: ${record.summary}`,
        severity: semgrep.severity ?? severityFor(record.status),
        metadata: {
          practice_id: record.id,
          status: record.status,
          enforcement: record.enforcement,
          owner: record.owner,
          source_file: record.source_file,
        },
      };

      if (record.scope.paths.include.length > 0 || record.scope.paths.exclude.length > 0) {
        rule.paths = {
          include: record.scope.paths.include,
          exclude: record.scope.paths.exclude,
        };
      }

      if (semgrep.pattern) {
        rule.pattern = semgrep.pattern;
      }
      if (semgrep.pattern_regex) {
        rule["pattern-regex"] = semgrep.pattern_regex;
      }

      return rule;
    });

  return { rules };
}

export function writeSemgrepConfig(records: PracticeRecord[], outputPath: string): SemgrepConfig {
  const config = buildSemgrepConfig(records);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(
    outputPath,
    `# Generated from practices/*.yml. Edit practice records, then run practice generate-semgrep.\n${stringify(config)}`,
    "utf8",
  );
  return config;
}

export function loadSemgrepConfig(records: PracticeRecord[], rulesPath: string): SemgrepConfig {
  if (!fs.existsSync(rulesPath)) {
    return buildSemgrepConfig(records);
  }

  const parsed = parse(fs.readFileSync(rulesPath, "utf8")) as SemgrepConfig;
  return {
    rules: parsed.rules ?? [],
  };
}

function severityFor(status: string): "ERROR" | "WARNING" | "INFO" {
  if (status === "banned") {
    return "ERROR";
  }
  if (status === "preferred" || status === "allowed") {
    return "INFO";
  }
  return "WARNING";
}

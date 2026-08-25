import fs from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import { practiceSchema, type PracticeRecord } from "./schema.js";

const yamlExtensions = new Set([".yaml", ".yml"]);

export function listPracticeFiles(root: string): string[] {
  if (!fs.existsSync(root)) {
    return [];
  }

  const files: string[] = [];
  const visit = (directory: string) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(absolutePath);
        continue;
      }

      if (entry.isFile() && yamlExtensions.has(path.extname(entry.name))) {
        files.push(absolutePath);
      }
    }
  };

  visit(root);
  return files.sort();
}

export function loadPractices(root: string): PracticeRecord[] {
  const files = listPracticeFiles(root);
  const records: PracticeRecord[] = [];

  for (const file of files) {
    const raw = fs.readFileSync(file, "utf8");
    const parsed = parse(raw);
    const validated = practiceSchema.parse(parsed);
    records.push({
      ...validated,
      source_file: path.relative(root, file),
    });
  }

  const seen = new Set<string>();
  for (const record of records) {
    if (seen.has(record.id)) {
      throw new Error(`Duplicate practice id: ${record.id}`);
    }
    seen.add(record.id);
  }

  return records;
}

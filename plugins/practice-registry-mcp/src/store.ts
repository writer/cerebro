import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import type { Database as DatabaseType } from "better-sqlite3";
import { isPassingDecision, outcomeForDecision } from "./outcome.js";
import type {
  PracticeCheckInput,
  PracticeDecision,
  PracticeObservation,
  PracticeObservationDetail,
  PracticeObservationStats,
  PracticeRecord,
} from "./schema.js";

export class PracticeStore {
  private readonly db: DatabaseType;

  constructor(dbPath: string) {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS practices (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        enforcement TEXT NOT NULL,
        owner TEXT NOT NULL,
        source_file TEXT NOT NULL,
        record_json TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        input_json TEXT NOT NULL,
        result_json TEXT NOT NULL,
        decision TEXT,
        blocking INTEGER NOT NULL DEFAULT 0,
        passed INTEGER NOT NULL DEFAULT 0,
        action_required INTEGER NOT NULL DEFAULT 0,
        rerun_required INTEGER NOT NULL DEFAULT 0,
        practice_ids TEXT NOT NULL DEFAULT '[]',
        summary TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
    this.ensureObservationColumns();
  }

  replacePractices(records: PracticeRecord[]): void {
    const replace = this.db.prepare(`
      INSERT INTO practices (
        id,
        title,
        status,
        enforcement,
        owner,
        source_file,
        record_json
      ) VALUES (
        @id,
        @title,
        @status,
        @enforcement,
        @owner,
        @source_file,
        @record_json
      )
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title,
        status = excluded.status,
        enforcement = excluded.enforcement,
        owner = excluded.owner,
        source_file = excluded.source_file,
        record_json = excluded.record_json
    `);

    const transaction = this.db.transaction((items: PracticeRecord[]) => {
      this.db.prepare("DELETE FROM practices").run();
      for (const item of items) {
        replace.run({
          ...item,
          record_json: JSON.stringify(item),
        });
      }
    });

    transaction(records);
  }

  allPractices(): PracticeRecord[] {
    const rows = this.db.prepare("SELECT record_json FROM practices ORDER BY id").all() as Array<{
      record_json: string;
    }>;
    return rows.map((row) => JSON.parse(row.record_json) as PracticeRecord);
  }

  getPractice(id: string): PracticeRecord | undefined {
    const row = this.db
      .prepare("SELECT record_json FROM practices WHERE id = ?")
      .get(id) as { record_json: string } | undefined;
    return row ? (JSON.parse(row.record_json) as PracticeRecord) : undefined;
  }

  recordObservation(kind: string, input: PracticeCheckInput | Record<string, unknown>, result: Record<string, unknown>): number {
    const metadata = observationMetadata(result);
    const inserted = this.db
      .prepare(
        `INSERT INTO observations (
          kind,
          input_json,
          result_json,
          decision,
          blocking,
          passed,
          action_required,
          rerun_required,
          practice_ids,
          summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        kind,
        JSON.stringify(input),
        JSON.stringify(result),
        metadata.decision,
        metadata.blocking ? 1 : 0,
        metadata.passed ? 1 : 0,
        metadata.action_required ? 1 : 0,
        metadata.rerun_required ? 1 : 0,
        JSON.stringify(metadata.practice_ids),
        metadata.summary,
      );
    return Number(inserted.lastInsertRowid);
  }

  recentObservations(options: { kind?: string; limit?: number; actionRequiredOnly?: boolean } = {}): PracticeObservation[] {
    const limit = Math.max(1, Math.min(options.limit ?? 20, 200));
    const kind = options.kind ?? null;
    const actionRequiredOnly = options.actionRequiredOnly ? 1 : 0;

    const rows = this.db
      .prepare(
        `SELECT
          id,
          kind,
          decision,
          blocking,
          passed,
          action_required,
          rerun_required,
          practice_ids,
          summary,
          created_at
        FROM observations
        WHERE (? IS NULL OR kind = ?)
          AND (? = 0 OR action_required = 1)
        ORDER BY id DESC
        LIMIT ?`,
      )
      .all(kind, kind, actionRequiredOnly, limit) as ObservationRow[];

    return rows.map(observationFromRow);
  }

  getObservationDetail(id: number): PracticeObservationDetail | undefined {
    const row = this.db
      .prepare(
        `SELECT
          id,
          kind,
          input_json,
          result_json,
          decision,
          blocking,
          passed,
          action_required,
          rerun_required,
          practice_ids,
          summary,
          created_at
        FROM observations
        WHERE id = ?`,
      )
      .get(id) as ObservationDetailRow | undefined;
    return row ? observationDetailFromRow(row) : undefined;
  }

  recentObservationDetails(options: { kind?: string; limit?: number } = {}): PracticeObservationDetail[] {
    const limit = Math.max(1, Math.min(options.limit ?? 20, 200));
    const kind = options.kind ?? null;

    const rows = this.db
      .prepare(
        `SELECT
          id,
          kind,
          input_json,
          result_json,
          decision,
          blocking,
          passed,
          action_required,
          rerun_required,
          practice_ids,
          summary,
          created_at
        FROM observations
        WHERE (? IS NULL OR kind = ?)
        ORDER BY id DESC
        LIMIT ?`,
      )
      .all(kind, kind, limit) as ObservationDetailRow[];

    return rows.map(observationDetailFromRow);
  }

  observationStats(limit = 100): PracticeObservationStats {
    const observations = this.recentObservations({ limit }).filter((observation) => observation.decision);
    const byDecision: Record<string, number> = {};
    const byKind: Record<string, number> = {};
    const practices = new Map<string, number>();

    for (const observation of observations) {
      if (observation.decision) {
        byDecision[observation.decision] = (byDecision[observation.decision] ?? 0) + 1;
      }
      byKind[observation.kind] = (byKind[observation.kind] ?? 0) + 1;
      for (const practiceId of observation.practice_ids) {
        practices.set(practiceId, (practices.get(practiceId) ?? 0) + 1);
      }
    }

    return {
      total: observations.length,
      passed: observations.filter((observation) => observation.passed).length,
      action_required: observations.filter((observation) => observation.action_required).length,
      rerun_required: observations.filter((observation) => observation.rerun_required).length,
      by_decision: byDecision,
      by_kind: byKind,
      top_practices: [...practices.entries()]
        .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .slice(0, 10)
        .map(([practice_id, count]) => ({ practice_id, count })),
    };
  }

  close(): void {
    this.db.close();
  }

  private ensureObservationColumns(): void {
    const existing = new Set(
      (this.db.prepare("PRAGMA table_info(observations)").all() as Array<{ name: string }>).map((column) => column.name),
    );
    const columns: Array<[string, string]> = [
      ["decision", "TEXT"],
      ["blocking", "INTEGER NOT NULL DEFAULT 0"],
      ["passed", "INTEGER NOT NULL DEFAULT 0"],
      ["action_required", "INTEGER NOT NULL DEFAULT 0"],
      ["rerun_required", "INTEGER NOT NULL DEFAULT 0"],
      ["practice_ids", "TEXT NOT NULL DEFAULT '[]'"],
      ["summary", "TEXT"],
    ];
    for (const [name, definition] of columns) {
      if (!existing.has(name)) {
        this.db.exec(`ALTER TABLE observations ADD COLUMN ${name} ${definition}`);
      }
    }
  }
}

type ObservationRow = {
  id: number;
  kind: string;
  decision: PracticeDecision | null;
  blocking: number;
  passed: number;
  action_required: number;
  rerun_required: number;
  practice_ids: string;
  summary: string | null;
  created_at: string;
};

type ObservationDetailRow = ObservationRow & {
  input_json: string;
  result_json: string;
};

function observationFromRow(row: ObservationRow): PracticeObservation {
  return {
    id: row.id,
    kind: row.kind,
    decision: row.decision,
    blocking: row.blocking === 1,
    passed: row.passed === 1,
    action_required: row.action_required === 1,
    rerun_required: row.rerun_required === 1,
    practice_ids: parsePracticeIds(row.practice_ids),
    summary: row.summary,
    created_at: row.created_at,
  };
}

function observationDetailFromRow(row: ObservationDetailRow): PracticeObservationDetail {
  return {
    ...observationFromRow(row),
    input: parseRecord(row.input_json),
    result: parseRecord(row.result_json),
  };
}

function observationMetadata(result: Record<string, unknown>): {
  decision: PracticeDecision | null;
  blocking: boolean;
  passed: boolean;
  action_required: boolean;
  rerun_required: boolean;
  practice_ids: string[];
  summary: string | null;
} {
  const decision = isPracticeDecision(result.decision) ? result.decision : null;
  const outcome = decision
    ? outcomeForDecision(decision)
    : {
        passed: Boolean(result.passed),
        action_required: Boolean(result.action_required),
        rerun_required: Boolean(result.rerun_required),
      };
  return {
    decision,
    blocking: result.blocking === true,
    passed: outcome.passed,
    action_required: outcome.action_required,
    rerun_required: outcome.rerun_required || (decision ? !isPassingDecision(decision) : false),
    practice_ids: extractPracticeIds(result),
    summary: typeof result.summary === "string" ? result.summary : null,
  };
}

function extractPracticeIds(result: Record<string, unknown>): string[] {
  const ids = new Set<string>();
  for (const value of collectionValues(result.matched_practices)) {
    if (typeof value.id === "string") {
      ids.add(value.id);
    }
  }
  for (const value of collectionValues(result.findings)) {
    if (typeof value.practice_id === "string") {
      ids.add(value.practice_id);
    }
  }
  const scanDiff = result.scan_diff;
  if (scanDiff && typeof scanDiff === "object" && !Array.isArray(scanDiff)) {
    for (const value of collectionValues((scanDiff as Record<string, unknown>).findings)) {
      if (typeof value.practice_id === "string") {
        ids.add(value.practice_id);
      }
    }
  }
  const exception = result.exception;
  if (exception && typeof exception === "object" && !Array.isArray(exception)) {
    const practiceId = (exception as Record<string, unknown>).practice_id;
    if (typeof practiceId === "string") {
      ids.add(practiceId);
    }
  }
  return [...ids].sort();
}

function collectionValues(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item));
}

function isPracticeDecision(value: unknown): value is PracticeDecision {
  return (
    value === "allowed" ||
    value === "follow_guidance" ||
    value === "revise_or_justify" ||
    value === "change_code" ||
    value === "ask_owner" ||
    value === "needs_review"
  );
}

function parsePracticeIds(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function parseRecord(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

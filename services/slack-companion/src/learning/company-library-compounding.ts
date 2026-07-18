import { randomUUID } from "node:crypto";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { recordMetric, telemetryEvent } from "../telemetry.js";
import {
  companyLibraryBatchFingerprint,
  normalizeCompanyLibraryRecord,
  type CompanyLibraryRecord,
  type CompanyLibraryRunReceipt,
  type CompanyLibraryStore,
} from "./company-library.js";
import type { CompanyLibraryCurator } from "./company-library-curator.js";
import type { SecurityMemoryStore } from "./security-memory/index.js";

const SOURCE_BATCH_SIZE = 24;
const SOURCE_BATCH_CONCURRENCY = 3;
const MERGE_BATCH_SIZE = 6;
const MAX_MERGE_DEPTH = 4;
const MIN_MERGE_REDUCTION_RATIO = 0.2;
const DEFAULT_INTERVAL_MS = 6 * 60 * 60_000;
const DEFAULT_MIN_NEW_RECORDS = 12;

export interface CompanyLibraryCompoundingResult extends CompanyLibraryRunReceipt {
  sourceWatermark?: string;
}

export class CompanyLibraryCompoundingService {
  private interval?: NodeJS.Timeout;
  private startup?: NodeJS.Timeout;
  private active?: Promise<CompanyLibraryCompoundingResult>;

  constructor(
    private readonly config: AppConfig,
    private readonly memory: Pick<SecurityMemoryStore, "recordsBySourceKind">,
    private readonly store: CompanyLibraryStore,
    private readonly curator: Pick<CompanyLibraryCurator, "synthesizeBatch" | "mergeDossiers" | "synthesizeTheses">,
  ) {}

  start(): void {
    if (!this.isEnabled() || this.interval) return;
    this.startup = setTimeout(() => void this.run().catch((error) => this.recordError(error)), 60_000);
    this.startup.unref?.();
    this.interval = setInterval(() => void this.run().catch((error) => this.recordError(error)), DEFAULT_INTERVAL_MS);
    this.interval.unref?.();
  }

  async stop(): Promise<void> {
    if (this.startup) clearTimeout(this.startup);
    if (this.interval) clearInterval(this.interval);
    this.startup = undefined;
    this.interval = undefined;
    await this.active?.catch(() => undefined);
  }

  run(input: { force?: boolean; minNewRecords?: number } = {}): Promise<CompanyLibraryCompoundingResult> {
    if (this.active) return this.active;
    const task = this.runOnce(input).finally(() => {
      if (this.active === task) this.active = undefined;
    });
    this.active = task;
    return task;
  }

  private async runOnce(input: { force?: boolean; minNewRecords?: number }): Promise<CompanyLibraryCompoundingResult> {
    const runId = randomUUID();
    const startedAt = new Date().toISOString();
    const lease = await this.store.acquireLease(runId);
    if (!lease) return this.skipped(runId, startedAt, "lease_unavailable");
    const receipt: CompanyLibraryCompoundingResult = {
      runId,
      status: "completed",
      startedAt,
      completedAt: startedAt,
      sourceRecords: 0,
      batchesProcessed: 0,
      batchesReused: 0,
      dossiers: 0,
      theses: 0,
    };
    this.log("company library compounding started", "company.library.compounding.started", { runId, force: Boolean(input.force) });
    try {
      const state = await this.store.state();
      const allCandidates = (await this.memory.recordsBySourceKind("slack_channel", 5_000))
        .filter((record) => record.promotionState !== "rejected")
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
      const candidates = input.force || !state.lastSourceCreatedAt
        ? allCandidates
        : allCandidates.filter((record) => record.createdAt > state.lastSourceCreatedAt!);
      receipt.sourceRecords = candidates.length;
      const minimum = Math.max(1, input.minNewRecords ?? DEFAULT_MIN_NEW_RECORDS);
      if (candidates.length < minimum && !input.force) {
        return await this.skipped(runId, startedAt, "below_threshold", candidates.length);
      }
      if (candidates.length === 0) {
        return await this.skipped(runId, startedAt, "no_new_records");
      }

      const facets: CompanyLibraryRecord[] = [];
      const sourceBatches = chunks(candidates, SOURCE_BATCH_SIZE);
      const batchFacets = await mapConcurrent(sourceBatches, SOURCE_BATCH_CONCURRENCY, async (batch, batchIndex) => {
        const fingerprint = companyLibraryBatchFingerprint(batch.map((record) => record.id));
        const existing = await this.store.batch(fingerprint);
        if (existing) {
          receipt.batchesReused += 1;
          return existing.records;
        }
        const records = await this.runStageWithRetries("source_batch", {
          runId,
          batch: batchIndex + 1,
          batches: sourceBatches.length,
          inputRecords: batch.length,
        }, () => this.curator.synthesizeBatch(batch));
        await this.store.saveBatch({
          fingerprint,
          sourceMemoryIds: batch.map((record) => record.id),
          records,
          processedAt: new Date().toISOString(),
        });
        receipt.batchesProcessed += 1;
        return records;
      });
      facets.push(...batchFacets.flat());

      const existingDossiers = (await this.store.list(500)).filter((record) => record.kind === "dossier");
      const affectedDomains = new Set(facets.map((record) => record.domainKey));
      const unchangedDossiers = input.force ? [] : existingDossiers.filter((record) => !affectedDomains.has(record.domainKey));
      const affectedDossiers = input.force ? [] : existingDossiers.filter((record) => affectedDomains.has(record.domainKey));
      const refreshedDossiers = await this.recursiveMerge([...affectedDossiers, ...facets], runId);
      const dossiers = mergeSameDomain([...unchangedDossiers, ...refreshedDossiers]);
      if (existingDossiers.length + facets.length > 0 && dossiers.length === 0) {
        throw new Error("Company library compounding produced no canonical dossiers.");
      }
      const theses = dossiers.length > 0
        ? await this.runStageWithRetries("thesis", { runId, inputRecords: dossiers.length }, () => this.curator.synthesizeTheses(dossiers))
        : [];

      const completedAt = new Date().toISOString();
      const sourceWatermark = candidates.at(-1)?.createdAt;
      Object.assign(receipt, {
        completedAt,
        dossiers: dossiers.length,
        theses: theses.length,
        sourceWatermark,
      });
      await this.store.publishSnapshot(runId, [...dossiers, ...theses], {
        lastSourceCreatedAt: sourceWatermark ?? state.lastSourceCreatedAt,
        lastRunId: runId,
        lastCompletedAt: completedAt,
      }, receipt);
      recordMetric("cerebro_slack_companion_company_library_run_total", { status: "completed" }, 1);
      this.log("company library compounding completed", "company.library.compounding.completed", receiptFields(receipt));
      telemetryEvent("company.library.compounding.completed", telemetryFields(receipt));
      return receipt;
    } catch (error) {
      const failed: CompanyLibraryCompoundingResult = {
        ...receipt,
        status: "failed",
        completedAt: new Date().toISOString(),
        errorType: errorType(error),
      };
      await this.store.saveRun(failed).catch(() => undefined);
      recordMetric("cerebro_slack_companion_company_library_run_total", { status: "failed" }, 1);
      this.log("company library compounding failed", "company.library.compounding.failed", receiptFields(failed), "error");
      telemetryEvent("company.library.compounding.failed", telemetryFields(failed));
      throw error;
    } finally {
      await this.store.releaseLease(lease).catch(() => undefined);
    }
  }

  private async recursiveMerge(records: CompanyLibraryRecord[], runId: string): Promise<CompanyLibraryRecord[]> {
    let current = mergeSameDomain(records);
    let stoppedForLowYield = false;
    for (let depth = 0; depth < MAX_MERGE_DEPTH && current.length > MERGE_BATCH_SIZE; depth += 1) {
      const next: CompanyLibraryRecord[] = [];
      const mergeBatches = chunks(current, MERGE_BATCH_SIZE);
      for (const [batchIndex, batch] of mergeBatches.entries()) {
        if (batch.length === 1) next.push(batch[0]!);
        else next.push(...await this.runStageWithRetries("dossier_merge", {
          runId,
          depth: depth + 1,
          batch: batchIndex + 1,
          batches: mergeBatches.length,
          inputRecords: batch.length,
        }, () => this.curator.mergeDossiers(batch)));
      }
      const merged = mergeSameDomain(next);
      const inputRecords = current.length;
      const reductionRatio = Math.max(0, inputRecords - merged.length) / inputRecords;
      current = merged;
      if (merged.length >= inputRecords || reductionRatio < MIN_MERGE_REDUCTION_RATIO) {
        stoppedForLowYield = true;
        this.log("company library recursive merge stopped", "company.library.compounding.merge_stopped", {
          runId,
          depth: depth + 1,
          inputRecords,
          outputRecords: merged.length,
          reductionRatio: Number(reductionRatio.toFixed(3)),
          reason: merged.length >= inputRecords ? "no_reduction" : "low_reduction",
        });
        break;
      }
    }
    if (!stoppedForLowYield && current.length > 1 && current.length <= MERGE_BATCH_SIZE) {
      const final = mergeSameDomain(await this.runStageWithRetries("dossier_final", {
        runId,
        inputRecords: current.length,
      }, () => this.curator.mergeDossiers(current)));
      if (final.length > 0) current = final;
    }
    return current;
  }

  private async runStageWithRetries<T>(
    stage: string,
    fields: Record<string, string | number>,
    operation: () => Promise<T>,
  ): Promise<T> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const startedAt = Date.now();
      this.log("company library stage started", "company.library.compounding.stage_started", { stage, attempt, ...fields });
      try {
        const result = await operation();
        this.log("company library stage completed", "company.library.compounding.stage_completed", {
          stage,
          attempt,
          durationMs: Date.now() - startedAt,
          outputRecords: Array.isArray(result) ? result.length : undefined,
          ...fields,
        });
        return result;
      } catch (error) {
        lastError = error;
        this.log("company library stage attempt failed", "company.library.compounding.stage_attempt_failed", {
          stage,
          attempt,
          durationMs: Date.now() - startedAt,
          errorType: errorType(error),
          retrying: attempt < 3,
          ...fields,
        }, "warn");
        if (attempt < 3) await new Promise((resolve) => setTimeout(resolve, 1_000 * 2 ** (attempt - 1)));
      }
    }
    throw lastError;
  }

  private async skipped(runId: string, startedAt: string, reason: string, sourceRecords = 0): Promise<CompanyLibraryCompoundingResult> {
    const receipt: CompanyLibraryCompoundingResult = {
      runId,
      status: "skipped",
      startedAt,
      completedAt: new Date().toISOString(),
      sourceRecords,
      batchesProcessed: 0,
      batchesReused: 0,
      dossiers: 0,
      theses: 0,
    };
    await this.store.saveRun(receipt).catch(() => undefined);
    recordMetric("cerebro_slack_companion_company_library_run_total", { status: "skipped", reason }, 1);
    this.log("company library compounding skipped", "company.library.compounding.skipped", { runId, reason, sourceRecords });
    return receipt;
  }

  private isEnabled(): boolean {
    return this.config.learning.enabled && this.config.learning.channelLearningEnabled;
  }

  private recordError(error: unknown): void {
    logger.warn("scheduled company library compounding failed", {
      event: "company.library.compounding.schedule_failed",
      errorType: errorType(error),
    });
  }

  private log(message: string, event: string, fields: Record<string, unknown>, level: "info" | "warn" | "error" = "info"): void {
    logger[level](message, { event, ...fields });
  }
}

function mergeSameDomain(records: CompanyLibraryRecord[]): CompanyLibraryRecord[] {
  const grouped = new Map<string, CompanyLibraryRecord[]>();
  for (const record of records) grouped.set(record.domainKey, [...(grouped.get(record.domainKey) ?? []), record]);
  return [...grouped.values()].map((group) => {
    if (group.length === 1) return group[0]!;
    const primary = [...group].sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0]!;
    const sourceMemoryIds = unique(group.flatMap((record) => record.sourceMemoryIds));
    const sourceArtifacts = unique(group.flatMap((record) => record.sourceArtifacts));
    return normalizeCompanyLibraryRecord({
      kind: primary.kind,
      domainKey: primary.domainKey,
      title: primary.title,
      summary: primary.summary,
      principles: unique(group.flatMap((record) => record.principles)),
      procedures: unique(group.flatMap((record) => record.procedures)),
      ownership: unique(group.flatMap((record) => record.ownership)),
      decisions: unique(group.flatMap((record) => record.decisions)),
      exceptions: unique(group.flatMap((record) => record.exceptions)),
      contradictions: unique(group.flatMap((record) => record.contradictions)),
      openQuestions: unique(group.flatMap((record) => record.openQuestions)),
      claims: group.flatMap((record) => record.claims),
      sourceMemoryIds,
      sourceArtifacts,
      channelIds: unique(group.flatMap((record) => record.channelIds)),
      confidence: Math.min(...group.map((record) => record.confidence)),
    });
  });
}

function chunks<T>(values: T[], size: number): T[][] {
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}

async function mapConcurrent<T, R>(
  values: T[],
  concurrency: number,
  operation: (value: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, concurrency), values.length) }, async () => {
    while (next < values.length) {
      const index = next;
      next += 1;
      results[index] = await operation(values[index] as T, index);
    }
  });
  await Promise.all(workers);
  return results;
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function receiptFields(receipt: CompanyLibraryCompoundingResult): Record<string, unknown> {
  return {
    runId: receipt.runId,
    status: receipt.status,
    sourceRecords: receipt.sourceRecords,
    batchesProcessed: receipt.batchesProcessed,
    batchesReused: receipt.batchesReused,
    dossiers: receipt.dossiers,
    theses: receipt.theses,
    sourceWatermark: receipt.sourceWatermark,
    errorType: receipt.errorType,
  };
}

function telemetryFields(receipt: CompanyLibraryCompoundingResult): Record<string, string | number | boolean | undefined> {
  return {
    component: "company-library",
    operation: "compound",
    "library.run_id": receipt.runId,
    "library.status": receipt.status,
    "library.source_records": receipt.sourceRecords,
    "library.batches_processed": receipt.batchesProcessed,
    "library.batches_reused": receipt.batchesReused,
    "library.dossiers": receipt.dossiers,
    "library.theses": receipt.theses,
    "error.type": receipt.errorType,
  };
}

function errorType(error: unknown): string {
  return error instanceof Error ? error.name : "unknown";
}

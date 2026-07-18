import { annotateMain, recordMetric } from "../../telemetry.js";
import type { SecurityMemoryRecord, SecurityMemoryWriteInput } from "../memory-types.js";
import { curatedDecisionToWriteInput } from "./codec.js";
import type { SecurityMemoryBatchWriteResult, SecurityMemoryStoreOptions } from "./types.js";

type RequiredCurator = NonNullable<SecurityMemoryStoreOptions["curator"]>;
type PersistPreparedWrite = (
  input: SecurityMemoryWriteInput,
  extractEntities: boolean,
) => Promise<{ record: SecurityMemoryRecord; inserted: boolean }>;

export async function curateMemoryWrite(
  input: SecurityMemoryWriteInput,
  curator: RequiredCurator,
  recent: SecurityMemoryRecord[],
): Promise<SecurityMemoryWriteInput | undefined> {
  const decision = await curator.curateWrite({ candidate: input, now: new Date(), recent });
  annotateMain({
    "memory.curator.write.should_store": decision.shouldStore,
    "memory.curator.write.promotion_state": decision.promotionState ?? "",
    "memory.curator.write.staleness_policy": decision.stalenessPolicy ?? "",
  });
  recordMetric("cerebro_slack_companion_memory_curator_write_total", { should_store: decision.shouldStore }, 1);
  return decision.shouldStore ? curatedDecisionToWriteInput(input, decision) : undefined;
}

export async function rememberManyCurated(input: {
  enabled: boolean;
  candidate: SecurityMemoryWriteInput;
  curator?: SecurityMemoryStoreOptions["curator"];
  recent: (limit: number) => Promise<SecurityMemoryRecord[]>;
  persist: PersistPreparedWrite;
}): Promise<SecurityMemoryBatchWriteResult> {
  const { candidate, curator } = input;
  if (!input.enabled || !curator) {
    return { records: [], storedCount: 0, reason: "Required curator is unavailable.", rejectionCategory: "other" };
  }
  if (candidate.sourceKind !== "slack_channel" || !curator.curateSlackChannelBatch) {
    const prepared = await curateMemoryWrite(candidate, curator, await input.recent(40));
    if (!prepared) return { records: [], storedCount: 0, reason: "No reusable operating knowledge.", rejectionCategory: "no_reusable_knowledge" };
    const stored = await input.persist(prepared, false);
    return {
      records: [stored.record],
      storedCount: stored.inserted ? 1 : 0,
      reason: stored.inserted ? "Stored one curated memory." : "The curated memory already exists.",
      rejectionCategory: stored.inserted ? undefined : "duplicate_only",
    };
  }

  const decision = await curator.curateSlackChannelBatch({
    candidate,
    now: new Date(),
    recent: await input.recent(60),
  });
  const records = new Map<string, SecurityMemoryRecord>();
  let storedCount = 0;
  for (const memory of decision.memories) {
    const stored = await input.persist(curatedDecisionToWriteInput(candidate, memory), false);
    records.set(stored.record.id, stored.record);
    if (stored.inserted) storedCount += 1;
  }
  const rejectionCategory = storedCount > 0
    ? undefined
    : decision.memories.length > 0
      ? "duplicate_only"
      : decision.rejectionCategory ?? "other";
  annotateMain({
    "memory.curator.batch.extracted_count": decision.memories.length,
    "memory.curator.batch.stored_count": storedCount,
    "memory.curator.batch.rejection_category": rejectionCategory ?? "",
  });
  recordMetric("cerebro_slack_companion_memory_curator_batch_total", {
    result: storedCount > 0 ? "stored" : "rejected",
    rejection_category: rejectionCategory ?? "none",
  }, 1);
  recordMetric("cerebro_slack_companion_memory_curator_batch_records_stored_total", {}, storedCount);
  return { records: [...records.values()], storedCount, reason: decision.reason, rejectionCategory };
}

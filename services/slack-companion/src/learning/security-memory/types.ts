import type { LearningDocWriteResult } from "../learning-docs.js";
import type {
  SecurityMemoryRecord,
} from "../memory-types.js";
import type {
  CuratedMemoryBatchRejectionCategory,
  SecurityMemoryCurator,
} from "../security-memory-curator.js";

export interface SecurityMemoryPromotionInput {
  id?: string;
  topic?: string;
}

export interface SecurityMemoryPromotionResult {
  promoted: boolean;
  record?: SecurityMemoryRecord;
  learningDoc?: LearningDocWriteResult;
  error?: string;
}

export interface SecurityMemoryHygieneResult {
  checked: number;
  expired: number;
  duplicateExpired: number;
  staleTransientExpired: number;
  dryRun: boolean;
}

export interface MemoryRecordItem {
  record: SecurityMemoryRecord;
  sk?: string;
}

export interface SecurityMemoryBatchWriteResult {
  records: SecurityMemoryRecord[];
  storedCount: number;
  reason: string;
  rejectionCategory?: CuratedMemoryBatchRejectionCategory;
}

export interface SecurityMemoryStoreOptions {
  curator?: Pick<SecurityMemoryCurator, "curateWrite" | "curateRecall" | "curateHygiene">
    & Partial<Pick<SecurityMemoryCurator, "curateSlackChannelBatch">>;
}

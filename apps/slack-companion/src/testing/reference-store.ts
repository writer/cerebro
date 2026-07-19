import { IdempotencyConflictError } from "../admission.js";
import type {
  AdmissionCommit,
  AdmissionCommitResult,
  RunReceiptV1,
} from "../contracts.js";
import type { DurableAdmissionPort } from "../ports.js";

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryAdmissionStore implements DurableAdmissionPort {
  private failNextCommit = false;
  private readonly queuedRunIds = new Set<string>();
  private readonly receipts = new Map<string, RunReceiptV1>();
  private readonly transitionCountByRun = new Map<string, number>();

  admitAndEnqueue(commit: AdmissionCommit): Promise<AdmissionCommitResult> {
    if (this.failNextCommit) {
      this.failNextCommit = false;
      return Promise.reject(new Error("injected admission failure"));
    }

    const prior = this.receipts.get(commit.receipt.idempotency_key);
    if (prior !== undefined) {
      if (prior.input_digest !== commit.receipt.input_digest) {
        return Promise.reject(new IdempotencyConflictError());
      }
      return Promise.resolve({ created: false, receipt: prior });
    }

    // These mutations model one atomic storage transaction.
    this.receipts.set(commit.receipt.idempotency_key, commit.receipt);
    this.queuedRunIds.add(commit.receipt.run_id);
    this.transitionCountByRun.set(
      commit.receipt.run_id,
      commit.transitions.length,
    );
    return Promise.resolve({ created: true, receipt: commit.receipt });
  }

  failNext(): void {
    this.failNextCommit = true;
  }

  hasQueuedRun(runId: string): boolean {
    return this.queuedRunIds.has(runId);
  }

  receiptCount(): number {
    return this.receipts.size;
  }

  transitionCount(runId: string): number {
    return this.transitionCountByRun.get(runId) ?? 0;
  }
}

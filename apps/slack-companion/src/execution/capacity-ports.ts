import type {
  CapacityAcquireRequest,
  CapacityAcquireResult,
  CapacityCooldownRequest,
  CapacityCooldownResult,
  CapacityCooldownV1,
  CapacityPermitV1,
  CapacityReclaimResult,
  CapacityReleaseRequest,
  CapacityReleaseResult,
} from "./capacity.js";

/**
 * Durable shared-capacity operations. Production adapters must make each
 * acquisition, release, cooldown extension, and expiry reclaim atomic.
 */
export interface DurableCapacityPort {
  acquire(request: CapacityAcquireRequest): Promise<CapacityAcquireResult>;

  /** Repeating the same release is safe; a different or stale proof fails. */
  release(request: CapacityReleaseRequest): Promise<CapacityReleaseResult>;

  /** Resource-wide cooldown can only stay the same or advance. */
  recordCooldown(
    request: CapacityCooldownRequest,
  ): Promise<CapacityCooldownResult>;

  readCooldown(resourceRef: string): Promise<CapacityCooldownV1 | undefined>;

  readPermit(permitId: string): Promise<CapacityPermitV1 | undefined>;

  /**
   * Fences expired owners before their slots become available. Repeating the
   * same observation returns no additional transitions.
   */
  reclaimExpired(
    resourceRef: string,
    observedAt: string,
  ): Promise<CapacityReclaimResult[]>;
}

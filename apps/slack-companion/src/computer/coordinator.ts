import {
  COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION,
  ComputerSandboxContractError,
  type ComputerSandboxActionResultV1,
  type ComputerSandboxActionV1,
  type ComputerSandboxProviderAttempt,
  type ComputerSandboxProvisionResult,
  type ComputerSandboxSessionCreateResult,
  type ComputerSandboxSessionRequestV1,
  type ComputerSandboxSessionV1,
} from "./contracts.js";
import type {
  ComputerSandboxProviderPort,
  ComputerSandboxProviderRegistry,
} from "./ports.js";
import {
  rankComputerSandboxProviders,
  validateComputerSandboxAction,
  validateComputerSandboxActionResult,
  validateComputerSandboxProvider,
  validateComputerSandboxSession,
  validateComputerSandboxSessionRequest,
} from "./policy.js";

export interface ComputerSandboxCoordinatorOptions {
  clock: { now(): Date };
  registry: ComputerSandboxProviderRegistry;
}

export function createComputerSandboxProviderRegistry(
  adapters: readonly ComputerSandboxProviderPort[],
): ComputerSandboxProviderRegistry {
  const snapshot = Object.freeze([...adapters]);
  return Object.freeze({
    list(): readonly ComputerSandboxProviderPort[] {
      return snapshot;
    },
    resolve(providerId: string): ComputerSandboxProviderPort | undefined {
      return snapshot.find((adapter) => adapter.provider_id === providerId);
    },
  });
}

export class ComputerSandboxCoordinator {
  private readonly clock: ComputerSandboxCoordinatorOptions["clock"];
  private readonly registry: ComputerSandboxProviderRegistry;

  constructor(options: ComputerSandboxCoordinatorOptions) {
    this.clock = options.clock;
    this.registry = options.registry;
    const ids = options.registry.list().map((adapter) => adapter.provider_id);
    if (
      ids.some(
        (id) => !/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/.test(id),
      ) ||
      new Set(ids).size !== ids.length
    ) {
      throw new ComputerSandboxContractError(
        "computer sandbox registry contains malformed or duplicate provider ids",
      );
    }
  }

  /**
   * Selects every currently compatible adapter in deterministic order.
   * `unavailable` proves no session was created and permits failover.
   * `unknown` stops failover until the same adapter reconciles the request.
   */
  async provision(
    request: ComputerSandboxSessionRequestV1,
  ): Promise<ComputerSandboxProvisionResult> {
    const observedAt = this.clock.now().toISOString();
    validateComputerSandboxSessionRequest(request, observedAt);
    const adapters = this.registry.list();
    const discovered = await Promise.all(
      adapters.map(async (adapter) => {
        const providerId = adapter.provider_id;
        try {
          const descriptor = await adapter.describe();
          validateComputerSandboxProvider(descriptor);
          if (descriptor.provider_id !== providerId) {
            throw new ComputerSandboxContractError(
              "provider descriptor id does not match its registered adapter",
            );
          }
          return { descriptor, provider_id: providerId, status: "available" as const };
        } catch {
          return { provider_id: providerId, status: "unavailable" as const };
        }
      }),
    );
    const descriptors = discovered.flatMap((item) =>
      item.status === "available" ? [item.descriptor] : []
    );
    const discoveryRejections = discovered.flatMap((item) =>
      item.status === "unavailable"
        ? [{ provider_id: item.provider_id, reasons: ["provider_discovery_failed"] }]
        : []
    );
    const ranking = rankComputerSandboxProviders(
      request,
      descriptors,
      observedAt,
    );
    const attempts: ComputerSandboxProviderAttempt[] = [];

    for (const candidate of ranking.compatible) {
      const adapter = this.registry.resolve(candidate.provider.provider_id);
      if (adapter === undefined) {
        throw new ComputerSandboxContractError(
          "compatible provider adapter disappeared from the registry",
        );
      }
      let result;
      try {
        result = await adapter.createSession(request);
      } catch {
        const reconciliationRef = createReconciliationRef(
          "session",
          candidate.provider.provider_id,
          request.request_id,
        );
        attempts.push({
          provider_id: candidate.provider.provider_id,
          reason_code: "adapter_error",
          status: "unknown",
        });
        return {
          attempts,
          reconciliation_ref: reconciliationRef,
          status: "unknown",
        };
      }
      assertSessionCreateOutcome(result);
      if (result.outcome === "unavailable") {
        if (result.provider_id !== candidate.provider.provider_id) {
          throw new ComputerSandboxContractError(
            "provider unavailability result names a different provider",
          );
        }
        attempts.push({
          provider_id: result.provider_id,
          reason_code: result.reason_code,
          status: "unavailable",
        });
        continue;
      }
      if (result.outcome === "unknown") {
        if (result.provider_id !== candidate.provider.provider_id) {
          throw new ComputerSandboxContractError(
            "provider unknown result names a different provider",
          );
        }
        attempts.push({
          provider_id: result.provider_id,
          reason_code: result.reason_code,
          status: "unknown",
        });
        return {
          attempts,
          reconciliation_ref: result.reconciliation_ref,
          status: "unknown",
        };
      }
      validateComputerSandboxSession(result.session, request);
      if (
        result.session.provider_id !== candidate.provider.provider_id ||
        result.session.provider_version !== candidate.provider.provider_version
      ) {
        throw new ComputerSandboxContractError(
          "created session does not match its selected provider",
        );
      }
      attempts.push({
        provider_id: result.session.provider_id,
        status: "created",
      });
      return { attempts, session: result.session, status: "created" };
    }
    return {
      attempts,
      rejections: [...ranking.rejected, ...discoveryRejections].sort(
        (left, right) => left.provider_id.localeCompare(right.provider_id),
      ),
      status: "unavailable",
    };
  }

  async reconcileProvision(
    providerId: string,
    request: ComputerSandboxSessionRequestV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxProvisionResult> {
    validateComputerSandboxSessionRequest(
      request,
      this.clock.now().toISOString(),
    );
    const adapter = this.requireAdapter(providerId);
    const result = await adapter.reconcileSession(request, reconciliationRef);
    assertSessionCreateOutcome(result);
    if (result.outcome === "created") {
      validateComputerSandboxSession(result.session, request);
      if (result.session.provider_id !== providerId) {
        throw new ComputerSandboxContractError(
          "reconciled session names a different provider",
        );
      }
      return {
        attempts: [{ provider_id: providerId, status: "created" }],
        session: result.session,
        status: "created",
      };
    }
    if (result.provider_id !== providerId) {
      throw new ComputerSandboxContractError(
        "reconciled session result names a different provider",
      );
    }
    if (result.outcome === "unknown") {
      return {
        attempts: [{
          provider_id: providerId,
          reason_code: result.reason_code,
          status: "unknown",
        }],
        reconciliation_ref: result.reconciliation_ref,
        status: "unknown",
      };
    }
    return {
      attempts: [{
        provider_id: providerId,
        reason_code: result.reason_code,
        status: "unavailable",
      }],
      rejections: [],
      status: "unavailable",
    };
  }

  async execute(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
  ): Promise<ComputerSandboxActionResultV1> {
    const now = this.clock.now().toISOString();
    validateComputerSandboxAction(action, session, now);
    const adapter = this.requireAdapter(session.provider_id);
    let result;
    try {
      result = await adapter.executeAction(session, action);
    } catch {
      result = {
        action_digest: action.authority.request_digest,
        action_id: action.action_id,
        authority_decision_id: action.authority.decision_id,
        outcome: {
          observed_at: now,
          outcome: "unknown" as const,
          reconciliation_ref: createReconciliationRef(
            "action",
            session.provider_id,
            action.action_id,
          ),
          uncertainty_code: "adapter_error",
        },
        provider_id: session.provider_id,
        provider_version: session.provider_version,
        schema_version: COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION,
        sequence: action.sequence,
        session_id: session.session_id,
      };
    }
    validateComputerSandboxActionResult(result, action, session);
    return result;
  }

  async reconcileAction(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxActionResultV1> {
    const now = this.clock.now().toISOString();
    validateComputerSandboxAction(action, session, now);
    const adapter = this.requireAdapter(session.provider_id);
    const result = await adapter.reconcileAction(
      session,
      action,
      reconciliationRef,
    );
    validateComputerSandboxActionResult(result, action, session);
    return result;
  }

  private requireAdapter(providerId: string): ComputerSandboxProviderPort {
    const adapter = this.registry.resolve(providerId);
    if (adapter === undefined) {
      throw new ComputerSandboxContractError(
        "computer sandbox provider is not registered",
      );
    }
    return adapter;
  }
}

function assertSessionCreateOutcome(
  result: ComputerSandboxSessionCreateResult,
): void {
  const outcome = (result as { outcome?: unknown }).outcome;
  if (!["created", "unavailable", "unknown"].includes(String(outcome))) {
    throw new ComputerSandboxContractError(
      "computer sandbox provider returned an unsupported session outcome",
    );
  }
}

function createReconciliationRef(
  kind: "action" | "session",
  providerId: string,
  identity: string,
): string {
  const encodedIdentity = encodeURIComponent(identity);
  return `computer-reconciliation://${kind}/${providerId}/${encodedIdentity}`;
}

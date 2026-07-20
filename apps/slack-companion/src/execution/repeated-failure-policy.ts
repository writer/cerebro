import type {
  RunLifecycleState,
  ServiceAvailabilityState,
} from "@writer/cerebro-sdk";

export interface ConsecutiveFailurePolicy {
  block_after_consecutive_failures: number;
  observation_receipt_limit: number;
}

export interface FailureObservationReceiptV1 {
  consecutive_failures: number;
  failure_fingerprint?: string;
  idempotency_key: string;
  kind: "failure" | "success";
  status: "blocked" | "degraded" | "reset";
}

export interface ConsecutiveFailureStateV1 {
  block_after_consecutive_failures: number;
  consecutive_failures: number;
  failure_fingerprint?: string;
  observation_receipt_limit: number;
  observation_receipts: FailureObservationReceiptV1[];
  schema_version: "consecutive-failure-state/v1";
}

export interface ConsecutiveFailureResult {
  receipt: FailureObservationReceiptV1;
  replayed: boolean;
  state: ConsecutiveFailureStateV1;
  status: "blocked" | "degraded";
}

export interface FailureResetResult {
  receipt: FailureObservationReceiptV1;
  replayed: boolean;
  state: ConsecutiveFailureStateV1;
  status: "reset";
}

export type FailureRunState = Extract<
  RunLifecycleState,
  "running" | "paused"
>;

export type FailureServiceState = Extract<
  ServiceAvailabilityState,
  "ready" | "degraded" | "recovering"
>;

export type FailureRunTransition =
  | { from: "running"; to: "paused" }
  | { from: "paused"; to: "blocked" };

export type FailureServiceTransition =
  | { from: "ready"; to: "degraded" }
  | { from: "recovering"; to: "degraded" };

export interface RunFailureInput {
  current_run_state: FailureRunState;
  current_service_state: FailureServiceState;
  failure_fingerprint: string;
  idempotency_key: string;
  policy: ConsecutiveFailurePolicy;
  state: ConsecutiveFailureStateV1;
}

export interface RunFailureDecision extends ConsecutiveFailureResult {
  run_state: Extract<RunLifecycleState, "paused" | "blocked">;
  run_transitions: FailureRunTransition[];
  service_state: Extract<ServiceAvailabilityState, "degraded">;
  service_transition?: FailureServiceTransition;
}

export interface TurnDependencyCircuitOptions extends ConsecutiveFailurePolicy {
  failure_fingerprint: (error: unknown) => string;
}

export interface DependencyInvocation {
  dependency_ref: string;
  idempotency_key: string;
  input_fingerprint: string;
}

export interface DependencyCircuitSnapshot {
  consecutive_failures: number;
  failure_fingerprint?: string;
  open: boolean;
}

interface CompletedDependencyInvocation {
  input_fingerprint: string;
  status: "completed";
  value: unknown;
}

interface FailedDependencyInvocation {
  error: unknown;
  input_fingerprint: string;
  status: "failed";
}

type DependencyInvocationResult =
  | CompletedDependencyInvocation
  | FailedDependencyInvocation;

interface DependencyCircuitState {
  failures: ConsecutiveFailureStateV1;
  in_flight: Map<string, InFlightDependencyInvocation>;
  invocations: Map<string, DependencyInvocationResult>;
}

interface InFlightDependencyInvocation {
  input_fingerprint: string;
  promise: Promise<unknown>;
}

export function emptyConsecutiveFailureState(
  inputPolicy: ConsecutiveFailurePolicy,
): ConsecutiveFailureStateV1 {
  const policy = validatePolicy(inputPolicy);
  return {
    block_after_consecutive_failures:
      policy.block_after_consecutive_failures,
    consecutive_failures: 0,
    observation_receipt_limit: policy.observation_receipt_limit,
    observation_receipts: [],
    schema_version: "consecutive-failure-state/v1",
  };
}

export function recordConsecutiveFailure(input: {
  failure_fingerprint: string;
  idempotency_key: string;
  policy: ConsecutiveFailurePolicy;
  state: ConsecutiveFailureStateV1;
}): ConsecutiveFailureResult {
  const policy = validatePolicy(input.policy);
  const state = validateState(input.state, policy);
  const idempotencyKey = requiredValue(
    input.idempotency_key,
    "idempotency_key",
  );
  const failureFingerprint = requiredValue(
    input.failure_fingerprint,
    "failure_fingerprint",
  );
  const prior = findObservationReceipt(state, idempotencyKey);
  if (prior !== undefined) {
    assertSameObservation(prior, "failure", failureFingerprint);
    if (prior.status === "reset") {
      throw new FailurePolicyInvariantError(
        "a failure receipt cannot have reset status",
      );
    }
    return {
      receipt: prior,
      replayed: true,
      state,
      status: prior.status,
    };
  }

  assertObservationCapacity(state);
  const consecutiveFailures =
    state.failure_fingerprint === failureFingerprint
      ? state.consecutive_failures + 1
      : 1;
  const status = failureStatus(consecutiveFailures, policy);
  const receipt: FailureObservationReceiptV1 = {
    consecutive_failures: consecutiveFailures,
    failure_fingerprint: failureFingerprint,
    idempotency_key: idempotencyKey,
    kind: "failure",
    status,
  };
  const next: ConsecutiveFailureStateV1 = {
    ...state,
    consecutive_failures: consecutiveFailures,
    failure_fingerprint: failureFingerprint,
    observation_receipts: [...state.observation_receipts, receipt],
  };
  return {
    receipt,
    replayed: false,
    state: next,
    status,
  };
}

export function resetConsecutiveFailures(input: {
  idempotency_key: string;
  policy: ConsecutiveFailurePolicy;
  state: ConsecutiveFailureStateV1;
}): FailureResetResult {
  const policy = validatePolicy(input.policy);
  const state = validateState(input.state, policy);
  const idempotencyKey = requiredValue(
    input.idempotency_key,
    "idempotency_key",
  );
  const prior = findObservationReceipt(state, idempotencyKey);
  if (prior !== undefined) {
    assertSameObservation(prior, "success");
    if (prior.status !== "reset") {
      throw new FailurePolicyInvariantError(
        "a success receipt must have reset status",
      );
    }
    return { receipt: prior, replayed: true, state, status: "reset" };
  }

  assertObservationCapacity(state);
  const receipt: FailureObservationReceiptV1 = {
    consecutive_failures: 0,
    idempotency_key: idempotencyKey,
    kind: "success",
    status: "reset",
  };
  return {
    receipt,
    replayed: false,
    state: {
      ...state,
      consecutive_failures: 0,
      failure_fingerprint: undefined,
      observation_receipts: [...state.observation_receipts, receipt],
    },
    status: "reset",
  };
}

export function decideRunFailure(input: RunFailureInput): RunFailureDecision {
  const result = recordConsecutiveFailure(input);
  const blocked = result.status === "blocked";
  const runTransitions: FailureRunTransition[] = [];

  if (input.current_run_state === "running") {
    runTransitions.push({ from: "running", to: "paused" });
  }
  if (blocked) {
    runTransitions.push({ from: "paused", to: "blocked" });
  }

  return {
    ...result,
    run_state: blocked ? "blocked" : "paused",
    run_transitions: runTransitions,
    service_state: "degraded",
    service_transition: degradedTransition(input.current_service_state),
  };
}

/** Create one circuit for each turn; do not share it across turns. */
export class TurnDependencyCircuit {
  private readonly dependencies = new Map<string, DependencyCircuitState>();
  private readonly fingerprintFailure: (error: unknown) => string;
  private readonly policy: ConsecutiveFailurePolicy;

  constructor(options: TurnDependencyCircuitOptions) {
    this.policy = validatePolicy(options);
    if (typeof options.failure_fingerprint !== "function") {
      throw new FailurePolicyInvariantError(
        "failure_fingerprint must be a function",
      );
    }
    this.fingerprintFailure = options.failure_fingerprint;
  }

  async execute<T>(
    invocation: DependencyInvocation,
    operation: () => T | Promise<T>,
  ): Promise<T> {
    const dependencyRef = requiredValue(
      invocation.dependency_ref,
      "dependency_ref",
    );
    const idempotencyKey = requiredValue(
      invocation.idempotency_key,
      "idempotency_key",
    );
    const inputFingerprint = requiredValue(
      invocation.input_fingerprint,
      "input_fingerprint",
    );
    const dependency = this.dependency(dependencyRef);
    const prior = dependency.invocations.get(idempotencyKey);
    if (prior !== undefined) {
      if (prior.input_fingerprint !== inputFingerprint) {
        throw new FailurePolicyIdempotencyConflictError();
      }
      if (prior.status === "failed") {
        throw prior.error;
      }
      return prior.value as T;
    }

    const inFlight = dependency.in_flight.get(idempotencyKey);
    if (inFlight !== undefined) {
      if (inFlight.input_fingerprint !== inputFingerprint) {
        throw new FailurePolicyIdempotencyConflictError();
      }
      return inFlight.promise as Promise<T>;
    }

    const snapshot = this.snapshot(dependencyRef);
    if (snapshot.open) {
      throw new DependencyCircuitOpenError(dependencyRef, snapshot);
    }
    assertObservationCapacity(
      dependency.failures,
      dependency.in_flight.size,
    );

    const promise = this.runInvocation(
      dependency,
      idempotencyKey,
      inputFingerprint,
      operation,
    );
    const inFlightEntry: InFlightDependencyInvocation = {
      input_fingerprint: inputFingerprint,
      promise,
    };
    dependency.in_flight.set(idempotencyKey, inFlightEntry);
    try {
      return await promise;
    } finally {
      const current = dependency.in_flight.get(idempotencyKey);
      if (current === inFlightEntry) {
        dependency.in_flight.delete(idempotencyKey);
      }
    }
  }

  snapshot(dependencyRef: string): DependencyCircuitSnapshot {
    const dependency = this.dependency(
      requiredValue(dependencyRef, "dependency_ref"),
    );
    return {
      consecutive_failures: dependency.failures.consecutive_failures,
      failure_fingerprint: dependency.failures.failure_fingerprint,
      open:
        dependency.failures.consecutive_failures >=
        this.policy.block_after_consecutive_failures,
    };
  }

  private dependency(dependencyRef: string): DependencyCircuitState {
    let dependency = this.dependencies.get(dependencyRef);
    if (dependency === undefined) {
      dependency = {
        failures: emptyConsecutiveFailureState(this.policy),
        in_flight: new Map(),
        invocations: new Map(),
      };
      this.dependencies.set(dependencyRef, dependency);
    }
    return dependency;
  }

  private async runInvocation<T>(
    dependency: DependencyCircuitState,
    idempotencyKey: string,
    inputFingerprint: string,
    operation: () => T | Promise<T>,
  ): Promise<T> {
    let value: T;
    try {
      value = await operation();
    } catch (error) {
      const failureFingerprint = requiredValue(
        this.fingerprintFailure(error),
        "failure_fingerprint",
      );
      dependency.failures = recordConsecutiveFailure({
        failure_fingerprint: failureFingerprint,
        idempotency_key: idempotencyKey,
        policy: this.policy,
        state: dependency.failures,
      }).state;
      dependency.invocations.set(idempotencyKey, {
        error,
        input_fingerprint: inputFingerprint,
        status: "failed",
      });
      throw error;
    }

    dependency.failures = resetConsecutiveFailures({
      idempotency_key: idempotencyKey,
      policy: this.policy,
      state: dependency.failures,
    }).state;
    dependency.invocations.set(idempotencyKey, {
      input_fingerprint: inputFingerprint,
      status: "completed",
      value,
    });
    return value;
  }
}

export class FailurePolicyInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FailurePolicyInvariantError";
  }
}

export class FailurePolicyIdempotencyConflictError extends Error {
  constructor() {
    super("idempotency key belongs to a different observation");
    this.name = "FailurePolicyIdempotencyConflictError";
  }
}

export class FailureObservationLimitError extends FailurePolicyInvariantError {
  constructor() {
    super("failure observation receipt limit is exhausted");
    this.name = "FailureObservationLimitError";
  }
}

export class DependencyCircuitOpenError extends Error {
  readonly consecutive_failures: number;
  readonly dependency_ref: string;
  readonly failure_fingerprint?: string;

  constructor(
    dependencyRef: string,
    snapshot: DependencyCircuitSnapshot,
  ) {
    super("dependency is unavailable for the remainder of this turn");
    this.name = "DependencyCircuitOpenError";
    this.consecutive_failures = snapshot.consecutive_failures;
    this.dependency_ref = dependencyRef;
    this.failure_fingerprint = snapshot.failure_fingerprint;
  }
}

function validatePolicy(
  policy: ConsecutiveFailurePolicy,
): ConsecutiveFailurePolicy {
  if (
    !Number.isSafeInteger(policy.block_after_consecutive_failures) ||
    policy.block_after_consecutive_failures <= 0
  ) {
    throw new FailurePolicyInvariantError(
      "block_after_consecutive_failures must be a positive integer",
    );
  }
  if (
    !Number.isSafeInteger(policy.observation_receipt_limit) ||
    policy.observation_receipt_limit <= 0
  ) {
    throw new FailurePolicyInvariantError(
      "observation_receipt_limit must be a positive integer",
    );
  }
  if (
    policy.observation_receipt_limit <
    policy.block_after_consecutive_failures
  ) {
    throw new FailurePolicyInvariantError(
      "observation_receipt_limit must cover the failure threshold",
    );
  }
  return policy;
}

function validateState(
  state: ConsecutiveFailureStateV1,
  policy: ConsecutiveFailurePolicy,
): ConsecutiveFailureStateV1 {
  if (state.schema_version !== "consecutive-failure-state/v1") {
    throw new FailurePolicyInvariantError(
      "unsupported consecutive failure state schema",
    );
  }
  if (
    state.block_after_consecutive_failures !==
      policy.block_after_consecutive_failures ||
    state.observation_receipt_limit !== policy.observation_receipt_limit
  ) {
    throw new FailurePolicyInvariantError(
      "failure policy does not match the persisted state",
    );
  }
  if (!Array.isArray(state.observation_receipts)) {
    throw new FailurePolicyInvariantError(
      "observation_receipts must be an array",
    );
  }
  if (
    state.observation_receipts.length > state.observation_receipt_limit
  ) {
    throw new FailurePolicyInvariantError(
      "observation receipt limit was exceeded",
    );
  }

  const idempotencyKeys = new Set<string>();
  let consecutiveFailures = 0;
  let failureFingerprint: string | undefined;
  for (const receipt of state.observation_receipts) {
    assertCanonicalValue(receipt.idempotency_key, "idempotency_key");
    if (idempotencyKeys.has(receipt.idempotency_key)) {
      throw new FailurePolicyInvariantError(
        "observation receipts must have unique idempotency keys",
      );
    }
    idempotencyKeys.add(receipt.idempotency_key);

    if (receipt.kind === "failure") {
      assertCanonicalValue(
        receipt.failure_fingerprint,
        "failure_fingerprint",
      );
      consecutiveFailures =
        failureFingerprint === receipt.failure_fingerprint
          ? consecutiveFailures + 1
          : 1;
      failureFingerprint = receipt.failure_fingerprint;
      if (receipt.consecutive_failures !== consecutiveFailures) {
        throw new FailurePolicyInvariantError(
          "failure receipt count does not match its history",
        );
      }
      if (receipt.status !== failureStatus(consecutiveFailures, policy)) {
        throw new FailurePolicyInvariantError(
          "failure receipt status does not match its history",
        );
      }
    } else if (receipt.kind !== "success") {
      throw new FailurePolicyInvariantError("unknown failure observation kind");
    } else if (receipt.failure_fingerprint !== undefined) {
      throw new FailurePolicyInvariantError(
        "a success observation cannot carry a failure fingerprint",
      );
    } else if (
      receipt.consecutive_failures !== 0 ||
      receipt.status !== "reset"
    ) {
      throw new FailurePolicyInvariantError(
        "a success receipt must record a reset streak",
      );
    } else {
      consecutiveFailures = 0;
      failureFingerprint = undefined;
    }
  }

  if (
    state.consecutive_failures !== consecutiveFailures ||
    state.failure_fingerprint !== failureFingerprint
  ) {
    throw new FailurePolicyInvariantError(
      "failure streak does not match observation receipt history",
    );
  }
  return state;
}

function failureStatus(
  consecutiveFailures: number,
  policy: ConsecutiveFailurePolicy,
): ConsecutiveFailureResult["status"] {
  return consecutiveFailures >= policy.block_after_consecutive_failures
    ? "blocked"
    : "degraded";
}

function assertSameObservation(
  prior: FailureObservationReceiptV1,
  kind: FailureObservationReceiptV1["kind"],
  failureFingerprint?: string,
): void {
  if (
    prior.kind !== kind ||
    prior.failure_fingerprint !== failureFingerprint
  ) {
    throw new FailurePolicyIdempotencyConflictError();
  }
}

function findObservationReceipt(
  state: ConsecutiveFailureStateV1,
  idempotencyKey: string,
): FailureObservationReceiptV1 | undefined {
  return state.observation_receipts.find(
    (receipt) => receipt.idempotency_key === idempotencyKey,
  );
}

function assertObservationCapacity(
  state: ConsecutiveFailureStateV1,
  reservedObservations = 0,
): void {
  if (
    state.observation_receipts.length + reservedObservations >=
    state.observation_receipt_limit
  ) {
    throw new FailureObservationLimitError();
  }
}

function degradedTransition(
  serviceState: FailureServiceState,
): FailureServiceTransition | undefined {
  switch (serviceState) {
    case "ready":
      return { from: "ready", to: "degraded" };
    case "recovering":
      return { from: "recovering", to: "degraded" };
    case "degraded":
      return undefined;
  }
}

function requiredValue(value: string | undefined, field: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new FailurePolicyInvariantError(`${field} must be non-empty`);
  }
  return normalized;
}

function assertCanonicalValue(value: string | undefined, field: string): void {
  const normalized = requiredValue(value, field);
  if (value !== normalized) {
    throw new FailurePolicyInvariantError(`${field} must be canonical`);
  }
}

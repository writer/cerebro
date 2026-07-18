import type {
  RunLifecycleState,
  ServiceAvailabilityState,
} from "@writer/cerebro-sdk";

export interface ConsecutiveFailurePolicy {
  block_after_consecutive_failures: number;
}

export interface FailureObservationV1 {
  failure_fingerprint?: string;
  idempotency_key: string;
  kind: "failure" | "success";
}

export interface ConsecutiveFailureStateV1 {
  consecutive_failures: number;
  failure_fingerprint?: string;
  last_observation?: FailureObservationV1;
  schema_version: "consecutive-failure-state/v1";
}

export interface ConsecutiveFailureResult {
  replayed: boolean;
  state: ConsecutiveFailureStateV1;
  status: "blocked" | "degraded";
}

export interface FailureResetResult {
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
  invocations: Map<string, DependencyInvocationResult>;
}

export function emptyConsecutiveFailureState(): ConsecutiveFailureStateV1 {
  return {
    consecutive_failures: 0,
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
  const state = validateState(input.state);
  const idempotencyKey = requiredValue(
    input.idempotency_key,
    "idempotency_key",
  );
  const failureFingerprint = requiredValue(
    input.failure_fingerprint,
    "failure_fingerprint",
  );
  const observation: FailureObservationV1 = {
    failure_fingerprint: failureFingerprint,
    idempotency_key: idempotencyKey,
    kind: "failure",
  };

  if (state.last_observation?.idempotency_key === idempotencyKey) {
    assertSameObservation(state.last_observation, observation);
    return {
      replayed: true,
      state,
      status: failureStatus(state.consecutive_failures, policy),
    };
  }

  const consecutiveFailures =
    state.failure_fingerprint === failureFingerprint
      ? state.consecutive_failures + 1
      : 1;
  const next: ConsecutiveFailureStateV1 = {
    consecutive_failures: consecutiveFailures,
    failure_fingerprint: failureFingerprint,
    last_observation: observation,
    schema_version: "consecutive-failure-state/v1",
  };
  return {
    replayed: false,
    state: next,
    status: failureStatus(consecutiveFailures, policy),
  };
}

export function resetConsecutiveFailures(input: {
  idempotency_key: string;
  state: ConsecutiveFailureStateV1;
}): FailureResetResult {
  const state = validateState(input.state);
  const observation: FailureObservationV1 = {
    idempotency_key: requiredValue(input.idempotency_key, "idempotency_key"),
    kind: "success",
  };

  if (state.last_observation?.idempotency_key === observation.idempotency_key) {
    assertSameObservation(state.last_observation, observation);
    return { replayed: true, state, status: "reset" };
  }

  return {
    replayed: false,
    state: {
      consecutive_failures: 0,
      last_observation: observation,
      schema_version: "consecutive-failure-state/v1",
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

    const snapshot = this.snapshot(dependencyRef);
    if (snapshot.open) {
      throw new DependencyCircuitOpenError(dependencyRef, snapshot);
    }

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
      state: dependency.failures,
    }).state;
    dependency.invocations.set(idempotencyKey, {
      input_fingerprint: inputFingerprint,
      status: "completed",
      value,
    });
    return value;
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
        failures: emptyConsecutiveFailureState(),
        invocations: new Map(),
      };
      this.dependencies.set(dependencyRef, dependency);
    }
    return dependency;
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
  return policy;
}

function validateState(
  state: ConsecutiveFailureStateV1,
): ConsecutiveFailureStateV1 {
  if (state.schema_version !== "consecutive-failure-state/v1") {
    throw new FailurePolicyInvariantError(
      "unsupported consecutive failure state schema",
    );
  }
  if (
    !Number.isSafeInteger(state.consecutive_failures) ||
    state.consecutive_failures < 0
  ) {
    throw new FailurePolicyInvariantError(
      "consecutive_failures must be a non-negative integer",
    );
  }
  if (
    (state.consecutive_failures === 0) !==
    (state.failure_fingerprint === undefined)
  ) {
    throw new FailurePolicyInvariantError(
      "failure fingerprint and consecutive count must describe the same streak",
    );
  }
  if (state.failure_fingerprint !== undefined) {
    assertCanonicalValue(state.failure_fingerprint, "failure_fingerprint");
  }
  if (state.last_observation !== undefined) {
    assertCanonicalValue(
      state.last_observation.idempotency_key,
      "idempotency_key",
    );
    if (state.last_observation.kind === "failure") {
      assertCanonicalValue(
        state.last_observation.failure_fingerprint,
        "failure_fingerprint",
      );
      if (
        state.last_observation.failure_fingerprint !==
        state.failure_fingerprint
      ) {
        throw new FailurePolicyInvariantError(
          "the latest failure observation must match the active streak",
        );
      }
    } else if (state.last_observation.kind !== "success") {
      throw new FailurePolicyInvariantError("unknown failure observation kind");
    } else if (state.last_observation.failure_fingerprint !== undefined) {
      throw new FailurePolicyInvariantError(
        "a success observation cannot carry a failure fingerprint",
      );
    } else if (state.consecutive_failures !== 0) {
      throw new FailurePolicyInvariantError(
        "a success observation must reset the active streak",
      );
    }
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
  prior: FailureObservationV1,
  next: FailureObservationV1,
): void {
  if (
    prior.kind !== next.kind ||
    prior.failure_fingerprint !== next.failure_fingerprint
  ) {
    throw new FailurePolicyIdempotencyConflictError();
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

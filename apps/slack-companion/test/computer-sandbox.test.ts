import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import {
  ComputerSandboxCoordinator,
  createComputerSandboxProviderRegistry,
} from "../src/computer/coordinator.js";
import type {
  ComputerSandboxActionResultV1,
  ComputerSandboxActionV1,
  ComputerSandboxProviderV1,
  ComputerSandboxSessionCreateResult,
  ComputerSandboxSessionRequestV1,
  ComputerSandboxSessionV1,
} from "../src/computer/contracts.js";
import type {
  ComputerSandboxProviderPort,
} from "../src/computer/ports.js";
import {
  computerSandboxActionDigest,
  computerSandboxActionPolicy,
  computerSandboxSessionIdentity,
  computerSandboxSessionRequestDigest,
  computerSandboxToolCatalogEntries,
  rankComputerSandboxProviders,
  validateComputerSandboxAction,
  validateComputerSandboxSessionRequest,
} from "../src/computer/policy.js";
import {
  createToolCatalog,
} from "../src/tools/catalog.js";

const NOW = "2026-07-28T12:00:00.000Z";
const LATER = "2026-07-28T12:30:00.000Z";
const VALID_UNTIL = "2026-07-28T13:00:00.000Z";

describe("provider-neutral computer sandboxes", () => {
  test("registers exact computer tool authority and replay policies", () => {
    const catalog = createToolCatalog(computerSandboxToolCatalogEntries());
    assert.equal(catalog.resolve("computer.observe", "1.0.0")?.effect_class, "read");
    assert.equal(
      catalog.resolve("computer.interact", "1.0.0")?.authority_class,
      "propose",
    );
    assert.equal(
      catalog.resolve("computer.actuate", "1.0.0")?.replay_policy,
      "reconcile_before_retry",
    );
    assert.equal(
      computerSandboxActionPolicy("submit").tool_id,
      "computer.actuate",
    );
    assert.equal(
      computerSandboxActionPolicy("type").replay_policy,
      "reconcile_before_retry",
    );
  });

  test("rejects broad network access and inline provider material", () => {
    assert.doesNotThrow(() => validateComputerSandboxSessionRequest(request()));
    assert.throws(
      () =>
        validateComputerSandboxSessionRequest({
          ...request(),
          allowed_origins: ["http://example.test"],
        }),
      /HTTPS origins/,
    );
    assert.throws(
      () =>
        validateComputerSandboxSessionRequest({
          ...request(),
          provider_config: { api_key: "secret" },
        } as ComputerSandboxSessionRequestV1),
      /unsupported fields: provider_config/,
    );
    assert.throws(
      () =>
        validateComputerSandboxSessionRequest({
          ...request(),
          allowed_origins: ["https://different.example.test"],
        }),
      /authority does not allow the exact request/,
    );
  });

  test("ranks arbitrary compatible providers deterministically", () => {
    const candidates = [
      provider("container-lab", "degraded"),
      provider("browser-grid", "ready"),
      provider("vm-pool", "ready"),
      provider("read-only", "ready", ["browser"], ["observe", "navigate"]),
    ];
    const first = rankComputerSandboxProviders(request(), candidates, NOW);
    const reversed = rankComputerSandboxProviders(
      request(),
      [...candidates].reverse(),
      NOW,
    );
    assert.deepEqual(
      first.compatible.map((candidate) => candidate.provider.provider_id),
      reversed.compatible.map((candidate) => candidate.provider.provider_id),
    );
    assert.equal(first.compatible[0]?.provider.state, "ready");
    assert.equal(first.compatible.at(-1)?.provider.state, "degraded");
    assert.deepEqual(first.rejected, [{
      provider_id: "read-only",
      reasons: [
        "provider_missing_capability_uploads",
        "provider_missing_action_type",
        "provider_missing_action_submit",
      ],
    }]);
  });

  test("honors explicit host preference before stable provider spread", () => {
    const ranked = rankComputerSandboxProviders(
      request(["browser-grid", "vm-pool"]),
      [provider("vm-pool"), provider("browser-grid")],
      NOW,
    );
    assert.deepEqual(
      ranked.compatible.map((candidate) => candidate.provider.provider_id),
      ["browser-grid", "vm-pool"],
    );
  });

  test("fails over only after a provider proves it created no session", async () => {
    const unavailable = new FakeProvider(
      provider("browser-grid"),
      { outcome: "unavailable", provider_id: "browser-grid", reason_code: "capacity" },
    );
    const created = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(unavailable, created);
    const result = await sandbox.provision(
      request(["browser-grid", "vm-pool"]),
    );
    assert.equal(result.status, "created");
    if (result.status !== "created") return;
    assert.equal(result.session.provider_id, "vm-pool");
    assert.deepEqual(result.attempts.map((attempt) => attempt.status), [
      "unavailable",
      "created",
    ]);
    assert.equal(unavailable.createCalls, 1);
    assert.equal(created.createCalls, 1);
  });

  test("stops provider failover on an unknown create outcome", async () => {
    const uncertain = new FakeProvider(provider("browser-grid"), {
      outcome: "unknown",
      provider_id: "browser-grid",
      reason_code: "provider_timeout",
      reconciliation_ref: "sandbox-reconciliation://create/1",
    });
    const next = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(uncertain, next);
    const input = request(["browser-grid", "vm-pool"]);
    const result = await sandbox.provision(input);
    assert.equal(result.status, "unknown");
    assert.equal(next.createCalls, 0);

    uncertain.createResult = {
      outcome: "created",
      replayed: true,
      session: session(input, uncertain.descriptor),
    };
    const reconciled = await sandbox.reconcileProvision(
      "browser-grid",
      input,
      "sandbox-reconciliation://create/1",
    );
    assert.equal(reconciled.status, "created");
  });

  test("rejects unsupported provider outcomes before reading a session", async () => {
    const malformed = new FakeProvider(provider("browser-grid"));
    malformed.createResult = { outcome: "surprise" } as never;
    await assert.rejects(
      () => sandboxCoordinator(malformed).provision(request()),
      /unsupported session outcome/,
    );
    await assert.rejects(
      () => sandboxCoordinator(malformed).reconcileProvision(
        "browser-grid",
        request(),
        "sandbox-reconciliation://create/1",
      ),
      /unsupported session outcome/,
    );
  });

  test("isolates provider discovery failures and treats thrown creates as unknown", async () => {
    const brokenDiscovery = new FakeProvider(provider("broken-discovery"));
    brokenDiscovery.describeError = true;
    const healthy = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(brokenDiscovery, healthy);
    const created = await sandbox.provision(
      request(["broken-discovery", "vm-pool"]),
    );
    assert.equal(created.status, "created");

    const throwing = new FakeProvider(provider("browser-grid"));
    throwing.createError = true;
    const untouched = new FakeProvider(provider("container-lab"));
    const uncertain = await sandboxCoordinator(throwing, untouched).provision(
      request(["browser-grid", "container-lab"]),
    );
    assert.equal(uncertain.status, "unknown");
    assert.equal(untouched.createCalls, 0);
  });

  test("binds every action to exact non-expired authority", async () => {
    const adapter = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(adapter);
    const provisioned = await sandbox.provision(request());
    assert.equal(provisioned.status, "created");
    if (provisioned.status !== "created") return;
    const action = authorizedAction(provisioned.session, "observe");
    const result = await sandbox.execute(provisioned.session, action);
    assert.equal(result.outcome.outcome, "succeeded");

    const changed = { ...action, input_ref: "computer-input://changed" };
    assert.throws(
      () => validateComputerSandboxAction(changed, provisioned.session, NOW),
      /authority does not allow the exact invocation/,
    );
    const submit = authorizedAction(provisioned.session, "submit");
    assert.equal(submit.authority.tool_id, "computer.actuate");
    assert.equal(
      computerSandboxActionPolicy(submit.kind).replay_policy,
      "reconcile_before_retry",
    );
  });

  test("requires explicit reconciliation after an unknown external effect", async () => {
    const adapter = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(adapter);
    const provisioned = await sandbox.provision(request());
    assert.equal(provisioned.status, "created");
    if (provisioned.status !== "created") return;
    const action = authorizedAction(provisioned.session, "submit");
    adapter.actionResult = actionResult(provisioned.session, action, {
      observed_at: NOW,
      outcome: "unknown",
      reconciliation_ref: "sandbox-reconciliation://action/1",
      uncertainty_code: "provider_timeout",
    });
    const uncertain = await sandbox.execute(provisioned.session, action);
    assert.equal(uncertain.outcome.outcome, "unknown");

    adapter.actionResult = actionResult(provisioned.session, action, {
      completed_at: NOW,
      outcome: "succeeded",
      output_digest: digest("observation"),
      output_ref: "computer-observation://sha256/result",
      provider_receipt_ref: "provider-receipt://action/1",
    });
    const reconciled = await sandbox.reconcileAction(
      provisioned.session,
      action,
      "sandbox-reconciliation://action/1",
    );
    assert.equal(reconciled.outcome.outcome, "succeeded");
    assert.equal(adapter.reconcileActionCalls, 1);
  });

  test("turns a thrown action call into a reconcilable unknown result", async () => {
    const adapter = new FakeProvider(provider("vm-pool"));
    const sandbox = sandboxCoordinator(adapter);
    const provisioned = await sandbox.provision(request());
    assert.equal(provisioned.status, "created");
    if (provisioned.status !== "created") return;
    const action = authorizedAction(provisioned.session, "submit");
    adapter.actionError = true;
    const result = await sandbox.execute(provisioned.session, action);
    assert.equal(result.outcome.outcome, "unknown");
    if (result.outcome.outcome !== "unknown") return;
    assert.match(
      result.outcome.reconciliation_ref,
      /^computer-reconciliation:\/\/action\/vm-pool\//,
    );
  });
});

class FakeProvider implements ComputerSandboxProviderPort {
  actionError = false;
  actionResult?: ComputerSandboxActionResultV1;
  createError = false;
  createCalls = 0;
  describeError = false;
  reconcileActionCalls = 0;

  constructor(
    readonly descriptor: ComputerSandboxProviderV1,
    public createResult?: ComputerSandboxSessionCreateResult,
  ) {}

  get provider_id(): string {
    return this.descriptor.provider_id;
  }

  async describe(): Promise<ComputerSandboxProviderV1> {
    if (this.describeError) throw new Error("discovery failed");
    return structuredClone(this.descriptor);
  }

  async createSession(
    input: ComputerSandboxSessionRequestV1,
  ): Promise<ComputerSandboxSessionCreateResult> {
    this.createCalls += 1;
    if (this.createError) throw new Error("create timed out");
    return structuredClone(this.createResult ?? {
      outcome: "created",
      replayed: false,
      session: session(input, this.descriptor),
    });
  }

  async reconcileSession(
    input: ComputerSandboxSessionRequestV1,
    _reconciliationRef: string,
  ): Promise<ComputerSandboxSessionCreateResult> {
    return structuredClone(this.createResult ?? {
      outcome: "created",
      replayed: true,
      session: session(input, this.descriptor),
    });
  }

  async executeAction(
    sandbox: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
  ): Promise<ComputerSandboxActionResultV1> {
    if (this.actionError) throw new Error("action timed out");
    return structuredClone(this.actionResult ?? actionResult(sandbox, action, {
      completed_at: NOW,
      outcome: "succeeded",
      output_digest: digest("observation"),
      output_ref: "computer-observation://sha256/result",
      provider_receipt_ref: "provider-receipt://action/1",
    }));
  }

  async reconcileAction(
    sandbox: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
    _reconciliationRef: string,
  ): Promise<ComputerSandboxActionResultV1> {
    this.reconcileActionCalls += 1;
    return this.executeAction(sandbox, action);
  }
}

function sandboxCoordinator(
  ...adapters: readonly FakeProvider[]
): ComputerSandboxCoordinator {
  return new ComputerSandboxCoordinator({
    clock: { now: () => new Date(NOW) },
    registry: createComputerSandboxProviderRegistry(adapters),
  });
}

function request(
  providerPreferences?: readonly string[],
): ComputerSandboxSessionRequestV1 {
  const input: Omit<ComputerSandboxSessionRequestV1, "authority"> = {
    allowed_origins: ["https://example.test", "https://files.example.test"],
    expires_at: LATER,
    idempotency_key: "computer-request-1",
    identity_ref: "identity-grant://subject/1",
    image_ref: "computer-image://sha256/base",
    network_policy_ref: "network-policy://restricted/browser",
    ...(providerPreferences === undefined
      ? {}
      : { provider_preferences: providerPreferences }),
    request_id: "computer-request-1",
    requested_at: NOW,
    required_actions: ["observe", "navigate", "type", "submit"],
    required_capabilities: ["browser", "uploads"],
    run_id: "run-1",
    schema_version: "computer-sandbox-session-request/v1",
    step_id: "step-create-session-1",
    subject_ref: "subject-1",
  };
  const authority = {
    authority_ref: "authority-create-session-1",
    decided_at: NOW,
    decision_id: "decision-create-session-1",
    expires_at: LATER,
    invocation_id: input.request_id,
    outcome: "allowed" as const,
    reason_code: "policy_allowed",
    request_digest: computerSandboxSessionRequestDigest({
      ...input,
      authority: {} as ComputerSandboxSessionRequestV1["authority"],
    }),
    run_id: input.run_id,
    schema_version: "tool-authority-decision/v1" as const,
    step_id: input.step_id,
    subject_ref: input.subject_ref,
    tool_id: "computer.session.create",
    tool_version: "1.0.0",
  };
  return { ...input, authority };
}

function provider(
  providerId: string,
  state: ComputerSandboxProviderV1["state"] = "ready",
  capabilities: ComputerSandboxProviderV1["capabilities"] = [
    "browser",
    "uploads",
  ],
  actions: ComputerSandboxProviderV1["supported_actions"] = [
    "activate",
    "close",
    "download",
    "focus",
    "navigate",
    "observe",
    "scroll",
    "submit",
    "type",
    "upload",
  ],
): ComputerSandboxProviderV1 {
  return {
    capabilities,
    max_session_seconds: 3_600,
    observed_at: NOW,
    provider_id: providerId,
    provider_version: "1.0.0",
    schema_version: "computer-sandbox-provider/v1",
    state,
    supported_actions: actions,
    valid_until: VALID_UNTIL,
  };
}

function session(
  input: ComputerSandboxSessionRequestV1,
  descriptor: ComputerSandboxProviderV1,
): ComputerSandboxSessionV1 {
  return {
    created_at: input.requested_at,
    expires_at: input.expires_at,
    generation: 1,
    provider_id: descriptor.provider_id,
    provider_session_ref: `provider-session://${descriptor.provider_id}/1`,
    provider_version: descriptor.provider_version,
    request_digest: computerSandboxSessionRequestDigest(input),
    request_id: input.request_id,
    revision: 1,
    schema_version: "computer-sandbox-session/v1",
    session_id: computerSandboxSessionIdentity(input),
    state: "active",
  };
}

function authorizedAction(
  sandbox: ComputerSandboxSessionV1,
  kind: ComputerSandboxActionV1["kind"],
): ComputerSandboxActionV1 {
  const policy = computerSandboxActionPolicy(kind);
  const action = {
    action_id: `action-${kind}-1`,
    idempotency_key: `action-${kind}-1`,
    input_digest: digest(`${kind}-input`),
    input_ref: `computer-input://${kind}/1`,
    kind,
    requested_at: NOW,
    run_id: "run-1",
    schema_version: "computer-sandbox-action/v1" as const,
    sequence: 1,
    session_id: sandbox.session_id,
    step_id: `step-${kind}-1`,
    subject_ref: "subject-1",
  };
  return {
    ...action,
    authority: {
      authority_ref: `authority-${kind}-1`,
      decided_at: NOW,
      decision_id: `decision-${kind}-1`,
      expires_at: LATER,
      invocation_id: action.action_id,
      outcome: "allowed",
      reason_code: "policy_allowed",
      request_digest: computerSandboxActionDigest({
        ...action,
        authority: undefined,
      } as unknown as ComputerSandboxActionV1),
      run_id: action.run_id,
      schema_version: "tool-authority-decision/v1",
      step_id: action.step_id,
      subject_ref: action.subject_ref,
      tool_id: policy.tool_id,
      tool_version: policy.tool_version,
    },
  };
}

function actionResult(
  sandbox: ComputerSandboxSessionV1,
  action: ComputerSandboxActionV1,
  outcome: ComputerSandboxActionResultV1["outcome"],
): ComputerSandboxActionResultV1 {
  return {
    action_digest: computerSandboxActionDigest(action),
    action_id: action.action_id,
    authority_decision_id: action.authority.decision_id,
    outcome,
    provider_id: sandbox.provider_id,
    provider_version: sandbox.provider_version,
    schema_version: "computer-sandbox-action-result/v1",
    sequence: action.sequence,
    session_id: sandbox.session_id,
  };
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

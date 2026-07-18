import assert from "node:assert/strict";
import test from "node:test";

import {
  createSlackActionRegistry,
  decideSlackAction,
  SlackActionContractError,
  type SlackActionCatalogV1,
  type SlackActionEnvelopeV1,
} from "../src/index.js";

const issuedAt = "2026-07-18T10:00:01.000Z";

test("snapshots a stable immutable action catalog", () => {
  const capabilities = [
    capability("memory.write", "v1", "required"),
    capability("memory.read", "v2", "optional"),
  ];
  const parameters = [
    { name: "target", required: true },
    { name: "mode", required: false },
  ];
  const actions = [actionContract({ capabilities, parameters })];
  const registry = createSlackActionRegistry(catalog(actions));

  capabilities.push(capability("changed", "v1", "optional"));
  parameters.push({ name: "changed", required: false });
  actions.push(actionContract({ action_id: "other.action" }));

  assert.equal(registry.catalog.catalog_id, "cerebro.slack.actions");
  assert.equal(registry.catalog.revision, 1);
  assert.deepEqual(registry.actions().map((action) => action.action_id), ["memory.remember"]);
  assert.deepEqual(registry.action("memory.remember")?.required_capabilities, [
    capability("memory.read", "v2", "optional"),
    capability("memory.write", "v1", "required"),
  ]);
  assert.deepEqual(registry.action("memory.remember")?.parameters, [
    { name: "mode", required: false },
    { name: "target", required: true },
  ]);
  assert.equal(Object.isFrozen(registry.catalog), true);
  assert.equal(Object.isFrozen(registry.catalog.actions), true);
  assert.equal(Object.isFrozen(registry.catalog.actions[0]), true);
  assert.equal(Object.isFrozen(registry.catalog.actions[0]?.parameters), true);
});

test("returns a deterministic receipt and replays the exact receipt on retry", () => {
  const registry = createSlackActionRegistry(catalog([actionContract()]));
  const action = envelope();
  const first = decideSlackAction(registry, {
    action,
    available_capabilities: [capability("memory.write")],
  });

  assert.equal(first.disposition, "admit");
  assert.equal(first.reason_code, "accepted");
  assert.match(first.receipt.catalog_digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(first.receipt.receipt_digest, /^sha256:[a-f0-9]{64}$/);
  assert.match(first.receipt.receipt_id, /^slack-action-decision:[a-f0-9]{64}$/);
  assert.match(first.receipt.request_digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.receipt), true);

  const retry = decideSlackAction(registry, {
    action: { ...action, parameters: { target: "team" } },
    available_capabilities: [capability("memory.write")],
    existing_receipt: first.receipt,
  });
  assert.equal(retry.disposition, "replay");
  if (retry.disposition !== "replay") assert.fail("expected receipt replay");
  assert.deepEqual(retry.receipt, first.receipt);
  assert.equal(Object.isFrozen(retry.receipt), true);
});

test("rejects conflicting reuse of an idempotency key without replacing its receipt", () => {
  const registry = createSlackActionRegistry(catalog([actionContract()]));
  const first = decideSlackAction(registry, {
    action: envelope(),
    available_capabilities: [capability("memory.write")],
  });
  assert.ok("receipt" in first);

  const conflict = decideSlackAction(registry, {
    action: envelope({ parameters: { target: "personal" } }),
    available_capabilities: [capability("memory.write")],
    existing_receipt: first.receipt,
  });
  assert.deepEqual(conflict, {
    disposition: "reject",
    reason_code: "idempotency_conflict",
    receipt_ref: first.receipt.receipt_id,
    schema_version: "slack-action-policy-decision/v1",
  });
});

test("fails closed for unknown, mismatched, incomplete, and unauthorized actions", () => {
  const registry = createSlackActionRegistry(catalog([actionContract()]));
  const reason = (
    action: SlackActionEnvelopeV1,
    capabilities = [capability("memory.write")],
  ) =>
    decideSlackAction(registry, {
      action,
      available_capabilities: capabilities,
    }).reason_code;

  assert.equal(reason(envelope({ action: "unknown.action" })), "unknown_action");
  assert.equal(reason(envelope({ command: "ask" })), "action_command_mismatch");
  assert.equal(reason(envelope({ subject_ref: undefined })), "subject_required");
  assert.equal(reason(envelope({ parameters: undefined })), "missing_parameter");
  assert.equal(
    reason(envelope({ parameters: { extra: "value", target: "team" } })),
    "unexpected_parameter",
  );
  assert.equal(reason(envelope(), []), "missing_capability");
  assert.equal(
    reason(envelope(), [capability("memory.write", "v2")]),
    "missing_capability",
  );
  assert.equal(
    reason(envelope(), [capability("memory.write", "1")]),
    "missing_capability",
  );
});

test("replays the pinned decision across a compatible catalog revision", () => {
  const firstRegistry = createSlackActionRegistry(catalog([actionContract()]));
  const first = decideSlackAction(firstRegistry, {
    action: envelope(),
    available_capabilities: [capability("memory.write")],
  });
  if (!("receipt" in first)) assert.fail("expected an action receipt");

  const nextRegistry = createSlackActionRegistry({
    ...catalog([actionContract()]),
    revision: 2,
  });
  const retry = decideSlackAction(nextRegistry, {
    action: envelope(),
    available_capabilities: [],
    existing_receipt: first.receipt,
  });
  assert.equal(retry.disposition, "replay");
  if (retry.disposition !== "replay") assert.fail("expected receipt replay");
  assert.deepEqual(retry.receipt, first.receipt);
  assert.equal(retry.receipt.catalog_revision, 1);
});

test("rejects tampering with any field bound by receipt integrity", () => {
  const registry = createSlackActionRegistry(catalog([actionContract()]));
  const rejected = decideSlackAction(registry, {
    action: envelope(),
    available_capabilities: [],
  });
  if (!("receipt" in rejected)) assert.fail("expected an action receipt");
  assert.equal(rejected.receipt.outcome, "rejected");

  const mutations: Array<Record<string, unknown>> = [
    { outcome: "accepted", reason_code: "accepted" },
    { reason_code: "unknown_action" },
    { action_id: "other.action" },
    { command: "ask" },
    { catalog_id: "other.catalog" },
    { catalog_revision: 2 },
    { catalog_digest: `sha256:${"0".repeat(64)}` },
    { request_digest: `sha256:${"0".repeat(64)}` },
    { receipt_digest: `sha256:${"0".repeat(64)}` },
    { receipt_id: `slack-action-decision:${"0".repeat(64)}` },
  ];
  for (const mutation of mutations) {
    assert.throws(
      () => decideSlackAction(registry, {
        action: envelope(),
        available_capabilities: [capability("memory.write")],
        existing_receipt: { ...rejected.receipt, ...mutation } as never,
      }),
      SlackActionContractError,
    );
  }
});

test("rejects malformed, ambiguous, and non-idempotent action catalogs", () => {
  const duplicate = catalog([actionContract(), actionContract()]);
  assert.throws(() => createSlackActionRegistry(duplicate), /duplicate action_id/);
  assert.throws(
    () => createSlackActionRegistry({ ...catalog([]), schema_version: "slack-action-catalog/v2" as never }),
    /version is unsupported/,
  );
  assert.throws(
    () => createSlackActionRegistry(catalog([
      { ...actionContract(), retry_policy: "none" as never },
    ])),
    /idempotent retry policy/,
  );
  assert.throws(
    () => createSlackActionRegistry(catalog([
      actionContract({ parameters: [
        { name: "target", required: true },
        { name: "target", required: false },
      ] }),
    ])),
    /duplicate parameter/,
  );
  assert.throws(
    () => createSlackActionRegistry({ ...catalog([]), unexpected: true } as never),
    SlackActionContractError,
  );
});

function catalog(actions: SlackActionCatalogV1["actions"]): SlackActionCatalogV1 {
  return {
    actions,
    catalog_id: "cerebro.slack.actions",
    revision: 1,
    schema_version: "slack-action-catalog/v1",
  };
}

function actionContract(input: {
  action_id?: string;
  parameters?: Array<{ name: string; required: boolean }>;
  capabilities?: Array<ReturnType<typeof capability>>;
} = {}): SlackActionCatalogV1["actions"][number] {
  return {
    action_id: input.action_id ?? "memory.remember",
    command: "remember",
    parameters: input.parameters ?? [{ name: "target", required: true }],
    required_capabilities: input.capabilities ?? [capability("memory.write")],
    retry_policy: "idempotent",
    schema_version: "slack-action-contract/v1",
    subject_requirement: "required",
  };
}

function capability(
  capabilityId: string,
  version = "v1",
  level: "optional" | "required" = "required",
) {
  return { capability_id: capabilityId, level, version };
}

function envelope(
  overrides: Partial<SlackActionEnvelopeV1> = {},
): SlackActionEnvelopeV1 {
  const base: SlackActionEnvelopeV1 = {
    action: "memory.remember",
    command: "remember",
    idempotency_key: "request-123",
    issued_at: issuedAt,
    parameters: { target: "team" },
    schema_version: "slack-action-envelope/v1",
    subject_ref: "slack-command://request-123",
  };
  const result = { ...base, ...overrides };
  if (overrides.parameters === undefined && "parameters" in overrides) {
    delete (result as { parameters?: Readonly<Record<string, string>> }).parameters;
  }
  if (overrides.subject_ref === undefined && "subject_ref" in overrides) {
    delete (result as { subject_ref?: string }).subject_ref;
  }
  return result;
}

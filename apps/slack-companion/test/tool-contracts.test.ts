import assert from "node:assert/strict";
import test from "node:test";

import {
  assertToolAuthorityDecision,
  assertToolInvocationAuthority,
  assertToolInvocationReceipt,
  createToolCatalog,
  TOOL_AUTHORITY_DECISION_SCHEMA_VERSION,
  TOOL_CATALOG_ENTRY_SCHEMA_VERSION,
  TOOL_INVOCATION_RECEIPT_SCHEMA_VERSION,
  TOOL_INVOCATION_RESULT_SCHEMA_VERSION,
  type ToolAuthorityDecisionV1,
  type ToolCatalogEntryV1,
  type ToolInvocationReceiptV1,
} from "../src/index.js";

const requestDigest = `sha256:${"a".repeat(64)}`;
const outputDigest = `sha256:${"b".repeat(64)}`;

test("catalog resolves exact versions and snapshots deterministic metadata", () => {
  const capabilities = ["cerebro:write", "cerebro:read"];
  const catalog = createToolCatalog([
    catalogEntry({
      tool_id: "findings.update",
      tool_version: "2.0.0",
      required_capabilities: capabilities,
    }),
    catalogEntry({ tool_id: "findings.read", tool_version: "1.0.0" }),
  ]);
  capabilities.push("changed:later");

  assert.deepEqual(
    catalog.list().map((entry) => `${entry.tool_id}@${entry.tool_version}`),
    ["findings.read@1.0.0", "findings.update@2.0.0"],
  );
  assert.deepEqual(
    catalog.resolve("findings.update", "2.0.0")?.required_capabilities,
    ["cerebro:read", "cerebro:write"],
  );
  assert.equal(catalog.resolve("findings.update", "1.0.0"), undefined);
  assert.equal(Object.isFrozen(catalog.list()), true);
  assert.equal(Object.isFrozen(catalog.list()[0]), true);
  assert.equal(
    Object.isFrozen(catalog.list()[0]?.required_capabilities),
    true,
  );
});

test("catalog rejects ambiguous coordinates and unsafe replay declarations", () => {
  const duplicate = catalogEntry();
  assert.throws(
    () => createToolCatalog([duplicate, { ...duplicate }]),
    /registered more than once/,
  );
  assert.throws(
    () =>
      createToolCatalog([
        catalogEntry({ tool_id: "Invalid Tool" }),
      ]),
    /tool id is malformed/,
  );
  assert.throws(
    () =>
      createToolCatalog([
        catalogEntry({
          effect_class: "external_effect",
          replay_policy: "safe",
        }),
      ]),
    /reconcile before retry/,
  );
  assert.throws(
    () =>
      createToolCatalog([
        catalogEntry({
          authority_class: "actuate",
          effect_class: "read",
        }),
      ]),
    /read tools cannot use actuate authority/,
  );
});

test("allowed authority binds the exact fenced invocation receipt", () => {
  const decision = authorityDecision();
  const receipt = invocationReceipt();

  assert.doesNotThrow(() => assertToolInvocationAuthority(decision, receipt));
  assert.throws(
    () =>
      assertToolInvocationAuthority(
        { ...decision, outcome: "denied" },
        receipt,
      ),
    /requires allowed authority/,
  );
  assert.throws(
    () =>
      assertToolInvocationAuthority(
        decision,
        { ...receipt, request_digest: `sha256:${"c".repeat(64)}` },
      ),
    /does not match invocation receipt/,
  );
  assert.throws(
    () =>
      assertToolInvocationAuthority(
        { ...decision, expires_at: "2026-07-18T10:00:01.000Z" },
        receipt,
      ),
    /expired before invocation/,
  );
});

test("receipt states require coherent timestamps and normalized results", () => {
  assert.doesNotThrow(() =>
    assertToolInvocationReceipt(
      invocationReceipt({
        state: "executing",
        completed_at: undefined,
        recorded_at: "2026-07-18T10:00:02.000Z",
        result: undefined,
      }),
    ),
  );
  assert.doesNotThrow(() =>
    assertToolInvocationReceipt(
      invocationReceipt({
        state: "failed",
        result: {
          schema_version: TOOL_INVOCATION_RESULT_SCHEMA_VERSION,
          invocation_id: "invocation-1",
          outcome: "failed",
          summary: "The tool did not complete.",
          error_code: "dependency_unavailable",
          retryable: true,
          recorded_at: "2026-07-18T10:00:03.000Z",
        },
      }),
    ),
  );
  assert.doesNotThrow(() =>
    assertToolInvocationReceipt(
      invocationReceipt({
        state: "unknown",
        completed_at: undefined,
        result: {
          schema_version: TOOL_INVOCATION_RESULT_SCHEMA_VERSION,
          invocation_id: "invocation-1",
          outcome: "unknown",
          summary: "The external outcome needs reconciliation.",
          uncertainty_code: "completion_not_recorded",
          recorded_at: "2026-07-18T10:00:03.000Z",
        },
      }),
    ),
  );

  assert.throws(
    () =>
      assertToolInvocationReceipt(
        invocationReceipt({ state: "succeeded", result: undefined }),
      ),
    /terminal receipt requires a start and result/,
  );
  assert.throws(
    () =>
      assertToolInvocationReceipt(
        invocationReceipt({
          state: "unknown",
          result: {
            schema_version: TOOL_INVOCATION_RESULT_SCHEMA_VERSION,
            invocation_id: "invocation-1",
            outcome: "unknown",
            summary: "The external outcome needs reconciliation.",
            uncertainty_code: "completion_not_recorded",
            recorded_at: "2026-07-18T10:00:03.000Z",
          },
        }),
      ),
    /unknown tool outcome cannot be completed/,
  );
});

test("contract validators reject arbitrary integration payload fields", () => {
  const decision = {
    ...authorityDecision(),
    raw_response: { status: "allowed" },
  } as ToolAuthorityDecisionV1;
  const receipt = {
    ...invocationReceipt(),
    provider_payload: { result: "not portable" },
  } as ToolInvocationReceiptV1;

  assert.throws(
    () => assertToolAuthorityDecision(decision),
    /contains an unsupported field/,
  );
  assert.throws(
    () => assertToolInvocationReceipt(receipt),
    /contains an unsupported field/,
  );
});

function catalogEntry(
  overrides: Partial<ToolCatalogEntryV1> = {},
): ToolCatalogEntryV1 {
  return {
    schema_version: TOOL_CATALOG_ENTRY_SCHEMA_VERSION,
    tool_id: "findings.read",
    tool_version: "1.0.0",
    title: "Read findings",
    summary: "Read normalized finding records.",
    input_schema_ref: "schemas/tools/findings-read-input/v1",
    result_schema_ref: "schemas/tools/findings-read-result/v1",
    effect_class: "read",
    authority_class: "observe",
    replay_policy: "safe",
    required_capabilities: ["cerebro:read"],
    ...overrides,
  };
}

function authorityDecision(
  overrides: Partial<ToolAuthorityDecisionV1> = {},
): ToolAuthorityDecisionV1 {
  return {
    schema_version: TOOL_AUTHORITY_DECISION_SCHEMA_VERSION,
    decision_id: "decision-1",
    invocation_id: "invocation-1",
    run_id: "run-1",
    step_id: "step-1",
    subject_ref: "subject-1",
    tool_id: "findings.read",
    tool_version: "1.0.0",
    request_digest: requestDigest,
    outcome: "allowed",
    authority_ref: "authority-1",
    reason_code: "capability_granted",
    decided_at: "2026-07-18T10:00:00.000Z",
    expires_at: "2026-07-18T10:05:00.000Z",
    ...overrides,
  };
}

function invocationReceipt(
  overrides: Partial<ToolInvocationReceiptV1> = {},
): ToolInvocationReceiptV1 {
  return {
    schema_version: TOOL_INVOCATION_RECEIPT_SCHEMA_VERSION,
    receipt_id: "receipt-1",
    invocation_id: "invocation-1",
    idempotency_key: "tool-invocation-1",
    run_id: "run-1",
    step_id: "step-1",
    tool_id: "findings.read",
    tool_version: "1.0.0",
    request_digest: requestDigest,
    authority_decision_id: "decision-1",
    generation: 4,
    fencing_token: 9,
    lease_token: "lease-1",
    sequence: 3,
    state: "succeeded",
    authorized_at: "2026-07-18T10:00:01.000Z",
    started_at: "2026-07-18T10:00:02.000Z",
    completed_at: "2026-07-18T10:00:03.000Z",
    recorded_at: "2026-07-18T10:00:03.000Z",
    result: {
      schema_version: TOOL_INVOCATION_RESULT_SCHEMA_VERSION,
      invocation_id: "invocation-1",
      outcome: "succeeded",
      summary: "Finding records are ready.",
      output_ref: "result-1",
      output_digest: outputDigest,
      recorded_at: "2026-07-18T10:00:03.000Z",
    },
    ...overrides,
  };
}

/** Stable identity for the repository-native, Slack-independent agent harness. */
export const CEREBRO_AGENT_GYM = Object.freeze({
  artifact_namespace: "cerebro-agent-gym",
  schema_version: "cerebro-agent-gym/v1",
});

export * from "./contract-error.js";
export * from "./canonical-json.js";
export * from "./corpus-manifest.js";
export * from "./corpus-inventory.js";
export * from "./corpus-build.js";
export * from "./corpus-leakage.js";
export * from "./corpus-coverage.js";
export * from "./corpus-admission.js";
export * from "./corpus-quality.js";
export * from "./fixture-case.js";
export * from "./model-runtime.js";
export * from "./model-budget.js";
export * from "./model-batch.js";
export * from "./model-failure.js";
export * from "./model-retry.js";
export * from "./model-invocation.js";
export * from "./model-ledger.js";
export * from "./recorded-model.js";
export * from "./artifact.js";
export * from "./candidate-manifest.js";
export * from "./cli.js";
export * from "./comparison.js";
export * from "./promotion-decision.js";
export * from "./replay-run.js";
export * from "./run-summary.js";
export * from "./scorecard.js";
export * from "./slack-simulator.js";
export * from "./tool-fixtures.js";
export * from "./tool-fixture-runtime.js";
export * from "./slack-delivery.js";
export * from "./slack-failure.js";
export * from "./slack-effects.js";
export * from "./slack-effect-runtime.js";
export * from "./slack-effect-snapshot.js";

/** Stable identity for the repository-native, Slack-independent agent harness. */
export const CEREBRO_AGENT_GYM = Object.freeze({
  artifact_namespace: "cerebro-agent-gym",
  schema_version: "cerebro-agent-gym/v1",
});

export class AgentGymContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentGymContractError";
  }
}

export * from "./fixture-case.js";
export * from "./artifact.js";
export * from "./candidate-manifest.js";
export * from "./cli.js";
export * from "./comparison.js";
export * from "./promotion-decision.js";
export * from "./replay-run.js";
export * from "./run-summary.js";
export * from "./scorecard.js";
export * from "./slack-simulator.js";
export * from "./slack-delivery.js";
export * from "./slack-failure.js";
export * from "./slack-effects.js";

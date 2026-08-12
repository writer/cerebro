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

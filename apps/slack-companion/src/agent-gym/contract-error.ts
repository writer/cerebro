export class AgentGymContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AgentGymContractError";
  }
}

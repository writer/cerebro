import type {
  ComputerSandboxActionResultV1,
  ComputerSandboxActionV1,
  ComputerSandboxProviderV1,
  ComputerSandboxSessionCreateResult,
  ComputerSandboxSessionRequestV1,
  ComputerSandboxSessionV1,
} from "./contracts.js";

/**
 * One host-owned provider adapter. It must honor request and action
 * idempotency keys, never return provider credentials, and return `unknown`
 * when it cannot prove whether an external effect occurred.
 */
export interface ComputerSandboxProviderPort {
  readonly provider_id: string;

  createSession(
    request: ComputerSandboxSessionRequestV1,
  ): Promise<ComputerSandboxSessionCreateResult>;

  describe(): Promise<ComputerSandboxProviderV1>;

  executeAction(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
  ): Promise<ComputerSandboxActionResultV1>;

  reconcileAction(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxActionResultV1>;

  reconcileSession(
    request: ComputerSandboxSessionRequestV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxSessionCreateResult>;
}

export interface ComputerSandboxProviderRegistry {
  list(): readonly ComputerSandboxProviderPort[];
  resolve(providerId: string): ComputerSandboxProviderPort | undefined;
}

import {
  ComputerSandboxCoordinator,
  createComputerSandboxProviderRegistry,
  type ComputerSandboxActionResultV1,
  type ComputerSandboxActionV1,
  type ComputerSandboxProviderPort,
  type ComputerSandboxProviderV1,
  type ComputerSandboxSessionCreateResult,
  type ComputerSandboxSessionRequestV1,
  type ComputerSandboxSessionV1,
} from "@writer/cerebro-slack-companion";

export interface ComputerSandboxGatewayBinding {
  baseUrl: string;
  providerId: string;
  timeoutMs: number;
  token: string;
}

export interface ComputerSandboxGatewayOptions
  extends ComputerSandboxGatewayBinding {
  fetchImpl?: typeof fetch;
}

export class ComputerSandboxGatewayProvider
  implements ComputerSandboxProviderPort {
  readonly provider_id: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly token: string;

  constructor(options: ComputerSandboxGatewayOptions) {
    this.provider_id = options.providerId;
    this.baseUrl = options.baseUrl.replace(/\/$/u, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs;
    this.token = options.token;
  }

  describe(): Promise<ComputerSandboxProviderV1> {
    return this.request("GET", "/v1/computer-sandbox/provider");
  }

  createSession(
    request: ComputerSandboxSessionRequestV1,
  ): Promise<ComputerSandboxSessionCreateResult> {
    return this.request("POST", "/v1/computer-sandbox/sessions", { request });
  }

  reconcileSession(
    request: ComputerSandboxSessionRequestV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxSessionCreateResult> {
    return this.request("POST", "/v1/computer-sandbox/sessions/reconcile", {
      reconciliation_ref: reconciliationRef,
      request,
    });
  }

  executeAction(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
  ): Promise<ComputerSandboxActionResultV1> {
    return this.request("POST", "/v1/computer-sandbox/actions", {
      action,
      session,
    });
  }

  reconcileAction(
    session: ComputerSandboxSessionV1,
    action: ComputerSandboxActionV1,
    reconciliationRef: string,
  ): Promise<ComputerSandboxActionResultV1> {
    return this.request("POST", "/v1/computer-sandbox/actions/reconcile", {
      action,
      reconciliation_ref: reconciliationRef,
      session,
    });
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: Record<string, unknown>,
  ): Promise<T> {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: {
        accept: "application/json",
        authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      method,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`Computer sandbox gateway returned HTTP ${response.status}.`);
    }
    const text = await readBoundedResponse(response, 1_048_576);
    const parsed: unknown = JSON.parse(text);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Computer sandbox gateway response is invalid.");
    }
    return parsed as T;
  }
}

async function readBoundedResponse(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader !== null) {
    const contentLength = Number(contentLengthHeader);
    if (
      !Number.isSafeInteger(contentLength)
      || contentLength < 0
      || contentLength > maxBytes
    ) {
      throw new Error("Computer sandbox gateway response is too large.");
    }
  }
  if (response.body === null) {
    throw new Error("Computer sandbox gateway response is invalid.");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error("Computer sandbox gateway response is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new Error("Computer sandbox gateway response is invalid.");
  }
}

export function createComputerSandboxRuntime(
  bindings: readonly ComputerSandboxGatewayBinding[],
  options: {
    clock?: { now(): Date };
    fetchImpl?: typeof fetch;
  } = {},
): ComputerSandboxCoordinator | undefined {
  if (bindings.length === 0) return undefined;
  const providers = bindings.map((binding) =>
    new ComputerSandboxGatewayProvider({
      ...binding,
      fetchImpl: options.fetchImpl,
    })
  );
  return new ComputerSandboxCoordinator({
    clock: options.clock ?? { now: () => new Date() },
    registry: createComputerSandboxProviderRegistry(providers),
  });
}

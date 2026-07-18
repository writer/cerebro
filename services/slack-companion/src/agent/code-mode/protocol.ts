export interface SandboxLimits {
  memoryLimitBytes: number;
  maxOutputBytes: number;
  timeoutMs: number;
}

export interface SandboxExecuteMessage {
  type: "execute";
  requestId: string;
  script: string;
  toolNames: string[];
  limits: SandboxLimits;
}

export interface SandboxToolResultMessage {
  type: "tool_result";
  requestId: string;
  callId: string;
  ok: boolean;
  payloadJson?: string;
  error?: string;
}

export interface SandboxToolCallMessage {
  type: "tool_call";
  requestId: string;
  callId: string;
  name: string;
  argumentsJson: string;
}

export interface SandboxResultMessage {
  type: "result";
  requestId: string;
  ok: boolean;
  resultJson?: string;
  errorCode?: string;
  error?: string;
}

export type ParentToSandboxMessage = SandboxExecuteMessage | SandboxToolResultMessage;
export type SandboxToParentMessage = SandboxToolCallMessage | SandboxResultMessage;

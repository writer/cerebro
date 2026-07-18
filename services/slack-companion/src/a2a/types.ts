export type A2AInstanceState = "active" | "draining" | "stopped";
export type A2AMessageKind = "task" | "handoff" | "status";

export interface A2AInstance {
  instanceId: string;
  label: string;
  role: string;
  commit: string;
  commitSubject?: string;
  capabilities: string[];
  state: A2AInstanceState;
  startedAt: string;
  heartbeatAt: string;
  expiresAt: number;
}

export interface A2APart {
  kind: "text" | "data";
  text?: string;
  data?: Record<string, unknown>;
}

export interface A2AMessage {
  messageId: string;
  contextId: string;
  taskId?: string;
  kind: A2AMessageKind;
  from: string;
  to: string;
  parts: A2APart[];
  createdAt: string;
  expiresAt: number;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  processedAt?: string;
}

export interface A2AAgentCard {
  protocolVersion: "0.3.0";
  name: string;
  description: string;
  version: string;
  capabilities: {
    streaming: false;
    pushNotifications: false;
    stateTransitionHistory: true;
  };
  skills: Array<{
    id: string;
    name: string;
    description: string;
    tags: string[];
  }>;
}

export interface A2AShutdownResult {
  state: "disabled" | "no_peer" | "acknowledged" | "timed_out";
  peerId?: string;
  messageId?: string;
  goalIds: string[];
  workPacketIds: string[];
}

export interface A2AWorkHandoff {
  packet_id: string;
  coordinator_id: string;
  context_id: string;
  task_id: string;
  request: Record<string, unknown>;
}

export type A2AMessageHandler = (message: A2AMessage) => Promise<A2APart[] | void>;

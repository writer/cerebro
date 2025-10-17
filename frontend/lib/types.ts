export type ReviewTaskStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "promoted"
  | "escalated";

export type ReviewTask = {
  id: string;
  session_id: string;
  org_id: string;
  status: ReviewTaskStatus;
  title: string;
  summary?: string | null;
  payload: Record<string, unknown>;
  promotion_target?: string | null;
  priority?: string | null;
  due_at?: string | null;
  escalated_to?: string | null;
  notification_channel?: string | null;
  ticket_reference?: string | null;
  created_by: string;
  created_at: string;
  resolved_by?: string | null;
  resolved_at?: string | null;
  resolution_notes?: string | null;
};

export type ReviewNotification = {
  id: string;
  task_id: string;
  org_id: string;
  channel: string;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
  delivered_at?: string | null;
};

export type RuntimeEvent = {
  id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type PolicySuggestion = {
  id: string;
  tool_name: string;
  cel_expression: string;
  support_count: number;
  reject_count: number;
  confidence: number;
  metadata: Record<string, unknown>;
  last_seen: string;
};

export type AgentMessage = {
  message_id: string;
  role: string;
  content: string;
  timestamp: string;
  metadata?: Record<string, unknown> | null;
};

export type SessionSummary = {
  session: {
    session_id: string;
    org_id: string;
    agent_type: string;
    title?: string | null;
    created_at: string;
    created_by: string;
    status: string;
    context: Record<string, unknown>;
  };
  messages: AgentMessage[];
  message_count: number;
};

export type MemoryEntry = {
  id: string;
  role?: string | null;
  summary?: string | null;
  decay_score: number;
  last_accessed_at: string;
  created_at: string;
  scopes: Array<Record<string, unknown>>;
  scope_labels: string[];
  metadata: Record<string, unknown>;
  token_count: number;
  content?: string | null;
  embedding_similarity?: number | null;
  lexical_similarity?: number | null;
  combined_similarity?: number | null;
  ann_selected?: boolean | null;
};

export type MemoryStats = {
  total_entries: number;
  recent_entries: number;
  presented_entries: number;
  average_decay: number;
  token_total: number;
  role_distribution: Record<string, number>;
  scope_distribution: Record<string, number>;
  top_memories: Array<{
    id: string;
    summary?: string | null;
    decay_score: number;
    last_accessed_at: string;
    role?: string | null;
    scope_labels: string[];
  }>;
};

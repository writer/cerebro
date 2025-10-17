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

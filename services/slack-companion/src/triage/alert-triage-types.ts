export type TriageClassification = "likely_security_issue" | "needs_context" | "likely_noise";
export type TriageSeverity = "critical" | "high" | "medium" | "low" | "info";
export type TriageTopic = "security_alert" | "assistant_follow_up" | "operational_update" | "other";

export interface AlertTriageInput {
  channelId: string;
  userId?: string;
  text: string;
  ts: string;
  threadTs?: string;
}

export interface AlertTriageResult {
  topic?: TriageTopic;
  classification: TriageClassification;
  severity?: TriageSeverity;
  confidence: number;
  shouldRespond: boolean;
  responseReason?: string;
  summary: string;
  evidence: string[];
  actionsTaken: string[];
  recommendedActions: string[];
  research: string[];
  source: "pi" | "cerebro_fallback";
}

export interface SlackMessageForTriage {
  channel?: string;
  text?: string;
  subtype?: string;
  bot_id?: string;
  user?: string;
  ts?: string;
  thread_ts?: string;
}

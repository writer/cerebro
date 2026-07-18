import type { AlertTriageResult } from "./alert-triage-types.js";

export function triageResultTelemetry(result: AlertTriageResult): Record<string, unknown> {
  return {
    "triage.topic": result.topic ?? "",
    "triage.classification": result.classification,
    "triage.severity": result.severity ?? "",
    "triage.confidence": result.confidence,
    "triage.should_respond": result.shouldRespond,
    "triage.source": result.source,
    "triage.evidence.count": result.evidence.length,
    "triage.action.count": result.actionsTaken.length,
    "triage.recommended_action.count": result.recommendedActions.length,
    "triage.research.count": result.research.length,
  };
}

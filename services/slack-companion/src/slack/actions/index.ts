import { registerAutonomyActions } from "./autonomy.js";
import { registerFindingActions } from "./findings.js";
import { registerGraphActions } from "./graph.js";
import { registerHomeActions } from "./home.js";
import { registerMonitorSuggestionActions } from "./monitor-suggestions.js";
import { registerProactiveSuggestionActions } from "./proactive-suggestions.js";
import { registerRuntimeActions } from "./runtime.js";
import { registerAssistantFeedbackActions } from "./assistant-feedback.js";
import { registerRiskAttestationActions } from "./risk-attestation.js";
import type { ActionDeps } from "./types.js";

export type { ActionDeps } from "./types.js";

export function registerActionHandlers(app: any, deps: ActionDeps): void {
  registerHomeActions(app, deps);
  registerFindingActions(app, deps);
  registerGraphActions(app, deps);
  registerRuntimeActions(app, deps);
  registerAutonomyActions(app, deps);
  registerProactiveSuggestionActions(app, deps);
  registerMonitorSuggestionActions(app, deps);
  registerAssistantFeedbackActions(app, deps);
  registerRiskAttestationActions(app, deps);
}

import type { AutonomyGoalServiceStats } from "./goal-service.js";
import { recordGauge } from "../telemetry.js";

export function recordAutonomyRunnerGauges(stats: AutonomyGoalServiceStats): void {
  recordGauge("cerebro_slack_companion_autonomy_goals", { status: "active" }, stats.active);
  recordGauge("cerebro_slack_companion_autonomy_goals", { status: "waiting" }, stats.waiting);
  recordGauge("cerebro_slack_companion_autonomy_goals", { status: "approval_needed" }, stats.approvalNeeded);
  recordGauge("cerebro_slack_companion_autonomy_goals", { status: "blocked" }, stats.blocked);
  recordGauge("cerebro_slack_companion_autonomy_due_count", {}, stats.dueCount);
  recordGauge("cerebro_slack_companion_autonomy_oldest_due_age_seconds", {}, stats.oldestDueAgeMs / 1000);
  recordGauge("cerebro_slack_companion_autonomy_claimed", {}, stats.claimed);
  recordGauge("cerebro_slack_companion_autonomy_stale_claims", {}, stats.staleClaims);
}

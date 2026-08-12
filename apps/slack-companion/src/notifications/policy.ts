export type SlackNotificationClassV1 = "alert" | "digest" | "followup";
export type SlackNotificationSeverityV1 = "critical" | "high" | "medium" | "low";

export interface SlackNotificationPreferencesV1 {
  readonly digest_hour: number;
  readonly enabled_classes: readonly SlackNotificationClassV1[];
  readonly minimum_severity: SlackNotificationSeverityV1;
  readonly quiet_hours_end: number;
  readonly quiet_hours_start: number;
  readonly schema_version: "slack-notification-preferences/v1";
  readonly timezone: string;
}

export interface SlackNotificationCandidateV1 {
  readonly class: SlackNotificationClassV1;
  readonly observed_at: string;
  readonly severity: SlackNotificationSeverityV1;
}

export type SlackNotificationDecisionV1 =
  | { readonly disposition: "deliver"; readonly schema_version: "slack-notification-decision/v1" }
  | { readonly disposition: "digest" | "suppress"; readonly reason: string; readonly schema_version: "slack-notification-decision/v1" };

export class SlackNotificationPolicyError extends Error {}

export function planSlackNotification(
  preferences: SlackNotificationPreferencesV1,
  candidate: SlackNotificationCandidateV1,
): SlackNotificationDecisionV1 {
  validatePreferences(preferences);
  if (!["alert", "digest", "followup"].includes(candidate.class)) {
    throw new SlackNotificationPolicyError("Notification class is invalid.");
  }
  rank(candidate.severity);
  if (!preferences.enabled_classes.includes(candidate.class)) {
    return Object.freeze({ disposition: "suppress", reason: "This notification class is disabled.", schema_version: "slack-notification-decision/v1" });
  }
  if (rank(candidate.severity) < rank(preferences.minimum_severity)) {
    return Object.freeze({ disposition: "suppress", reason: "This notification is below the configured severity.", schema_version: "slack-notification-decision/v1" });
  }
  const instant = new Date(candidate.observed_at);
  if (!Number.isFinite(instant.getTime()) || instant.toISOString() !== candidate.observed_at) {
    throw new SlackNotificationPolicyError("observed_at is invalid.");
  }
  let hour: number;
  try {
    const part = new Intl.DateTimeFormat("en-US", { hour: "2-digit", hourCycle: "h23", timeZone: preferences.timezone }).formatToParts(instant).find((item) => item.type === "hour");
    hour = Number(part?.value);
  } catch {
    throw new SlackNotificationPolicyError("timezone is invalid.");
  }
  const quiet = preferences.quiet_hours_start === preferences.quiet_hours_end
    ? false
    : preferences.quiet_hours_start < preferences.quiet_hours_end
      ? hour >= preferences.quiet_hours_start && hour < preferences.quiet_hours_end
      : hour >= preferences.quiet_hours_start || hour < preferences.quiet_hours_end;
  if (quiet && candidate.severity !== "critical") {
    return Object.freeze({ disposition: "digest", reason: `Quiet hours end at ${String(preferences.quiet_hours_end).padStart(2, "0")}:00.`, schema_version: "slack-notification-decision/v1" });
  }
  return Object.freeze({ disposition: "deliver", schema_version: "slack-notification-decision/v1" });
}

function validatePreferences(value: SlackNotificationPreferencesV1): void {
  if (value.schema_version !== "slack-notification-preferences/v1"
    || !Number.isInteger(value.digest_hour) || value.digest_hour < 0 || value.digest_hour > 23
    || !Number.isInteger(value.quiet_hours_start) || value.quiet_hours_start < 0 || value.quiet_hours_start > 23
    || !Number.isInteger(value.quiet_hours_end) || value.quiet_hours_end < 0 || value.quiet_hours_end > 23
    || !Array.isArray(value.enabled_classes) || new Set(value.enabled_classes).size !== value.enabled_classes.length
    || value.enabled_classes.some((item) => !["alert", "digest", "followup"].includes(item))) {
    throw new SlackNotificationPolicyError("Notification preferences are invalid.");
  }
  rank(value.minimum_severity);
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value.timezone }).format(0);
  } catch {
    throw new SlackNotificationPolicyError("timezone is invalid.");
  }
}

function rank(value: SlackNotificationSeverityV1): number {
  const index = ["low", "medium", "high", "critical"].indexOf(value);
  if (index < 0) throw new SlackNotificationPolicyError("Notification severity is invalid.");
  return index;
}

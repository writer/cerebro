export type ReportDefinitionParameter = {
  id: string;
  description?: string;
  required?: boolean;
};

export type ReportDefinition = {
  id: string;
  name: string;
  description?: string;
  parameters?: ReportDefinitionParameter[];
};

export type ReportDefinitionsResponse = {
  reports: ReportDefinition[];
};

export type ReportSchedule = {
  id: string;
  tenant_id: string;
  report_id: string;
  parameters: Record<string, string>;
  interval_seconds: number;
  enabled: boolean;
  next_run_at: string;
  last_run_at?: string;
  created_at: string;
  updated_at: string;
};

export type ReportScheduleListResponse = { schedules: ReportSchedule[] };
export type ReportScheduleResponse = { schedule: ReportSchedule };

export type ReportRun = {
  id: string;
  report_id: string;
  status?: string;
  generated_at?: string;
  parameters?: Record<string, string>;
};

export type ReportRunListResponse = { runs: ReportRun[] };

export type IntervalUnit = "minutes" | "hours" | "days";

export const INTERVAL_UNITS: { value: IntervalUnit; label: string; seconds: number }[] = [
  { value: "minutes", label: "Minutes", seconds: 60 },
  { value: "hours", label: "Hours", seconds: 3600 },
  { value: "days", label: "Days", seconds: 86400 },
];

export const REPORT_SCHEDULE_MIN_INTERVAL_SECONDS = 60;
export const REPORT_SCHEDULE_MAX_INTERVAL_SECONDS = 31 * 24 * 60 * 60;

export const TENANT_PARAMETER_ID = "tenant_id";

export const intervalToSeconds = (value: number, unit: IntervalUnit): number => {
  const unitSeconds = INTERVAL_UNITS.find((option) => option.value === unit)?.seconds ?? 60;
  return Math.round(value * unitSeconds);
};

export const describeInterval = (seconds: number): string => {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "—";
  }
  for (const [unitSeconds, label] of [
    [86400, "day"],
    [3600, "hour"],
    [60, "minute"],
  ] as const) {
    if (seconds % unitSeconds === 0) {
      const count = seconds / unitSeconds;
      return `Every ${count} ${label}${count === 1 ? "" : "s"}`;
    }
  }
  const minutes = Math.max(1, Math.round(seconds / 60));
  return `Every ${minutes} minutes`;
};

// scheduleParameterFields returns the parameters an operator supplies for a
// report schedule, excluding the tenant which the server injects from the caller.
export const scheduleParameterFields = (
  definition: ReportDefinition | undefined,
): ReportDefinitionParameter[] =>
  (definition?.parameters ?? []).filter((parameter) => parameter.id !== TENANT_PARAMETER_ID);

export const sanitizeScheduleParameters = (
  parameters: Record<string, string>,
): Record<string, string> => {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(parameters)) {
    const trimmedKey = key.trim();
    const trimmedValue = (value ?? "").trim();
    if (trimmedKey === "" || trimmedValue === "") {
      continue;
    }
    sanitized[trimmedKey] = trimmedValue;
  }
  return sanitized;
};

export const missingRequiredParameters = (
  definition: ReportDefinition | undefined,
  parameters: Record<string, string>,
): string[] =>
  scheduleParameterFields(definition)
    .filter((parameter) => parameter.required)
    .filter((parameter) => (parameters[parameter.id] ?? "").trim() === "")
    .map((parameter) => parameter.id);

export const reportNameForID = (
  definitions: ReportDefinition[] | undefined,
  reportID: string,
): string => definitions?.find((definition) => definition.id === reportID)?.name ?? reportID;

export type ReportRunIntent = "success" | "danger" | "warning" | "info";

export const reportRunIntent = (status: string | undefined): ReportRunIntent => {
  switch ((status ?? "").toLowerCase()) {
    case "completed":
    case "succeeded":
    case "success":
      return "success";
    case "failed":
    case "error":
      return "danger";
    case "running":
    case "queued":
    case "pending":
      return "info";
    default:
      return "warning";
  }
};

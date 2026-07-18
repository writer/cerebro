export type ReleaseStatus = "deploying" | "verified" | "failed" | "rolled_back" | "superseded";
export type ReleaseCheckStatus = "pending" | "passed" | "failed";

export interface ReleaseCheck {
  status: ReleaseCheckStatus;
  detail?: string;
}

export interface ReleaseReceipt {
  schemaVersion: 1;
  recordType: "companion_release_receipt";
  version: string;
  previousVersion?: string;
  commitSha: string;
  commitSubject?: string;
  deployMode: "ecs" | "pulumi";
  deployReason: string;
  components: string[];
  changedFileCount: number;
  status: ReleaseStatus;
  statusDetail?: string;
  failedChecks: string[];
  checks: {
    slack: ReleaseCheck;
    image: ReleaseCheck;
    runtime: ReleaseCheck;
    cerebro: ReleaseCheck;
  };
  commitUrl?: string;
  pullRequestUrl?: string;
  deployRunUrl?: string;
  startedAt: string;
  updatedAt: string;
  completedAt?: string;
  runningVersion?: string;
  threadTsByChannel: Record<string, string>;
  notificationClaims: Record<string, number>;
  notifications: Record<string, string>;
}

export interface ReleasePointer {
  version: string;
  updatedAt: string;
}

export function releaseReceiptFromItem(value: unknown): ReleaseReceipt | undefined {
  if (!isRecord(value)) return undefined;
  if (value.schemaVersion !== 1 || value.recordType !== "companion_release_receipt") return undefined;
  if (!isBoundedString(value.version, 80) || !isBoundedString(value.commitSha, 64)) return undefined;
  if (value.deployMode !== "ecs" && value.deployMode !== "pulumi") return undefined;
  if (!isBoundedString(value.deployReason, 120) || !isReleaseStatus(value.status)) return undefined;
  if (!isIsoDate(value.startedAt) || !isIsoDate(value.updatedAt)) return undefined;
  if (!Number.isInteger(value.changedFileCount) || Number(value.changedFileCount) < 0) return undefined;
  if (!isStringArray(value.components, 12, 80) || !isStringArray(value.failedChecks, 8, 80)) return undefined;

  const checks = releaseChecksFrom(value.checks);
  const threadTsByChannel = stringRecordFrom(value.threadTsByChannel, 100, 80);
  const notificationClaims = numberRecordFrom(value.notificationClaims, 300);
  const notifications = stringRecordFrom(value.notifications, 300, 64);
  if (!checks || !threadTsByChannel || !notificationClaims || !notifications) return undefined;

  const optionalStrings: Array<[unknown, number]> = [
    [value.previousVersion, 80],
    [value.commitSubject, 200],
    [value.statusDetail, 500],
    [value.runningVersion, 80],
    [value.completedAt, 40],
  ];
  if (optionalStrings.some(([candidate, max]) => candidate !== undefined && !isBoundedString(candidate, max))) return undefined;

  const urls = [value.commitUrl, value.pullRequestUrl, value.deployRunUrl];
  if (urls.some((candidate) => candidate !== undefined && !isSafeGithubUrl(candidate))) return undefined;

  return {
    schemaVersion: 1,
    recordType: "companion_release_receipt",
    version: value.version,
    previousVersion: optionalString(value.previousVersion),
    commitSha: value.commitSha,
    commitSubject: optionalString(value.commitSubject),
    deployMode: value.deployMode,
    deployReason: value.deployReason,
    components: [...value.components],
    changedFileCount: Number(value.changedFileCount),
    status: value.status,
    statusDetail: optionalString(value.statusDetail),
    failedChecks: [...value.failedChecks],
    checks,
    commitUrl: optionalString(value.commitUrl),
    pullRequestUrl: optionalString(value.pullRequestUrl),
    deployRunUrl: optionalString(value.deployRunUrl),
    startedAt: value.startedAt,
    updatedAt: value.updatedAt,
    completedAt: optionalString(value.completedAt),
    runningVersion: optionalString(value.runningVersion),
    threadTsByChannel,
    notificationClaims,
    notifications,
  };
}

export function releasePointerFromItem(value: unknown): ReleasePointer | undefined {
  if (!isRecord(value) || !isBoundedString(value.version, 80) || !isIsoDate(value.updatedAt)) return undefined;
  return { version: value.version, updatedAt: value.updatedAt };
}

function releaseChecksFrom(value: unknown): ReleaseReceipt["checks"] | undefined {
  if (!isRecord(value)) return undefined;
  const slack = releaseCheckFrom(value.slack);
  const image = releaseCheckFrom(value.image);
  const runtime = releaseCheckFrom(value.runtime);
  const cerebro = releaseCheckFrom(value.cerebro);
  return slack && image && runtime && cerebro ? { slack, image, runtime, cerebro } : undefined;
}

function releaseCheckFrom(value: unknown): ReleaseCheck | undefined {
  if (!isRecord(value) || !isReleaseCheckStatus(value.status)) return undefined;
  if (value.detail !== undefined && !isBoundedString(value.detail, 300)) return undefined;
  return { status: value.status, detail: optionalString(value.detail) };
}

function stringRecordFrom(value: unknown, maxEntries: number, maxValueLength: number): Record<string, string> | undefined {
  if (!isRecord(value) || Object.keys(value).length > maxEntries) return undefined;
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!/^[A-Za-z0-9_.:-]{1,120}$/.test(key) || !isBoundedString(item, maxValueLength)) return undefined;
    result[key] = item;
  }
  return result;
}

function numberRecordFrom(value: unknown, maxEntries: number): Record<string, number> | undefined {
  if (!isRecord(value) || Object.keys(value).length > maxEntries) return undefined;
  const result: Record<string, number> = {};
  for (const [key, item] of Object.entries(value)) {
    if (!/^[A-Za-z0-9_.:-]{1,120}$/.test(key) || typeof item !== "number" || !Number.isFinite(item)) return undefined;
    result[key] = item;
  }
  return result;
}

function isSafeGithubUrl(value: unknown): value is string {
  if (!isBoundedString(value, 300)) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com";
  } catch {
    return false;
  }
}

function isReleaseStatus(value: unknown): value is ReleaseStatus {
  return value === "deploying" || value === "verified" || value === "failed" || value === "rolled_back" || value === "superseded";
}

function isReleaseCheckStatus(value: unknown): value is ReleaseCheckStatus {
  return value === "pending" || value === "passed" || value === "failed";
}

function isStringArray(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => isBoundedString(item, maxLength));
}

function isBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function isIsoDate(value: unknown): value is string {
  return isBoundedString(value, 40) && Number.isFinite(Date.parse(value));
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const MAX_SECURITY_TEXT_CODE_UNITS = 65_536;

const SLACK_TOKEN_PATTERN = /xox[baprs]-[A-Za-z0-9-]+/g;
const CLOUD_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const PRIVATE_KEY_PATTERN =
  /-----BEGIN ([A-Z0-9 ]{1,32}) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g;
const ASSIGNED_SECRET_PATTERN =
  /\b(bearer|api[_-]?key|token|secret|password)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi;

export const SECURITY_REDACTION_CLASSES = [
  "assigned_secret",
  "cloud_access_key",
  "private_key",
  "slack_token",
] as const;

export type SecurityRedactionClassV1 = (typeof SECURITY_REDACTION_CLASSES)[number];

export interface SecurityRedactionLabelsV1 {
  readonly assigned_secret: string;
  readonly cloud_access_key: string;
  readonly private_key: string;
  readonly slack_token: string;
}

export interface SecurityRedactionOptionsV1 {
  readonly labels?: Partial<SecurityRedactionLabelsV1>;
}

export interface SecurityRedactionReceiptV1 {
  readonly redacted_text: string;
  readonly redaction_classes: readonly SecurityRedactionClassV1[];
  readonly redaction_count: number;
  readonly schema_version: "security-redaction-receipt/v1";
}

export class SecurityRedactionInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityRedactionInputError";
  }
}

/**
 * Replace common credential-shaped values in one bounded text field.
 *
 * Callers must handle an input error without persisting or logging the rejected
 * value. This helper is a final text boundary, not a secret discovery system.
 */
export function redactSecurityText(value: string): string {
  return redactSecurityTextWithReceipt(value).redacted_text;
}

export function redactSecurityTextWithReceipt(
  value: string,
  options: SecurityRedactionOptionsV1 = {},
): SecurityRedactionReceiptV1 {
  if (typeof value !== "string") {
    throw new SecurityRedactionInputError("security text must be a string");
  }
  if (value.length > MAX_SECURITY_TEXT_CODE_UNITS) {
    throw new SecurityRedactionInputError(
      `security text exceeds ${MAX_SECURITY_TEXT_CODE_UNITS} code units`,
    );
  }

  const labels = {
    assigned_secret: "[redacted_secret]",
    cloud_access_key: "[redacted_cloud_access_key]",
    private_key: "[redacted_private_key]",
    slack_token: "[redacted_slack_token]",
    ...options.labels,
  };
  const classes = new Set<SecurityRedactionClassV1>();
  let redactionCount = 0;
  const redactedText = value
    .replace(SLACK_TOKEN_PATTERN, () =>
      replacement("slack_token", labels.slack_token, classes, () => redactionCount += 1)
    )
    .replace(CLOUD_ACCESS_KEY_PATTERN, () =>
      replacement("cloud_access_key", labels.cloud_access_key, classes, () => redactionCount += 1)
    )
    .replace(PRIVATE_KEY_PATTERN, () =>
      replacement("private_key", labels.private_key, classes, () => redactionCount += 1)
    )
    .replace(ASSIGNED_SECRET_PATTERN, (match, name: string) => {
      redactionCount += 1;
      classes.add("assigned_secret");
      return `${name}=${labels.assigned_secret}`;
    });

  return Object.freeze({
    redacted_text: redactedText,
    redaction_classes: Object.freeze(
      [...classes].sort((left, right) => left.localeCompare(right)),
    ),
    redaction_count: redactionCount,
    schema_version: "security-redaction-receipt/v1",
  });
}

function replacement(
  redactionClass: SecurityRedactionClassV1,
  label: string,
  classes: Set<SecurityRedactionClassV1>,
  increment: () => void,
): string {
  classes.add(redactionClass);
  increment();
  return label;
}

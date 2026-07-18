const MAX_SECURITY_TEXT_CODE_UNITS = 65_536;

const SLACK_TOKEN_PATTERN = /xox[baprs]-[A-Za-z0-9-]+/g;
const CLOUD_ACCESS_KEY_PATTERN = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g;
const PRIVATE_KEY_PATTERN =
  /-----BEGIN ([A-Z0-9 ]{1,32}) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----/g;
const ASSIGNED_SECRET_PATTERN =
  /\b(bearer|api[_-]?key|token|secret|password)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi;

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
  if (typeof value !== "string") {
    throw new SecurityRedactionInputError("security text must be a string");
  }
  if (value.length > MAX_SECURITY_TEXT_CODE_UNITS) {
    throw new SecurityRedactionInputError(
      `security text exceeds ${MAX_SECURITY_TEXT_CODE_UNITS} code units`,
    );
  }

  return value
    .replace(SLACK_TOKEN_PATTERN, "[redacted_slack_token]")
    .replace(CLOUD_ACCESS_KEY_PATTERN, "[redacted_cloud_access_key]")
    .replace(PRIVATE_KEY_PATTERN, "[redacted_private_key]")
    .replace(ASSIGNED_SECRET_PATTERN, "$1=[redacted_secret]");
}

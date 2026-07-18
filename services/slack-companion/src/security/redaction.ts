export function redactSecurityText(value: string): string {
  return value
    .replace(/xox[baprs]-[A-Za-z0-9-]+/g, "[redacted_slack_token]")
    .replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "[redacted_aws_access_key]")
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]+?-----END [^-]+ PRIVATE KEY-----/g, "[redacted_private_key]")
    .replace(/\b(bearer|api[_-]?key|token|secret|password)\s*[:=]\s*["']?[^"'\s]+/gi, "$1=[redacted_secret]");
}

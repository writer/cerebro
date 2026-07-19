export function hasSecuritySignal(value: string): boolean {
  return /\b(admin|anomaly|attack|credential|critical|cve|exfil|exposure|high|malware|mfa|okta|phishing|privilege|root|secret|suspicious|token|vulnerability)\b/i.test(value);
}

export function hasSpecificText(items: readonly string[]): boolean {
  return items.some((item) => {
    const trimmed = item.trim();
    if (trimmed.length < 12) return false;
    return !isGenericTriageText(trimmed);
  });
}

export function isGenericTriageText(value: string): boolean {
  return /\b(not enough context|needs more context|review the source alert fields|check related cerebro findings|rerun triage|no response action is needed|does not contain enough verified context|graph reasoning was unavailable|generic advice)\b/i.test(value);
}

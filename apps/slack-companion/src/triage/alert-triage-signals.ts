export function hasSecuritySignal(value: string): boolean {
  return /\b(admin|anomaly|attack|breach|compromis(?:e|ed)|credential|critical|cve|detect(?:ion|ed)|exfil|exploit(?:ed)?|exposure|high|iam|leak(?:ed)?|malware|mfa|okta|phishing|privilege|public|ransomware|root|secret|suspicious|token|unauthori[sz]ed|vulnerabilit(?:y|ies))\b/i.test(value);
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

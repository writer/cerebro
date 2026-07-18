import type { Finding, FindingEvidence, JsonRecord, RuntimeHealth } from "../cerebro/types.js";

export function text(value: unknown, fallback = "unknown"): string {
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return fallback;
}

export function findingTitle(finding: Finding): string {
  return text(finding.title ?? finding.summary ?? finding.id, "finding");
}

export function findingStatusLine(finding: Finding): string {
  const severity = text(finding.severity, "severity unknown");
  const status = text(finding.status, "status unknown");
  const score = finding.risk_score === undefined ? "" : ` · risk ${finding.risk_score}`;
  const owner = finding.assignee ? ` · ${finding.assignee}` : "";
  return `${severity} · ${status}${score}${owner}`;
}

export function runtimeId(runtime: RuntimeHealth): string {
  return text(runtime.runtime_id ?? runtime.id, "runtime");
}

export function runtimeStatusLine(runtime: RuntimeHealth): string {
  const source = text(runtime.source_id, "source unknown");
  const sync = text(runtime.sync_status ?? runtime.status, "sync unknown");
  const graph = text(runtime.graph_status, "graph unknown");
  const findings = text(runtime.finding_status, "findings unknown");
  return `${source} · sync ${sync} · graph ${graph} · findings ${findings}`;
}

export function evidenceLine(evidence: FindingEvidence): string {
  const label = text(evidence.summary ?? evidence.evidence_type ?? evidence.id, "evidence");
  const observed = evidence.observed_at ? ` · ${evidence.observed_at}` : "";
  return `${label}${observed}`;
}

export function answerFromGraphReason(response: JsonRecord): string {
  const links = evidenceLinksFromGraphReason(response);
  const direct = directGraphAnswer(response);
  if (direct) return withEvidenceLinks(direct, links);

  const events = response.events;
  if (Array.isArray(events)) {
    const textEvent = events.find((event) => directGraphAnswer(objectValue(event)));
    const text = directGraphAnswer(objectValue(textEvent));
    if (text) {
      return withEvidenceLinks(text, links);
    }
  }

  if (links.length > 0) {
    return `Cerebro returned graph evidence, but no written answer.\nEvidence: ${formatEvidenceLinks(links)}`;
  }
  return "Cerebro did not return a written graph answer or evidence link. Ask again with a narrower entity, runtime, finding id, or time window.";
}

export function trimForSlack(value: string, max = 2800): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max - 1)}…`;
}

export function containsAssistantProtocolLeak(value: string): boolean {
  return /<\/?parameter\b|<parameter\s+name=|<\/?(tool_use|tool_result|function_call|function_calls|thinking)\b|\braw_final_assistant_output\b/i.test(value);
}

function directGraphAnswer(response: Record<string, unknown> | undefined): string | undefined {
  if (!response) return undefined;
  for (const key of ["answer", "answer_markdown", "summary", "final_answer", "response", "message"]) {
    const value = response[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

function withEvidenceLinks(answer: string, links: EvidenceLink[]): string {
  if (links.length === 0) return answer;
  return `${answer}\nEvidence: ${formatEvidenceLinks(links)}`;
}

function formatEvidenceLinks(links: EvidenceLink[]): string {
  return links
    .slice(0, 3)
    .map((link) => `<${link.url}|${escapeLinkLabel(link.label ?? "Open evidence")}>`)
    .join(" · ");
}

interface EvidenceLink {
  url: string;
  label?: string;
}

function evidenceLinksFromGraphReason(response: unknown): EvidenceLink[] {
  const seen = new Set<string>();
  const links: EvidenceLink[] = [];
  collectEvidenceLinks(response, links, seen, 0, undefined);
  return links;
}

function collectEvidenceLinks(value: unknown, links: EvidenceLink[], seen: Set<string>, depth: number, parentKey: string | undefined): void {
  if (depth > 6 || links.length >= 6 || value === null || value === undefined) return;

  if (typeof value === "string") {
    if (!shouldCollectUrlFromString(parentKey)) return;
    for (const url of urlsFromString(value)) {
      if (seen.has(url)) continue;
      seen.add(url);
      links.push({ url, label: labelFromKey(parentKey) });
      if (links.length >= 6) return;
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) collectEvidenceLinks(item, links, seen, depth + 1, parentKey);
    return;
  }

  if (typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  const label = text(record.title ?? record.label ?? record.name ?? record.id, "");
  for (const [key, child] of Object.entries(record)) {
    if (isLinkKey(key)) {
      for (const url of urlsFromString(child)) {
        if (seen.has(url)) continue;
        seen.add(url);
        links.push({ url, label: label || labelFromKey(key) });
        if (links.length >= 6) return;
      }
    }
    collectEvidenceLinks(child, links, seen, depth + 1, key);
  }
}

function urlsFromString(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return value.match(/https?:\/\/[^\s<>)"]+/g)?.map((url) => url.replace(/[.,;:!?]+$/, "")) ?? [];
}

function isLinkKey(key: string): boolean {
  return /\b(url|uri|href|link|permalink|web_url|evidence_url|finding_url)\b/i.test(key);
}

function shouldCollectUrlFromString(key: string | undefined): boolean {
  if (!key) return false;
  const normalized = key.toLowerCase();
  return isLinkKey(key) || ["citation", "evidence", "source", "reference", "external_ref", "ticket"].some((term) => normalized.includes(term));
}

function labelFromKey(key: string | undefined): string {
  if (!key) return "Open evidence";
  if (/finding/i.test(key)) return "Open finding";
  if (/evidence/i.test(key)) return "Open evidence";
  return "Open evidence";
}

function escapeLinkLabel(value: string): string {
  return value.replace(/[|<>]/g, "").slice(0, 80) || "Open evidence";
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

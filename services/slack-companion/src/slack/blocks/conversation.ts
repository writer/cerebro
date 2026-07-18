import { containsAssistantProtocolLeak, trimForSlack } from "../format.js";

export function cleanConversationalReply(value: string, max?: number): string | undefined {
  const visible = cleanVisibleReply(value, max);
  if (!visible) return undefined;
  const cleaned = visible
    .split("\n")
    .filter((line) => !looksLikeReportLine(line))
    .join("\n")
    .trim();
  if (!cleaned) return undefined;
  return max === undefined ? cleaned : trimForSlack(cleaned, max);
}

export function firstUsefulAction(actions: string[]): string | undefined {
  return actions.find((action) => !/\b(no response action is needed|rerun triage|review the source alert fields|wait for .+ to name|wait for .+ specific|actual question)\b/i.test(action));
}

export function firstUsefulCompletedAction(actions: string[]): string | undefined {
  return actions.find((item) => !/\b(fallback path|checked security memory)\b/i.test(item));
}

export function actionSentence(action: string): string {
  const cleaned = trimForSlack(action.replace(/\s+/g, " ").trim().replace(/\.+$/, ""), 260);
  if (/^checked\b/i.test(cleaned)) return `${cleaned.replace(/^checked\b/i, "I checked")}.`;
  if (/^built\b/i.test(cleaned)) return `${cleaned.replace(/^built\b/i, "I built")}.`;
  return sentenceWithPeriod(cleaned);
}

export function nextActionSentence(action: string): string {
  const cleaned = trimForSlack(action.replace(/\s+/g, " ").trim().replace(/\.+$/, ""), 420);
  return sentenceWithPeriod(`Next, ${cleaned.charAt(0).toLowerCase()}${cleaned.slice(1)}`);
}

export function isRepeatedLine(left: string, right: string): boolean {
  const normalizedLeft = normalizeLine(left);
  const normalizedRight = normalizeLine(right);
  return normalizedLeft.includes(normalizedRight) || normalizedRight.includes(normalizedLeft);
}

export function uniqueLine(value: string, index: number, values: string[]): boolean {
  const normalized = normalizeLine(value);
  return values.findIndex((item) => normalizeLine(item) === normalized) === index;
}

export function composeSingleReply(lines: string[]): string {
  const cleaned = lines.map((line) => trimForSlack(line.trim(), 900)).filter(Boolean).filter(uniqueLine);
  return trimForSlack(cleaned.join("\n"), 1400);
}

export const SLACK_REPLY_PART_MAX_CHARS = 2800;

export function splitReplyForSlack(value: string, maxChars: number = SLACK_REPLY_PART_MAX_CHARS): string[] {
  const trimmed = value.trim();
  if (!trimmed) return [];
  const cap = Math.max(120, maxChars);
  if (trimmed.length <= cap) return [trimmed];

  const parts: string[] = [];
  let remaining = trimmed;
  while (remaining.length > cap) {
    let cut = -1;
    for (const sep of ["\n\n", "\n", ". ", " "]) {
      const searchLimit = Math.max(0, cap - sep.length);
      const idx = remaining.lastIndexOf(sep, searchLimit);
      if (idx > Math.floor(cap * 0.4)) {
        cut = sep === ". " ? idx + 1 : idx;
        break;
      }
    }
    if (cut <= 0 || cut > cap) cut = cap;
    parts.push(remaining.slice(0, cut).trim());
    remaining = remaining.slice(cut).trim();
  }
  if (remaining) parts.push(remaining);
  return parts;
}

export function composeReplyParts(lines: string[], maxChars: number = SLACK_REPLY_PART_MAX_CHARS): string[] {
  const cleaned = lines
    .map((line) => line.trim())
    .filter(Boolean)
    .filter(uniqueLine);
  if (cleaned.length === 0) return [];

  const content = cleaned.join("\n");
  const cap = Math.max(120, maxChars);
  let parts = splitReplyForSlack(content, cap);
  let reservedChars = -1;
  while (parts.length > 1) {
    const nextReservedChars = numberingReserve(parts.length);
    if (nextReservedChars === reservedChars) break;
    reservedChars = nextReservedChars;
    parts = splitReplyForSlack(content, Math.max(120, cap - reservedChars));
  }
  return numberReplyParts(parts);
}

function numberReplyParts(parts: string[]): string[] {
  if (parts.length <= 1) return parts;
  return parts.map((part, index) => {
    const prefix = `(${index + 1}/${parts.length}) `;
    return `${prefix}${part}`;
  });
}

function numberingReserve(maxParts: number): number {
  const digits = String(Math.max(1, maxParts)).length;
  return digits * 2 + 5;
}

function cleanVisibleReply(value: string, max?: number): string | undefined {
  const normalized = value.replace(/\s+\n/g, "\n").trim();
  const cleaned = max === undefined ? normalized : trimForSlack(normalized, max);
  if (!cleaned || containsAssistantProtocolLeak(cleaned)) return undefined;
  return cleaned;
}

function sentenceWithPeriod(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

function looksLikeReportLine(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) return true;
  if (/^(?:[-*•]\s*)?(?:found|checked|evidence|next(?: actions?)?|research|tool trail|observation|why it matters|suggested action|key points?|done|actions taken|memory updates?):\s+/i.test(trimmed)) {
    return true;
  }
  return /^(?:[-*•]\s*)?[a-z][a-z0-9]*(?:_[a-z0-9]+)+:\s*(?:checked|failed)(?:\s+\([^)]*\))?\.?$/i.test(trimmed);
}

function normalizeLine(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

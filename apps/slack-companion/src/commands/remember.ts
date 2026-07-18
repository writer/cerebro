import { Buffer } from "node:buffer";

const MAX_REMEMBER_INPUT_LENGTH = 2_000;
const MAX_REMEMBER_CONTENT_LENGTH = 900;
const MAX_AUTHOR_NAME_LENGTH = 60;
const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export interface SlackRememberCommandOptions {
  readonly author_name?: string;
  /** Exact companion mention already verified by the transport host. */
  readonly expected_mention?: string;
}

export interface SlackRememberCommandV1 {
  readonly content: string;
  readonly details: string;
  readonly explicit_details: string;
  readonly explicit_summary: string;
  readonly explicit_topic: string;
  readonly schema_version: "slack-remember-command/v1";
  readonly summary: string;
  readonly tags: readonly string[];
  readonly topic: string;
  readonly working_memory_target: "memory" | "team";
}

export class SlackRememberCommandError extends Error {}

/**
 * Parses explicit remember language without authorizing the actor or reading or
 * writing a memory store. Mention verification remains a transport-host duty.
 */
export function parseSlackRememberCommand(
  text: string,
  options: SlackRememberCommandOptions = {},
): SlackRememberCommandV1 | undefined {
  validateInput(text);
  const routedText = stripExpectedMention(text.trim(), options.expected_mention);
  if (routedText === undefined) return undefined;
  const match = routedText.match(
    /^(?:(?:hey|hi)\s+)?(?:cerebro[,:]?\s+)?(?:please\s+)?remember\b(?:\s+(?:that|this))?(?:\s*[:,-]\s*|\s+)?([\s\S]*)$/i,
  );
  if (!match) return undefined;

  const content = cleanContent(match[1] ?? "");
  if (!content) {
    throw new SlackRememberCommandError("Add content after the Slack remember command.");
  }

  const authorName = cleanAuthorName(options.author_name);
  const subject = subjectFromContent(content) ?? firstPersonSubject(content, authorName);
  const topic = subject
    ? `Slack context: ${subject}`
    : `Remembered note: ${topicSnippet(content)}`;
  const summary = summaryFor(content, subject);
  const teamContext = Boolean(subject) || looksLikeTeamContext(content);
  const tags = Object.freeze(unique([
    "slack-remember",
    teamContext ? "team-context" : "operator-note",
    ...keywordTags(content),
  ]).slice(0, 8));

  return Object.freeze({
    content,
    details: `Explicit Slack remember command: ${content}`,
    explicit_details: [
      `Raw remembered text: ${content}`,
      `Interpreted topic: ${topic}`,
      subject ? `Interpreted subject: ${subject}` : "",
      `Working memory target: ${teamContext ? "team" : "memory"}`,
    ].filter(Boolean).join("\n"),
    explicit_summary: `Cerebro was explicitly told to remember: ${content}`,
    explicit_topic: `Explicit memory: ${topicSnippet(content)}`,
    schema_version: "slack-remember-command/v1",
    summary,
    tags,
    topic,
    working_memory_target: teamContext ? "team" : "memory",
  });
}

export function containsSlackMention(text: string): boolean {
  validateInput(text);
  return /<@[A-Z0-9]+>/.test(text);
}

function validateInput(text: string): void {
  if (
    typeof text !== "string"
    || Buffer.byteLength(text, "utf8") > MAX_REMEMBER_INPUT_LENGTH
    || UNSAFE_CONTROL_CHARACTERS.test(text)
    || hasLoneSurrogate(text)
  ) {
    throw new SlackRememberCommandError("The Slack remember input is invalid.");
  }
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function cleanContent(value: string): string {
  const content = trimContentBoundary(value).replace(/\s+/g, " ");
  if (Buffer.byteLength(content, "utf8") > MAX_REMEMBER_CONTENT_LENGTH) {
    throw new SlackRememberCommandError("The Slack remember content is too long.");
  }
  return content;
}

function trimContentBoundary(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && isContentBoundaryCharacter(value.charAt(start))) {
    start += 1;
  }
  while (end > start && isContentBoundaryCharacter(value.charAt(end - 1))) {
    end -= 1;
  }
  return value.slice(start, end);
}

function isContentBoundaryCharacter(character: string): boolean {
  return character === "\""
    || character === "'"
    || character === "`"
    || character.trim().length === 0;
}

function cleanAuthorName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.replace(/\s+/g, " ").trim();
  if (
    !normalized
    || Buffer.byteLength(normalized, "utf8") > MAX_AUTHOR_NAME_LENGTH
    || UNSAFE_CONTROL_CHARACTERS.test(normalized)
    || hasLoneSurrogate(normalized)
  ) {
    throw new SlackRememberCommandError("The Slack remember author name is invalid.");
  }
  return normalized;
}

function stripExpectedMention(
  text: string,
  expectedMention: string | undefined,
): string | undefined {
  const mention = text.match(/^(<@[A-Z0-9]+>)(?:\s+|$)/)?.[1];
  if (!mention) return text;
  if (
    expectedMention === undefined
    || !/^<@[A-Z0-9]+>$/.test(expectedMention)
    || mention !== expectedMention
  ) {
    return undefined;
  }
  return text.slice(mention.length).trimStart();
}

function subjectFromContent(content: string): string | undefined {
  const match = content.match(
    /^([\p{L}][\p{L}0-9_.-]{1,40})(?:\s+(?:says|said|jokes|is|has|often|usually|mostly|prefers|likes|does|will|can)\b|['’]s\b)/iu,
  );
  return match?.[1] ? titleCaseName(match[1]) : undefined;
}

function firstPersonSubject(
  content: string,
  authorName: string | undefined,
): string | undefined {
  if (!authorName) return undefined;
  return /\b(I|me|my|mine|what I say|I say)\b/i.test(content)
    ? authorName
    : undefined;
}

function summaryFor(content: string, subject: string | undefined): string {
  if (!subject) return content;
  const subjectPattern = new RegExp(`^${escapeRegExp(subject)}\\b`, "i");
  return subjectPattern.test(content) ? content : `${subject}: ${content}`;
}

function looksLikeTeamContext(content: string): boolean {
  return /\b(slack|team|channel|thread|person|people|joke|jokes|joking|tone|preference|prefers|usually|often|mostly)\b/i.test(content);
}

function keywordTags(content: string): string[] {
  const tags: string[] = [];
  if (/\b(?:slack|thread|channel)\b/i.test(content)) tags.push("slack");
  if (/\b(?:joke|jokes|joking)\b/i.test(content)) tags.push("tone");
  if (/\b(?:graph|cypher|finding|alert|triage)\b/i.test(content)) {
    tags.push("security-triage");
  }
  return tags;
}

function topicSnippet(content: string): string {
  let end = content.length;
  while (end > 0 && ".?!".includes(content.charAt(end - 1))) {
    end -= 1;
  }
  return truncateCodePoints(content, 72, end) || "note";
}

function truncateCodePoints(
  value: string,
  limit: number,
  boundary = value.length,
): string {
  if (boundary <= limit) {
    return boundary === value.length ? value : value.slice(0, boundary);
  }
  let count = 0;
  let end = 0;
  for (const codePoint of value) {
    if (end >= boundary || count === limit) break;
    count += 1;
    end += codePoint.length;
  }
  const boundedEnd = Math.min(end, boundary);
  return boundedEnd === value.length ? value : value.slice(0, boundedEnd);
}

function titleCaseName(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import {
  SLACK_THREAD_SCRATCHPAD_LIMITS,
  SlackThreadScratchpadError,
  type SlackThreadScratchpadNoteV1,
  type SlackThreadScratchpadV1,
} from "./contracts.js";
import { redactSecurityText } from "../security/redaction.js";

const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u;

export type SlackThreadScratchpadCommandV1 =
  | {
      readonly action: "add";
      readonly content: string;
      readonly schema_version: "slack-thread-scratchpad-command/v1";
    }
  | {
      readonly action: "clear" | "show";
      readonly schema_version: "slack-thread-scratchpad-command/v1";
    };

export function parseSlackThreadScratchpadCommand(
  text: string,
): SlackThreadScratchpadCommandV1 | undefined {
  const normalized = text.replace(/\s+/gu, " ").trim();
  const command = normalized.toLocaleLowerCase("en-US");
  if (command === "scratchpad" || command === "scratchpad show") {
    return Object.freeze({
      action: "show",
      schema_version: "slack-thread-scratchpad-command/v1",
    });
  }
  if (command === "clear scratchpad" || command === "scratchpad clear") {
    return Object.freeze({
      action: "clear",
      schema_version: "slack-thread-scratchpad-command/v1",
    });
  }
  const addPrefix = "scratchpad add";
  if (!command.startsWith(addPrefix)) return undefined;
  const remainder = normalized.slice(addPrefix.length);
  if (remainder.length === 0) return undefined;
  const startsWithSpace = remainder[0] === " ";
  const startsWithSeparator = isScratchpadAddSeparator(remainder[0]);
  if (!startsWithSpace && !startsWithSeparator) return undefined;
  let content = remainder.slice(1).trimStart();
  if (startsWithSpace && isScratchpadAddSeparator(content[0])) {
    content = content.slice(1).trimStart();
  }
  if (!content) return undefined;
  content = normalizeScratchpadContent(content);
  return Object.freeze({
    action: "add",
    content,
    schema_version: "slack-thread-scratchpad-command/v1",
  });
}

function isScratchpadAddSeparator(value: string | undefined): boolean {
  return value === ":" || value === "," || value === "-";
}

export function normalizeScratchpadContent(content: string): string {
  const normalized = content.replace(/\s+/gu, " ").trim();
  if (
    normalized.length === 0
    || Buffer.byteLength(normalized, "utf8")
      > SLACK_THREAD_SCRATCHPAD_LIMITS.max_note_utf8_bytes
    || UNSAFE_CONTROL_CHARACTERS.test(normalized)
    || hasLoneSurrogate(normalized)
  ) {
    throw new SlackThreadScratchpadError("The scratchpad note is invalid or too long.");
  }
  return redactSecurityText(normalized);
}

export function slackThreadScratchpadRef(
  teamId: string,
  channelId: string,
  threadTs: string,
): string {
  for (const [label, value] of [
    ["team", teamId],
    ["channel", channelId],
    ["thread", threadTs],
  ] as const) {
    if (!value.trim() || UNSAFE_CONTROL_CHARACTERS.test(value)) {
      throw new SlackThreadScratchpadError(`The Slack ${label} identity is invalid.`);
    }
  }
  return `slack-scratchpad://sha256/${digest(`${teamId}:${channelId}:${threadTs}`)}`;
}

export function slackScratchpadAuthorRef(teamId: string, userId: string): string {
  if (!teamId.trim() || !userId.trim() || UNSAFE_CONTROL_CHARACTERS.test(userId)) {
    throw new SlackThreadScratchpadError("The Slack scratchpad author is invalid.");
  }
  return `slack-user://sha256/${digest(`${teamId}:${userId}`)}`;
}

export function validateSlackThreadScratchpad(
  scratchpad: SlackThreadScratchpadV1,
  now: Date,
): SlackThreadScratchpadV1 {
  if (
    scratchpad.schema_version !== "slack-thread-scratchpad/v1"
    || !validRef(scratchpad.thread_ref)
    || !Array.isArray(scratchpad.notes)
    || scratchpad.notes.length > SLACK_THREAD_SCRATCHPAD_LIMITS.max_notes
  ) {
    throw new SlackThreadScratchpadError("The thread scratchpad is invalid.");
  }
  const noteIds = new Set<string>();
  const notes = scratchpad.notes.map((note) => {
    validateNote(note, scratchpad.thread_ref);
    if (noteIds.has(note.note_id)) {
      throw new SlackThreadScratchpadError("The thread scratchpad contains a duplicate note.");
    }
    noteIds.add(note.note_id);
    return Object.freeze({ ...note });
  }).filter((note) => Date.parse(note.expires_at) > now.getTime())
    .sort((left, right) =>
      left.created_at.localeCompare(right.created_at)
      || left.note_id.localeCompare(right.note_id)
    );
  const totalBytes = notes.reduce(
    (total, note) => total + Buffer.byteLength(note.content, "utf8"),
    0,
  );
  if (totalBytes > SLACK_THREAD_SCRATCHPAD_LIMITS.max_total_utf8_bytes) {
    throw new SlackThreadScratchpadError("The thread scratchpad exceeds its storage limit.");
  }
  return Object.freeze({
    notes: Object.freeze(notes),
    schema_version: "slack-thread-scratchpad/v1",
    thread_ref: scratchpad.thread_ref,
  });
}

export function formatSlackThreadScratchpadContext(
  scratchpad: SlackThreadScratchpadV1,
): string | undefined {
  if (scratchpad.notes.length === 0) return undefined;
  return scratchpad.notes
    .map((note, index) =>
      `${index + 1}. [${note.source === "cerebro" ? "verified Cerebro turn" : "thread note"}] ${note.content}`
    )
    .join("\n");
}

export function verifiedTurnScratchpadContent(
  question: string,
  answer: string,
): string {
  const normalizedQuestion = compactText(question);
  const normalizedAnswer = compactText(answer);
  if (!normalizedQuestion || !normalizedAnswer) {
    throw new SlackThreadScratchpadError(
      "A verified turn needs a question and answer.",
    );
  }
  return normalizeScratchpadContent(truncateUtf8(
    `Question: ${normalizedQuestion} Verified answer: ${normalizedAnswer}`,
    SLACK_THREAD_SCRATCHPAD_LIMITS.max_note_utf8_bytes,
  ));
}

function validateNote(note: SlackThreadScratchpadNoteV1, threadRef: string): void {
  if (
    note.schema_version !== "slack-thread-scratchpad-note/v1"
    || note.thread_ref !== threadRef
    || !validRef(note.note_id)
    || !validRef(note.author_ref)
    || (note.source !== "cerebro" && note.source !== "human")
    || (
      note.source === "cerebro"
      && (note.evidence_ref === undefined || !validRef(note.evidence_ref))
    )
    || (note.source === "human" && note.evidence_ref !== undefined)
    || normalizeScratchpadContent(note.content) !== note.content
    || !canonicalTimestamp(note.created_at)
    || !canonicalTimestamp(note.expires_at)
    || Date.parse(note.expires_at) <= Date.parse(note.created_at)
  ) {
    throw new SlackThreadScratchpadError("The thread scratchpad note is invalid.");
  }
}

function compactText(value: string): string {
  return value.replace(/\s+/gu, " ").trim();
}

function truncateUtf8(value: string, maximumBytes: number): string {
  if (Buffer.byteLength(value, "utf8") <= maximumBytes) return value;
  let result = "";
  for (const codePoint of value) {
    if (Buffer.byteLength(result + codePoint, "utf8") > maximumBytes - 3) break;
    result += codePoint;
  }
  return `${result.trimEnd()}...`;
}

function validRef(value: string): boolean {
  return value.length <= 256 && REF_PATTERN.test(value);
}

function canonicalTimestamp(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
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

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

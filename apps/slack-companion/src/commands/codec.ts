const MAX_ENCODED_VALUE_LENGTH = 2_048;
const MAX_ARGUMENTS = 32;
const MAX_PARAMETERS = 16;
const NAME_PATTERN = /^[a-z][a-z0-9_.:-]{0,95}$/;
const OPAQUE_REF_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;

export interface SlackCommandEnvelopeV1 {
  readonly arguments: readonly string[];
  readonly command: string;
  readonly issued_at: string;
  readonly request_id: string;
  readonly schema_version: "slack-command-envelope/v1";
}

export interface SlackActionEnvelopeV1 {
  readonly action: string;
  readonly command: string;
  readonly idempotency_key: string;
  readonly issued_at: string;
  readonly parameters?: Readonly<Record<string, string>>;
  readonly schema_version: "slack-action-envelope/v1";
  readonly subject_ref?: string;
}

export class SlackCommandCodecError extends Error {}

export function encodeSlackCommandEnvelope(input: SlackCommandEnvelopeV1): string {
  return encodeValue(validateCommandEnvelope(input));
}

export function decodeSlackCommandEnvelope(value: string): SlackCommandEnvelopeV1 {
  return validateCommandEnvelope(decodeValue(value));
}

export function encodeSlackActionEnvelope(input: SlackActionEnvelopeV1): string {
  return encodeValue(validateActionEnvelope(input));
}

export function decodeSlackActionEnvelope(value: string): SlackActionEnvelopeV1 {
  return validateActionEnvelope(decodeValue(value));
}

function validateCommandEnvelope(value: unknown): SlackCommandEnvelopeV1 {
  const input = record(value, "Slack command envelope");
  exactFields(input, ["arguments", "command", "issued_at", "request_id", "schema_version"]);
  if (input.schema_version !== "slack-command-envelope/v1") {
    throw new SlackCommandCodecError("Slack command envelope version is unsupported.");
  }
  if (!Array.isArray(input.arguments) || input.arguments.length > MAX_ARGUMENTS) {
    throw new SlackCommandCodecError("Slack command arguments are invalid.");
  }
  const args = input.arguments.map((argument, index) =>
    boundedText(argument, `Slack command argument ${index + 1}`, 512),
  );
  return Object.freeze({
    arguments: Object.freeze(args),
    command: name(input.command, "Slack command"),
    issued_at: timestamp(input.issued_at, "Slack command issued_at"),
    request_id: opaqueValue(input.request_id, "Slack command request_id"),
    schema_version: "slack-command-envelope/v1",
  });
}

function validateActionEnvelope(value: unknown): SlackActionEnvelopeV1 {
  const input = record(value, "Slack action envelope");
  exactFields(input, [
    "action",
    "command",
    "idempotency_key",
    "issued_at",
    "parameters",
    "schema_version",
    "subject_ref",
  ]);
  if (input.schema_version !== "slack-action-envelope/v1") {
    throw new SlackCommandCodecError("Slack action envelope version is unsupported.");
  }
  const parameters = optionalParameters(input.parameters);
  const subjectRef = optionalSubjectRef(input.subject_ref);
  return Object.freeze({
    action: name(input.action, "Slack action"),
    command: name(input.command, "Slack action command"),
    idempotency_key: opaqueValue(
      input.idempotency_key,
      "Slack action idempotency_key",
    ),
    issued_at: timestamp(input.issued_at, "Slack action issued_at"),
    ...(parameters === undefined ? {} : { parameters }),
    schema_version: "slack-action-envelope/v1",
    ...(subjectRef === undefined ? {} : { subject_ref: subjectRef }),
  });
}

function optionalParameters(value: unknown): Readonly<Record<string, string>> | undefined {
  if (value === undefined) return undefined;
  const parameters = record(value, "Slack action parameters");
  const entries = Object.entries(parameters).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length > MAX_PARAMETERS) {
    throw new SlackCommandCodecError("Slack action has too many parameters.");
  }
  const validated: Record<string, string> = {};
  for (const [key, item] of entries) {
    validated[name(key, "Slack action parameter")] = boundedText(
      item,
      `Slack action parameter ${key}`,
      512,
    );
  }
  return Object.freeze(validated);
}

function optionalSubjectRef(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const ref = boundedText(value, "Slack action subject_ref", 2_048);
  if (!OPAQUE_REF_PATTERN.test(ref)) {
    throw new SlackCommandCodecError("Slack action subject_ref must be an opaque reference.");
  }
  return ref;
}

function encodeValue(value: object): string {
  const encoded = Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  if (encoded.length > MAX_ENCODED_VALUE_LENGTH) {
    throw new SlackCommandCodecError("Slack encoded value exceeds the supported size.");
  }
  return encoded;
}

function decodeValue(value: string): unknown {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_ENCODED_VALUE_LENGTH
    || !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new SlackCommandCodecError("Slack encoded value is invalid.");
  }
  let decoded: string;
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) {
      throw new SlackCommandCodecError("Slack encoded value is not canonical.");
    }
    decoded = bytes.toString("utf8");
  } catch (error) {
    if (error instanceof SlackCommandCodecError) throw error;
    throw new SlackCommandCodecError("Slack encoded value is invalid.");
  }
  try {
    return JSON.parse(decoded) as unknown;
  } catch {
    throw new SlackCommandCodecError("Slack encoded value does not contain JSON.");
  }
}

function exactFields(value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) {
    throw new SlackCommandCodecError("Slack envelope contains unknown fields.");
  }
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SlackCommandCodecError(`${field} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function name(value: unknown, field: string): string {
  const normalized = boundedText(value, field, 96);
  if (!NAME_PATTERN.test(normalized)) {
    throw new SlackCommandCodecError(`${field} has an unsupported name.`);
  }
  return normalized;
}

function opaqueValue(value: unknown, field: string): string {
  const normalized = boundedText(value, field, 256);
  if (/\s/.test(normalized)) {
    throw new SlackCommandCodecError(`${field} must not contain whitespace.`);
  }
  return normalized;
}

function timestamp(value: unknown, field: string): string {
  const normalized = boundedText(value, field, 64);
  const parsed = Date.parse(normalized);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== normalized) {
    throw new SlackCommandCodecError(
      `${field} must be a canonical ISO-8601 timestamp.`,
    );
  }
  return normalized;
}

function boundedText(value: unknown, field: string, maximum: number): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new SlackCommandCodecError(`${field} is invalid.`);
  }
  return value;
}

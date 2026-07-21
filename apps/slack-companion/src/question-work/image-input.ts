import { Buffer } from "node:buffer";

export const QUESTION_IMAGE_INPUT_LIMITS = {
  max_images: 4,
  max_image_bytes: 4 * 1024 * 1024,
  max_total_bytes: 8 * 1024 * 1024,
} as const;

export const QUESTION_IMAGE_CAPABILITY_REFS = [
  "agent.input.image",
  "slack.files.read",
] as const;

export type QuestionImageMimeType =
  | "image/gif"
  | "image/jpeg"
  | "image/png"
  | "image/webp";

/** Host-projected Slack metadata. file_ref stays opaque to portable code. */
export interface SlackQuestionImageFile {
  file_ref: string;
  mime_type: string;
  name?: string;
  size_bytes?: number;
}

export interface QuestionImageReferenceV1 {
  declared_bytes?: number;
  file_ref: string;
  mime_type: QuestionImageMimeType;
  name?: string;
}

/** Durable input contains references and bounds, never private image bytes. */
export interface QuestionImageInputManifestV1 {
  images: QuestionImageReferenceV1[];
  schema_version: "question-image-input/v1";
  total_declared_bytes: number;
}

export interface QuestionImagePlanV1 {
  manifest?: QuestionImageInputManifestV1;
  question: string;
  required_capability_refs: string[];
  schema_version: "question-image-plan/v1";
}

export interface QuestionImageReadResult {
  bytes: Uint8Array;
  mime_type: string;
}

/**
 * The host resolves one authenticated Slack file reference. It must not follow
 * an untrusted redirect or return more than max_bytes.
 */
export interface QuestionImageResolverPort {
  readImage(
    reference: QuestionImageReferenceV1,
    max_bytes: number,
  ): Promise<QuestionImageReadResult>;
}

/** Model-ready image content for Pi, Flue, or an equivalent vision runtime. */
export interface QuestionModelImageInput {
  data: string;
  mimeType: QuestionImageMimeType;
  type: "image";
}

export class QuestionImageInputError extends Error {}

export function planSlackQuestionImageInput(input: {
  files?: readonly SlackQuestionImageFile[];
  question?: string;
}): QuestionImagePlanV1 {
  const images = (input.files ?? []).flatMap((file) => {
    const mimeType = normalizeMimeType(file.mime_type);
    if (!mimeType.startsWith("image/")) return [];
    if (!isSupportedMimeType(mimeType)) {
      throw new QuestionImageInputError("Cerebro can inspect PNG, JPEG, WebP, and GIF images in Slack.");
    }
    requireReference(file.file_ref, "image file_ref");
    const declaredBytes = optionalBoundedBytes(file.size_bytes);
    const name = optionalName(file.name);
    return [{
      ...(declaredBytes === undefined ? {} : { declared_bytes: declaredBytes }),
      file_ref: file.file_ref,
      mime_type: mimeType,
      ...(name === undefined ? {} : { name }),
    } satisfies QuestionImageReferenceV1];
  });
  validateImageReferences(images);
  const question = input.question?.replace(/\s+/g, " ").trim()
    || (images.length > 0 ? "Inspect the attached image and explain what it shows." : "");
  if (!question) throw new QuestionImageInputError("A Slack question needs text or an image.");
  const manifest = images.length > 0 ? {
    images,
    schema_version: "question-image-input/v1" as const,
    total_declared_bytes: images.reduce((total, image) => total + (image.declared_bytes ?? 0), 0),
  } : undefined;
  return {
    ...(manifest === undefined ? {} : { manifest }),
    question,
    required_capability_refs: manifest ? [...QUESTION_IMAGE_CAPABILITY_REFS] : [],
    schema_version: "question-image-plan/v1",
  };
}

export async function resolveQuestionImageInput(
  manifest: QuestionImageInputManifestV1,
  resolver: QuestionImageResolverPort,
): Promise<QuestionModelImageInput[]> {
  validateManifest(manifest);
  const resolved: QuestionModelImageInput[] = [];
  let totalBytes = 0;
  for (const reference of manifest.images) {
    const result = await resolver.readImage(reference, QUESTION_IMAGE_INPUT_LIMITS.max_image_bytes);
    if (!(result.bytes instanceof Uint8Array) || result.bytes.byteLength === 0) {
      throw new QuestionImageInputError("The Slack image is empty or unavailable.");
    }
    if (result.bytes.byteLength > QUESTION_IMAGE_INPUT_LIMITS.max_image_bytes) {
      throw new QuestionImageInputError("Each Slack image must be 4 MB or smaller.");
    }
    const resolvedMimeType = normalizeMimeType(result.mime_type);
    if (!isSupportedMimeType(resolvedMimeType) || resolvedMimeType !== reference.mime_type) {
      throw new QuestionImageInputError("The downloaded Slack image type does not match its file metadata.");
    }
    totalBytes += result.bytes.byteLength;
    if (totalBytes > QUESTION_IMAGE_INPUT_LIMITS.max_total_bytes) {
      throw new QuestionImageInputError("Slack images must total 8 MB or less.");
    }
    resolved.push({
      data: Buffer.from(result.bytes).toString("base64"),
      mimeType: reference.mime_type,
      type: "image",
    });
  }
  return resolved;
}

function validateManifest(manifest: QuestionImageInputManifestV1): void {
  if (manifest.schema_version !== "question-image-input/v1") {
    throw new QuestionImageInputError("The question image manifest version is unsupported.");
  }
  validateImageReferences(manifest.images);
  const declared = manifest.images.reduce((total, image) => total + (image.declared_bytes ?? 0), 0);
  if (manifest.total_declared_bytes !== declared) {
    throw new QuestionImageInputError("The question image manifest byte total does not match its images.");
  }
}

function validateImageReferences(images: readonly QuestionImageReferenceV1[]): void {
  if (images.length > QUESTION_IMAGE_INPUT_LIMITS.max_images) {
    throw new QuestionImageInputError("Attach up to 4 images at a time.");
  }
  const refs = new Set<string>();
  let totalBytes = 0;
  for (const image of images) {
    requireReference(image.file_ref, "image file_ref");
    if (refs.has(image.file_ref)) throw new QuestionImageInputError("Slack image references must be distinct.");
    refs.add(image.file_ref);
    if (!isSupportedMimeType(image.mime_type)) {
      throw new QuestionImageInputError("Cerebro can inspect PNG, JPEG, WebP, and GIF images in Slack.");
    }
    if (image.declared_bytes !== undefined) {
      optionalBoundedBytes(image.declared_bytes);
      totalBytes += image.declared_bytes;
    }
  }
  if (totalBytes > QUESTION_IMAGE_INPUT_LIMITS.max_total_bytes) {
    throw new QuestionImageInputError("Slack images must total 8 MB or less.");
  }
}

function optionalBoundedBytes(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new QuestionImageInputError("Slack image size must be a positive integer.");
  }
  if (value > QUESTION_IMAGE_INPUT_LIMITS.max_image_bytes) {
    throw new QuestionImageInputError("Each Slack image must be 4 MB or smaller.");
  }
  return value;
}

function optionalName(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new QuestionImageInputError("Slack image names must be text.");
  const name = value.trim();
  if (!name || name.length > 500) throw new QuestionImageInputError("Slack image names must be 500 characters or fewer.");
  return name;
}

function normalizeMimeType(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.split(";", 1)[0]!.trim().toLowerCase();
}

function isSupportedMimeType(value: string): value is QuestionImageMimeType {
  return value === "image/gif" || value === "image/jpeg" || value === "image/png" || value === "image/webp";
}

function requireReference(value: string, label: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 2_048) {
    throw new QuestionImageInputError(`${label} must be a non-empty opaque reference within 2,048 characters.`);
  }
}

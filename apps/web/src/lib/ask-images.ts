export const ASK_IMAGE_MAX_COUNT = 4;
export const ASK_IMAGE_MAX_BYTES = 4 * 1024 * 1024;
export const ASK_IMAGE_TOTAL_MAX_BYTES = 8 * 1024 * 1024;
export const ASK_AGENT_REQUEST_MAX_BYTES = 12 * 1024 * 1024;

export const ASK_IMAGE_MEDIA_TYPES = [
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
] as const;

export type AskImageMediaType = (typeof ASK_IMAGE_MEDIA_TYPES)[number];

export type AskImageAttachment = {
  id: string;
  name: string;
  media_type: AskImageMediaType;
  data_url: string;
  size_bytes: number;
};

const mediaTypes = new Set<string>(ASK_IMAGE_MEDIA_TYPES);
const dataURLPattern = /^data:(image\/(?:png|jpeg|webp|gif));base64,([A-Za-z0-9+/]+={0,2})$/;

const decodedBase64Size = (value: string) => {
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return Math.floor((value.length * 3) / 4) - padding;
};

export const askImageError = (file: Pick<File, "name" | "size" | "type">) => {
  if (!mediaTypes.has(file.type)) return "Select a PNG, JPEG, WebP, or GIF image.";
  if (file.size > ASK_IMAGE_MAX_BYTES) return "Select an image 4 MB or smaller.";
  if (file.size <= 0) return "Select an image that is not empty.";
  return null;
};

export const parseAskImageDataURL = (value: unknown) => {
  if (typeof value !== "string") return null;
  const match = dataURLPattern.exec(value);
  if (!match) return null;
  const sizeBytes = decodedBase64Size(match[2]);
  if (sizeBytes <= 0 || sizeBytes > ASK_IMAGE_MAX_BYTES) return null;
  return {
    mediaType: match[1] as AskImageMediaType,
    sizeBytes,
  };
};

export const normalizeAskImages = (value: unknown): AskImageAttachment[] | null => {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > ASK_IMAGE_MAX_COUNT) return null;
  let totalBytes = 0;
  const images: AskImageAttachment[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const source = item as Record<string, unknown>;
    const parsed = parseAskImageDataURL(source.data_url);
    if (!parsed || source.media_type !== parsed.mediaType) return null;
    totalBytes += parsed.sizeBytes;
    if (totalBytes > ASK_IMAGE_TOTAL_MAX_BYTES) return null;
    images.push({
      id: typeof source.id === "string" && source.id.trim() ? source.id.trim().slice(0, 128) : `image-${images.length + 1}`,
      name: typeof source.name === "string" && source.name.trim() ? source.name.trim().slice(0, 255) : `image-${images.length + 1}`,
      media_type: parsed.mediaType,
      data_url: source.data_url as string,
      size_bytes: parsed.sizeBytes,
    });
  }
  return images;
};

const readFileAsDataURL = (file: File) => new Promise<string>((resolve, reject) => {
  const reader = new FileReader();
  reader.onerror = () => reject(new Error("The image could not be read."));
  reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
  reader.readAsDataURL(file);
});

export const addAskImageFiles = async (
  current: AskImageAttachment[],
  selected: File[],
): Promise<{ images: AskImageAttachment[]; error: string | null }> => {
  if (current.length + selected.length > ASK_IMAGE_MAX_COUNT) {
    return { images: current, error: "Attach up to 4 images." };
  }
  const invalid = selected.map(askImageError).find(Boolean);
  if (invalid) return { images: current, error: invalid };
  const selectedBytes = selected.reduce((total, file) => total + file.size, 0);
  const currentBytes = current.reduce((total, image) => total + image.size_bytes, 0);
  if (currentBytes + selectedBytes > ASK_IMAGE_TOTAL_MAX_BYTES) {
    return { images: current, error: "Keep attached images under 8 MB total." };
  }
  try {
    const additions = await Promise.all(selected.map(async (file, index) => ({
      id: typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `image-${Date.now()}-${index}`,
      name: file.name,
      media_type: file.type as AskImageMediaType,
      data_url: await readFileAsDataURL(file),
      size_bytes: file.size,
    })));
    return { images: [...current, ...additions], error: null };
  } catch (error) {
    return { images: current, error: error instanceof Error ? error.message : "The image could not be read." };
  }
};

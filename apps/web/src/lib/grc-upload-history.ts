import type { GRCUploadResponse } from "@/lib/grc";

export const GRC_UPLOAD_HISTORY_LIMIT = 5;

export const grcUploadHistoryKey = (target: string, tenantID: string) =>
  `cerebro.grc.uploads.${target}.${tenantID.trim() || "default"}`;

export const grcUploadHistoryWith = (
  current: GRCUploadResponse[],
  upload: GRCUploadResponse,
  limit = GRC_UPLOAD_HISTORY_LIMIT,
) => {
  const uploadID = upload.upload_id.trim();
  return [
    upload,
    ...current.filter((item) => item.upload_id.trim() !== uploadID),
  ].slice(0, limit);
};

export const readGRCUploadHistory = (storage: Storage | null | undefined, key: string) => {
  if (!storage) return [];
  try {
    const value = storage.getItem(key);
    if (!value) return [];
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is GRCUploadResponse =>
      Boolean(
        item &&
        typeof item === "object" &&
        typeof item.upload_id === "string" &&
        typeof item.file_name === "string" &&
        Array.isArray(item.events) &&
        typeof item.generated_at === "string",
      ),
    );
  } catch {
    return [];
  }
};

export const writeGRCUploadHistory = (
  storage: Storage | null | undefined,
  key: string,
  uploads: GRCUploadResponse[],
) => {
  if (!storage) return;
  storage.setItem(key, JSON.stringify(uploads.slice(0, GRC_UPLOAD_HISTORY_LIMIT)));
};

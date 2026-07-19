export const GRC_UPLOAD_MAX_BYTES = 32 * 1024 * 1024;
export const GRC_UPLOAD_MAX_LABEL = "32 MB";
export const GRC_UPLOAD_FILE_HELP = "PDF, Word, text, or Markdown. 32 MB max.";
export const GRC_UPLOAD_ACCEPT = ".pdf,.doc,.docx,.txt,.md,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/markdown";

const GRC_UPLOAD_ALLOWED_EXTENSIONS = new Set(["doc", "docx", "md", "pdf", "txt"]);
const GRC_UPLOAD_ALLOWED_MIME_TYPES = new Set([
  "application/msword",
  "application/pdf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/markdown",
  "text/plain",
]);

type UploadFile = { name?: string; size: number; type?: string };

export const grcUploadTooLargeMessage = () => `Select a file ${GRC_UPLOAD_MAX_LABEL} or smaller.`;

export const isGRCUploadWithinLimit = (file: Pick<UploadFile, "size"> | null | undefined) =>
  !file || file.size <= GRC_UPLOAD_MAX_BYTES;

export const isGRCUploadSupportedType = (file: Pick<UploadFile, "name" | "type"> | null | undefined) => {
  if (!file) return true;
  const extension = (file.name ?? "").split(".").pop()?.trim().toLowerCase();
  const mimeType = (file.type ?? "").trim().toLowerCase();
  return Boolean(
    (extension && GRC_UPLOAD_ALLOWED_EXTENSIONS.has(extension)) ||
    (mimeType && GRC_UPLOAD_ALLOWED_MIME_TYPES.has(mimeType)),
  );
};

export const grcUploadFileSizeLabel = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 10 * 1024 * 1024 ? 0 : 1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${Math.round(bytes)} B`;
};

export const grcUploadUnsupportedTypeMessage = () => "Select a PDF, Word, text, or Markdown file.";

export const grcUploadFileError = (file: UploadFile | null | undefined) => {
  if (!isGRCUploadWithinLimit(file)) return grcUploadTooLargeMessage();
  if (!isGRCUploadSupportedType(file)) return grcUploadUnsupportedTypeMessage();
  return null;
};

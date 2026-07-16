import { describe, expect, it } from "vitest";

import {
  GRC_UPLOAD_MAX_BYTES,
  grcUploadFileError,
  grcUploadFileSizeLabel,
  isGRCUploadSupportedType,
  isGRCUploadWithinLimit,
} from "./grc-upload-limits";

describe("GRC upload limits", () => {
  it("accepts files at the upload limit", () => {
    expect(isGRCUploadWithinLimit({ size: GRC_UPLOAD_MAX_BYTES })).toBe(true);
    expect(grcUploadFileError({ name: "policy.pdf", size: GRC_UPLOAD_MAX_BYTES, type: "application/pdf" })).toBeNull();
  });

  it("rejects files above the upload limit", () => {
    expect(isGRCUploadWithinLimit({ size: GRC_UPLOAD_MAX_BYTES + 1 })).toBe(false);
    expect(grcUploadFileError({ size: GRC_UPLOAD_MAX_BYTES + 1 })).toBe("Select a file 32 MB or smaller.");
  });

  it("accepts supported document types", () => {
    expect(isGRCUploadSupportedType({ name: "policy.pdf", type: "" })).toBe(true);
    expect(isGRCUploadSupportedType({ name: "policy", type: "text/markdown" })).toBe(true);
  });

  it("rejects unsupported document types", () => {
    expect(isGRCUploadSupportedType({ name: "policy.csv", type: "text/csv" })).toBe(false);
    expect(grcUploadFileError({ name: "policy.csv", size: 128, type: "text/csv" })).toBe("Select a PDF, Word, text, or Markdown file.");
  });

  it("formats selected file sizes", () => {
    expect(grcUploadFileSizeLabel(42)).toBe("42 B");
    expect(grcUploadFileSizeLabel(10 * 1024)).toBe("10 KB");
    expect(grcUploadFileSizeLabel(2.5 * 1024 * 1024)).toBe("2.5 MB");
  });
});

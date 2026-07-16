import { describe, expect, it } from "vitest";

import type { GRCUploadResponse } from "@/lib/grc";
import { grcUploadHistoryKey, grcUploadHistoryWith, readGRCUploadHistory } from "./grc-upload-history";

const upload = (uploadID: string, fileName = `${uploadID}.pdf`): GRCUploadResponse => ({
  upload_id: uploadID,
  target: "policy",
  file_name: fileName,
  events: [],
  generated_at: "2026-06-29T00:00:00Z",
});

describe("GRC upload history", () => {
  it("uses tenant-scoped storage keys", () => {
    expect(grcUploadHistoryKey("policy", "tenant-1")).toBe("cerebro.grc.uploads.policy.tenant-1");
    expect(grcUploadHistoryKey("policy", "")).toBe("cerebro.grc.uploads.policy.default");
  });

  it("deduplicates uploads by ID and keeps newest first", () => {
    const result = grcUploadHistoryWith([upload("one"), upload("two")], upload("one", "updated.pdf"));
    expect(result.map((item) => item.file_name)).toEqual(["updated.pdf", "two.pdf"]);
  });

  it("ignores malformed stored history", () => {
    const storage = {
      getItem: () => JSON.stringify([upload("one"), { upload_id: "two", file_name: "two.pdf" }, { nope: true }]),
    } as Storage;
    expect(readGRCUploadHistory(storage, "key")).toHaveLength(1);
  });
});

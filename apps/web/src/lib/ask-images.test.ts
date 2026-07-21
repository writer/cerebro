import { describe, expect, it } from "vitest";

import {
  ASK_IMAGE_MAX_BYTES,
  normalizeAskImages,
  parseAskImageDataURL,
} from "./ask-images";

describe("Ask image inputs", () => {
  it("normalizes supported inline images from their encoded bytes", () => {
    expect(normalizeAskImages([{
      id: " screenshot ",
      name: "risk.png",
      media_type: "image/png",
      data_url: "data:image/png;base64,iVBORw==",
      size_bytes: 999,
    }])).toEqual([{
      id: "screenshot",
      name: "risk.png",
      media_type: "image/png",
      data_url: "data:image/png;base64,iVBORw==",
      size_bytes: 4,
    }]);
  });

  it("rejects remote URLs, mismatched media types, and too many images", () => {
    expect(normalizeAskImages([{
      media_type: "image/png",
      data_url: "https://example.com/risk.png",
    }])).toBeNull();
    expect(normalizeAskImages([{
      media_type: "image/jpeg",
      data_url: "data:image/png;base64,iVBORw==",
    }])).toBeNull();
    expect(normalizeAskImages(Array.from({ length: 5 }, () => ({
      media_type: "image/png",
      data_url: "data:image/png;base64,iVBORw==",
    })))).toBeNull();
  });

  it("rejects decoded images above the per-image limit", () => {
    const encoded = "A".repeat(Math.ceil((ASK_IMAGE_MAX_BYTES + 1) / 3) * 4);
    expect(parseAskImageDataURL(`data:image/png;base64,${encoded}`)).toBeNull();
  });
});

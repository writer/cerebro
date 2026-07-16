import { describe, expect, it, vi } from "vitest";

import { forwardLegacyAskBody } from "./route";

describe("legacy Ask response streaming", () => {
  it("releases the reader after forwarding a complete response", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2]));
        controller.enqueue(new Uint8Array([3]));
        controller.close();
      },
    });
    const chunks: Uint8Array[] = [];

    await expect(forwardLegacyAskBody(body, (chunk) => chunks.push(chunk))).resolves.toEqual({
      chunkCount: 2,
      streamedBytes: 3,
    });
    expect(chunks).toHaveLength(2);
    expect(body.locked).toBe(false);
  });

  it("cancels upstream and releases the reader when forwarding fails", async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([1]));
      },
      cancel,
    });
    const failure = new Error("consumer closed");

    await expect(forwardLegacyAskBody(body, () => {
      throw failure;
    })).rejects.toBe(failure);
    expect(cancel).toHaveBeenCalledWith(failure);
    expect(body.locked).toBe(false);
  });
});

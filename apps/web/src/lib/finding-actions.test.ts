import { describe, expect, it, vi } from "vitest";

import { runFindingMutation } from "./finding-actions";

describe("finding mutations", () => {
  it("clears saving state and provides retryable copy after a network failure", async () => {
    const onError = vi.fn();
    const onSettled = vi.fn();
    const onSuccess = vi.fn();

    await expect(runFindingMutation({
      failurePrefix: "Finding update failed",
      onError,
      onSettled,
      onSuccess,
      request: async () => { throw new Error("network failed"); },
    })).resolves.toBe(false);

    expect(onError).toHaveBeenCalledWith("Finding update could not reach the API. Check your connection and retry.");
    expect(onSettled).toHaveBeenCalledOnce();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it("clears saving state after a successful update", async () => {
    const onSettled = vi.fn();
    const onSuccess = vi.fn();

    await expect(runFindingMutation({
      failurePrefix: "Finding update failed",
      onError: vi.fn(),
      onSettled,
      onSuccess,
      request: async () => ({ data: {}, ok: true, status: 200 }),
    })).resolves.toBe(true);

    expect(onSettled).toHaveBeenCalledOnce();
    expect(onSuccess).toHaveBeenCalledOnce();
  });
});

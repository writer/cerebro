import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  warmCerebroProxyCache: vi.fn(),
}));

vi.mock("@/lib/cerebro-proxy", () => ({
  warmCerebroProxyCache: mocks.warmCerebroProxyCache,
}));

type WarmerGlobal = typeof globalThis & {
  __cerebroProxyCacheWarmer?: ReturnType<typeof setInterval>;
};

afterEach(() => {
  const shared = globalThis as WarmerGlobal;
  if (shared.__cerebroProxyCacheWarmer) {
    clearInterval(shared.__cerebroProxyCacheWarmer);
    delete shared.__cerebroProxyCacheWarmer;
  }
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  mocks.warmCerebroProxyCache.mockReset();
});

describe("web instrumentation", () => {
  it("starts the dashboard warm without blocking server readiness", async () => {
    vi.stubEnv("NEXT_RUNTIME", "nodejs");
    const pending = Promise.withResolvers<"miss">();
    mocks.warmCerebroProxyCache.mockReturnValue(pending.promise);
    const { register } = await import("./instrumentation");

    await expect(register()).resolves.toBeUndefined();

    expect(mocks.warmCerebroProxyCache).toHaveBeenCalledOnce();
    expect(mocks.warmCerebroProxyCache).toHaveBeenCalledWith(
      "grc/dashboard",
      "?limit=12&enrichments=deferred&view=summary",
    );
    pending.resolve("miss");
    await pending.promise;
  });
});

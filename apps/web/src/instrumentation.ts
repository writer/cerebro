const HOME_DASHBOARD_PATH = "grc/dashboard";
const HOME_DASHBOARD_SEARCH = "?limit=12&enrichments=deferred&view=summary";
const WARM_INTERVAL_MS = 30_000;

type WarmerGlobal = typeof globalThis & {
  __cerebroProxyCacheWarmer?: ReturnType<typeof setInterval>;
};

export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  const { warmCerebroProxyCache } = await import("@/lib/cerebro-proxy");
  const warm = () => {
    void warmCerebroProxyCache(HOME_DASHBOARD_PATH, HOME_DASHBOARD_SEARCH)
      .catch((error: unknown) => {
        console.warn("cerebro dashboard cache warm failed", {
          error_kind: error instanceof Error ? error.constructor.name : typeof error,
        });
      });
  };

  warm();
  const shared = globalThis as WarmerGlobal;
  if (!shared.__cerebroProxyCacheWarmer) {
    shared.__cerebroProxyCacheWarmer = setInterval(warm, WARM_INTERVAL_MS);
    shared.__cerebroProxyCacheWarmer.unref?.();
  }
}

import {
  securityProducersFromValue,
  type SecurityProducer,
} from "@/lib/security-producers";

type FetchSecurityProducersOptions = {
  fetcher?: typeof fetch;
  signal?: AbortSignal;
};

export type SecurityProducerCatalogResult =
  | { state: "ready"; producers: SecurityProducer[] }
  | { state: "unavailable" };

const unavailable = (): SecurityProducerCatalogResult => ({ state: "unavailable" });

export const fetchSecurityProducers = async (
  options: FetchSecurityProducersOptions = {},
): Promise<SecurityProducerCatalogResult> => {
  try {
    const response = await (options.fetcher ?? fetch)("/api/security-producers", {
      cache: "no-store",
      signal: options.signal,
    });
    if (!response.ok) return unavailable();
    const payload = await response.json() as unknown;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return unavailable();
    const configured = (payload as Record<string, unknown>).producers;
    if (!Array.isArray(configured)) return unavailable();
    const producers = securityProducersFromValue(configured);
    if (producers.length !== configured.length) return unavailable();
    return { state: "ready", producers };
  } catch {
    return unavailable();
  }
};

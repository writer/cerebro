import {
  securityProducersFromValue,
  type SecurityProducer,
} from "@/lib/security-producers";

type FetchSecurityProducersOptions = {
  fetcher?: typeof fetch;
  signal?: AbortSignal;
};

export const fetchSecurityProducers = async (
  options: FetchSecurityProducersOptions = {},
): Promise<SecurityProducer[]> => {
  try {
    const response = await (options.fetcher ?? fetch)("/api/security-producers", {
      cache: "no-store",
      signal: options.signal,
    });
    if (!response.ok) return [];
    const payload = await response.json() as { producers?: unknown };
    return securityProducersFromValue(payload?.producers);
  } catch {
    return [];
  }
};

export const asRecord = (data: unknown): Record<string, unknown> | null => {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return null;
  }
  return data as Record<string, unknown>;
};

export const extractRecords = (
  data: unknown,
  keys: string[] = [
    "items",
    "results",
    "sources",
    "runtimes",
    "source_runtimes",
    "claims",
    "findings",
    "evidence",
    "runs",
    "reports",
    "rules",
    "nodes",
    "edges",
    "events",
    "timeline",
  ],
): Record<string, unknown>[] => {
  if (Array.isArray(data)) {
    return data.filter((item) => item && typeof item === "object") as Record<string, unknown>[];
  }

  const record = asRecord(data);
  if (!record) {
    return [];
  }

  for (const key of keys) {
    const value = record[key];
    if (Array.isArray(value)) {
      return value.filter((item) => item && typeof item === "object") as Record<string, unknown>[];
    }
  }

  return [];
};

export const firstString = (
  record: Record<string, unknown>,
  keys: string[],
): string | undefined => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
};

export const firstNumber = (
  record: Record<string, unknown>,
  keys: string[],
): number | undefined => {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (typeof value === "string" && value.length > 0) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
    }
  }
  return undefined;
};

export const withQuery = (path: string, params: Record<string, string | number>) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== "" && value != null) {
      query.set(key, String(value));
    }
  });
  const queryString = query.toString();
  return queryString ? `${path}?${queryString}` : path;
};

export const initialQueryParam = (key: string) => {
  if (typeof window === "undefined") {
    return "";
  }
  return new URLSearchParams(window.location.search).get(key) ?? "";
};

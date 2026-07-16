export type CerebroResponse<T = unknown> = {
  ok: boolean;
  status: number;
  contentType: string | null;
  data: T;
};

export const fetchCerebro = async <T = unknown>(
  path: string,
  apiKey?: string,
  init: RequestInit = {},
): Promise<CerebroResponse<T>> => {
  const headers = new Headers(init.headers);
  if (apiKey) {
    headers.set("X-API-Key", apiKey);
  }
  const response = await fetch(`/api/cerebro${path}`, {
    ...init,
    headers,
    cache: "no-store",
  });
  const text = await response.text();
  const contentType = response.headers.get("content-type");
  let data: unknown = text;

  if (contentType?.includes("json")) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  return {
    ok: response.ok,
    status: response.status,
    contentType,
    data: data as T,
  };
};

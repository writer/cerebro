export type AccessTokenProvider =
  | (() => Promise<string | undefined> | string | undefined)
  | undefined;

export interface HttpClientOptions {
  baseUrl: string;
  getAccessToken?: AccessTokenProvider;
  defaultHeaders?: Record<string, string>;
  fetch?: typeof fetch;
}

export type RequestOptions = Omit<RequestInit, "body"> & {
  body?: RequestInit["body"] | Record<string, unknown>;
  searchParams?: Record<string, string | number | boolean | undefined>;
};

export class HttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class HttpClient {
  private readonly baseUrl: string;
  private readonly getAccessToken?: AccessTokenProvider;
  private readonly defaultHeaders: Record<string, string>;
  private readonly fetchImpl: typeof fetch;

  constructor(options: HttpClientOptions) {
    if (!options.baseUrl) {
      throw new Error("baseUrl is required");
    }
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.getAccessToken = options.getAccessToken;
    this.defaultHeaders = options.defaultHeaders ?? {};
    const fetchCandidate = options.fetch ?? globalThis.fetch;
    if (!fetchCandidate) {
      throw new Error("No fetch implementation available; provide one via options.fetch");
    }
    this.fetchImpl = fetchCandidate.bind(globalThis);
  }

  get base(): string {
    return this.baseUrl;
  }

  async get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: "GET" });
  }

  async post<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: "POST" });
  }

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const { searchParams, body, ...rest } = options;
    const url = this.buildUrl(path, searchParams);
    const headers = await this.buildHeaders(rest.headers);

    const init: RequestInit = {
      ...rest,
      headers,
    };

    if (body !== undefined) {
      init.body = this.resolveBody(body, headers);
    }

    const response = await this.fetchImpl(url, init);

    const contentType = response.headers.get("content-type") || "";
    const isJson = contentType.includes("application/json");

    if (!response.ok) {
      const errorBody = isJson ? await response.json().catch(() => undefined) : await response.text();
      throw new HttpError(
        `Request to ${url} failed with status ${response.status}`,
        response.status,
        errorBody,
      );
    }

    if (response.status === 204) {
      return undefined as unknown as T;
    }

    if (isJson) {
      return (await response.json()) as T;
    }

    // Fallback to text when JSON is not provided
    return (await response.text()) as unknown as T;
  }

  private buildUrl(path: string, searchParams?: Record<string, string | number | boolean | undefined>): string {
    let target = path;
    if (!/^https?:/i.test(path)) {
      target = `${this.baseUrl}${path.startsWith("/") ? "" : "/"}${path}`;
    }
    const url = new URL(target);
    if (searchParams) {
      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined) continue;
        url.searchParams.set(key, String(value));
      }
    }
    return url.toString();
  }

  private async buildHeaders(headers?: HeadersInit): Promise<Headers> {
    const merged = new Headers();
    merged.set("accept", "application/json");
    for (const [key, value] of Object.entries(this.defaultHeaders)) {
      merged.set(key.toLowerCase(), value);
    }
    if (headers) {
      const headerObj = new Headers(headers);
      headerObj.forEach((value, key) => merged.set(key, value));
    }

    if (this.getAccessToken) {
      const tokenResult = this.getAccessToken();
      const token = typeof tokenResult === "string" ? tokenResult : await tokenResult;
      if (token && !merged.has("authorization")) {
        merged.set("authorization", `Bearer ${token}`);
      }
    }

    return merged;
  }

  private resolveBody(body: RequestOptions["body"], headers: Headers): BodyInit | null | undefined {
    if (body === null || typeof body === "string" || isBodyInit(body)) {
      return body as BodyInit | null | undefined;
    }

    if (isPlainObject(body)) {
      if (!headers.has("content-type")) {
        headers.set("content-type", "application/json");
      }
      return JSON.stringify(body);
    }

    return body as BodyInit | null | undefined;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isBodyInit(value: unknown): value is BodyInit {
  if (value === null) return true;
  if (typeof Blob !== "undefined" && value instanceof Blob) return true;
  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) return true;
  if (typeof FormData !== "undefined" && value instanceof FormData) return true;
  if (typeof URLSearchParams !== "undefined" && value instanceof URLSearchParams) return true;
  if (ArrayBuffer.isView(value)) return true;
  return false;
}

export default HttpClient;

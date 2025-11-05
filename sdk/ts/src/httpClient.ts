export type AccessTokenProvider =
  | (() => Promise<string | undefined> | string | undefined)
  | undefined;

export interface HttpClientOptions {
  baseUrl: string;
  getAccessToken?: AccessTokenProvider;
  defaultHeaders?: Record<string, string>;
  fetch?: typeof fetch;
  timeoutMs?: number;
  retry?: RetryOptions | number;
  beforeRequest?: HttpRequestMiddleware | HttpRequestMiddleware[];
  afterResponse?: HttpResponseMiddleware | HttpResponseMiddleware[];
}

export type RequestOptions = Omit<RequestInit, "body"> & {
  body?: RequestInit["body"] | Record<string, unknown>;
  searchParams?: Record<string, string | number | boolean | undefined>;
  retry?: RetryOptions | number;
  timeoutMs?: number;
};

export interface RetryOptions {
  retries?: number;
  delayMs?: number | ((attempt: number) => number);
  retryOn?: (response: Response | null, error: unknown | null, attempt: number) => boolean | Promise<boolean>;
}

export interface HttpRequestContext {
  url: string;
  init: RequestInit;
  attempt: number;
}

export type HttpRequestMiddleware = (context: HttpRequestContext) => Promise<void> | void;

export interface HttpResponseContext extends HttpRequestContext {
  response: Response;
}

export type HttpResponseMiddleware = (context: HttpResponseContext) => Promise<void> | void;

export class HttpTimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`Request timed out after ${timeoutMs}ms`);
    this.name = "HttpTimeoutError";
  }
}

export interface HttpStream<TChunk = Uint8Array> extends AsyncIterable<TChunk> {
  response: Response;
  cancel(reason?: unknown): Promise<void>;
  text(encoding?: string): AsyncIterable<string>;
}

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
  private readonly timeoutMs?: number;
  private readonly retryConfig?: RetryOptions | number;
  private readonly beforeRequestMiddlewares: HttpRequestMiddleware[];
  private readonly afterResponseMiddlewares: HttpResponseMiddleware[];

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
    this.timeoutMs = options.timeoutMs;
    this.retryConfig = options.retry;
    this.beforeRequestMiddlewares = toArray(options.beforeRequest);
    this.afterResponseMiddlewares = toArray(options.afterResponse);
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

  async put<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: "PUT" });
  }

  async patch<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: "PATCH" });
  }

  async delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, method: "DELETE" });
  }

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const response = await this.send(path, options);

    if (response.status === 204 || response.headers.get("content-length") === "0") {
      return undefined as unknown as T;
    }

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      return (await response.json()) as T;
    }

    return (await response.text()) as unknown as T;
  }

  async requestRaw(path: string, options: RequestOptions = {}): Promise<Response> {
    return this.send(path, options);
  }

  async stream(path: string, options: RequestOptions = {}): Promise<HttpStream> {
    const response = await this.send(path, options);
    if (!response.body) {
      throw new Error("Response body is not streamable for the requested endpoint");
    }
    return createHttpStream(response);
  }

  private async send(path: string, options: RequestOptions = {}): Promise<Response> {
    const {
      searchParams,
      body,
      retry: retryOverride,
      timeoutMs: requestTimeout,
      ...rest
    } = options;
    const url = this.buildUrl(path, searchParams);
    const normalizedRetry = normalizeRetryOptions(retryOverride ?? this.retryConfig);
    const timeoutMs = requestTimeout ?? this.timeoutMs;

    let attempt = 0;
    let lastError: unknown;

    while (attempt < normalizedRetry.maxAttempts) {
      attempt += 1;

      const headers = await this.buildHeaders(rest.headers);
      const init: RequestInit = { ...rest, headers };
      if (body !== undefined) {
        init.body = this.resolveBody(body, headers);
      }

      const requestContext: HttpRequestContext = {
        url,
        init,
        attempt,
      };

      await this.applyRequestMiddlewares(requestContext);

      try {
        const response = await this.performFetch(requestContext.url, requestContext.init, timeoutMs);
        const responseContext: HttpResponseContext = {
          ...requestContext,
          response,
        };

        await this.applyResponseMiddlewares(responseContext);

        if (!response.ok) {
          if (attempt < normalizedRetry.maxAttempts && await normalizedRetry.shouldRetry(response, null, attempt)) {
            if (response.body) {
              await response.body.cancel().catch(() => undefined);
            }
            await delay(normalizedRetry.getDelay(attempt));
            continue;
          }

          const errorBody = await parseErrorBody(response);
          throw new HttpError(
            `Request to ${requestContext.url} failed with status ${response.status}`,
            response.status,
            errorBody,
          );
        }

        return response;
      } catch (error) {
        if (error instanceof HttpError) {
          throw error;
        }

        lastError = error;
        if (attempt >= normalizedRetry.maxAttempts || !(await normalizedRetry.shouldRetry(null, error, attempt))) {
          throw error;
        }

        await delay(normalizedRetry.getDelay(attempt));
      }
    }

    throw lastError ?? new Error("Request failed after exhausting retry attempts");
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

  private async applyRequestMiddlewares(context: HttpRequestContext): Promise<void> {
    for (const middleware of this.beforeRequestMiddlewares) {
      await middleware(context);
    }
  }

  private async applyResponseMiddlewares(context: HttpResponseContext): Promise<void> {
    for (const middleware of this.afterResponseMiddlewares) {
      await middleware(context);
    }
  }

  private async performFetch(url: string, init: RequestInit, timeoutMs?: number): Promise<Response> {
    const { signal, cleanup } = this.composeSignal(init.signal, timeoutMs);
    try {
      const finalInit = signal ? { ...init, signal } : init;
      return await this.fetchImpl(url, finalInit);
    } finally {
      cleanup();
    }
  }

  private composeSignal(original: AbortSignal | null | undefined, timeoutMs?: number): { signal?: AbortSignal; cleanup: () => void } {
    const baseSignal = original ?? undefined;
    if (timeoutMs === undefined) {
      return { signal: baseSignal, cleanup: () => undefined };
    }

    if (timeoutMs <= 0 || typeof AbortController === "undefined") {
      return { signal: baseSignal, cleanup: () => undefined };
    }

    const timeoutController = new AbortController();
    const timeoutId = setTimeout(() => timeoutController.abort(new HttpTimeoutError(timeoutMs)), timeoutMs);
    const { signal, cleanup } = mergeSignals(baseSignal, timeoutController.signal);

    return {
      signal,
      cleanup: () => {
        clearTimeout(timeoutId);
        cleanup();
      },
    };
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

function normalizeRetryOptions(options?: RetryOptions | number): NormalizedRetryOptions {
  if (typeof options === "number") {
    return normalizeRetryOptions({ retries: options });
  }

  const retries = Math.max(0, options?.retries ?? 0);
  const maxAttempts = retries + 1;
  const delayConfig = options?.delayMs;
  const delayFn = typeof delayConfig === "function"
    ? delayConfig
    : (attempt: number) => {
        if (typeof delayConfig === "number") {
          return Math.max(0, delayConfig);
        }
        return defaultBackoffDelay(attempt);
      };
  const shouldRetry = options?.retryOn ?? defaultRetryEvaluator;

  return {
    maxAttempts,
    getDelay: (attempt: number) => delayFn(attempt),
    shouldRetry: async (response, error, attempt) => shouldRetry(response, error, attempt),
  };
}

const defaultRetryStatus = new Set([408, 425, 429, 500, 502, 503, 504]);

async function defaultRetryEvaluator(
  response: Response | null,
  error: unknown | null,
  _attempt: number,
): Promise<boolean> {
  if (response) {
    return defaultRetryStatus.has(response.status);
  }

  if (error instanceof HttpTimeoutError) {
    return true;
  }

  if (error instanceof DOMException && error.name === "AbortError") {
    return true;
  }

  return error instanceof TypeError;
}

interface NormalizedRetryOptions {
  maxAttempts: number;
  getDelay: (attempt: number) => number;
  shouldRetry: (response: Response | null, error: unknown | null, attempt: number) => Promise<boolean>;
}

const defaultBackoffDelay = (attempt: number): number => {
  const base = 200;
  return Math.min(2000, Math.round(base * 2 ** (attempt - 1)));
};

function delay(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function parseErrorBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch (error) {
      return { parseError: (error as Error)?.message };
    }
  }

  try {
    return await response.text();
  } catch (error) {
    return { parseError: (error as Error)?.message };
  }
}

function mergeSignals(primary?: AbortSignal, secondary?: AbortSignal): { signal?: AbortSignal; cleanup: () => void } {
  if (!primary) {
    return { signal: secondary, cleanup: () => undefined };
  }
  if (!secondary) {
    return { signal: primary, cleanup: () => undefined };
  }

  const anyFactory = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFactory === "function") {
    return { signal: anyFactory.call(AbortSignal, [primary, secondary]), cleanup: () => undefined };
  }

  const controller = new AbortController();

  const abortPrimary = () => controller.abort(primary.reason ?? new DOMException("Aborted", "AbortError"));
  const abortSecondary = () => controller.abort(secondary.reason ?? new DOMException("Aborted", "AbortError"));

  if (primary.aborted) {
    controller.abort(primary.reason ?? new DOMException("Aborted", "AbortError"));
  } else {
    primary.addEventListener("abort", abortPrimary);
  }

  if (!controller.signal.aborted) {
    if (secondary.aborted) {
      controller.abort(secondary.reason ?? new DOMException("Aborted", "AbortError"));
    } else {
      secondary.addEventListener("abort", abortSecondary);
    }
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      primary.removeEventListener("abort", abortPrimary);
      secondary.removeEventListener("abort", abortSecondary);
    },
  };
}

function toArray<T>(input?: T | T[]): T[] {
  if (!input) return [];
  return Array.isArray(input) ? input : [input];
}

function createHttpStream(response: Response): HttpStream {
  const body = response.body;
  if (!body) {
    throw new Error("Response does not include a readable body");
  }

  const byteIterable: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      const reader = body.getReader();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) {
            break;
          }
          if (value) {
            yield value;
          }
        }
      } finally {
        reader.releaseLock();
      }
    },
  };

  return {
    response,
    async cancel(reason?: unknown) {
      await body.cancel(reason).catch(() => undefined);
    },
    [Symbol.asyncIterator]() {
      return byteIterable[Symbol.asyncIterator]();
    },
    text(encoding = "utf-8") {
      const decoder = new TextDecoder(encoding);
      return {
        async *[Symbol.asyncIterator]() {
          let emitted = false;
          for await (const chunk of byteIterable) {
            emitted = true;
            yield decoder.decode(chunk, { stream: true });
          }
          const tail = decoder.decode();
          if (tail || !emitted) {
            if (tail) {
              yield tail;
            }
          }
        },
      };
    },
  };
}

export default HttpClient;

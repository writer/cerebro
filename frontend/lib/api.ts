import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from "axios";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN;
const WITH_CREDENTIALS = process.env.NEXT_PUBLIC_API_WITH_CREDENTIALS
  ? process.env.NEXT_PUBLIC_API_WITH_CREDENTIALS === "true"
  : true;
const CSRF_HEADER_NAME = process.env.NEXT_PUBLIC_CSRF_HEADER_NAME ?? "X-CSRF-Token";
const CSRF_COOKIE_NAME = process.env.NEXT_PUBLIC_CSRF_COOKIE_NAME ?? "cerebro_csrf_token";

type RetriableConfig = AxiosRequestConfig & { __isRetryRequest?: boolean };

let client: AxiosInstance | null = null;
let refreshPromise: Promise<void> | null = null;

const refreshClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: WITH_CREDENTIALS,
  headers: {
    "Content-Type": "application/json",
  },
});

export function setAuthTokens(_: { accessToken?: string | null; refreshToken?: string | null }) {
  // Tokens are managed via HTTP-only cookies; this function is retained for compatibility.
}

export function clearAuthTokens() {
  // No-op: cookie management occurs server-side.
}

function readCookie(name: string): string | null {
  if (typeof document === "undefined") {
    return null;
  }
  const value = document.cookie
    .split(";")
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith(`${name}=`));
  return value ? decodeURIComponent(value.split("=")[1]) : null;
}

function applyCsrfHeader(config: AxiosRequestConfig) {
  const method = (config.method ?? "get").toUpperCase();
  if (["GET", "HEAD", "OPTIONS"].includes(method)) {
    return;
  }

  const csrfToken = readCookie(CSRF_COOKIE_NAME);
  if (!csrfToken) {
    return;
  }

  config.headers = config.headers ?? {};
  config.headers[CSRF_HEADER_NAME] = csrfToken;
}

function attachInterceptors(instance: AxiosInstance) {
  instance.interceptors.request.use((config) => {
    if (API_TOKEN) {
      config.headers = config.headers ?? {};
      config.headers.Authorization = `Bearer ${API_TOKEN}`;
    }

    applyCsrfHeader(config);
    return config;
  });

  instance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const { response } = error;
      const originalConfig = error.config as RetriableConfig | undefined;

      if (!response || !originalConfig) {
        return Promise.reject(error);
      }

      if (response.status === 401 && !API_TOKEN) {
        if (originalConfig.__isRetryRequest) {
          return Promise.reject(error);
        }

        originalConfig.__isRetryRequest = true;

        if (refreshPromise === null) {
          refreshPromise = refreshClient
            .post("/auth/refresh", {})
            .then(() => void 0)
            .catch((refreshError) => {
              throw refreshError;
            });
        }

        try {
          await refreshPromise;
          return instance.request(originalConfig);
        } catch (refreshError) {
          return Promise.reject(refreshError);
        } finally {
          refreshPromise = null;
        }
      }

      return Promise.reject(error);
    }
  );
}

function getClient(): AxiosInstance {
  if (!client) {
    client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        "Content-Type": "application/json",
        ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
      },
      withCredentials: WITH_CREDENTIALS,
    });

    attachInterceptors(client);
  }

  return client;
}

attachInterceptors(refreshClient);

export async function apiGet<T>(path: string, params?: Record<string, unknown>) {
  const response = await getClient().get<T>(path, { params });
  return response.data;
}

export async function apiPost<T>(path: string, body: unknown) {
  const response = await getClient().post<T>(path, body);
  return response.data;
}

export async function apiGetBlob(
  path: string,
  params?: Record<string, unknown>,
  responseType: "blob" | "arraybuffer" | "text" = "blob",
) {
  const response = await getClient().get(path, { params, responseType });
  return response.data;
}

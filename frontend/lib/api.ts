import axios, { AxiosError, AxiosInstance, AxiosRequestConfig } from "axios";

// Fallback to local FastAPI instance when environment variables are not provided.
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN;
const WITH_CREDENTIALS = !!process.env.NEXT_PUBLIC_API_WITH_CREDENTIALS;

const ACCESS_TOKEN_KEY = "cerebro_access_token";
const REFRESH_TOKEN_KEY = "cerebro_refresh_token";

let client: AxiosInstance | null = null;
let refreshPromise: Promise<string | null> | null = null;
let tokensInitialized = false;
let inMemoryAccessToken: string | null = API_TOKEN ?? null;
let inMemoryRefreshToken: string | null = null;

type RetriableConfig = AxiosRequestConfig & { __isRetryRequest?: boolean };

const refreshClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: WITH_CREDENTIALS,
  headers: {
    "Content-Type": "application/json",
  },
});

function initializeTokensFromStorage() {
  if (tokensInitialized) {
    return;
  }
  tokensInitialized = true;

  if (typeof window === "undefined") {
    return;
  }

  const storedAccess = localStorage.getItem(ACCESS_TOKEN_KEY);
  const storedRefresh = localStorage.getItem(REFRESH_TOKEN_KEY);

  if (storedAccess) {
    inMemoryAccessToken = storedAccess;
  }
  if (storedRefresh) {
    inMemoryRefreshToken = storedRefresh;
  }
}

function setStoredAccessToken(token: string | null) {
  if (typeof window === "undefined") {
    return;
  }
  if (token) {
    localStorage.setItem(ACCESS_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
  }
}

function setStoredRefreshToken(token: string | null) {
  if (typeof window === "undefined") {
    return;
  }
  if (token) {
    localStorage.setItem(REFRESH_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }
}

function getStoredRefreshToken() {
  if (typeof window === "undefined") {
    return null;
  }
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setAuthTokens(tokens: { accessToken?: string | null; refreshToken?: string | null }) {
  initializeTokensFromStorage();

  if (Object.prototype.hasOwnProperty.call(tokens, "accessToken")) {
    inMemoryAccessToken = tokens.accessToken ?? null;
    setStoredAccessToken(inMemoryAccessToken);

    if (client) {
      if (inMemoryAccessToken) {
        client.defaults.headers.common.Authorization = `Bearer ${inMemoryAccessToken}`;
      } else {
        delete client.defaults.headers.common.Authorization;
      }
    }
  }

  if (Object.prototype.hasOwnProperty.call(tokens, "refreshToken")) {
    inMemoryRefreshToken = tokens.refreshToken ?? null;
    setStoredRefreshToken(inMemoryRefreshToken);
  }
}

export function clearAuthTokens() {
  setAuthTokens({ accessToken: null, refreshToken: null });
}

async function refreshAccessToken(): Promise<string | null> {
  initializeTokensFromStorage();
  const refreshToken = inMemoryRefreshToken ?? getStoredRefreshToken();
  if (!refreshToken) {
    return null;
  }

  try {
    const response = await refreshClient.post<{ access_token: string; refresh_token?: string }>(
      "/auth/refresh",
      { refresh_token: refreshToken }
    );

    const { access_token: accessToken, refresh_token: nextRefreshToken } = response.data;

    if (!accessToken) {
      clearAuthTokens();
      return null;
    }

    setAuthTokens({
      accessToken,
      refreshToken: nextRefreshToken ?? refreshToken,
    });

    return accessToken;
  } catch (error) {
    clearAuthTokens();
    return null;
  }
}

function attachInterceptors(instance: AxiosInstance) {
  instance.interceptors.request.use((config) => {
    initializeTokensFromStorage();

    const token = inMemoryAccessToken ?? API_TOKEN ?? null;
    if (token) {
      config.headers = config.headers ?? {};
      config.headers.Authorization = `Bearer ${token}`;
    } else if (config.headers?.Authorization) {
      delete config.headers.Authorization;
    }

    return config;
  });

  instance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const response = error.response;
      const originalConfig = error.config as RetriableConfig | undefined;

      if (!response || !originalConfig) {
        return Promise.reject(error);
      }

      if (response.status === 401) {
        if (originalConfig.__isRetryRequest) {
          clearAuthTokens();
          return Promise.reject(error);
        }

        originalConfig.__isRetryRequest = true;

        refreshPromise = refreshPromise ?? refreshAccessToken();
        const newToken = await refreshPromise;
        refreshPromise = null;

        if (newToken) {
          originalConfig.headers = originalConfig.headers ?? {};
          originalConfig.headers.Authorization = `Bearer ${newToken}`;
          return instance.request(originalConfig);
        }

        clearAuthTokens();
      }

      return Promise.reject(error);
    }
  );
}

function getClient(): AxiosInstance {
  if (!client) {
    initializeTokensFromStorage();

    client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        "Content-Type": "application/json",
        ...(API_TOKEN && !inMemoryAccessToken ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
      },
      withCredentials: WITH_CREDENTIALS,
    });

    if (inMemoryAccessToken) {
      client.defaults.headers.common.Authorization = `Bearer ${inMemoryAccessToken}`;
    }

    attachInterceptors(client);
  }

  return client;
}

export async function apiGet<T>(path: string, params?: Record<string, unknown>) {
  const response = await getClient().get<T>(path, { params });
  return response.data;
}

export async function apiPost<T>(path: string, body: unknown) {
  const response = await getClient().post<T>(path, body);
  return response.data;
}

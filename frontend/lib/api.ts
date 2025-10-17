import axios, { AxiosInstance } from "axios";

// Fallback to local FastAPI instance when environment variables are not provided.
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN;

let client: AxiosInstance | null = null;

function getClient(): AxiosInstance {
  if (!client) {
    client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        "Content-Type": "application/json",
        ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {})
      },
      withCredentials: !!process.env.NEXT_PUBLIC_API_WITH_CREDENTIALS
    });
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

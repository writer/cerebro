export const API_BASE =
  process.env.NEXT_PUBLIC_CEREBRO_API_BASE ?? "http://localhost:8080";

export const normalizePath = (path: string) =>
  path.startsWith("/") ? path : `/${path}`;

export const buildApiUrl = (path: string) => {
  const normalized = normalizePath(path);
  return `${API_BASE.replace(/\/$/, "")}${normalized}`;
};

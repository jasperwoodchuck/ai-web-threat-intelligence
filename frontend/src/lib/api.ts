const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim() ?? "";
const API_BASE_URL = configuredBaseUrl.replace(/\/+$/, "");

export const isProductionApiConfigured = import.meta.env.DEV || API_BASE_URL.length > 0;
export const analysisApiBaseUrl = API_BASE_URL;

export function apiUrl(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
}

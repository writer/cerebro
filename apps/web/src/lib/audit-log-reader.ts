import {
  auditLogSearchParams,
  normalizeAuditLogPage,
  type AuditLogPage,
  type AuditLogQuery,
} from "./audit-log";

export const AUDIT_EVENT_CONTRACT_PATH = "platform/audit-events";

export interface AuditLogReader {
  list(query: AuditLogQuery, signal?: AbortSignal): Promise<AuditLogPage>;
}

export class AuditLogReaderError extends Error {
  readonly status: number;

  constructor(message: string, status = 502) {
    super(message);
    this.name = "AuditLogReaderError";
    this.status = status;
  }
}

type HttpAuditLogReaderOptions = {
  endpoint: URL;
  fetcher?: typeof fetch;
  headers?: HeadersInit;
};

export function createHttpAuditLogReader({
  endpoint,
  fetcher = fetch,
  headers,
}: HttpAuditLogReaderOptions): AuditLogReader {
  return {
    async list(query, signal) {
      const target = new URL(endpoint);
      target.search = auditLogSearchParams(query).toString();

      let response: Response;
      try {
        response = await fetcher(target, {
          cache: "no-store",
          headers,
          method: "GET",
          signal,
        });
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          throw new AuditLogReaderError("Audit events request timed out.", 504);
        }
        throw new AuditLogReaderError("Audit events are unavailable.");
      }

      if (!response.ok) {
        throw new AuditLogReaderError("Audit events are unavailable.");
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new AuditLogReaderError("Audit events response was invalid.");
      }
      try {
        return normalizeAuditLogPage(payload);
      } catch {
        throw new AuditLogReaderError("Audit events response was invalid.");
      }
    },
  };
}

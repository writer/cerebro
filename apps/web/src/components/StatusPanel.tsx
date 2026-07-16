"use client";

import { useCallback, useEffect, useState } from "react";

import { useApiKey, useCurrentUser } from "@/components/providers";
import { identityPosture } from "@/lib/identity";
import { RuntimeState, runtimeStateCopy, runtimeStateForError, runtimeStateLabel } from "@/lib/runtime-state";

type StatusState = {
  config?: {
    apiBase?: string;
    forwardRequestAuth?: boolean;
    serverAuthConfigured?: boolean;
  };
  health?: Record<string, unknown>;
  healthz?: Record<string, unknown>;
  probes?: ProbeResult[];
  checkedAt?: string;
  error?: string;
};

type ProbeResult = {
  data?: Record<string, unknown>;
  durationMs: number;
  key: string;
  label: string;
  ok: boolean;
  path: string;
  state: RuntimeState;
  status: number;
};

const STATUS_TIMEOUT_MS = 5000;
const STATUS_PROBES = [
  { key: "health", label: "API health", path: "/api/cerebro/health" },
  { key: "healthz", label: "API healthz", path: "/api/cerebro/healthz" },
  { key: "dashboard", label: "Dashboard proxy", path: "/api/cerebro/grc/dashboard?limit=1&view=summary" },
];

const parseStatus = async (response: Response): Promise<Record<string, unknown>> => {
  const text = await response.text();
  let body: unknown = text;
  if (response.headers.get("content-type")?.includes("json")) {
    try { body = JSON.parse(text); } catch { body = text; }
  }
  const result = body && typeof body === "object" && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : { status: response.ok ? "ok" : "unavailable", response: body };
  if (!response.ok) return { ...result, status_code: response.status, status_text: response.statusText };
  return result;
};

const formatValue = (value: unknown) => {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Date) return value.toISOString();
  return JSON.stringify(value);
};

const stateClass = (state: RuntimeState) => {
  if (state === "ready") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (state === "permission-denied") return "border-amber-200 bg-amber-50 text-amber-700";
  if (state === "unavailable" || state === "partial" || state === "stale") return "border-amber-200 bg-amber-50 text-amber-700";
  if (state === "error") return "border-red-200 bg-red-50 text-red-700";
  return "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-muted)]";
};

export default function StatusPanel() {
  const { apiKey } = useApiKey();
  const { error: identityError, loading: identityLoading, user } = useCurrentUser();
  const [state, setState] = useState<StatusState>({});
  const [loading, setLoading] = useState(true);
  const identity = identityPosture({ error: identityError, loading: identityLoading, user });

  const fetchStatus = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    const headers: HeadersInit = apiKey ? { "X-API-Key": apiKey } : {};

    const runProbe = async (probe: typeof STATUS_PROBES[number]): Promise<ProbeResult> => {
      const started = performance.now();
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal?.addEventListener("abort", abort, { once: true });
      const timer = window.setTimeout(() => controller.abort(), STATUS_TIMEOUT_MS);
      try {
        const response = await fetch(probe.path, { headers, cache: "no-store", signal: controller.signal });
        const data = await parseStatus(response);
        return {
          ...probe,
          data,
          durationMs: Math.round(performance.now() - started),
          ok: response.ok,
          state: response.ok ? "ready" : runtimeStateForError(String(response.status)),
          status: response.status,
        };
      } catch (err) {
        const message = controller.signal.aborted && !signal?.aborted
          ? `Timed out after ${STATUS_TIMEOUT_MS}ms`
          : err instanceof Error ? err.message : "Unable to reach API";
        return {
          ...probe,
          data: { error: message, status: "unavailable" },
          durationMs: Math.round(performance.now() - started),
          ok: false,
          state: runtimeStateForError(message),
          status: 0,
        };
      } finally {
        signal?.removeEventListener("abort", abort);
        window.clearTimeout(timer);
      }
    };

    try {
      const configPromise = fetch("/api/config", { cache: "no-store", signal })
        .then((response) => response.ok ? response.json() as Promise<StatusState["config"]> : undefined)
        .catch(() => undefined);
      const [configJson, probes] = await Promise.all([
        configPromise,
        Promise.all(STATUS_PROBES.map(runProbe)),
      ]);
      if (signal?.aborted) return;
      const health = probes.find((probe) => probe.key === "health")?.data;
      const healthz = probes.find((probe) => probe.key === "healthz")?.data;
      setState({ checkedAt: new Date().toISOString(), config: configJson, health, healthz, probes });
    } catch (err) {
      if (!signal?.aborted) setState({ error: err instanceof Error ? err.message : "Unable to reach API" });
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [apiKey]);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void fetchStatus(controller.signal), 0);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [fetchStatus]);

  const probes = state.probes ?? [];
  const failingProbes = probes.filter((probe) => !probe.ok);
  const overallState: RuntimeState = loading ? "loading" : state.error ? "error" : failingProbes.length > 0 ? "partial" : "ready";

  return (
    <div id="quick-status" className="surface-panel">
      <div className="flex items-center justify-between border-b border-[color:var(--border)] px-5 py-3.5">
        <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">Runtime Health</h3>
        <div className="flex items-center gap-3">
          {state.checkedAt && <span className="text-[11px] text-[var(--text-muted)]">Checked {new Date(state.checkedAt).toLocaleTimeString()}</span>}
          <button type="button" onClick={() => void fetchStatus()} disabled={loading} className="secondary-button px-2.5 py-1.5 text-[12px]">
            {loading ? "Checking..." : "Refresh"}
          </button>
        </div>
      </div>
      <div className="p-5">
        <div className="space-y-4">
          <div className={`rounded-lg border px-4 py-3 text-[13px] ${stateClass(overallState)}`}>
            <div className="font-semibold">{runtimeStateCopy[overallState].label}</div>
            <div className="mt-1 text-[12px]">{state.error || runtimeStateCopy[overallState].description}</div>
          </div>

          <div className="grid gap-3 lg:grid-cols-4">
            {[
              { label: "Web app", value: loading ? "Checking" : "Ready", detail: "Local UI is responding" },
              { label: "Identity", value: identity.label, detail: identity.sourceLabel },
              { label: "API base", value: state.config?.apiBase ?? "Unknown", detail: state.config?.serverAuthConfigured ? "server auth configured" : "server auth not configured" },
              { label: "Auth forwarding", value: state.config?.forwardRequestAuth ? "Enabled" : "Disabled", detail: apiKey ? "API key present" : "no API key in browser" },
            ].map((item) => (
              <div key={item.label} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{item.label}</div>
                <div className="mt-1 break-all text-[13px] font-semibold text-[var(--text-primary)]">{item.value}</div>
                <div className="mt-1 break-all text-[11px] text-[var(--text-muted)]">{item.detail}</div>
              </div>
            ))}
          </div>

          <div className="overflow-hidden rounded-lg border border-[color:var(--border)]">
            <table className="w-full text-left text-[12px]">
              <thead className="bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                <tr>
                  <th className="px-3 py-2 font-semibold">Probe</th>
                  <th className="px-3 py-2 font-semibold">State</th>
                  <th className="px-3 py-2 font-semibold">Status</th>
                  <th className="px-3 py-2 font-semibold">Latency</th>
                  <th className="px-3 py-2 font-semibold">Path</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--border)]">
                {(probes.length > 0 ? probes : STATUS_PROBES.map((probe) => ({
                  ...probe,
                  durationMs: 0,
                  ok: false,
                  state: loading ? "loading" as RuntimeState : "unavailable" as RuntimeState,
                  status: 0,
                }))).map((probe) => (
                  <tr key={probe.key} className="bg-[var(--surface)]">
                    <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{probe.label}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded-full border px-2 py-0.5 text-[11px] ${stateClass(probe.state)}`}>
                        {runtimeStateLabel(probe.state)}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">{probe.status || "—"}</td>
                    <td className="px-3 py-2 text-[var(--text-secondary)]">{probe.durationMs ? `${probe.durationMs}ms` : "—"}</td>
                    <td className="px-3 py-2 font-mono text-[var(--text-muted)]">{probe.path}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {!loading && !state.error && (
            <div className="grid gap-4 md:grid-cols-2">
              {[
                { title: "Health", data: state.health },
                { title: "Healthz", data: state.healthz },
              ].map((block) => (
                <div key={block.title} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-4">
                  <div className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]">{block.title}</div>
                  <div className="mt-2 space-y-1.5">
                    {block.data && Object.entries(block.data).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between gap-2 text-[12px]">
                        <span className="text-[var(--text-muted)]">{key}</span>
                        <span className="text-right font-mono text-[var(--text-primary)]">{formatValue(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

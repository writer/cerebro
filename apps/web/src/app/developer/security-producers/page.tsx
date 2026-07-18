"use client";

import { useEffect, useState } from "react";

import { PageHeader, Panel } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import {
  fetchSecurityProducers,
  type SecurityProducerCatalogResult,
} from "@/lib/security-producers-client";

type RuntimeSnapshot = {
  ok: boolean;
  status: number;
  data: unknown;
};

type ProducerCatalogState = SecurityProducerCatalogResult | { state: "loading" };

export default function SecurityProducersPage() {
  const [snapshot, setSnapshot] = useState<RuntimeSnapshot | null>(null);
  const [producerCatalog, setProducerCatalog] = useState<ProducerCatalogState>({ state: "loading" });
  const [producerCatalogRequest, setProducerCatalogRequest] = useState(0);

  useEffect(() => {
    let cancelled = false;
    fetchCerebro("/source-runtimes")
      .then((response) => {
        if (!cancelled) {
          setSnapshot({ ok: response.ok, status: response.status, data: response.data });
        }
      })
      .catch((error: Error) => {
        if (!cancelled) {
          setSnapshot({ ok: false, status: 0, data: error.message });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    fetchSecurityProducers({ signal: controller.signal }).then((result) => {
      if (!cancelled) {
        setProducerCatalog(result);
      }
    });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [producerCatalogRequest]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Producers"
        description="Source runtime coverage, graph context tools, and security producer queries."
      />

      <Panel title="Runtime Health Snapshot">
        {!snapshot && <div className="text-[13px] text-slate-500">Loading runtime snapshot...</div>}
        {snapshot && (
          <div className={snapshot.ok ? "text-[13px] text-slate-700" : "text-[13px] text-red-600"}>
            `/source-runtimes` returned status {snapshot.status || "unavailable"}.
          </div>
        )}
      </Panel>

      <Panel title="Producer Coverage">
        {producerCatalog.state === "loading" ? (
          <div className="rounded-md border border-slate-200 bg-slate-50 p-4 text-[13px] text-slate-600">
            Loading producer catalog...
          </div>
        ) : producerCatalog.state === "unavailable" ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 p-4 text-[13px] text-amber-900">
            <div>Producer catalog is unavailable. Check your access or service connection, then retry.</div>
            <button
              type="button"
              className="mt-3 rounded-md border border-amber-300 bg-white px-3 py-1.5 text-[12px] font-semibold text-amber-900 hover:bg-amber-100"
              onClick={() => {
                setProducerCatalog({ state: "loading" });
                setProducerCatalogRequest((request) => request + 1);
              }}
            >
              Retry
            </button>
          </div>
        ) : producerCatalog.producers.length === 0 ? (
          <div className="rounded-md border border-slate-200 bg-slate-50 p-4 text-[13px] text-slate-600">
            No security producers are configured for this deployment.
          </div>
        ) : (
          <div className="grid gap-3 lg:grid-cols-3">
            {producerCatalog.producers.map((producer) => (
              <div key={producer.id} className="rounded-md border border-slate-200 bg-slate-50 p-4">
                <div className="text-[13px] font-semibold text-slate-900">{producer.label}</div>
                {producer.description && <div className="mt-1 text-[12px] leading-5 text-slate-600">{producer.description}</div>}
                {producer.repo && <div className="mt-1 text-[12px] text-slate-500">{producer.repo}</div>}
                <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-500">Runtimes / Sources</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {producer.runtimeIds.length === 0 && producer.sourceIds.length === 0 && <span className="text-[12px] text-slate-500">No runtimes configured.</span>}
                  {producer.runtimeIds.map((runtimeID) => (
                    <span key={runtimeID} className="rounded bg-white px-2 py-0.5 text-[11px] text-slate-700 ring-1 ring-slate-200">
                      {runtimeID}
                    </span>
                  ))}
                  {producer.sourceIds.map((sourceID) => (
                    <span key={sourceID} className="rounded bg-indigo-50 px-2 py-0.5 text-[11px] text-indigo-700 ring-1 ring-indigo-100">
                      {sourceID}
                    </span>
                  ))}
                </div>
                <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-500">MCP / Graph Context</div>
                <div className="mt-1 flex flex-wrap gap-1">
                  {producer.mcpTools.length === 0 && <span className="text-[12px] text-slate-500">No tools configured.</span>}
                  {producer.mcpTools.map((tool) => (
                    <span key={tool} className="rounded bg-white px-2 py-0.5 text-[11px] text-slate-700 ring-1 ring-slate-200">
                      {tool}
                    </span>
                  ))}
                </div>
                {producer.responseActions.length > 0 && (
                  <>
                    <div className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-slate-500">Response Actions</div>
                    <div className="mt-1 divide-y divide-slate-200">
                      {producer.responseActions.map((action) => (
                        <div key={`${action.id}-${action.runtimeAction ?? action.mcpTool ?? action.mode}`} className="py-2 text-[11px] text-slate-700">
                          <div className="flex flex-wrap items-center justify-between gap-1">
                            <span className="font-semibold text-slate-900">{action.label}</span>
                            <span className="font-mono text-slate-500">{action.id}</span>
                          </div>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {[...action.providers, action.mode, action.dryRun ? "dry-run" : "", action.requiresApproval ? "approval" : ""].filter(Boolean).map((chip) => (
                              <span key={chip} className="rounded bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-600 ring-1 ring-slate-100">
                                {chip}
                              </span>
                            ))}
                          </div>
                          {(action.mcpTool || action.runtimeAction) && (
                            <div className="mt-1 truncate font-mono text-[10px] text-slate-500">
                              {action.mcpTool ?? "runtime"} {action.runtimeAction ? `-> ${action.runtimeAction}` : ""}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </>
                )}
                {(producer.resourceTemplates.length > 0 || producer.contextKeys.length > 0) && (
                  <div className="mt-3 grid gap-2 text-[12px] text-slate-600">
                    {producer.resourceTemplates.length > 0 && (
                      <div>
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Resources</div>
                        <div className="mt-1 space-y-1">
                          {producer.resourceTemplates.slice(0, 3).map((template) => (
                            <div key={template} className="truncate rounded bg-white px-2 py-1 font-mono text-[11px] text-slate-600 ring-1 ring-slate-200">
                              {template}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {producer.contextKeys.length > 0 && (
                      <div>
                        <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Ask context</div>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {producer.contextKeys.map((key) => (
                            <span key={key} className="rounded bg-white px-2 py-0.5 font-mono text-[11px] text-slate-600 ring-1 ring-slate-200">
                              {key}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

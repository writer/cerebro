"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { PageHeader, Panel } from "@/components/grc/Primitives";
import { useApiKey } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import {
  AGENT_PLATFORM_FALLBACK_CONTRACT,
  agentPlatformDomainById,
  normalizeAgentPlatformContract,
  type AgentPlatformCapability,
  type AgentPlatformContract,
  type AgentPlatformRuntimeEvent,
} from "@/lib/agent-platform-contract";

type ContractSource = "api" | "fallback";

type ContractState = {
  contract: AgentPlatformContract;
  error?: string;
  source: ContractSource;
  status?: number;
};

const CAPABILITY_LIMIT = 40;
const EVENT_LIMIT = 40;
const REQUIREMENT_LIMIT = 30;
const INVARIANT_LIMIT = 30;

const emptyContractState: ContractState = {
  contract: AGENT_PLATFORM_FALLBACK_CONTRACT,
  source: "fallback",
};

const riskClasses: Record<string, string> = {
  low: "border-blue-200 bg-blue-50 text-blue-700",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  high: "border-red-200 bg-red-50 text-red-700",
};

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 break-words text-lg font-semibold text-slate-900">{value}</div>
    </div>
  );
}

function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "success" | "warning" | "danger" }) {
  const classes = {
    danger: "border-red-200 bg-red-50 text-red-700",
    neutral: "border-slate-200 bg-white text-slate-600",
    success: "border-emerald-200 bg-emerald-50 text-emerald-700",
    warning: "border-amber-200 bg-amber-50 text-amber-800",
  };
  return <span className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] font-medium ${classes[tone]}`}>{children}</span>;
}

function RiskPill({ risk }: { risk: string }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase ${riskClasses[risk] ?? riskClasses.medium}`}>
      {risk}
    </span>
  );
}

function FieldList({ className = "", label, mono = false, values }: { className?: string; label: string; mono?: boolean; values: readonly string[] }) {
  return (
    <div className={className}>
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {values.length === 0 ? (
          <span className="text-[12px] text-slate-400">No values</span>
        ) : (
          values.map((value, index) => (
            <span key={`${value}-${index}`} className={`max-w-full break-words rounded-md bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600 ring-1 ring-slate-200 ${mono ? "font-mono" : ""}`}>
              {value}
            </span>
          ))
        )}
      </div>
    </div>
  );
}

const loadedCopy = (loaded: number, total: number, noun: string) =>
  loaded >= total ? `Showing ${loaded.toLocaleString()} ${noun}.` : `Showing first ${loaded.toLocaleString()} of ${total.toLocaleString()} ${noun}.`;

const operatorText = (value: string) =>
  value
    .replace(/\breplay fixtures\b/gi, "replay records")
    .replace(/\bfixtures\b/gi, "records")
    .replace(/\bfixture\b/gi, "record");

function CapabilityTable({ capabilities, contract }: { capabilities: readonly AgentPlatformCapability[]; contract: AgentPlatformContract }) {
  const visible = capabilities.slice(0, CAPABILITY_LIMIT);
  if (capabilities.length === 0) {
    return <div className="rounded-md border border-slate-200 bg-white p-4 text-[12px] text-slate-500">No agent capabilities returned.</div>;
  }
  return (
    <div>
      <div className="mb-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
        {loadedCopy(visible.length, capabilities.length, "capabilities")}
      </div>
      <div className="overflow-x-auto rounded-md border border-slate-200 bg-white">
        <table className="w-full min-w-[920px] text-left text-[12px]">
          <thead className="border-b border-slate-200 bg-slate-50 text-[11px] uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-3 py-2 font-semibold">Capability</th>
              <th className="px-3 py-2 font-semibold">Domain</th>
              <th className="px-3 py-2 font-semibold">Risk</th>
              <th className="px-3 py-2 font-semibold">Default</th>
              <th className="px-3 py-2 font-semibold">Eval</th>
              <th className="px-3 py-2 font-semibold">Scopes</th>
              <th className="px-3 py-2 font-semibold">Events</th>
              <th className="px-3 py-2 font-semibold">Evidence fields</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {visible.map((capability) => {
              const domain = agentPlatformDomainById(capability.domainId, contract);
              return (
                <tr key={capability.id} className="align-top">
                  <td className="px-3 py-3">
                    <div className="font-semibold text-slate-900">{capability.name}</div>
                    <div className="mt-1 max-w-[22rem] text-slate-600">{operatorText(capability.summary)}</div>
                    <div className="mt-1 font-mono text-[11px] text-slate-500">{capability.id}@{capability.version}</div>
                  </td>
                  <td className="px-3 py-3 text-slate-700">{domain?.name ?? capability.domainId}</td>
                  <td className="px-3 py-3"><RiskPill risk={capability.risk} /></td>
                  <td className="px-3 py-3"><Pill tone={capability.defaultOn ? "success" : "neutral"}>{capability.defaultOn ? "On by default" : "Opt in"}</Pill></td>
                  <td className="px-3 py-3">
                    <Pill tone={capability.eval.required ? "warning" : "neutral"}>{capability.eval.status || "Eval status missing"}</Pill>
                  </td>
                  <td className="px-3 py-3 text-slate-700">{capability.requiredScopes.length}</td>
                  <td className="px-3 py-3 text-slate-700">{capability.runtimeEvents.length}</td>
                  <td className="px-3 py-3 text-slate-700">{capability.provenance.length}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RuntimeEventRow({ event }: { event: AgentPlatformRuntimeEvent }) {
  const domain = agentPlatformDomainById(event.domainId);
  return (
    <div className="grid gap-3 border-b border-slate-100 px-4 py-3 last:border-b-0 md:grid-cols-[13rem_7rem_1fr]">
      <div>
        <div className="break-all font-mono text-[12px] font-semibold text-slate-900">{event.name}</div>
        <div className="mt-1 text-[11px] text-slate-500">{domain?.name ?? event.domainId}</div>
      </div>
      <div className="flex flex-wrap gap-1.5">
        <Pill>{event.stage}</Pill>
        {event.terminal && <Pill tone="warning">terminal</Pill>}
      </div>
      <div className="grid gap-2 md:grid-cols-2">
        <FieldList label="Payload" values={event.payloadFields} mono />
        <FieldList label="Provenance" values={event.provenanceFields} mono />
      </div>
    </div>
  );
}

export function AgentPlatformDashboard() {
  const { apiKey } = useApiKey();
  const [state, setState] = useState<ContractState>(emptyContractState);

  useEffect(() => {
    let cancelled = false;
    fetchCerebro<unknown>("/api/v1/agent-platform/contract", apiKey)
      .then((response) => {
        if (cancelled) return;
        if (!response.ok) {
          setState({
            contract: AGENT_PLATFORM_FALLBACK_CONTRACT,
            error: "Contract API unavailable.",
            source: "fallback",
            status: response.status,
          });
          return;
        }
        setState({
          contract: normalizeAgentPlatformContract(response.data),
          source: "api",
          status: response.status,
        });
      })
      .catch((error: Error) => {
        if (cancelled) return;
        setState({
          contract: AGENT_PLATFORM_FALLBACK_CONTRACT,
          error: error.message ? "Contract API unavailable." : "Contract API unavailable.",
          source: "fallback",
        });
      });
    return () => {
      cancelled = true;
    };
  }, [apiKey]);

  const contract = state.contract;
  const connectorCapability = contract.capabilities.find((capability) => capability.id === "connector-oauth-mcp");
  const liveStatus = state.source === "api" ? "Live API" : "Stored contract";
  const highRiskCapabilities = contract.capabilities.filter((capability) => capability.risk === "high").length;
  const missingEvalCapabilities = contract.capabilities.filter((capability) => capability.eval.required && !capability.eval.status).length;
  const visibleEvents = contract.runtimeEvents.slice(0, EVENT_LIMIT);
  const visibleRequirements = contract.provenanceRequirements.slice(0, REQUIREMENT_LIMIT);
  const visibleInvariants = contract.invariants.slice(0, INVARIANT_LIMIT);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Platform"
        description="Review agent runtime coverage, connector auth boundaries, capability gates, eval status, trace events, and required evidence fields."
      />

      <Panel title="Agent contract status">
        {state.error && (
          <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 p-3 text-[12px] text-amber-800">
            Live contract did not load. Showing the stored contract.
          </div>
        )}
        <div className="grid gap-3 md:grid-cols-5">
          <MiniStat label="Version" value={contract.version} />
          <MiniStat label="Source" value={liveStatus} />
          <MiniStat label="High risk" value={highRiskCapabilities} />
          <MiniStat label="Capabilities" value={contract.capabilities.length} />
          <MiniStat label="Eval gaps" value={missingEvalCapabilities} />
        </div>
      </Panel>

      <Panel title="Connector and OAuth controls">
        <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
          <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
            <div className="text-[13px] font-semibold text-slate-900">{connectorCapability?.name ?? "Connector boundary"}</div>
            <p className="mt-1 text-[12px] leading-5 text-slate-600">{connectorCapability?.summary ?? "Connector auth controls are stored in the agent contract."}</p>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <FieldList label="Auth models" values={contract.connectorInfrastructure.authModels} mono />
              <FieldList label="Token boundaries" values={contract.connectorInfrastructure.tokenBoundaries} />
              <FieldList label="Credential stores" values={contract.connectorInfrastructure.credentialStores} />
              <FieldList label="MCP surfaces" values={contract.connectorInfrastructure.mcpSurfaces} mono />
            </div>
          </div>
          <div className="rounded-md border border-slate-200 bg-white p-4">
            <FieldList label="OAuth surfaces" values={contract.connectorInfrastructure.oauthSurfaces} mono />
            <FieldList className="mt-4" label="Required controls" values={contract.connectorInfrastructure.requiredControls} />
          </div>
        </div>
      </Panel>

      <Panel title="Agent capabilities">
        <CapabilityTable capabilities={contract.capabilities} contract={contract} />
      </Panel>

      <div className="grid gap-6 xl:grid-cols-2">
        <Panel title="Runtime events">
          <div className="mb-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
            {loadedCopy(visibleEvents.length, contract.runtimeEvents.length, "runtime events")}
          </div>
          <div className="overflow-hidden rounded-md border border-slate-200 bg-white">
            {visibleEvents.map((event) => (
              <RuntimeEventRow key={event.name} event={event} />
            ))}
          </div>
        </Panel>

        <Panel title="Required evidence fields">
          <div className="mb-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
            {loadedCopy(visibleRequirements.length, contract.provenanceRequirements.length, "requirements")}
          </div>
          <div className="grid gap-3">
            {visibleRequirements.map((requirement) => {
              const domain = agentPlatformDomainById(requirement.domainId, contract);
              return (
                <div key={requirement.surface} className="rounded-md border border-slate-200 bg-white p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="font-mono text-[12px] font-semibold text-slate-900">{requirement.surface}</div>
                      <div className="mt-1 text-[11px] text-slate-500">{domain?.name ?? requirement.domainId}</div>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {requirement.citationRequired && <Pill tone="success">citations</Pill>}
                      {requirement.budgetRequired && <Pill tone="warning">budget</Pill>}
                      {requirement.fallbackRequired && <Pill tone="warning">Stored contract</Pill>}
                    </div>
                  </div>
                  <FieldList className="mt-3" label="Required fields" values={requirement.requiredFields} mono />
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <Panel title="Required checks">
        <div className="mb-3 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
          {loadedCopy(visibleInvariants.length, contract.invariants.length, "checks")}
        </div>
        <div className="divide-y divide-slate-200 rounded-md border border-slate-200">
          {visibleInvariants.map((invariant) => {
            const domain = agentPlatformDomainById(invariant.domainId, contract);
            return (
              <div key={invariant.id} className="grid gap-2 bg-white p-4 md:grid-cols-[8rem_1fr]">
                <div>
                  <div className="font-mono text-[12px] font-semibold text-slate-900">{invariant.id}</div>
                  <div className="mt-1 text-[11px] text-slate-500">{domain?.name ?? invariant.domainId}</div>
                </div>
                <div className="text-[13px] leading-5 text-slate-700">{invariant.statement}</div>
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

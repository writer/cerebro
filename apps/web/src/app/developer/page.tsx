"use client";

import Link from "next/link";
import { useMemo } from "react";

import IdentityContractPanel from "@/components/identity/IdentityContractPanel";
import StatusPanel from "@/components/StatusPanel";
import { PageHeader, Panel } from "@/components/grc/Primitives";
import { tagSlug } from "@/lib/openapi";
import { useOpenApi } from "@/lib/openapi-store";

const developerLinks = [
  { label: "Agent Platform", href: "/developer/agents", description: "Provenance principles for runtimes and evals." },
  { label: "Audit Events", href: "/developer/audit", description: "Search actions by actor, resource, or outcome." },
  { label: "Identity Contract", href: "/developer/identity", description: "Current user and write-stamp fields." },
  { label: "Security Producers", href: "/developer/producers", description: "Sources producing security evidence." },
  { label: "Risk Model", href: "/developer/scoring", description: "How assets and attack paths are scored." },
  { label: "Ask Evals", href: "/developer/evals", description: "Local Ask quality evals and rubric outcomes." },
];

export default function DeveloperPage() {
  const { status, model, error } = useOpenApi();
  const operationsByTag = useMemo(() => {
    const map = new Map<string, number>();
    model?.operations.forEach((op) => {
      map.set(op.tag, (map.get(op.tag) ?? 0) + 1);
    });
    return map;
  }, [model]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Developer Tools"
        description="Diagnostics, evals, and API reference."
      />

      <StatusPanel />

      <IdentityContractPanel compact />

      <Panel title="Developer Utilities">
        <div className="grid gap-3 lg:grid-cols-2">
          {developerLinks.map((link) => (
            <Link key={link.href} href={link.href} prefetch={false} className="rounded-md border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white">
              <div className="text-[13px] font-semibold text-slate-900">{link.label}</div>
              <div className="mt-1 text-[12px] text-slate-500">{link.description}</div>
            </Link>
          ))}
        </div>
      </Panel>

      <Panel title="OpenAPI Resources">
        {(status === "loading" || status === "idle") && <div className="text-[13px] text-slate-500">Loading OpenAPI data...</div>}
        {status === "error" && <div className="text-[13px] text-red-600">{error}</div>}
        <div className="grid gap-3 lg:grid-cols-3">
          {model?.tags.map((tag) => (
            <Link key={tag.name} href={`/resources/${tagSlug(tag.name)}`} prefetch={false} className="rounded-md border border-slate-200 bg-slate-50 p-4 transition hover:border-slate-300 hover:bg-white">
              <div className="text-[13px] font-semibold text-slate-900">{tag.name}</div>
              <div className="mt-1 text-[12px] text-slate-500">{tag.description ?? "OpenAPI-defined resource group."}</div>
              <div className="mt-2 inline-flex rounded-md bg-white px-2.5 py-0.5 text-[11px] font-medium text-slate-600 ring-1 ring-inset ring-slate-200">{operationsByTag.get(tag.name) ?? 0} endpoints</div>
            </Link>
          ))}
        </div>
      </Panel>
    </div>
  );
}

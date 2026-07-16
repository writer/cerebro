"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";

import ResourceExplorer from "@/components/ResourceExplorer";
import { ErrorBlock, LoadingBlock } from "@/components/grc/Primitives";
import { tagSlug } from "@/lib/openapi";
import { useOpenApi } from "@/lib/openapi-store";

export default function ResourcePage() {
  const params = useParams<{ slug: string }>();
  const slug = Array.isArray(params?.slug) ? params.slug[0] : params?.slug;
  const { status, model, error } = useOpenApi();
  const [query, setQuery] = useState("");

  const tag = useMemo(
    () => model?.tags.find((item) => tagSlug(item.name) === slug),
    [model, slug],
  );

  const operations = useMemo(() => {
    const list = model?.operations.filter((op) => tagSlug(op.tag) === slug);
    if (!query) return list ?? [];
    const q = query.toLowerCase();
    return (list ?? []).filter((op) => op.path.toLowerCase().includes(q) || op.summary?.toLowerCase().includes(q));
  }, [model, query, slug]);

  const schemaCount = operations.filter((op) => op.response?.schema).length;

  if (status === "loading" || status === "idle") {
    return <LoadingBlock label="Loading API resources..." />;
  }
  if (status === "error") {
    return <ErrorBlock error={error ?? "API resource metadata could not load."} recoveryDetail="API resources will appear when OpenAPI metadata is reachable." />;
  }
  if (!tag) {
    return (
      <div className="space-y-3">
        <div className="text-[13px] text-slate-500">Resource not found.</div>
        <Link href="/" className="text-[13px] text-indigo-600 hover:text-indigo-800">Back to overview</Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">{tag.name}</h1>
        {tag.description && <p className="mt-1 text-[13px] text-slate-500">{tag.description}</p>}
        <div className="mt-2 flex flex-wrap gap-2">
          <span className="rounded-md bg-slate-100 px-2.5 py-0.5 text-[11px] font-medium text-slate-600">{operations.length} endpoints</span>
          <span className="rounded-md bg-slate-100 px-2.5 py-0.5 text-[11px] font-medium text-slate-600">{schemaCount} schemas</span>
        </div>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter endpoints..."
          className="mt-3 w-full max-w-md rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30"
        />
      </div>
      <ResourceExplorer operations={operations} schemas={model?.schemas ?? {}} />
    </div>
  );
}

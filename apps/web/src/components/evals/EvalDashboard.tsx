"use client";

import { useEffect, useMemo, useState } from "react";

import { Panel } from "@/components/grc/Primitives";
import type { AskEvalReport, AskEvalRun } from "@/lib/evals/types";

const reportURLs = ["/evals/ask/latest.json", "/evals/security-agent/latest.json"];

const statusClass = (status: string) =>
  status === "passed"
    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
    : "border-rose-200 bg-rose-50 text-rose-700";

function replayHref(run: AskEvalRun) {
  const params = new URLSearchParams();
  params.set("q", run.question);
  if (run.model) params.set("model", run.model);
  if (run.scopeUrn) params.set("scope_urn", run.scopeUrn);
  return `/ask?${params.toString()}`;
}

function JudgeRows({ run }: { run: AskEvalRun }) {
  const judges = Object.entries(run.judges ?? {});
  if (judges.length === 0) return null;
  return (
    <div className="mt-3 rounded-md border border-slate-100 bg-slate-50 p-3">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">Judges</div>
      <div className="mt-2 space-y-1">
        {judges.map(([id, judge]) => (
          <div key={id} className="flex items-start gap-2 text-[12px]">
            <span className={judge.passed ? "text-emerald-600" : "text-rose-600"}>{judge.passed ? "PASS" : "FAIL"}</span>
            <span className="font-medium text-slate-700">{id}:</span>
            <span className="text-slate-500">{judge.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RunCard({ run }: { run: AskEvalRun }) {
  return (
    <article className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[13px] font-semibold text-slate-900">{run.name}</div>
          <div className="mt-1 text-[12px] text-slate-500">{run.question}</div>
        </div>
        <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${statusClass(run.status)}`}>
          {run.status}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-slate-500">
        <span className="rounded-full border border-slate-200 px-2 py-0.5">{run.fixtureKind ?? "golden"}</span>
        {run.provenance?.source && <span className="rounded-full border border-slate-200 px-2 py-0.5">source: {run.provenance.source}</span>}
        {run.traceId && <span className="rounded-full border border-slate-200 px-2 py-0.5">trace: {run.traceId}</span>}
      </div>
      <div className="mt-3 grid gap-2 text-[12px] text-slate-600 md:grid-cols-4">
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Score</div>
          <div className="font-semibold text-slate-900">{run.score}%</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Rows</div>
          <div className="font-semibold text-slate-900">{run.rowCount}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Citations</div>
          <div className="font-semibold text-slate-900">{run.citationCount}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Latency</div>
          <div className="font-semibold text-slate-900">{run.durationMs} ms</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Query plan</div>
          <div className="break-all font-semibold text-slate-900">{run.queryPlanIntent ?? "—"}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Plan source</div>
          <div className="break-all font-semibold text-slate-900">{run.queryPlanSource ?? "—"}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Corrected</div>
          <div className="font-semibold text-slate-900">{run.queryPlanCorrected ? "yes" : "no"}</div>
        </div>
        <div className="rounded-md bg-slate-50 p-2">
          <div className="text-[10px] uppercase tracking-wide text-slate-400">Diagnostics</div>
          <div className="font-semibold text-slate-900">{run.conversionDiagnosticsCount ?? 0}</div>
        </div>
      </div>
      <p className="mt-3 rounded-md border border-slate-100 bg-slate-50 p-3 text-[13px] text-slate-700">
        {run.summary || "No summary captured."}
      </p>
      {run.diff?.changed && (
        <div className="mt-3 grid gap-2 text-[12px] md:grid-cols-2">
          <div className="rounded-md border border-emerald-100 bg-emerald-50 p-2">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-emerald-700">Added</div>
            <div className="mt-1 text-emerald-800">{run.diff.added.join(" ") || "None"}</div>
          </div>
          <div className="rounded-md border border-rose-100 bg-rose-50 p-2">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-rose-700">Removed</div>
            <div className="mt-1 text-rose-800">{run.diff.removed.join(" ") || "None"}</div>
          </div>
        </div>
      )}
      <JudgeRows run={run} />
      <div className="mt-3 space-y-1">
        {run.rubrics.map((rubric) => (
          <div key={rubric.id} className="flex items-start gap-2 text-[12px]">
            <span className={rubric.passed ? "text-emerald-600" : "text-rose-600"}>
              {rubric.passed ? "PASS" : "FAIL"}
            </span>
            <span className="font-medium text-slate-700">{rubric.label}:</span>
            <span className="text-slate-500">{rubric.detail}</span>
          </div>
        ))}
      </div>
      <a
        href={replayHref(run)}
        className="mt-3 inline-flex rounded-md border border-slate-200 px-2.5 py-1 text-[12px] font-semibold text-slate-700 transition hover:border-slate-300 hover:bg-slate-50"
      >
        Replay in Ask
      </a>
      {(run.events?.length ?? 0) > 0 && (
        <details className="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-[12px] text-slate-700">
          <summary className="cursor-pointer font-semibold text-slate-800">Event timeline ({run.events?.length ?? 0})</summary>
          <div className="mt-2 space-y-1">
            {run.events?.map((event, index) => (
              <div key={`${event.event}:${index}`} className="font-mono text-[11px] text-slate-600">
                {index + 1}. {event.event}
              </div>
            ))}
          </div>
          {run.cypherPreview && (
            <pre className="mt-3 overflow-x-auto rounded-md bg-white p-2 font-mono text-[11px] text-slate-700">{run.cypherPreview}</pre>
          )}
        </details>
      )}
    </article>
  );
}

export default function EvalDashboard() {
  const [reports, setReports] = useState<AskEvalReport[] | null>(null);
  const [error, setError] = useState("");
  const [fixtureFilter, setFixtureFilter] = useState<"all" | "golden" | "candidate">("all");

  useEffect(() => {
    let cancelled = false;
    Promise.all(
      reportURLs.map(async (url) => {
        const response = await fetch(url, { cache: "no-store" });
        if (response.status === 404) return null;
        if (!response.ok) throw new Error(`Eval report request failed (${response.status})`);
        return (await response.json()) as AskEvalReport;
      }),
    )
      .then((payload) => {
        if (!cancelled) setReports(payload.filter((report): report is AskEvalReport => Boolean(report)));
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Unable to load eval reports");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const runs = useMemo(() => reports?.flatMap((report) => report.runs) ?? [], [reports]);
  const visibleRuns = useMemo(
    () => runs.filter((run) => fixtureFilter === "all" || (run.fixtureKind ?? "golden") === fixtureFilter),
    [fixtureFilter, runs],
  );
  const generatedAt = useMemo(() => reports?.map((report) => report.generatedAt).sort().at(-1), [reports]);
  const totals = {
    passed: runs.filter((run) => run.status === "passed").length,
    failed: runs.filter((run) => run.status === "failed").length,
    total: runs.length,
  };

  if (error) {
    return <Panel title="Eval Report Error"><div className="text-[13px] text-rose-600">{error}</div></Panel>;
  }

  if (!reports) {
    return <Panel title="Latest Report"><div className="text-[13px] text-slate-500">Loading eval reports...</div></Panel>;
  }

  if (reports.length === 0) {
    return (
      <Panel title="No Eval Report Found">
        <div className="space-y-3 text-[13px] text-slate-600">
          <p>Run the local eval suite to generate `.eval-reports/ask/latest.json`.</p>
          <pre className="overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[12px] text-slate-800">
            npm run eval:ask:local
          </pre>
        </div>
      </Panel>
    );
  }

  return (
    <>
      <Panel title="Latest Report">
        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-md bg-slate-50 p-3">
            <div className="text-[10px] uppercase tracking-wide text-slate-400">Generated</div>
            <div className="text-[13px] font-semibold text-slate-900">{generatedAt ? new Date(generatedAt).toLocaleString() : "—"}</div>
          </div>
          <div className="rounded-md bg-slate-50 p-3">
            <div className="text-[10px] uppercase tracking-wide text-slate-400">Passed</div>
            <div className="text-[13px] font-semibold text-emerald-700">{totals.passed}</div>
          </div>
          <div className="rounded-md bg-slate-50 p-3">
            <div className="text-[10px] uppercase tracking-wide text-slate-400">Failed</div>
            <div className="text-[13px] font-semibold text-rose-700">{totals.failed}</div>
          </div>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {(["all", "golden", "candidate"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => setFixtureFilter(value)}
              className={`rounded-md border px-2.5 py-1 text-[12px] font-semibold ${
                fixtureFilter === value ? "border-indigo-300 bg-indigo-50 text-indigo-700" : "border-slate-200 text-slate-600"
              }`}
            >
              {value}
            </button>
          ))}
        </div>
      </Panel>

      <div className="grid gap-4">
        {visibleRuns.map((run) => (
          <RunCard key={`${run.kind}:${run.id}`} run={run} />
        ))}
      </div>
    </>
  );
}

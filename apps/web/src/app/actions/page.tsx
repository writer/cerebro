"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { actionStateIntent, actionTimeLabel, summarizeActionPage, type ActionPage } from "@/lib/actions";
import { grcPath, useGRCQuery } from "@/lib/grc-client";

const PAGE_SIZE = 50;

export default function ActionsPage() {
  const [pageTokens, setPageTokens] = useState<string[]>([""]);
  const pageToken = pageTokens.at(-1) ?? "";
  const path = grcPath("/v1/actions", {
    limit: PAGE_SIZE,
    ...(pageToken ? { page_token: pageToken } : {}),
  });
  const query = useGRCQuery<ActionPage>(path);
  const actions = useMemo(() => query.data?.actions ?? [], [query.data?.actions]);
  const summary = useMemo(() => summarizeActionPage(actions), [actions]);
  const nextPageToken = query.data?.next_page_token ?? "";

  return (
    <div>
      <PageHeader
        title="Actions"
        description="Remediation work for confirmed findings. Rust owns every state transition, actor binding, approval receipt, execution receipt, and verification receipt shown here."
        contractId="rust-actions"
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Waiting for approval" value={summary.waitingForApproval} detail="Current page" intent={summary.waitingForApproval > 0 ? actionStateIntent("waiting_for_approval") : "neutral"} state={query.state} />
        <MetricCard label="In execution" value={summary.inExecution} detail="Claimed, executing, or outcome unknown" intent={summary.inExecution > 0 ? "warning" : "neutral"} state={query.state} />
        <MetricCard label="Verified" value={summary.verified} detail="Current page" intent={summary.verified > 0 ? actionStateIntent("verified") : "neutral"} state={query.state} />
        <MetricCard label="Failed or rolled back" value={summary.failedOrRolledBack} detail="Current page" intent={summary.failedOrRolledBack > 0 ? actionStateIntent("failed") : "neutral"} state={query.state} />
      </div>

      <div className="mt-4">
        {query.loading && !query.data ? <LoadingBlock label="Loading Actions from the Rust authority..." /> : null}
        {query.error ? <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Check the Rust Action authority and signed browser identity, then try again." /> : null}
        {!query.loading && !query.error && actions.length === 0 ? <EmptyBlock label="No Actions are recorded for this tenant." /> : null}
        {actions.length > 0 ? (
          <Panel
            title="Action queue"
            action={<span className="text-[11px] text-[var(--text-muted)]">Newest authority updates first</span>}
          >
            <div className="overflow-auto">
              <table className="w-full min-w-[1080px] text-left text-[12px]">
                <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                  <tr>
                    <th className="px-3 py-2 font-semibold">Action</th>
                    <th className="px-3 py-2 font-semibold">Finding</th>
                    <th className="px-3 py-2 font-semibold">Target</th>
                    <th className="px-3 py-2 font-semibold">State</th>
                    <th className="px-3 py-2 font-semibold">Verification</th>
                    <th className="px-3 py-2 font-semibold">Version</th>
                    <th className="px-3 py-2 font-semibold">Proposed</th>
                    <th className="px-3 py-2 font-semibold"><span className="sr-only">Open</span></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[color:var(--border)]">
                  {actions.map((action) => (
                    <tr key={action.proposal.operation_id} className="align-top">
                      <td className="px-3 py-3">
                        <div className="font-semibold text-[var(--text-primary)]">{action.proposal.action_kind.replaceAll("_", " ")}</div>
                        <div className="mt-1 max-w-[18rem] truncate font-mono text-[10px] text-[var(--text-muted)]" title={action.proposal.operation_id}>{action.proposal.operation_id}</div>
                      </td>
                      <td className="px-3 py-3 font-mono text-[11px] text-[var(--text-secondary)]">{action.proposal.finding_id}</td>
                      <td className="px-3 py-3 font-mono text-[11px] text-[var(--text-secondary)]">{action.proposal.target_id}</td>
                      <td className="px-3 py-3"><Badge value={action.state} /></td>
                      <td className="px-3 py-3"><Badge value={action.verification_state} /></td>
                      <td className="px-3 py-3 text-[var(--text-secondary)]">{action.version}</td>
                      <td className="px-3 py-3 text-[var(--text-secondary)]">
                        <div>{actionTimeLabel(action.proposal.proposed_at_unix_ms)}</div>
                        <div className="mt-1 text-[11px] text-[var(--text-muted)]">{action.proposal.proposed_by}</div>
                      </td>
                      <td className="px-3 py-3 text-right">
                        <Link href={`/actions/${encodeURIComponent(action.proposal.operation_id)}`} className="secondary-button inline-flex px-3 py-1.5 text-[12px]">
                          Open
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-4 flex items-center justify-between">
              <button
                type="button"
                className="secondary-button px-3 py-2 text-[12px]"
                disabled={pageTokens.length === 1}
                onClick={() => setPageTokens((tokens) => tokens.slice(0, -1))}
              >
                Previous page
              </button>
              <span className="text-[11px] text-[var(--text-muted)]">Page {pageTokens.length}</span>
              <button
                type="button"
                className="secondary-button px-3 py-2 text-[12px]"
                disabled={!nextPageToken}
                onClick={() => {
                  if (nextPageToken) setPageTokens((tokens) => [...tokens, nextPageToken]);
                }}
              >
                Next page
              </button>
            </div>
          </Panel>
        ) : null}
      </div>
    </div>
  );
}

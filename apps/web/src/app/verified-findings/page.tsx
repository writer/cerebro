"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import {
  ACTION_STAGE_DETAIL,
  ACTION_STAGE_IDS,
  ACTION_STAGE_LABELS,
  actionStage,
  actionStageIntent,
  indexActionDefinitions,
  summarizeActionStages,
  type ActionDefinition,
  type ActionOperation,
  type ActionPage,
  type ActionStageID,
} from "@/lib/actions";
import { grcPath, useGRCQuery } from "@/lib/grc-client";
import { useQueryParamState } from "@/lib/query-params";

const PAGE_SIZE = 50;

const isActionStage = (value: string): value is ActionStageID =>
  (ACTION_STAGE_IDS as readonly string[]).includes(value);

const humanizeKind = (kind: string) => kind.replaceAll("_", " ").replaceAll(".", " / ");

const ageLabel = (unixMillis?: number | null) => {
  if (!unixMillis || !Number.isSafeInteger(unixMillis) || unixMillis < 1) return "";
  const days = Math.floor((Date.now() - unixMillis) / 86_400_000);
  if (days < 0) return "";
  if (days === 0) return "today";
  return `${days}d old`;
};

export default function ActionsPage() {
  const [pageTokens, setPageTokens] = useState<string[]>([""]);
  const [stage, setStage] = useQueryParamState("stage");
  const pageToken = pageTokens.at(-1) ?? "";
  const path = grcPath("/v1/actions", {
    limit: PAGE_SIZE,
    ...(pageToken ? { page_token: pageToken } : {}),
  });
  const query = useGRCQuery<ActionPage>(path);
  // The definition catalog carries blast radius, so a failed read degrades the
  // row detail rather than the queue itself.
  const definitionQuery = useGRCQuery<ActionDefinition[]>(grcPath("/v1/action-definitions", {}));
  const definitions = useMemo(
    () => indexActionDefinitions(definitionQuery.data ?? undefined),
    [definitionQuery.data],
  );
  const actions = useMemo(() => query.data?.actions ?? [], [query.data?.actions]);
  const stages = useMemo(() => summarizeActionStages(actions), [actions]);
  const activeStage = isActionStage(stage) ? stage : null;
  const visibleActions = useMemo(
    () => (activeStage ? actions.filter((action) => actionStage(action.state) === activeStage) : actions),
    [actions, activeStage],
  );
  const nextPageToken = query.data?.next_page_token ?? "";

  return (
    <div>
      <PageHeader
        title="Verified Findings"
        description="Findings an agent confirmed against empirical evidence, and the remediation each one produced."
        contractId="rust-actions"
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {ACTION_STAGE_IDS.map((id) => (
          <StageCard
            key={id}
            id={id}
            count={stages[id]}
            selected={activeStage === id}
            loading={query.loading && !query.data}
            onSelect={() => setStage(activeStage === id ? "" : id)}
          />
        ))}
      </div>

      <div className="mt-4">
        {query.loading && !query.data ? <LoadingBlock label="Loading verified findings..." /> : null}
        {query.error ? <ErrorBlock error={query.error} onRetry={() => void query.reload()} recoveryDetail="Check the Action authority and signed browser identity, then try again." /> : null}
        {!query.loading && !query.error && actions.length === 0 ? (
          <EmptyBlock label="Nothing has been verified yet. A finding appears here once validation confirms it against evidence." />
        ) : null}
        {actions.length > 0 ? (
          <Panel
            title={activeStage ? ACTION_STAGE_LABELS[activeStage] : "All Verified Findings"}
            action={<span className="text-[11px] text-[var(--text-muted)]">Newest authority updates first</span>}
          >
            {/* Stage counts are derived from the loaded page, since the authority list API has no state filter or totals. */}
            <div className="mb-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
              Counts describe the {actions.length.toLocaleString()} verified findings on this page.
            </div>
            {visibleActions.length === 0 ? (
              <EmptyBlock label={`Nothing is ${ACTION_STAGE_LABELS[activeStage ?? "proposed"].toLowerCase()} on this page.`} />
            ) : (
              <div className="overflow-auto">
                <table className="w-full min-w-[980px] text-left text-[12px]">
                  <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Finding</th>
                      <th className="px-3 py-2 font-semibold">Affected</th>
                      <th className="px-3 py-2 font-semibold">Verification</th>
                      <th className="px-3 py-2 font-semibold">Remediation</th>
                      <th className="px-3 py-2 font-semibold">Stage</th>
                      <th className="px-3 py-2 font-semibold"><span className="sr-only">Open</span></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[color:var(--border)]">
                    {visibleActions.map((action) => (
                      <ActionRow
                        key={action.proposal.operation_id}
                        action={action}
                        definition={definitions[action.proposal.action_kind]}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="mt-4 flex items-center justify-between">
              <button
                type="button"
                className="secondary-button px-3 py-2 text-[12px]"
                disabled={pageTokens.length === 1}
                onClick={() => setPageTokens((tokens) => tokens.slice(0, -1))}
              >
                Previous Page
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
                Next Page
              </button>
            </div>
          </Panel>
        ) : null}
      </div>
    </div>
  );
}

function StageCard({
  count,
  id,
  loading,
  onSelect,
  selected,
}: {
  count: number;
  id: ActionStageID;
  loading: boolean;
  onSelect: () => void;
  selected: boolean;
}) {
  const intent = count > 0 ? actionStageIntent(id) : "neutral";
  const accent = intent === "danger"
    ? "border-l-red-500"
    : intent === "warning"
      ? "border-l-amber-500"
      : intent === "success"
        ? "border-l-emerald-500"
        : "border-l-slate-300";
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      title={ACTION_STAGE_DETAIL[id]}
      className={`rounded-lg border border-l-4 bg-white px-4 py-3 text-left transition ${accent} ${selected ? "border-indigo-400 ring-1 ring-indigo-200" : "border-slate-200 hover:border-slate-300"}`}
    >
      <div className="text-[11px] font-medium uppercase tracking-wide text-slate-500">{ACTION_STAGE_LABELS[id]}</div>
      <div className="mt-1 text-[22px] font-semibold leading-none text-slate-900">{loading ? "--" : count.toLocaleString()}</div>
      <div className="mt-1.5 text-[11px] leading-4 text-slate-500">{ACTION_STAGE_DETAIL[id]}</div>
    </button>
  );
}

function ActionRow({
  action,
  definition,
}: {
  action: ActionOperation;
  definition?: ActionDefinition;
}) {
  const stage = actionStage(action.state);
  const evidence = action.verification_receipt?.receipt.evidence_urns?.length ?? 0;
  const age = ageLabel(action.proposal.proposed_at_unix_ms);

  return (
    <tr className="align-top">
      <td className="px-3 py-3">
        <Link
          href={`/findings/${encodeURIComponent(action.proposal.finding_id)}`}
          className="block max-w-[20rem] truncate font-semibold text-indigo-700 hover:underline"
          title={action.proposal.finding_id}
        >
          {action.proposal.finding_id}
        </Link>
        <div className="mt-1 text-[11px] text-[var(--text-muted)]">
          Confirmed at graph revision {action.proposal.graph_revision.toLocaleString()}
        </div>
      </td>
      <td className="px-3 py-3">
        <Link
          href={`/explore?root_urn=${encodeURIComponent(action.proposal.target_id)}`}
          className="block max-w-[18rem] truncate font-mono text-[11px] text-indigo-700 hover:underline"
          title={action.proposal.target_id}
        >
          {action.proposal.target_id}
        </Link>
      </td>
      <td className="px-3 py-3">
        <Badge value={action.verification_state} />
        <div className="mt-1 text-[11px] text-[var(--text-muted)]">
          {evidence > 0 ? `${evidence.toLocaleString()} evidence refs` : "No evidence refs returned"}
        </div>
        <div className="mt-1 truncate text-[11px] text-[var(--text-muted)]" title={action.proposal.proposed_by}>
          {action.proposal.proposed_by}{age ? ` - ${age}` : ""}
        </div>
      </td>
      <td className="px-3 py-3">
        <div className="font-medium text-[var(--text-primary)]">{humanizeKind(action.proposal.action_kind)}</div>
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          {definition?.destructive
            ? <Badge value="destructive" tone="severity" />
            : definition
              ? <Badge value="non-destructive" />
              : null}
          {definition?.reversible_by
            ? <span className="text-[11px] text-emerald-700">Reversible</span>
            : definition
              ? <span className="text-[11px] text-amber-700">No rollback action</span>
              : null}
        </div>
        {definition?.effect && (
          <div className="mt-1 text-[11px] text-[var(--text-muted)]">{humanizeKind(definition.effect)}</div>
        )}
      </td>
      <td className="px-3 py-3">
        <Badge value={ACTION_STAGE_LABELS[stage]} />
        <div className="mt-1 text-[11px] text-[var(--text-muted)]">{humanizeKind(action.state)}</div>
      </td>
      <td className="px-3 py-3 text-right">
        <Link href={`/verified-findings/${encodeURIComponent(action.proposal.operation_id)}`} className="secondary-button inline-flex px-3 py-1.5 text-[12px]">
          Open
        </Link>
      </td>
    </tr>
  );
}

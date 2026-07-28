"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { actionStateIntent, actionStateLabel, actionTimeLabel, type ActionEvent, type ActionOperation } from "@/lib/actions";
import { useGRCQuery } from "@/lib/grc-client";

function DetailRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid gap-1 border-b border-[color:var(--border)] py-2.5 last:border-0 sm:grid-cols-[12rem_1fr]">
      <dt className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</dt>
      <dd className={`break-all text-[12px] text-[var(--text-secondary)] ${mono ? "font-mono text-[11px]" : ""}`}>{value}</dd>
    </div>
  );
}

export default function ActionDetailPage() {
  const params = useParams<{ operationID: string }>();
  const operationID = typeof params.operationID === "string" ? params.operationID : "";
  const encodedOperationID = encodeURIComponent(operationID);
  const actionQuery = useGRCQuery<ActionOperation>(operationID ? `/v1/actions/${encodedOperationID}` : null);
  const historyQuery = useGRCQuery<ActionEvent[]>(operationID ? `/v1/actions/${encodedOperationID}/history` : null);
  const action = actionQuery.data;
  const history = useMemo(() => historyQuery.data ?? [], [historyQuery.data]);

  if (actionQuery.loading && !action) {
    return <LoadingBlock label="Loading Action authority records..." />;
  }
  if (actionQuery.error || !action) {
    return (
      <ErrorBlock
        error={actionQuery.error || "The Action was not returned by the Rust authority."}
        onRetry={() => {
          void actionQuery.reload();
        }}
        recoveryDetail="Confirm the operation ID and signed tenant identity, then try again."
      />
    );
  }

  const proposal = action.proposal;
  const approval = action.approval_receipt;
  const verification = action.verification_receipt?.receipt;

  return (
    <div>
      <PageHeader
        title={proposal.action_kind.replaceAll("_", " ")}
        description={`Action ${proposal.operation_id} is bound to finding revision ${proposal.finding_revision_digest.slice(0, 12)} and graph revision ${proposal.graph_revision}.`}
        contractId="rust-action-detail"
        action={<Link href="/actions" className="secondary-button px-3 py-2 text-[12px]">Back to Actions</Link>}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="State" value={actionStateLabel(action.state)} detail={`Version ${action.version}`} intent={actionStateIntent(action.state)} />
        <MetricCard label="Verification" value={actionStateLabel(action.verification_state)} detail={verification ? actionTimeLabel(verification.verified_at_unix_ms) : "No verification receipt"} intent={action.verification_state === "verified" ? "success" : action.verification_state === "rejected" || action.verification_state === "stale" ? "warning" : "neutral"} />
        <MetricCard label="Approval" value={approval?.approved ? "Approved" : approval ? "Rejected" : "Not recorded"} detail={approval ? `By ${approval.decided_by}` : "Signed decision required"} intent={approval?.approved ? "success" : approval ? "danger" : "neutral"} />
        <MetricCard label="Execution" value={action.executed_at_unix_ms ? "Receipt recorded" : action.claimed_by ? "Claimed" : "Not started"} detail={action.executor_actor_id || action.claimed_by || "No executor"} intent={action.state === "outcome_unknown" ? actionStateIntent(action.state) : action.executed_at_unix_ms ? "success" : "neutral"} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Panel title="Finding and target">
          <dl>
            <DetailRow label="Finding" value={proposal.finding_id} mono />
            <DetailRow label="Finding revision" value={proposal.finding_revision_digest} mono />
            <DetailRow label="Validation receipt" value={proposal.finding_validation_receipt_digest} mono />
            <DetailRow label="Graph revision" value={String(proposal.graph_revision)} />
            <DetailRow label="Target" value={proposal.target_id} mono />
            <DetailRow label="Expected effects" value={proposal.expected_effects.map((effect) => `${effect.effect_kind} on ${effect.target_id}`).join(", ")} />
          </dl>
        </Panel>

        <Panel title="Proposal authority">
          <dl>
            <DetailRow label="Proposed by" value={proposal.proposed_by} mono />
            <DetailRow label="Proposed" value={actionTimeLabel(proposal.proposed_at_unix_ms)} />
            <DetailRow label="Expires" value={actionTimeLabel(proposal.proposal_expires_at_unix_ms)} />
            <DetailRow label="Proposal digest" value={proposal.proposal_digest} mono />
            <DetailRow label="Action definition" value={proposal.action_definition_digest} mono />
            <DetailRow label="Simulation" value={proposal.simulation_digest} mono />
            <DetailRow label="Verification plan" value={proposal.verification_plan_digest} mono />
            <DetailRow label="Idempotency key" value={proposal.idempotency_key} mono />
          </dl>
        </Panel>

        <Panel title="Execution receipt">
          <dl>
            <DetailRow label="Claimed by" value={action.claimed_by || "Not claimed"} mono={Boolean(action.claimed_by)} />
            <DetailRow label="Claimed" value={actionTimeLabel(action.claimed_at_unix_ms)} />
            <DetailRow label="Executor" value={action.executor_actor_id || "No executor receipt"} mono={Boolean(action.executor_actor_id)} />
            <DetailRow label="Executed" value={actionTimeLabel(action.executed_at_unix_ms)} />
            <DetailRow label="External receipt" value={action.external_receipt_ref || "Not recorded"} mono={Boolean(action.external_receipt_ref)} />
            <DetailRow label="Observed effect" value={action.observed_effect_digest || "Not recorded"} mono={Boolean(action.observed_effect_digest)} />
          </dl>
        </Panel>

        <Panel title="Independent verification">
          <dl>
            <DetailRow label="State" value={actionStateLabel(action.verification_state)} />
            <DetailRow label="Verifier" value={verification?.verifier_actor_id || "No verifier receipt"} mono={Boolean(verification?.verifier_actor_id)} />
            <DetailRow label="Previous source revision" value={verification?.previous_source_revision || "Not recorded"} mono={Boolean(verification?.previous_source_revision)} />
            <DetailRow label="Observed source revision" value={verification?.observed_source_revision || "Not recorded"} mono={Boolean(verification?.observed_source_revision)} />
            <DetailRow label="Effective" value={verification ? (verification.effective ? "Confirmed" : "Not confirmed") : "Not verified"} />
            <DetailRow label="Verified" value={actionTimeLabel(verification?.verified_at_unix_ms)} />
            <DetailRow label="Evidence" value={verification?.evidence_urns.join(", ") || "No verification evidence"} mono={Boolean(verification?.evidence_urns.length)} />
          </dl>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel
          title="Authority history"
          action={
            <span className="text-[11px] text-[var(--text-muted)]">
              {historyQuery.loading && history.length === 0
                ? "Loading committed versions"
                : historyQuery.error
                  ? "History unavailable"
                  : `${history.length} committed versions`}
            </span>
          }
        >
          <div className="space-y-3">
            {historyQuery.error && (
              <ErrorBlock
                error={historyQuery.error}
                onRetry={() => {
                  void historyQuery.reload();
                }}
                recoveryDetail="The Action record is available. Retry loading its committed history."
              />
            )}
            {historyQuery.loading && history.length === 0 ? (
              <LoadingBlock label="Loading committed Action history..." />
            ) : history.length === 0 && !historyQuery.error ? (
              <EmptyBlock label="No committed Action history was returned." />
            ) : history.length > 0 ? (
              <div className="overflow-auto">
                <table className="w-full min-w-[900px] text-left text-[12px]">
                  <thead className="border-b border-[color:var(--border)] bg-[var(--surface-muted)] text-[11px] uppercase tracking-wider text-[var(--text-muted)]">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Version</th>
                      <th className="px-3 py-2 font-semibold">Event</th>
                      <th className="px-3 py-2 font-semibold">State</th>
                      <th className="px-3 py-2 font-semibold">Actor</th>
                      <th className="px-3 py-2 font-semibold">Committed</th>
                      <th className="px-3 py-2 font-semibold">Operation digest</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[color:var(--border)]">
                    {history.map((event) => (
                      <tr key={`${event.operation.version}:${event.operation_digest}`}>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{event.operation.version}</td>
                        <td className="px-3 py-3"><Badge value={event.event_kind} /></td>
                        <td className="px-3 py-3"><Badge value={event.operation.state} /></td>
                        <td className="px-3 py-3 font-mono text-[11px] text-[var(--text-secondary)]">{event.actor_id}</td>
                        <td className="px-3 py-3 text-[var(--text-secondary)]">{actionTimeLabel(event.committed_at_unix_ms)}</td>
                        <td className="max-w-[18rem] truncate px-3 py-3 font-mono text-[10px] text-[var(--text-muted)]" title={event.operation_digest}>{event.operation_digest}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        </Panel>
      </div>

      <div className="mt-4 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-3 text-[12px] text-[var(--text-secondary)]">
        Submit approval, execution, and verification commands through clients that hold the corresponding signed Action scopes. Each command must use the current version shown above.
      </div>
    </div>
  );
}

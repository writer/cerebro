"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { FormEvent, useMemo, useState } from "react";

import AskAboutLink from "@/components/ask/AskAboutLink";
import { CoverageMetadata } from "@/components/connectors/CoverageMetadata";
import { useApiKey } from "@/components/providers";
import GraphViewer from "@/components/grc/LazyGraphViewer";
import { Badge, DataStateBanner, MetricCard, PageHeader, Panel, ResultLimitNotice, RiskBadge, RiskBreakdown, SeverityDot } from "@/components/grc/Primitives";
import { fetchCerebro } from "@/lib/cerebro-client";
import { runFindingMutation } from "@/lib/finding-actions";
import { securityProducerForFinding, securityProducerResponseActionCandidates } from "@/lib/security-producer-response";
import { pluralize } from "@/lib/format";
import { displayDate, GRCAuditPacket, GRCEntityImpact, humanize, shortEntity } from "@/lib/grc";
import { grcEntityImpactPath, grcPath, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, grcBoundedRows } from "@/lib/grc-list";

type Tab = "overview" | "evidence" | "graph" | "timeline";
type FindingActionKey = "assign" | "due" | "note" | "ticket" | "resolve" | "suppress";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";
const secondaryButtonClass = "rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50";
const primaryButtonClass = "rounded-md border border-indigo-500 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50";
const FINDING_RESOURCE_URN_LIMIT = 50;
const FINDING_SOURCE_COVERAGE_LIMIT = 24;

const formatDateInput = (value?: string) => {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toISOString().slice(0, 10);
};

const focusElement = (id: string) => {
  window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" }), 0);
};

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`border-b-2 px-4 py-2 text-[13px] font-medium transition ${
        active
          ? "border-indigo-500 text-indigo-600"
          : "border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-700"
      }`}
    >
      {label}
    </button>
  );
}

function KeyValueRow({ label, value, mono = false, href }: { label: string; value: string; mono?: boolean; href?: string }) {
  const content = href ? (
    <Link href={href} className={`text-indigo-600 hover:text-indigo-800 ${mono ? "font-mono text-[12px]" : ""}`}>{value}</Link>
  ) : (
    <span className={`text-slate-800 ${mono ? "font-mono text-[12px]" : ""}`}>{value}</span>
  );
  return (
    <div className="flex items-center justify-between gap-2 border-b border-slate-100 py-2 text-[13px]">
      <span className="text-slate-500">{label}</span>
      <span className="text-right">{content}</span>
    </div>
  );
}

function ResourceURNsPanel({ urns }: { urns?: string[] }) {
  const boundedURNs = grcBoundedRows({ rows: urns, limit: FINDING_RESOURCE_URN_LIMIT });
  if (boundedURNs.rows.length === 0) return null;
  return (
    <Panel title={`Resource URNs (${boundedURNs.meta.total?.toLocaleString() ?? boundedURNs.rows.length})`}>
      <div className="space-y-1.5">
        <ResultLimitNotice loaded={boundedURNs.rows.length} meta={boundedURNs.meta} limit={FINDING_RESOURCE_URN_LIMIT} noun="resource URNs" />
        {boundedURNs.rows.map((urn) => (
          <div key={urn} className="flex items-center justify-between rounded-md bg-slate-50 px-3 py-2">
            <span className="truncate font-mono text-[12px] text-slate-700">{urn}</span>
            <Link href={`/impact?root_urn=${encodeURIComponent(urn)}`} className="ml-2 shrink-0 text-[12px] font-medium text-indigo-600 hover:text-indigo-800">
              Impact
            </Link>
          </div>
        ))}
      </div>
    </Panel>
  );
}

const firstAttribute = (attributes: Record<string, string> | undefined, keys: string[]) => {
  for (const key of keys) {
    const value = attributes?.[key]?.trim();
    if (value) return value;
  }
  return "";
};

const listFromValue = (value?: string | string[]) => {
  if (Array.isArray(value)) return value.map((item) => item.trim()).filter(Boolean);
  if (!value) return [];
  const trimmed = value.trim();
  if (!trimmed) return [];
  return trimmed
    .split(/[,;|]/)
    .map((item) => item.trim())
    .filter(Boolean);
};

function AuditContextPanel({ finding }: { finding: GRCAuditPacket["finding"] }) {
  const attributes = finding.attributes;
  const evidenceType = finding.evidence_type || firstAttribute(attributes, ["policy_evidence_type", "evidence_type"]);
  const assessmentMethods = [
    ...listFromValue(finding.assessment_methods),
    ...listFromValue(firstAttribute(attributes, ["policy_assessment_methods", "assessment_methods"])),
  ];
  const auditorGuidance = [
    ...listFromValue(finding.auditor_guidance),
    ...listFromValue(firstAttribute(attributes, ["policy_auditor_guidance", "auditor_guidance"])),
  ];
  const riskStatement = finding.risk_statement || firstAttribute(attributes, ["policy_risk_statement", "risk_statement"]);
  const remediationIntent = finding.remediation_intent || firstAttribute(attributes, ["policy_remediation_intent", "remediation_intent"]);
  const sourceCoverageRefs = finding.source_coverage_refs ?? [];
  const boundedSourceCoverage = grcBoundedRows({ rows: sourceCoverageRefs, limit: FINDING_SOURCE_COVERAGE_LIMIT });
  const hasContext = evidenceType || assessmentMethods.length > 0 || auditorGuidance.length > 0 || riskStatement || remediationIntent || sourceCoverageRefs.length > 0;

  if (!hasContext) return null;

  return (
    <Panel title="Audit Context">
      <div className="space-y-4">
        {(evidenceType || assessmentMethods.length > 0) && (
          <div className="flex flex-wrap gap-2">
            {evidenceType && <Badge value={humanize(evidenceType)} />}
            {assessmentMethods.map((method) => (
              <span key={method} className="rounded-md bg-slate-50 px-2 py-1 text-[11px] font-semibold text-slate-600">
                {humanize(method)}
              </span>
            ))}
          </div>
        )}
        {(riskStatement || remediationIntent) && (
          <div className="grid gap-3 md:grid-cols-2">
            {riskStatement && (
              <div className="rounded-md bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Risk statement</div>
                <div className="mt-1 text-[12px] leading-5 text-slate-700">{riskStatement}</div>
              </div>
            )}
            {remediationIntent && (
              <div className="rounded-md bg-slate-50 p-3">
                <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Remediation intent</div>
                <div className="mt-1 text-[12px] leading-5 text-slate-700">{remediationIntent}</div>
              </div>
            )}
          </div>
        )}
        {auditorGuidance.length > 0 && (
          <div className="rounded-md bg-slate-50 p-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Auditor guidance</div>
            <ul className="mt-2 space-y-1">
              {auditorGuidance.slice(0, 4).map((guidance) => (
                <li key={guidance} className="text-[12px] leading-5 text-slate-700">{guidance}</li>
              ))}
            </ul>
          </div>
        )}
        {sourceCoverageRefs.length > 0 && (
          <div>
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-slate-500">Source coverage</div>
            <ResultLimitNotice className="mb-3" loaded={boundedSourceCoverage.rows.length} meta={boundedSourceCoverage.meta} limit={FINDING_SOURCE_COVERAGE_LIMIT} noun="coverage records" />
            <div className="grid gap-2 md:grid-cols-2">
              {boundedSourceCoverage.rows.map((coverage, index) => (
                <Link
                  key={`${coverage.source_id}-${coverage.dimension_id}-${index}`}
                  href={coverage.source_id ? `/connectors/${encodeURIComponent(coverage.source_id)}?tab=scope` : "/connectors"}
                  className="rounded-md border border-slate-200 bg-white p-3 transition hover:border-indigo-200 hover:bg-indigo-50/40"
                >
                  <div className="mb-2 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-[12px] font-semibold text-slate-900">{coverage.dimension_id || coverage.dimension_type || "coverage"}</div>
                      <div className="mt-0.5 font-mono text-[11px] text-slate-500">{coverage.source_id || "source"} · {coverage.dimension_type || "dimension"}</div>
                    </div>
                    {coverage.support_level && <Badge value={coverage.support_level} />}
                  </div>
                  <CoverageMetadata item={coverage} compact />
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

function TimelinePanel({
  evidence,
  finding,
  onOpenEvidence,
  onOpenRemediation,
  onOpenWaiver,
}: {
  evidence: GRCAuditPacket["evidence"];
  finding: GRCAuditPacket["finding"];
  onOpenEvidence: () => void;
  onOpenRemediation: () => void;
  onOpenWaiver: () => void;
}) {
  const events = useMemo(() => {
    const items: { date: string; label: string; detail: string; type: "finding" | "evidence" | "sla" }[] = [];
    if (finding.first_observed_at) {
      items.push({ date: finding.first_observed_at, label: "First observed", detail: `Severity: ${finding.severity}`, type: "finding" });
    }
    evidence.forEach((e) => {
      if (e.created_at) {
        items.push({
          date: e.created_at,
          label: "Evidence collected",
          detail: `${e.event_ids?.length ?? 0} events, ${e.claim_ids?.length ?? 0} claims`,
          type: "evidence",
        });
      }
    });
    if (finding.due_at) {
      items.push({ date: finding.due_at, label: "SLA due", detail: finding.sla_status, type: "sla" });
    }
    if (finding.last_observed_at) {
      items.push({ date: finding.last_observed_at, label: "Last observed", detail: finding.status, type: "finding" });
    }
    return items.sort((a, b) => a.date.localeCompare(b.date));
  }, [finding, evidence]);

  const dotColor = (type: string) => {
    if (type === "evidence") return "bg-indigo-500";
    if (type === "sla") return "bg-amber-500";
    return "bg-slate-400";
  };

  return (
    <div className="space-y-0">
      {events.map((event, i) => (
        <div key={`${event.date}-${i}`} className="flex gap-3 py-2.5">
          <div className="flex flex-col items-center">
            <div className={`mt-1 h-2.5 w-2.5 rounded-full ${dotColor(event.type)}`} />
            {i < events.length - 1 && <div className="w-px flex-1 bg-slate-200" />}
          </div>
          <div className="min-w-0 flex-1 pb-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[13px] font-medium text-slate-900">{event.label}</span>
              <span className="shrink-0 text-[12px] text-slate-500">{displayDate(event.date)}</span>
            </div>
            <div className="text-[12px] text-slate-500">{event.detail}</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {event.type === "finding" && finding.entity && (
                <>
                  <Link href={`/impact?root_urn=${encodeURIComponent(finding.entity)}`} className={secondaryButtonClass}>Open evidence graph</Link>
                  <Link href={`/explore?root_urn=${encodeURIComponent(finding.entity)}`} className={secondaryButtonClass}>Open graph</Link>
                </>
              )}
              {event.type === "evidence" && (
                <button type="button" onClick={onOpenEvidence} className={secondaryButtonClass}>
                  Review evidence
                </button>
              )}
              {event.type === "sla" && (
                <>
                  <button type="button" onClick={onOpenRemediation} className={primaryButtonClass}>
                    Create remediation
                  </button>
                  <button type="button" onClick={onOpenWaiver} className={secondaryButtonClass}>
                    Create waiver
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      ))}
      {events.length === 0 && (
        <div className="py-4 text-center text-[13px] text-slate-500">No timeline events available.</div>
      )}
    </div>
  );
}

function FindingWorkflowPanel({
  actionError,
  actionSaving,
  actionSuccess,
  assigneeDraft,
  dueDateDraft,
  finding,
  noteDraft,
  onAssign,
  onDueDate,
  onNote,
  onResolve,
  onSuppress,
  onTicket,
  resolveReason,
  setAssigneeDraft,
  setDueDateDraft,
  setNoteDraft,
  setResolveReason,
  setSuppressReason,
  setTicketExternalID,
  setTicketName,
  setTicketURL,
  suppressReason,
  ticketExternalID,
  ticketName,
  ticketURL,
}: {
  actionError: string | null;
  actionSaving: FindingActionKey | null;
  actionSuccess: string | null;
  assigneeDraft: string;
  dueDateDraft: string;
  finding: GRCAuditPacket["finding"];
  noteDraft: string;
  onAssign: (event: FormEvent<HTMLFormElement>) => void;
  onDueDate: (event: FormEvent<HTMLFormElement>) => void;
  onNote: (event: FormEvent<HTMLFormElement>) => void;
  onResolve: (event: FormEvent<HTMLFormElement>) => void;
  onSuppress: (event: FormEvent<HTMLFormElement>) => void;
  onTicket: (event: FormEvent<HTMLFormElement>) => void;
  resolveReason: string;
  setAssigneeDraft: (value: string) => void;
  setDueDateDraft: (value: string) => void;
  setNoteDraft: (value: string) => void;
  setResolveReason: (value: string) => void;
  setSuppressReason: (value: string) => void;
  setTicketExternalID: (value: string) => void;
  setTicketName: (value: string) => void;
  setTicketURL: (value: string) => void;
  suppressReason: string;
  ticketExternalID: string;
  ticketName: string;
  ticketURL: string;
}) {
  const notes = finding.notes ?? [];
  const tickets = finding.tickets ?? [];
  const externalRefs = finding.external_refs ?? [];
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Workflow</div>
          <h2 className="mt-1 text-[15px] font-semibold text-slate-900">Push updates to Cerebro</h2>
        </div>
        <Badge value={finding.status} />
      </div>
      <p className="mt-2 text-[12px] leading-5 text-slate-500">
        Change owner, due date, notes, tickets, and lifecycle state.
      </p>

      {actionError && <div className="mt-3 rounded-md border border-red-100 bg-red-50 px-3 py-2 text-[12px] text-red-700">{actionError}</div>}
      {actionSuccess && <div className="mt-3 rounded-md border border-emerald-100 bg-emerald-50 px-3 py-2 text-[12px] text-emerald-700">{actionSuccess}</div>}

      <div className="mt-4 space-y-4">
        <form onSubmit={onAssign} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
          <label className={labelClass}>
            Assignee
            <input value={assigneeDraft} onChange={(event) => setAssigneeDraft(event.target.value)} placeholder={finding.assignee || finding.owner || "identity-team"} className={inputClass} />
          </label>
          <div className="mt-2 flex justify-end">
            <button type="submit" disabled={actionSaving === "assign"} className={secondaryButtonClass}>
              {actionSaving === "assign" ? "Saving..." : "Save owner"}
            </button>
          </div>
        </form>

        <form onSubmit={onDueDate} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
          <label className={labelClass}>
            Due date
            <input type="date" value={dueDateDraft} onChange={(event) => setDueDateDraft(event.target.value)} placeholder={formatDateInput(finding.due_at)} className={inputClass} />
          </label>
          <div className="mt-2 flex justify-end">
            <button type="submit" disabled={actionSaving === "due"} className={secondaryButtonClass}>
              {actionSaving === "due" ? "Saving..." : "Save due date"}
            </button>
          </div>
        </form>

        <form onSubmit={onNote} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
          <label className={labelClass}>
            Note
            <textarea value={noteDraft} onChange={(event) => setNoteDraft(event.target.value)} placeholder="What changed, who was contacted, or why this is acceptable..." className={`${inputClass} min-h-20 normal-case tracking-normal`} />
          </label>
          <div className="mt-2 flex justify-end">
            <button type="submit" disabled={actionSaving === "note" || noteDraft.trim().length === 0} className={secondaryButtonClass}>
              {actionSaving === "note" ? "Adding..." : "Add note"}
            </button>
          </div>
        </form>

        <form id="finding-remediation" onSubmit={onTicket} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
          <div className="grid gap-2">
            <label className={labelClass}>Ticket URL<input value={ticketURL} onChange={(event) => setTicketURL(event.target.value)} placeholder="https://tracker.example.com/browse/SEC-123" className={inputClass} /></label>
            <label className={labelClass}>Name<input value={ticketName} onChange={(event) => setTicketName(event.target.value)} placeholder="SEC-123" className={inputClass} /></label>
            <label className={labelClass}>External ID<input value={ticketExternalID} onChange={(event) => setTicketExternalID(event.target.value)} placeholder="SEC-123" className={inputClass} /></label>
          </div>
          <div className="mt-2 flex justify-end">
            <button type="submit" disabled={actionSaving === "ticket" || ticketURL.trim().length === 0} className={secondaryButtonClass}>
              {actionSaving === "ticket" ? "Linking..." : "Link ticket"}
            </button>
          </div>
        </form>

        <div className="grid gap-3">
          <form onSubmit={onResolve} className="rounded-lg border border-emerald-100 bg-emerald-50 p-3">
            <label className="text-[11px] font-medium uppercase tracking-wider text-emerald-700">
              Resolution reason
              <textarea value={resolveReason} onChange={(event) => setResolveReason(event.target.value)} placeholder="Evidence confirms remediation..." className={`${inputClass} min-h-16 normal-case tracking-normal`} />
            </label>
            <div className="mt-2 flex justify-end">
              <button type="submit" disabled={actionSaving === "resolve" || resolveReason.trim().length === 0} className={primaryButtonClass}>
                {actionSaving === "resolve" ? "Resolving..." : "Resolve finding"}
              </button>
            </div>
          </form>
          <form id="finding-waiver" onSubmit={onSuppress} className="rounded-lg border border-amber-100 bg-amber-50 p-3">
            <label className="text-[11px] font-medium uppercase tracking-wider text-amber-700">
              Suppression reason
              <textarea value={suppressReason} onChange={(event) => setSuppressReason(event.target.value)} placeholder="Accepted exception, false positive, compensating control..." className={`${inputClass} min-h-16 normal-case tracking-normal`} />
            </label>
            <div className="mt-2 flex justify-end">
              <button type="submit" disabled={actionSaving === "suppress" || suppressReason.trim().length === 0} className={secondaryButtonClass}>
                {actionSaving === "suppress" ? "Suppressing..." : "Suppress"}
              </button>
            </div>
          </form>
        </div>
      </div>

      {(notes.length > 0 || tickets.length > 0 || externalRefs.length > 0) && (
        <div className="mt-5 space-y-4 border-t border-slate-100 pt-4">
          {notes.length > 0 && (
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Notes</div>
              <div className="mt-2 space-y-2">
                {notes.slice(0, 3).map((note) => (
                  <div key={note.id || note.body} className="rounded-md bg-slate-50 px-3 py-2 text-[12px] leading-5 text-slate-600">
                    <div>{note.body}</div>
                    {note.created_at && <div className="mt-1 text-[11px] text-slate-400">{displayDate(note.created_at)}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {tickets.length > 0 && (
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Tickets</div>
              <div className="mt-2 space-y-1.5">
                {tickets.slice(0, 3).map((ticket) => (
                  <a key={ticket.url} href={ticket.url} target="_blank" rel="noreferrer" className="block truncate rounded-md bg-slate-50 px-3 py-2 text-[12px] font-medium text-indigo-600 hover:bg-slate-100">
                    {ticket.name || ticket.external_id || ticket.url}
                  </a>
                ))}
              </div>
            </div>
          )}
          {externalRefs.length > 0 && (
            <div>
              <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">External lifecycle</div>
              <div className="mt-2 space-y-1.5">
                {externalRefs.slice(0, 3).map((ref) => (
                  <div key={`${ref.system}-${ref.external_id}`} className="rounded-md bg-slate-50 px-3 py-2 text-[12px] text-slate-600">
                    <span className="font-medium text-slate-800">{ref.system || "external"}</span>
                    {ref.external_status ? ` ${ref.external_status}` : ""}
                    {ref.external_id ? ` · ${ref.external_id}` : ""}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function FindingDetailPage() {
  const { apiKey } = useApiKey();
  const params = useParams<{ id: string }>();
  const findingID = useMemo(() => decodeURIComponent(params.id ?? ""), [params.id]);
  const [tab, setTab] = useState<Tab>("overview");
  const [actionSaving, setActionSaving] = useState<FindingActionKey | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [assigneeDraft, setAssigneeDraft] = useState("");
  const [dueDateDraft, setDueDateDraft] = useState("");
  const [noteDraft, setNoteDraft] = useState("");
  const [ticketURL, setTicketURL] = useState("");
  const [ticketName, setTicketName] = useState("");
  const [ticketExternalID, setTicketExternalID] = useState("");
  const [resolveReason, setResolveReason] = useState("");
  const [suppressReason, setSuppressReason] = useState("");

  const { data, error, lastSuccessfulAt, reload, state: queryState } = useGRCQuery<GRCAuditPacket>(
    findingID ? grcPath(`/grc/audit-packets/${encodeURIComponent(findingID)}`, { limit: GRC_DETAIL_LIMIT }) : null,
  );

  const entityURN = data?.finding?.entity;
  const { data: impactData } = useGRCQuery<GRCEntityImpact>(
    entityURN && tab === "graph" ? grcEntityImpactPath(entityURN, { limit: "50" }) : null,
  );

  const finding = data?.finding;
  const rawControls = data?.controls ?? finding?.controls;
  const rawEvidence = data?.evidence;
  const boundedControlRows = useMemo(
    () => grcBoundedRows({ rows: rawControls, limit: GRC_DETAIL_LIMIT }),
    [rawControls],
  );
  const boundedEvidenceRows = useMemo(
    () => grcBoundedRows({ rows: rawEvidence, limit: GRC_DETAIL_LIMIT, total: finding?.evidence_count }),
    [rawEvidence, finding?.evidence_count],
  );
  const controls = boundedControlRows.rows;
  const evidence = boundedEvidenceRows.rows;
  const evidenceTotal = boundedEvidenceRows.meta.total ?? evidence.length;

  const mutateFinding = async (key: FindingActionKey, path: string, method: "POST" | "PUT", body: Record<string, unknown>, success: string) => {
    setActionSaving(key);
    setActionError(null);
    setActionSuccess(null);
    return runFindingMutation({
      failurePrefix: "Finding update failed",
      onError: setActionError,
      onSettled: () => setActionSaving(null),
      onSuccess: () => {
        setActionSuccess(success);
        void reload();
      },
      request: () => fetchCerebro(path, apiKey, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
    });
  };

  const assignFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const ok = await mutateFinding(
      "assign",
      `/findings/${encodeURIComponent(findingID)}/assign`,
      "PUT",
      { assignee: assigneeDraft.trim() },
      assigneeDraft.trim() ? "Owner updated." : "Owner cleared.",
    );
    if (ok) setAssigneeDraft("");
  };

  const setFindingDueDate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const body = dueDateDraft ? { dueAt: new Date(`${dueDateDraft}T00:00:00Z`).toISOString() } : {};
    const ok = await mutateFinding(
      "due",
      `/findings/${encodeURIComponent(findingID)}/due`,
      "PUT",
      body,
      dueDateDraft ? "Due date updated." : "Due date cleared.",
    );
    if (ok) setDueDateDraft("");
  };

  const addFindingNote = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const note = noteDraft.trim();
    if (!note) return;
    const ok = await mutateFinding(
      "note",
      `/findings/${encodeURIComponent(findingID)}/notes`,
      "POST",
      { note },
      "Note added.",
    );
    if (ok) setNoteDraft("");
  };

  const linkFindingTicket = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const url = ticketURL.trim();
    if (!url) return;
    const ok = await mutateFinding(
      "ticket",
      `/findings/${encodeURIComponent(findingID)}/tickets`,
      "POST",
      { url, name: ticketName.trim(), externalId: ticketExternalID.trim() },
      "Ticket linked.",
    );
    if (ok) {
      setTicketURL("");
      setTicketName("");
      setTicketExternalID("");
    }
  };

  const resolveFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const reason = resolveReason.trim();
    if (!reason) return;
    const ok = await mutateFinding(
      "resolve",
      `/findings/${encodeURIComponent(findingID)}/resolve`,
      "POST",
      { reason },
      "Finding resolved.",
    );
    if (ok) setResolveReason("");
  };

  const suppressFinding = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const reason = suppressReason.trim();
    if (!reason) return;
    const ok = await mutateFinding(
      "suppress",
      `/findings/${encodeURIComponent(findingID)}/suppress`,
      "POST",
      { reason },
      "Finding suppressed.",
    );
    if (ok) setSuppressReason("");
  };

  const openEvidenceFromTimeline = () => {
    setTab("evidence");
    focusElement("finding-evidence");
  };

  const openRemediationFromTimeline = () => {
    setTab("overview");
    if (finding) {
      setTicketName((current) => current || `Remediate ${finding.id}`);
      setTicketExternalID((current) => current || finding.id);
    }
    focusElement("finding-remediation");
  };

  const openWaiverFromTimeline = () => {
    setTab("overview");
    if (finding) {
      setSuppressReason((current) => current || `Temporary exception requested for ${finding.id}: `);
    }
    focusElement("finding-waiver");
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={finding?.title || "Finding Detail"}
        description={finding?.summary || "Loading finding details..."}
        action={
          <div className="flex items-center gap-2">
            {finding?.entity && (
              <AskAboutLink
                variant="button"
                question={`Which entities are affected by ${finding.title} and what should be reviewed first?`}
                scopeUrn={finding.entity}
                title="Ask about this finding"
                context={{
                  route: `/findings/${encodeURIComponent(finding.id)}`,
                  routeLabel: "Finding Detail",
                  title: finding.title,
                  findingId: finding.id,
                  rule_id: finding.rule_id,
                  runtime_id: finding.runtime_id,
                  source_id: finding.source_id,
                  severity: finding.severity,
                  status: finding.status,
                  oauth_app_id: finding.attributes?.oauthAppId ?? finding.attributes?.oauth_app_id,
                  oauth_grant_id: finding.attributes?.oauthGrantId ?? finding.attributes?.oauth_grant_id,
                  security_producer_id: securityProducerForFinding(finding)?.id,
                  response_action_candidates: securityProducerResponseActionCandidates(finding),
                  chips: [
                    { label: "Finding", value: finding.id },
                    finding.rule_id ? { label: "Rule", value: finding.rule_id } : null,
                    finding.source_id ? { label: "Source", value: finding.source_id } : null,
                  ].filter(Boolean) as { label: string; value: string }[],
                }}
              >
                Ask
              </AskAboutLink>
            )}
            <button type="button" onClick={() => void reload()} className="rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              Refresh
            </button>
          </div>
        }
      />

      <DataStateBanner
        state={queryState}
        subject="Finding details"
        error={error}
        lastSuccessfulAt={lastSuccessfulAt}
        onRetry={() => void reload()}
        detail={queryState === "loading" ? "Loading finding details." : queryState === "unavailable" ? "Finding details will appear when graph data is reachable." : undefined}
      />

      {finding && (
        <>
          <div className="grid gap-4 md:grid-cols-5">
            <MetricCard label="Risk Score" value={<RiskBadge score={finding.risk_score} />} detail={`L ${finding.likelihood_score ?? "\u2014"} / I ${finding.impact_score ?? "\u2014"} / C ${finding.confidence_score ?? "\u2014"}`} intent={(finding.risk_score ?? 0) >= 85 ? "danger" : "neutral"} />
            <MetricCard label="Severity" value={<div className="flex items-center gap-1.5"><SeverityDot severity={finding.severity} /><Badge value={finding.severity} tone="severity" /></div>} detail={finding.status} intent={finding.severity === "CRITICAL" ? "danger" : "neutral"} />
            <MetricCard label="Owner" value={finding.owner || "Unassigned"} detail={finding.sla_status} intent={!finding.owner || finding.owner === "Unassigned" ? "warning" : "success"} />
            <MetricCard label="Evidence" value={evidence.length} detail={`${evidenceTotal.toLocaleString()} total`} />
            <MetricCard label="Controls" value={controls.length} detail={pluralize(controls.length, "mapped objective")} />
          </div>

          <div className="border-b border-slate-200">
            <div className="flex gap-0">
              <TabButton label="Overview" active={tab === "overview"} onClick={() => setTab("overview")} />
              <TabButton label={`Evidence (${evidence.length})`} active={tab === "evidence"} onClick={() => setTab("evidence")} />
              <TabButton label="Impact Graph" active={tab === "graph"} onClick={() => setTab("graph")} />
              <TabButton label="Timeline" active={tab === "timeline"} onClick={() => setTab("timeline")} />
            </div>
          </div>

          {tab === "overview" && (
            <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px]">
              <div className="space-y-6">
                <div className="rounded-lg bg-indigo-50 p-4 text-[13px] text-indigo-900">
                  <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-indigo-600">Recommended Action</div>
                  {data.recommended_action}
                </div>

                <AuditContextPanel finding={finding} />

                <RiskBreakdown finding={finding} />

                <Panel title="Mapped Controls">
                  <div className="space-y-3">
                    {controls.length > 0 && <ResultLimitNotice loaded={controls.length} meta={boundedControlRows.meta} limit={GRC_DETAIL_LIMIT} noun="controls" />}
                    <div className="flex flex-wrap gap-2">
                    {controls.length === 0 && <span className="text-[13px] text-slate-500">No controls mapped.</span>}
                    {controls.map((c) => (
                      <Link
                        key={`${c.framework_name}-${c.control_id}`}
                        href={`/controls?framework=${encodeURIComponent(c.framework_name)}&control=${encodeURIComponent(c.control_id)}`}
                        className="rounded-md border border-slate-200 px-3 py-1.5 text-[12px] font-medium text-slate-700 transition hover:border-indigo-300 hover:text-indigo-600"
                      >
                        {c.framework_name} {c.control_id}
                      </Link>
                    ))}
                    </div>
                  </div>
                </Panel>

                <ResourceURNsPanel urns={finding.resource_urns} />
              </div>

              <div className="space-y-4">
                <FindingWorkflowPanel
                  actionError={actionError}
                  actionSaving={actionSaving}
                  actionSuccess={actionSuccess}
                  assigneeDraft={assigneeDraft}
                  dueDateDraft={dueDateDraft}
                  finding={finding}
                  noteDraft={noteDraft}
                  onAssign={(event) => void assignFinding(event)}
                  onDueDate={(event) => void setFindingDueDate(event)}
                  onNote={(event) => void addFindingNote(event)}
                  onResolve={(event) => void resolveFinding(event)}
                  onSuppress={(event) => void suppressFinding(event)}
                  onTicket={(event) => void linkFindingTicket(event)}
                  resolveReason={resolveReason}
                  setAssigneeDraft={setAssigneeDraft}
                  setDueDateDraft={setDueDateDraft}
                  setNoteDraft={setNoteDraft}
                  setResolveReason={setResolveReason}
                  setSuppressReason={setSuppressReason}
                  setTicketExternalID={setTicketExternalID}
                  setTicketName={setTicketName}
                  setTicketURL={setTicketURL}
                  suppressReason={suppressReason}
                  ticketExternalID={ticketExternalID}
                  ticketName={ticketName}
                  ticketURL={ticketURL}
                />
                <div className="rounded-lg border border-slate-200 bg-white p-4">
                  <div className="mb-3 text-[11px] font-medium uppercase tracking-wider text-slate-500">Details</div>
                  <KeyValueRow label="Finding ID" value={finding.id} mono />
                  <KeyValueRow label="Entity" value={shortEntity(finding.entity)} mono href={finding.entity ? `/impact?root_urn=${encodeURIComponent(finding.entity)}` : undefined} />
                  <KeyValueRow label="Runtime" value={shortEntity(finding.runtime_id)} mono />
                  <KeyValueRow label="Source" value={finding.source_id || "\u2014"} mono />
                  <KeyValueRow label="Rule" value={shortEntity(finding.rule_id)} mono />
                  <KeyValueRow label="Policy" value={finding.policy_name || shortEntity(finding.policy_id)} mono />
                  <KeyValueRow label="First seen" value={displayDate(finding.first_observed_at)} />
                  <KeyValueRow label="Last seen" value={displayDate(finding.last_observed_at)} />
                  <KeyValueRow label="Due" value={displayDate(finding.due_at)} />
                  <KeyValueRow label="Status reason" value={finding.status_reason || "\u2014"} />
                  <KeyValueRow label="Status updated" value={displayDate(finding.status_updated_at)} />
                  <KeyValueRow label="Risk model" value={finding.risk_model_version || "\u2014"} mono />
                  <KeyValueRow label="Generated" value={displayDate(data.generated_at)} />
                </div>
              </div>
            </div>
          )}

          {tab === "evidence" && (
            <div id="finding-evidence" className="space-y-3">
              <ResultLimitNotice loaded={evidence.length} meta={boundedEvidenceRows.meta} limit={GRC_DETAIL_LIMIT} noun="evidence items" />
              <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
                <table className="w-full text-left text-[13px]">
                  <thead>
                    <tr className="border-b border-slate-100 bg-slate-50/80">
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Evidence ID</th>
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Run / Rule</th>
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Events</th>
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Claims</th>
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Graph Roots</th>
                      <th className="px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidence.map((item) => (
                      <tr key={item.id} className="border-b border-slate-50 transition hover:bg-slate-50/60">
                        <td className="px-4 py-3 font-mono text-[12px] text-slate-600">{item.id}</td>
                        <td className="px-4 py-3 text-[12px] text-slate-500">
                          <div>{shortEntity(item.run_id)}</div>
                          <div>{shortEntity(item.rule_id)}</div>
                        </td>
                        <td className="px-4 py-3 tabular-nums text-slate-600">{item.event_ids?.length ?? 0}</td>
                        <td className="px-4 py-3 tabular-nums text-slate-600">{item.claim_ids?.length ?? 0}</td>
                        <td className="px-4 py-3 text-[12px]">
                          {(item.graph_root_urns ?? []).slice(0, 2).map((urn) => (
                            <Link key={urn} href={`/impact?root_urn=${encodeURIComponent(urn)}`} className="mr-2 text-indigo-600 hover:text-indigo-800">{shortEntity(urn)}</Link>
                          ))}
                          {!item.graph_root_urns?.length && <span className="text-slate-400">&mdash;</span>}
                        </td>
                        <td className="px-4 py-3 text-slate-500">{displayDate(item.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {evidence.length === 0 && (
                  <div className="flex items-center justify-center p-8 text-[13px] text-slate-500">No evidence attached.</div>
                )}
              </div>
            </div>
          )}

          {tab === "graph" && (
            <div className="space-y-6">
              <Panel title="Relationships" action={finding?.entity ? <Link href={`/explore?root_urn=${encodeURIComponent(finding.entity)}`} className="text-[12px] font-medium text-indigo-600 hover:text-indigo-800">Open graph</Link> : undefined}>
                <GraphViewer graph={data.graph} />
              </Panel>
              {impactData?.graph && impactData.graph.root && (
                <Panel title="Entity Neighborhood">
                  <GraphViewer graph={impactData.graph} />
                </Panel>
              )}
            </div>
          )}

          {tab === "timeline" && (
            <Panel title="Finding Lifecycle">
              <TimelinePanel
                finding={finding}
                evidence={evidence}
                onOpenEvidence={openEvidenceFromTimeline}
                onOpenRemediation={openRemediationFromTimeline}
                onOpenWaiver={openWaiverFromTimeline}
              />
            </Panel>
          )}
        </>
      )}
    </div>
  );
}

"use client";

import {
  Activity,
  ArrowRight,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Download,
  LockKeyhole,
  MessageSquare,
  MoreVertical,
  Play,
  RefreshCw,
  Send,
  Sparkles,
  UserPlus,
  Wrench,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { type FormEvent, type ReactNode, useMemo, useState } from "react";

import GraphViewer from "@/components/grc/LazyGraphViewer";
import { Badge, ErrorBlock, LoadingBlock, MetricCard, Panel, ResultLimitNotice, SeverityDot } from "@/components/grc/Primitives";
import {
  displayDate,
  GRCRiskScoreFactor,
  GRCVendor,
  GRCVendorAction,
  GRCVendorCloseAction,
  GRCVendorDetailResponse,
  GRCVendorFreshnessClock,
  GRCVendorMonitoringSignal,
  GRCVendorObligation,
  GRCVendorPacket,
  GRCQuestionnaireAssignment,
  GRCQuestionnaireCitation,
  GRCQuestionnaireRun,
  GRCQuestionnaireRunAnswer,
  GRCQuestionnaireRunEvidenceGap,
  GRCQuestionnaireRunResponse,
  GRCQuestionnaireRunsResponse,
  GRCVendorRelatedRecord,
  humanize,
  shortEntity,
} from "@/lib/grc";
import { grcPath, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { primaryAnswerForRun, questionnaireDirectionLabel, questionnaireQueueRows, questionnaireRollups, questionnaireStateIntent, type QuestionnaireQueueRow } from "@/lib/questionnaires";

const EMPTY_FINDINGS: NonNullable<GRCVendorDetailResponse["findings"]> = [];
const EMPTY_EVIDENCE: NonNullable<GRCVendorDetailResponse["evidence"]> = [];
const EMPTY_QUESTIONNAIRE_RUNS: GRCQuestionnaireRun[] = [];

function DetailRow({ label, value }: { label: string; value?: string }) {
  return (
    <div className="grid grid-cols-[140px_minmax(0,1fr)] gap-3 py-2 text-[13px]">
      <dt className="text-[var(--text-muted)]">{label}</dt>
      <dd className="break-words text-[var(--text-primary)]">{value?.trim() || "Not set"}</dd>
    </div>
  );
}

const ownerLabel = (vendor?: GRCVendor) => {
  if (!vendor) return "Not set";
  return vendor.owner || vendor.security_owner_user_id || vendor.business_owner_user_id || "Owner missing";
};

function RelationshipList({ items }: { items: GRCVendorRelatedRecord[] }) {
  if (items.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No linked records.</div>;
  }
  const boundedItems = grcBoundedRows({ rows: items, limit: GRC_DETAIL_LIMIT });
  return (
    <div>
      <ResultLimitNotice className="mb-2" loaded={boundedItems.rows.length} meta={boundedItems.meta} limit={GRC_DETAIL_LIMIT} noun="linked records" />
      <div className="divide-y divide-[color:var(--border)]">
        {boundedItems.rows.map((item) => (
          <div key={item.urn} className="py-3">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{item.label || shortEntity(item.urn)}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[12px] text-[var(--text-muted)]">
                  <span>{humanize(item.entity_type)}</span>
                  {item.relation && <span>{humanize(item.relation)}</span>}
                  {item.source_id && <span>{item.source_id}</span>}
                </div>
              </div>
              <Link href={`/inventory/${encodeURIComponent(item.urn)}`} className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
                Open
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ActionList({ actions }: { actions: GRCVendorAction[] }) {
  if (actions.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No packet actions.</div>;
  }
  return (
    <div className="divide-y divide-[color:var(--border)]">
      {actions.map((action) => (
        <div key={action.id} className="py-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">{action.label}</div>
              <div className="mt-1 text-[12px] text-[var(--text-muted)]">{action.reason || humanize(action.action_type)}</div>
            </div>
            {typeof action.priority === "number" && <Badge value={`P${action.priority}`} />}
          </div>
        </div>
      ))}
    </div>
  );
}

function CloseActionList({ actions }: { actions: GRCVendorCloseAction[] }) {
  if (actions.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No close conditions.</div>;
  }
  return (
    <div className="divide-y divide-[color:var(--border)]">
      {actions.map((action) => (
        <div key={action.id} className="py-3">
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">{action.label}</div>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{action.closes_when}</div>
          {action.finding_key && <div className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">{action.finding_key}</div>}
        </div>
      ))}
    </div>
  );
}

function FreshnessList({ clocks }: { clocks: GRCVendorFreshnessClock[] }) {
  if (clocks.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No evidence freshness checks.</div>;
  }
  const boundedClocks = grcBoundedRows({ rows: clocks, limit: GRC_DETAIL_LIMIT });
  return (
    <div>
      <ResultLimitNotice className="mb-2" loaded={boundedClocks.rows.length} meta={boundedClocks.meta} limit={GRC_DETAIL_LIMIT} noun="freshness checks" />
      <div className="divide-y divide-[color:var(--border)]">
      {boundedClocks.rows.map((clock) => (
        <div key={clock.id} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_120px]">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{clock.label}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{clock.reason || humanize(clock.source)}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">
              {clock.observed_at ? `Observed ${displayDate(clock.observed_at)}` : clock.expires_at ? `Expires ${displayDate(clock.expires_at)}` : "No date"}
            </div>
          </div>
          <div className="flex items-start justify-start md:justify-end">
            <Badge value={clock.status || "unknown"} />
          </div>
        </div>
      ))}
      </div>
    </div>
  );
}

function ObligationList({ obligations }: { obligations: GRCVendorObligation[] }) {
  if (obligations.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No vendor obligations in packet.</div>;
  }
  const boundedObligations = grcBoundedRows({ rows: obligations, limit: GRC_DETAIL_LIMIT });
  return (
    <div>
      <ResultLimitNotice className="mb-2" loaded={boundedObligations.rows.length} meta={boundedObligations.meta} limit={GRC_DETAIL_LIMIT} noun="obligations" />
      <div className="divide-y divide-[color:var(--border)]">
      {boundedObligations.rows.map((obligation) => (
        <div key={obligation.id} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_120px]">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{obligation.label}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{obligation.reason || humanize(obligation.source)}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">
              {obligation.due_at ? `Due ${displayDate(obligation.due_at)}` : obligation.expires_at ? `Expires ${displayDate(obligation.expires_at)}` : "No date"}
            </div>
          </div>
          <div className="flex items-start justify-start md:justify-end">
            <Badge value={obligation.status || "unknown"} />
          </div>
        </div>
      ))}
      </div>
    </div>
  );
}

function ScoreFactorList({ factors }: { factors: GRCRiskScoreFactor[] }) {
  if (factors.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">Risk tier not scored.</div>;
  }
  return (
    <div className="divide-y divide-[color:var(--border)]">
      {factors.map((factor) => (
        <div key={factor.id} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_96px]">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{factor.label}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{factor.reason || "Score input missing"}</div>
          </div>
          <div className="text-left md:text-right">
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{factor.score}/100</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">Weight {factor.weight}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function MonitoringSignalList({ signals }: { signals: GRCVendorMonitoringSignal[] }) {
  if (signals.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No active monitoring signals.</div>;
  }
  const boundedSignals = grcBoundedRows({ rows: signals, limit: GRC_DETAIL_LIMIT });
  return (
    <div>
      <ResultLimitNotice className="mb-2" loaded={boundedSignals.rows.length} meta={boundedSignals.meta} limit={GRC_DETAIL_LIMIT} noun="monitoring signals" />
      <div className="divide-y divide-[color:var(--border)]">
      {boundedSignals.rows.map((signal) => (
        <div key={signal.id} className="grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_120px]">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{signal.label}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{signal.reason || humanize(signal.source)}</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{signal.observed_at ? displayDate(signal.observed_at) : "No observed date"}</div>
          </div>
          <div className="flex items-start justify-start md:justify-end">
            <Badge value={signal.severity || "medium"} tone="severity" />
          </div>
        </div>
      ))}
      </div>
    </div>
  );
}

function BadgeList({ items, emptyLabel }: { items: string[]; emptyLabel: string }) {
  if (items.length === 0) {
    return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">{emptyLabel}</div>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => <Badge key={item} value={item} />)}
    </div>
  );
}

function QuestionnaireReviewsPanel({ tenantID, vendorURN }: { tenantID: string; vendorURN: string }) {
  const [selectedRowID, setSelectedRowID] = useState<string | null>(null);
  const [assignmentOwner, setAssignmentOwner] = useState("");
  const [assignmentTeam, setAssignmentTeam] = useState("");
  const [assignmentReason, setAssignmentReason] = useState("");
  const [commentBody, setCommentBody] = useState("");
  const [decisionState, setDecisionState] = useState("needs_input");
  const [decisionReason, setDecisionReason] = useState("");
  const runsQuery = useGRCQuery<GRCQuestionnaireRunsResponse>(
    grcPath("/grc/questionnaire-runs", {
      tenant_id: tenantID,
      direction: "vendor_review",
      vendor_urn: vendorURN,
      limit: 50,
    }),
  );
  const mutation = useGRCMutation<GRCQuestionnaireRunResponse>();
  const runs = runsQuery.data?.runs ?? EMPTY_QUESTIONNAIRE_RUNS;
  const rows = useMemo(() => questionnaireQueueRows(runs), [runs]);
  const rollups = useMemo(() => questionnaireRollups(runs, runsQuery.data?.summary), [runs, runsQuery.data?.summary]);
  const selectedRow = rows.find((row) => row.id === selectedRowID) ?? rows[0] ?? null;
  const selectedRun = selectedRow ? runs.find((run) => run.run_id === selectedRow.runID) ?? null : null;
  const selectedAnswer = primaryAnswerForRun(selectedRun, selectedRow?.questionID);
  const selectedQuestionID = selectedAnswer?.question_id ?? selectedRow?.questionID ?? null;
  const selectedGap = primaryQuestionnaireGap(selectedAnswer);
  const selectedSlotID = selectedGap ? selectedGap.slot_id || "" : firstOpenQuestionnaireSlotID(selectedAnswer);
  const queueHref = useMemo(() => {
    const params = new URLSearchParams({ direction: "vendor_review", vendor_urn: vendorURN });
    if (tenantID) params.set("tenant_id", tenantID);
    return `/questionnaires?${params.toString()}`;
  }, [tenantID, vendorURN]);

  const resetRowActionForms = () => {
    setAssignmentOwner("");
    setAssignmentTeam("");
    setAssignmentReason("");
    setCommentBody("");
    setDecisionState("needs_input");
    setDecisionReason("");
  };

  const selectQueueRow = (rowID: string) => {
    setSelectedRowID(rowID);
    resetRowActionForms();
  };

  const reloadRuns = () => { void runsQuery.reload(); };

  const processRun = async () => {
    if (!selectedRun) return;
    try {
      await mutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/process`, { tenant_id: tenantID || undefined });
    } catch {
      return;
    }
    reloadRuns();
  };

  const submitAssignment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun) return;
    try {
      await mutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/assignments`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        gap_id: selectedGap?.id || undefined,
        slot_id: selectedSlotID || undefined,
        owner_id: assignmentOwner,
        team: assignmentTeam,
        reason: assignmentReason,
      });
    } catch {
      return;
    }
    reloadRuns();
  };

  const submitDecision = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun) return;
    try {
      await mutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/decisions`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        state: decisionState,
        reason: decisionReason,
      });
    } catch {
      return;
    }
    reloadRuns();
  };

  const submitComment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun || !commentBody.trim()) return;
    try {
      await mutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/comments`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        body: commentBody,
      });
      setCommentBody("");
    } catch {
      return;
    }
    reloadRuns();
  };

  return (
    <Panel
      title="Questionnaire queue"
      action={(
        <div className="flex flex-wrap items-center gap-2">
          <Link href={queueHref} className="primary-button inline-flex items-center gap-2 px-3 py-1.5 text-[12px]">
            Add questionnaire
          </Link>
          <button type="button" onClick={reloadRuns} className="secondary-button px-3 py-1.5 text-[12px]">Refresh</button>
        </div>
      )}
    >
      {runsQuery.error && <ErrorBlock error={runsQuery.error} onRetry={reloadRuns} recoveryDetail="The questionnaire queue needs the GRC questionnaire API." />}
      {runsQuery.loading && !runsQuery.data ? (
        <LoadingBlock label="Loading questionnaire queue..." />
      ) : (
        <div className="space-y-5">
          <div className="grid gap-3 md:grid-cols-5">
            <MetricCard label="Reviews" value={rollups.total} detail="vendor questionnaires" />
            <MetricCard label="Blocked" value={rollups.blocked} detail="answers blocked" intent={rollups.blocked > 0 ? "danger" : "success"} />
            <MetricCard label="Needs review" value={rollups.needsReview} detail="answers queued" intent={rollups.needsReview > 0 ? "warning" : "success"} />
            <MetricCard label="Ready" value={rollups.ready} detail="answers with citations" intent="success" />
            <MetricCard label="Stale evidence" value={rollups.stale} detail="answers affected" intent={rollups.stale > 0 ? "warning" : "success"} />
          </div>

          {mutation.error && <ErrorBlock error={mutation.error} recoveryDetail="The questionnaire action did not save." />}

          {rows.length === 0 ? (
            <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No vendor questionnaires for this vendor.</div>
          ) : (
            <div className="grid gap-5 xl:grid-cols-[360px_minmax(0,1fr)]">
              <div className="divide-y divide-[color:var(--border)] rounded-md border border-[color:var(--border)]">
                {rows.map((row) => (
                  <button
                    key={row.id}
                    type="button"
                    onClick={() => selectQueueRow(row.id)}
                    className={`block w-full p-3 text-left transition hover:bg-[var(--surface-muted)] ${selectedRow?.id === row.id ? "bg-[var(--surface-muted)]" : ""}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{row.question}</div>
                        <div className="mt-1 truncate text-[12px] text-[var(--text-muted)]">{row.title}</div>
                      </div>
                      <Badge value={row.state} />
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2 text-[12px] text-[var(--text-muted)]">
                      <span>{row.owner || "Unassigned"}</span>
                      <span>{row.citationCount} citations</span>
                      <span>Due {displayDate(row.dueAt)}</span>
                    </div>
                  </button>
                ))}
              </div>

              {selectedRun && selectedRow && (
                <QuestionnaireRunDetail
                  actionSaving={mutation.saving}
                  answer={selectedAnswer}
                  assignmentOwner={assignmentOwner}
                  assignmentReason={assignmentReason}
                  assignmentTeam={assignmentTeam}
                  commentBody={commentBody}
                  decisionReason={decisionReason}
                  decisionState={decisionState}
                  onAssignmentOwnerChange={setAssignmentOwner}
                  onAssignmentReasonChange={setAssignmentReason}
                  onAssignmentTeamChange={setAssignmentTeam}
                  onCommentBodyChange={setCommentBody}
                  onDecisionReasonChange={setDecisionReason}
                  onDecisionStateChange={setDecisionState}
                  onProcess={processRun}
                  onSubmitAssignment={submitAssignment}
                  onSubmitComment={submitComment}
                  onSubmitDecision={submitDecision}
                  row={selectedRow}
                  run={selectedRun}
                />
              )}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function QuestionnaireRunDetail({
  actionSaving,
  answer,
  assignmentOwner,
  assignmentReason,
  assignmentTeam,
  commentBody,
  decisionReason,
  decisionState,
  onAssignmentOwnerChange,
  onAssignmentReasonChange,
  onAssignmentTeamChange,
  onCommentBodyChange,
  onDecisionReasonChange,
  onDecisionStateChange,
  onProcess,
  onSubmitAssignment,
  onSubmitComment,
  onSubmitDecision,
  row,
  run,
}: {
  actionSaving: boolean;
  answer: ReturnType<typeof primaryAnswerForRun>;
  assignmentOwner: string;
  assignmentReason: string;
  assignmentTeam: string;
  commentBody: string;
  decisionReason: string;
  decisionState: string;
  onAssignmentOwnerChange: (value: string) => void;
  onAssignmentReasonChange: (value: string) => void;
  onAssignmentTeamChange: (value: string) => void;
  onCommentBodyChange: (value: string) => void;
  onDecisionReasonChange: (value: string) => void;
  onDecisionStateChange: (value: string) => void;
  onProcess: () => Promise<void>;
  onSubmitAssignment: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitComment: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitDecision: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  row: QuestionnaireQueueRow;
  run: GRCQuestionnaireRun;
}) {
  const citations = answer?.citations ?? [];
  const slots = answer?.evidence_slots ?? [];
  const gaps = [...(answer?.missing_evidence ?? []), ...(answer?.conflicts ?? [])];
  const assignments = run.assignments ?? [];
  const decisions = run.decisions ?? [];
  const comments = run.comments ?? [];
  const timeline = run.timeline ?? [];
  const assignmentGap = primaryQuestionnaireGap(answer);
  const assignmentSlotID = assignmentGap ? assignmentGap.slot_id || "" : firstOpenQuestionnaireSlotID(answer);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge value={answer?.answer_state ?? run.status} />
            <span className={`rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${questionnaireIntentClass(questionnaireStateIntent(answer?.answer_state ?? run.status))}`}>
              {questionnaireDirectionLabel(run.direction)}
            </span>
          </div>
          <h3 className="mt-2 text-[15px] font-semibold text-[var(--text-primary)]">{row.question}</h3>
          <div className="mt-1 flex flex-wrap gap-2 text-[12px] text-[var(--text-muted)]">
            <span>{run.title}</span>
            <span>Due {displayDate(row.dueAt)}</span>
            <span>{row.owner || "Unassigned"}</span>
          </div>
        </div>
        <button type="button" onClick={() => { void onProcess(); }} disabled={actionSaving} className="secondary-button inline-flex items-center gap-2 px-3 py-1.5 text-[13px]">
          <Play className="h-4 w-4" aria-hidden="true" />
          {actionSaving ? "Processing" : "Process"}
        </button>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <MetricCard label="Citations" value={citations.length} detail="linked sources" intent={citations.length > 0 ? "success" : "warning"} />
        <MetricCard label="Missing" value={gaps.length} detail="open gaps" intent={gaps.length > 0 ? "warning" : "success"} />
        <MetricCard label="Freshness" value={humanize(answer?.freshness?.status || "unknown")} detail={answer?.freshness?.observed_at ? `Observed ${displayDate(answer.freshness.observed_at)}` : "No observed date"} intent={(answer?.freshness?.status || "").toLowerCase() === "stale" ? "warning" : "neutral"} />
        <MetricCard label="Controls" value={row.mappedControls.length} detail={row.mappedControls.slice(0, 2).join(", ") || "none mapped"} />
      </div>

      <QuestionnaireSection title="Draft answer">
        <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[13px] leading-5 text-[var(--text-secondary)]">
          {answer?.draft_answer || "No draft answer is ready."}
        </div>
      </QuestionnaireSection>

      <div className="grid gap-5 lg:grid-cols-2">
        <QuestionnaireSection title="Evidence slots">
          {slots.length === 0 ? <QuestionnaireEmpty label="No evidence slots recorded." /> : (
            <div className="space-y-2">
              {slots.map((slot) => (
                <div key={slot.id} className="rounded-md border border-[color:var(--border)] p-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[13px] font-medium text-[var(--text-primary)]">{slot.label || humanize(slot.id)}</span>
                    <Badge value={slot.state} />
                  </div>
                  {(slot.missing_reasons ?? []).length > 0 && <div className="mt-2 text-[12px] text-[var(--text-muted)]">{slot.missing_reasons?.join("; ")}</div>}
                </div>
              ))}
            </div>
          )}
        </QuestionnaireSection>

        <QuestionnaireSection title="Citations">
          {citations.length === 0 ? <QuestionnaireEmpty label="No citations linked." /> : (
            <div className="space-y-2">
              {citations.map((citation) => (
                <div key={citation.id} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                  <div className="font-semibold text-[var(--text-primary)]">{citation.label || shortEntity(citation.id)}</div>
                  <div className="mt-1 text-[var(--text-muted)]">{questionnaireCitationDetail(citation, answer?.freshness?.status)}</div>
                </div>
              ))}
            </div>
          )}
        </QuestionnaireSection>
      </div>

      <QuestionnaireSection title="Blockers">
        {gaps.length === 0 ? <QuestionnaireEmpty label="No blockers recorded." /> : (
          <div className="space-y-2">
            {gaps.map((gap) => (
              <div key={gap.id} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
                <div className="font-semibold">{humanize(gap.code)}</div>
                <div className="mt-1">{gap.reason || gap.slot_id || "Reviewer follow-up required."}</div>
                <div className="mt-1 text-amber-800/80 dark:text-amber-100/80">{questionnaireGapDetail(gap)}</div>
              </div>
            ))}
          </div>
        )}
      </QuestionnaireSection>

      <div className="grid gap-3 lg:grid-cols-2">
        <form onSubmit={onSubmitAssignment} className="space-y-2 rounded-md border border-[color:var(--border)] p-3">
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">Assign answer</div>
          <input value={assignmentOwner} onChange={(event) => onAssignmentOwnerChange(event.target.value)} className="control-input w-full px-3 py-1.5 text-[13px]" aria-label="Assignment owner" />
          <input value={assignmentTeam} onChange={(event) => onAssignmentTeamChange(event.target.value)} className="control-input w-full px-3 py-1.5 text-[13px]" aria-label="Assignment team" />
          <input value={assignmentReason} onChange={(event) => onAssignmentReasonChange(event.target.value)} className="control-input w-full px-3 py-1.5 text-[13px]" aria-label="Assignment reason" />
          {(assignmentGap || assignmentSlotID) && (
            <div className="text-[12px] text-[var(--text-muted)]">Assigning {assignmentGap ? humanize(assignmentGap.code) : humanize(assignmentSlotID)}.</div>
          )}
          <button type="submit" disabled={actionSaving || (!assignmentOwner.trim() && !assignmentTeam.trim())} className="secondary-button inline-flex w-full items-center justify-center gap-2 px-3 py-1.5 text-[13px]">
            <UserPlus className="h-4 w-4" aria-hidden="true" />
            Assign
          </button>
        </form>

        <form onSubmit={onSubmitDecision} className="space-y-2 rounded-md border border-[color:var(--border)] p-3">
          <div className="text-[13px] font-semibold text-[var(--text-primary)]">Record decision</div>
          <select value={decisionState} onChange={(event) => onDecisionStateChange(event.target.value)} className="control-input w-full px-3 py-1.5 text-[13px]" aria-label="Decision state">
            <option value="needs_input">Needs input</option>
            <option value="approved">Approved</option>
            <option value="approved_with_conditions">Approved with conditions</option>
            <option value="rejected">Rejected</option>
          </select>
          <input value={decisionReason} onChange={(event) => onDecisionReasonChange(event.target.value)} className="control-input w-full px-3 py-1.5 text-[13px]" aria-label="Decision reason" />
          <button type="submit" disabled={actionSaving} className="primary-button inline-flex w-full items-center justify-center gap-2 px-3 py-1.5 text-[13px]">
            <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
            Save decision
          </button>
        </form>
      </div>

      <form onSubmit={onSubmitComment} className="grid gap-2 rounded-md border border-[color:var(--border)] p-3 lg:grid-cols-[1fr_auto]">
        <textarea
          value={commentBody}
          onChange={(event) => onCommentBodyChange(event.target.value)}
          className="control-input min-h-[72px] w-full resize-y px-3 py-1.5 text-[13px] leading-5"
          aria-label="Comment body"
          placeholder="note, blocker update, or handoff"
        />
        <button type="submit" disabled={actionSaving || !commentBody.trim()} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[13px]">
          <MessageSquare className="h-4 w-4" aria-hidden="true" />
          Add comment
        </button>
      </form>

      <div className="grid gap-5 lg:grid-cols-3">
        <QuestionnaireSection title="Assignments">
          {assignments.length === 0 ? <QuestionnaireEmpty label="No assignments." /> : (
            <div className="divide-y divide-[color:var(--border)]">
              {assignments.map((assignment) => (
                <div key={assignment.id} className="py-3 text-[13px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold text-[var(--text-primary)]">{assignment.owner_id || assignment.team || "Unassigned"}</span>
                    <Badge value={assignment.status} />
                  </div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">{questionnaireAssignmentDetail(assignment)}</div>
                </div>
              ))}
            </div>
          )}
        </QuestionnaireSection>

        <QuestionnaireSection title="Decisions">
          {decisions.length === 0 ? <QuestionnaireEmpty label="No decisions." /> : (
            <div className="divide-y divide-[color:var(--border)]">
              {decisions.map((decision) => (
                <div key={decision.id} className="py-3 text-[13px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold text-[var(--text-primary)]">{decision.actor_id || "Reviewer"}</span>
                    <Badge value={decision.decision} />
                  </div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">{decision.reason || "No reason"}</div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">{displayDate(decision.created_at)}</div>
                </div>
              ))}
            </div>
          )}
        </QuestionnaireSection>

        <QuestionnaireSection title="Comments">
          {comments.length === 0 ? <QuestionnaireEmpty label="No comments." /> : (
            <div className="divide-y divide-[color:var(--border)]">
              {comments.map((comment) => (
                <div key={comment.id} className="py-3 text-[13px]">
                  <div className="font-semibold text-[var(--text-primary)]">{comment.actor_id || "Comment"}</div>
                  <div className="mt-1 text-[var(--text-secondary)]">{comment.body}</div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">{displayDate(comment.created_at)}</div>
                </div>
              ))}
            </div>
          )}
        </QuestionnaireSection>
      </div>

      <QuestionnaireSection title="Timeline">
        {timeline.length === 0 ? <QuestionnaireEmpty label="No timeline events." /> : (
          <div className="divide-y divide-[color:var(--border)]">
            {timeline.map((event) => (
              <div key={event.id} className="grid gap-2 py-3 text-[13px] md:grid-cols-[150px_minmax(0,1fr)]">
                <div className="text-[12px] text-[var(--text-muted)]">{displayDate(event.created_at)}</div>
                <div>
                  <div className="font-semibold text-[var(--text-primary)]">{event.summary || humanize(event.event_type)}</div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">{event.actor_id || "System"}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </QuestionnaireSection>
    </div>
  );
}

function QuestionnaireSection({ children, title }: { children: ReactNode; title: string }) {
  return (
    <section>
      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">{title}</h3>
      {children}
    </section>
  );
}

function QuestionnaireEmpty({ label }: { label: string }) {
  return <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">{label}</div>;
}

const primaryQuestionnaireGap = (answer?: GRCQuestionnaireRunAnswer | null) =>
  [...(answer?.missing_evidence ?? []), ...(answer?.conflicts ?? [])][0] ?? null;

const firstOpenQuestionnaireSlotID = (answer?: GRCQuestionnaireRunAnswer | null) =>
  (answer?.evidence_slots ?? []).find((slot) => slot.state !== "satisfied")?.id ?? "";

const questionnaireCitationDetail = (citation: GRCQuestionnaireCitation, fallbackFreshness?: string) =>
  [
    citation.source || "source",
    citation.evidence_type ? humanize(citation.evidence_type) : "",
    citation.resource_urn ? shortEntity(citation.resource_urn) : citation.evidence_packet_id || citation.evidence_id ? shortEntity(citation.evidence_packet_id || citation.evidence_id || "") : "",
    citation.freshness_status || fallbackFreshness || "unknown",
  ].filter(Boolean).join(" · ");

const questionnaireGapDetail = (gap: GRCQuestionnaireRunEvidenceGap) =>
  [
    gap.slot_id ? `Slot ${humanize(gap.slot_id)}` : "",
    gap.control_id ? `Control ${gap.control_id}` : "",
    gap.evidence_packet_id ? `Packet ${shortEntity(gap.evidence_packet_id)}` : "",
    gap.review_state ? humanize(gap.review_state) : "",
  ].filter(Boolean).join(" · ");

const questionnaireAssignmentDetail = (assignment: GRCQuestionnaireAssignment) =>
  [
    assignment.reason,
    assignment.gap_id ? `Gap ${shortEntity(assignment.gap_id)}` : "",
    assignment.slot_id ? `Slot ${humanize(assignment.slot_id)}` : "",
    assignment.question_id ? `Question ${shortEntity(assignment.question_id)}` : "",
  ].filter(Boolean).join(" · ") || "No reason";

const questionnaireIntentClass = (intent: "neutral" | "danger" | "warning" | "success") => {
  switch (intent) {
    case "danger":
      return "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-200";
    case "warning":
      return "bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-100";
    case "success":
      return "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-200";
    default:
      return "bg-[var(--surface-muted)] text-[var(--text-secondary)]";
  }
};

const packetActions = (packet?: GRCVendorPacket, vendor?: GRCVendor) =>
  packet?.next_actions ?? vendor?.next_actions ?? [];

const packetCloseActions = (packet?: GRCVendorPacket, vendor?: GRCVendor) =>
  packet?.close_actions ?? vendor?.close_actions ?? [];

function VendorGraphPanel({ graph, vendorURN }: { graph: GRCVendorDetailResponse["graph"]; vendorURN: string }) {
  const [loaded, setLoaded] = useState(false);
  const nodeCount = (graph?.neighbors?.length ?? 0) + (graph?.root ? 1 : 0);
  const edgeCount = graph?.relations?.length ?? 0;

  return (
    <Panel
      title="Graph"
      action={<Link href={`/explore?root_urn=${encodeURIComponent(vendorURN)}`} className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">Open graph</Link>}
    >
      {!graph?.root ? (
        <div className="flex items-center justify-center rounded-md border border-dashed border-[color:var(--border-strong)] bg-[var(--surface-muted)] p-10 text-[13px] text-[var(--text-muted)]">
          No graph context available.
        </div>
      ) : loaded ? (
        <GraphViewer graph={graph} />
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-md border border-dashed border-[color:var(--border-strong)] bg-[var(--surface-muted)] p-4">
          <div>
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">{nodeCount} linked entities</div>
            <div className="mt-1 text-[12px] text-[var(--text-muted)]">{edgeCount} relationships available</div>
          </div>
          <button type="button" onClick={() => setLoaded(true)} className="secondary-button px-3 py-1.5 text-[13px]">
            Load graph
          </button>
        </div>
      )}
    </Panel>
  );
}

type VendorTab = "overview" | "risks" | "questionnaire" | "evidence" | "graph" | "activity";

const vendorTabs: { id: VendorTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "risks", label: "Risks" },
  { id: "questionnaire", label: "Questionnaire" },
  { id: "evidence", label: "Evidence" },
  { id: "graph", label: "Graph" },
  { id: "activity", label: "Activity" },
];

const statusTextClass = (value?: string) => {
  const normalized = (value ?? "").toLowerCase();
  if (["critical", "high", "restricted", "overdue", "blocked", "missing", "alert"].includes(normalized)) return "text-rose-400";
  if (["needs_work", "due_soon", "needs_review", "in_progress", "watch", "stale"].includes(normalized)) return "text-violet-300";
  if (["current", "approved", "complete", "completed", "uploaded"].includes(normalized)) return "text-emerald-300";
  return "text-[var(--text-primary)]";
};

const statusBadgeClass = (value?: string) => {
  const normalized = (value ?? "").toLowerCase();
  if (["critical", "high", "restricted", "overdue", "blocked", "missing", "alert", "rejected"].includes(normalized)) {
    return "border-rose-500/30 bg-rose-500/10 text-rose-300";
  }
  if (["needs_work", "due_soon", "needs_review", "in_progress", "pending", "watch", "stale"].includes(normalized)) {
    return "border-violet-500/30 bg-violet-500/10 text-violet-200";
  }
  if (["current", "approved", "complete", "completed", "uploaded", "matched"].includes(normalized)) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  }
  return "border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]";
};

function InlineStatus({ value }: { value?: string }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-1 text-[12px] font-medium ${statusBadgeClass(value)}`}>
      {humanize(value || "unknown")}
    </span>
  );
}

function InitialBadge({ label }: { label?: string }) {
  const initials = (label || "Unassigned")
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "NA";

  return (
    <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[var(--surface-muted)] text-[10px] font-semibold text-[var(--text-secondary)]">
      {initials}
    </span>
  );
}

function ConsoleStatCard({
  detail,
  label,
  progress,
  tone = "neutral",
  value,
}: {
  detail: ReactNode;
  label: string;
  progress?: number;
  tone?: "danger" | "neutral" | "primary" | "warning";
  value: ReactNode;
}) {
  const dotClass = tone === "danger" ? "bg-rose-500" : tone === "warning" ? "bg-amber-500" : tone === "primary" ? "bg-violet-400" : "bg-[var(--text-muted)]";

  return (
    <div className="surface-panel group min-h-[118px] p-4 transition hover:border-[color:var(--border-strong)]">
      <div className="flex items-start justify-between gap-3">
        <div className="text-[13px] text-[var(--text-muted)]">{label}</div>
        <ChevronRight className="h-4 w-4 text-[var(--text-muted)] transition group-hover:text-[var(--text-primary)]" aria-hidden="true" />
      </div>
      <div className={`mt-2 text-[26px] font-semibold leading-none ${tone === "danger" ? "text-rose-400" : "text-[var(--text-primary)]"}`}>{value}</div>
      {progress == null ? (
        <div className="mt-3 flex items-center gap-2 text-[12px] text-[var(--text-muted)]">
          <span className={`h-1.5 w-1.5 rounded-full ${dotClass}`} />
          <span>{detail}</span>
        </div>
      ) : (
        <div className="mt-4 h-1.5 w-[70%] rounded-full bg-[var(--surface-muted)]">
          <div className="h-full rounded-full bg-violet-400" style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} />
        </div>
      )}
    </div>
  );
}

function VendorHero({
  actions,
  assessmentProgress,
  exposureDriverCount,
  exposureLevel,
  onOpenReview,
  onRefresh,
  owner,
  pageTitle,
  riskScore,
  riskTier,
  vendor,
  vendorLifecycle,
}: {
  actions: GRCVendorAction[];
  assessmentProgress: number;
  exposureDriverCount: number;
  exposureLevel: string;
  onOpenReview: () => void;
  onRefresh: () => void;
  owner: string;
  pageTitle: string;
  riskScore?: number;
  riskTier?: string;
  vendor: GRCVendor;
  vendorLifecycle: string;
}) {
  const latestFreshness = (vendor.evidence_freshness ?? [])[0];
  const freshnessLabel = latestFreshness?.observed_at
    ? displayDate(latestFreshness.observed_at)
    : displayDate(vendor.last_material_change_at || vendor.last_review_completed_at);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 text-[13px] text-[var(--text-muted)]">
        <Link href="/vendors" className="transition hover:text-[var(--text-primary)]">Vendors</Link>
        <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="text-[var(--text-secondary)]">{pageTitle}</span>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[36px] font-semibold leading-tight tracking-normal text-[var(--text-primary)]">{pageTitle}</h1>
          <p className="mt-1 text-[14px] text-[var(--text-muted)]">{vendor.services_provided || humanize(vendor.category) || "Vendor review record"}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={onRefresh} className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]">
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            Refresh
          </button>
          <button type="button" onClick={onOpenReview} className="primary-button inline-flex items-center gap-2 px-4 py-2 text-[13px]">
            Open review
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </button>
          <button type="button" className="secondary-button p-2" aria-label="More vendor actions">
            <MoreVertical className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-4 text-[13px] text-[var(--text-muted)]">
        <InlineStatus value={vendorLifecycle} />
        <span className="h-5 w-px bg-[var(--border)]" />
        <span>Score <span className="ml-1 font-semibold text-[var(--text-primary)]">{typeof riskScore === "number" ? `${riskScore}/100` : "Not scored"}</span></span>
        <span className="h-5 w-px bg-[var(--border)]" />
        <span>Tier <span className="ml-1 font-semibold text-[var(--text-primary)]">{riskTier ? humanize(riskTier) : "Not set"}</span></span>
        <span className="h-5 w-px bg-[var(--border)]" />
        <span className="inline-flex items-center gap-2">Owner <InitialBadge label={owner} /> <span className="font-semibold text-[var(--text-primary)]">{owner}</span></span>
        <span className="h-5 w-px bg-[var(--border)]" />
        <span className="inline-flex items-center gap-2">Next review <CalendarDays className="h-4 w-4" aria-hidden="true" /> <span className="font-semibold text-[var(--text-primary)]">{displayDate(vendor.review_due_at)}</span></span>
        <span className="h-5 w-px bg-[var(--border)]" />
        <span>Freshness <span className="ml-1 inline-flex items-center gap-1 font-semibold text-[var(--text-primary)]"><span className={`h-1.5 w-1.5 rounded-full ${vendor.evidence_freshness_state === "stale" ? "bg-amber-400" : "bg-emerald-400"}`} /> {freshnessLabel}</span></span>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <ConsoleStatCard label="Open risks" value={vendor.open_findings ?? 0} detail={`${vendor.high_findings ?? 0} high`} tone={(vendor.open_findings ?? 0) > 0 ? "danger" : "neutral"} />
        <ConsoleStatCard label="Assessment progress" value={`${assessmentProgress}%`} detail="complete" progress={assessmentProgress} tone="primary" />
        <ConsoleStatCard label="Pending actions" value={actions.length} detail={actions.length ? "Requires attention" : "No pending actions"} tone={actions.length ? "warning" : "neutral"} />
        <ConsoleStatCard label="Exposure" value={humanize(exposureLevel)} detail={`${exposureDriverCount} driver${exposureDriverCount === 1 ? "" : "s"}`} tone={["critical", "high"].includes(exposureLevel) ? "danger" : "neutral"} />
      </div>
    </div>
  );
}

function VendorTabBar({ activeTab, onChange }: { activeTab: VendorTab; onChange: (tab: VendorTab) => void }) {
  return (
    <div className="border-b border-[color:var(--border)]">
      <div className="flex gap-5 overflow-x-auto">
        {vendorTabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={`relative whitespace-nowrap pb-3 text-[13px] font-medium transition ${
              activeTab === tab.id ? "text-[var(--primary)] after:absolute after:bottom-0 after:left-0 after:h-0.5 after:w-full after:rounded-full after:bg-[var(--primary)]" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function PriorityIssuesPanel({ findings }: { findings: NonNullable<GRCVendorDetailResponse["findings"]> }) {
  return (
    <Panel title="Priority issues" action={<Link href="/risk-inbox" className="inline-flex items-center gap-1 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">View all risks <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link>}>
      {findings.length === 0 ? (
        <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No open risks on this vendor.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table table-fixed [&_td]:px-2 [&_th]:px-2">
            <colgroup>
              <col className="w-[76px]" />
              <col />
              <col className="w-[88px]" />
              <col className="w-[84px]" />
              <col className="w-[24px]" />
            </colgroup>
            <thead><tr><th>Severity</th><th>Issue</th><th>Owner</th><th>Status</th><th /></tr></thead>
            <tbody>
              {findings.slice(0, 4).map((finding) => (
                <tr key={finding.id}>
                  <td><span className="inline-flex items-center gap-2"><SeverityDot severity={finding.severity} />{humanize(finding.severity)}</span></td>
                  <td>
                    <Link href={`/findings/${encodeURIComponent(finding.id)}`} className="font-semibold text-[var(--text-primary)] hover:text-[var(--primary)]">{finding.title}</Link>
                    <div className="mt-1 text-[12px] text-[var(--text-muted)]">{finding.evidence_count} evidence records</div>
                  </td>
                  <td>
                    <span className="inline-flex items-center gap-2">
                      <InitialBadge label={finding.owner} />
                      <span>{finding.owner || "Unassigned"}</span>
                    </span>
                  </td>
                  <td><InlineStatus value={finding.sla_status || "open"} /></td>
                  <td className="text-right"><MoreVertical className="ml-auto h-4 w-4 text-[var(--text-muted)]" aria-hidden="true" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function RequiredDocumentsPanel({
  packetControls,
  packetMissingItems,
  packetReadyItems,
  vendor,
}: {
  packetControls?: GRCVendorPacket["controls"];
  packetMissingItems: string[];
  packetReadyItems: string[];
  vendor: GRCVendor;
}) {
  const freshness = vendor.evidence_freshness?.[0];
  const isReady = (label: string) => packetReadyItems.some((item) => item.toLowerCase().includes(label.toLowerCase()));
  const isMissing = (label: string) => packetMissingItems.some((item) => item.toLowerCase().includes(label.toLowerCase()));
  const documents = [
    { name: "SOC 2 Type II Report", status: packetControls?.soc2_status || vendor.soc2_status || (isReady("SOC 2") ? "current" : "missing"), updated: freshness?.observed_at },
    { name: "Data Processing Agreement", status: packetControls?.dpa_status || vendor.dpa_status || (isReady("DPA") ? "current" : "missing"), updated: vendor.contract_start_at },
    { name: "ISO 27001 Certificate", status: packetControls?.iso27001_status || vendor.iso27001_status || (isMissing("ISO") ? "missing" : "not_set"), updated: undefined },
    { name: "Security review packet", status: vendor.security_review_status || "not_set", updated: vendor.last_review_completed_at },
    { name: "Subprocessor list", status: vendor.subprocessor === "yes" ? "needs_review" : "not_applicable", updated: vendor.last_review_completed_at },
  ];

  return (
    <Panel title="Required documents" action={<span className="rounded-full bg-[var(--surface-muted)] px-2 py-0.5 text-[12px] font-semibold text-[var(--text-secondary)]">{documents.length}</span>}>
      <div className="overflow-x-auto">
        <table className="data-table">
          <thead><tr><th>Document</th><th>Status</th><th>Last updated</th><th /></tr></thead>
          <tbody>
            {documents.map((document) => {
              const unavailable = ["missing", "not_set", "needs_review"].includes(document.status);
              return (
                <tr key={document.name}>
                  <td>
                    <span className="inline-flex items-center gap-2 font-semibold text-[var(--text-primary)]">
                      {unavailable ? <XCircle className="h-4 w-4 text-rose-400" aria-hidden="true" /> : <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden="true" />}
                      {document.name}
                    </span>
                  </td>
                  <td><InlineStatus value={document.status === "current" ? "uploaded" : document.status} /></td>
                  <td>{document.updated ? displayDate(document.updated) : "Not uploaded"}</td>
                  <td className="text-right">
                    {unavailable ? (
                      <button type="button" className="secondary-button px-2.5 py-1 text-[12px]">Upload</button>
                    ) : (
                      <button type="button" className="rounded-md p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--text-primary)]" aria-label={`Download ${document.name}`}>
                        <Download className="h-4 w-4" aria-hidden="true" />
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function ReviewWorkflowPanel({
  assessmentState,
  monitoringSignals,
  monitoringState,
  remediationState,
  vendor,
  vendorLifecycle,
}: {
  assessmentState: string;
  monitoringSignals: GRCVendorMonitoringSignal[];
  monitoringState: string;
  remediationState: string;
  vendor: GRCVendor;
  vendorLifecycle: string;
}) {
  const rows = [
    { icon: <LockKeyhole className="h-5 w-5" aria-hidden="true" />, label: "Lifecycle", value: vendorLifecycle, detail: vendor.lifecycle_reason || "No lifecycle reason." },
    { icon: <Wrench className="h-5 w-5" aria-hidden="true" />, label: "Remediation", value: remediationState, detail: `${vendor.open_remediation_items ?? 0} open issues` },
    { icon: <ClipboardCheck className="h-5 w-5" aria-hidden="true" />, label: "Assessment", value: assessmentState, detail: `${vendor.assessment_progress ?? 0}% complete` },
    { icon: <Activity className="h-5 w-5" aria-hidden="true" />, label: "Monitoring", value: monitoringState, detail: `${monitoringSignals.length} active signal${monitoringSignals.length === 1 ? "" : "s"}` },
  ];

  return (
    <Panel title="Review workflow" action={<Link href="/vendors" className="inline-flex items-center gap-1 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">Vendor list <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /></Link>}>
      <div className="divide-y divide-[color:var(--border)]">
        {rows.map((row) => (
          <div key={row.label} className="grid grid-cols-[42px_minmax(0,1fr)] gap-3 py-4 first:pt-0 last:pb-0">
            <div className="flex h-9 w-9 items-center justify-center rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] text-[var(--text-secondary)]">{row.icon}</div>
            <div>
              <div className="text-[12px] text-[var(--text-muted)]">{row.label}</div>
              <div className={`mt-0.5 text-[14px] font-semibold ${statusTextClass(row.value)}`}>{humanize(row.value)}</div>
              <div className="mt-0.5 text-[12px] text-[var(--text-muted)]">{row.detail}</div>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

const moneyLabel = (amount?: string, currency?: string) => {
  const trimmedAmount = amount?.trim();
  if (!trimmedAmount) return "";
  const trimmedCurrency = currency?.trim();
  return trimmedCurrency ? `${trimmedCurrency} ${trimmedAmount}` : trimmedAmount;
};

function CommercialPanel({ commercial, vendor }: { commercial?: GRCVendorPacket["commercial"]; vendor: GRCVendor }) {
  return (
    <Panel title="Commercial">
      <dl className="divide-y divide-[color:var(--border)]">
        <DetailRow label="Spend" value={moneyLabel(commercial?.spend_amount ?? vendor.spend_amount, commercial?.spend_currency ?? vendor.spend_currency)} />
        <DetailRow label="Contract value" value={moneyLabel(commercial?.contract_value ?? vendor.contract_value, commercial?.contract_currency ?? vendor.contract_currency)} />
        <DetailRow label="Renewal" value={humanize(commercial?.renewal_state || vendor.renewal_state)} />
        <DetailRow label="Renewal notice" value={displayDate(commercial?.renewal_notice_at || vendor.renewal_notice_at)} />
        <DetailRow label="Contact" value={commercial?.primary_contact || vendor.primary_contact} />
        <DetailRow label="Business unit" value={commercial?.business_unit || vendor.business_unit} />
        <DetailRow label="Cost center" value={commercial?.cost_center || vendor.cost_center} />
      </dl>
    </Panel>
  );
}

function VendorContextPanel({
  exposureLevel,
  packetControls,
  packetOperations,
  packetState,
  remediationState,
  vendor,
  vendorLifecycle,
}: {
  exposureLevel: string;
  packetControls?: GRCVendorPacket["controls"];
  packetOperations?: GRCVendorPacket["operations"];
  packetState: string;
  remediationState: string;
  vendor: GRCVendor;
  vendorLifecycle: string;
}) {
  return (
    <Panel title="Vendor context">
      <dl className="divide-y divide-[color:var(--border)]">
        <DetailRow label="Lifecycle" value={humanize(vendorLifecycle)} />
        <DetailRow label="Source status" value={humanize(vendor.source_status || vendor.status)} />
        <DetailRow label="Category" value={humanize(vendor.category)} />
        <DetailRow label="Website" value={vendor.website_url} />
        <DetailRow label="Services" value={vendor.services_provided} />
        <DetailRow label="Packet" value={humanize(packetState)} />
        <DetailRow label="Exposure" value={humanize(exposureLevel)} />
        <DetailRow label="Remediation" value={humanize(remediationState)} />
        <DetailRow label="Security review" value={humanize(packetControls?.security_review_status || vendor.security_review_status)} />
        <DetailRow label="DPA" value={humanize(packetControls?.dpa_status || vendor.dpa_status)} />
        <DetailRow label="SOC 2" value={humanize(packetControls?.soc2_status || vendor.soc2_status)} />
        <DetailRow label="Data deletion" value={humanize(packetOperations?.data_deletion_state || vendor.data_deletion_state)} />
      </dl>
    </Panel>
  );
}

function AskVendorPanel({ vendorName }: { vendorName: string }) {
  const [draft, setDraft] = useState("");
  const prompts = [
    "Summarize open risks",
    "What evidence is missing?",
    "Show top risk drivers",
  ];

  return (
    <Panel title="Ask Cerebro" action={<span className="rounded-md border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-violet-200">BETA</span>}>
      <div className="space-y-3">
        <div className="grid grid-cols-[36px_minmax(0,1fr)] gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-200">
            <Sparkles className="h-5 w-5" aria-hidden="true" />
          </div>
          <div className="rounded-md bg-[var(--surface-muted)] px-3 py-2 text-[13px] text-[var(--text-secondary)]">
            Ask about {vendorName} risks, evidence, and next review steps.
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {prompts.map((prompt) => (
            <button key={prompt} type="button" onClick={() => setDraft(prompt)} className="secondary-button px-2 py-1 text-[11px]">
              {prompt}
            </button>
          ))}
        </div>
        <form className="flex items-center gap-2 rounded-md border border-[color:var(--border)] bg-[var(--surface-raised)] px-2 py-2" onSubmit={(event) => event.preventDefault()}>
          <input value={draft} onChange={(event) => setDraft(event.target.value)} className="min-w-0 flex-1 bg-transparent px-1 text-[13px] text-[var(--text-primary)] outline-none placeholder:text-[var(--text-muted)]" placeholder="Ask a question..." aria-label="Ask Cerebro" />
          <button type="submit" className="primary-button inline-flex h-7 w-7 items-center justify-center p-0" aria-label="Ask">
            <Send className="h-4 w-4" aria-hidden="true" />
          </button>
        </form>
        <div className="text-[11px] text-[var(--text-muted)]">Verify decisions before closing review tasks.</div>
      </div>
    </Panel>
  );
}

export default function VendorDetailPage() {
  const params = useParams<{ urn?: string }>();
  const searchParams = useSearchParams();
  const [activeTab, setActiveTab] = useState<VendorTab>("overview");
  const vendorID = decodeURIComponent(String(params.urn ?? ""));
  const tenantID = searchParams.get("tenant_id") ?? "";
  const detailQuery = useGRCQuery<GRCVendorDetailResponse>(
    vendorID ? grcPath(`/grc/vendors/${encodeURIComponent(vendorID)}`, { tenant_id: tenantID, limit: 100 }) : null,
  );
  const data = detailQuery.data;
  const vendor = data?.vendor;
  const packet = data?.packet;
  const packetRisk = packet?.risk;
  const packetRiskScore = packet?.risk_score;
  const packetControls = packet?.controls;
  const packetAssessments = packet?.assessments;
  const packetMonitoring = packet?.monitoring;
  const packetCommercial = packet?.commercial;
  const packetOperations = packet?.operations;
  const relationships = data?.relationships ?? {};
  const findings = data?.findings ?? EMPTY_FINDINGS;
  const evidence = data?.evidence ?? EMPTY_EVIDENCE;
  const boundedEvidence = useMemo(() => grcBoundedRows({ rows: evidence, limit: GRC_DETAIL_LIMIT }), [evidence]);
  const actions = packetActions(packet, vendor);
  const closeActions = packetCloseActions(packet, vendor);
  const scoreFactors = packetRiskScore?.score_factors ?? vendor?.score_factors ?? [];
  const monitoringSignals = packetMonitoring?.monitoring_signals ?? vendor?.monitoring_signals ?? [];
  const reviews = useMemo(() => [
    ...(relationships.security_reviews ?? []),
    ...(relationships.security_questionnaires ?? []),
    ...(relationships.assurance_documents ?? []),
  ], [relationships.assurance_documents, relationships.security_questionnaires, relationships.security_reviews]);
  const pageTitle = vendor?.name || "Vendor";
  const vendorLifecycle = vendor?.lifecycle_state || "unknown";
  const riskScore = packetRiskScore?.risk_score ?? vendor?.risk_score;
  const riskTier = packetRiskScore?.risk_tier ?? vendor?.risk_tier;
  const assessmentState = packetAssessments?.assessment_state ?? vendor?.assessment_state ?? "unknown";
  const monitoringState = packetMonitoring?.monitoring_state ?? vendor?.monitoring_state ?? "unknown";
  const packetState = packetOperations?.packet_state ?? vendor?.packet_state ?? "unknown";
  const exposureLevel = packetOperations?.exposure_level ?? vendor?.exposure_level ?? "unknown";
  const remediationState = packetOperations?.remediation_state ?? vendor?.remediation_state ?? "unknown";
  const offboardingState = packetOperations?.offboarding_state ?? vendor?.offboarding_state ?? "";
  const packetReadyItems = packetOperations?.packet_ready_items ?? vendor?.packet_ready_items ?? [];
  const packetMissingItems = packetOperations?.packet_missing_items ?? vendor?.packet_missing_items ?? [];
  const exposureReasons = packetOperations?.exposure_reasons ?? vendor?.exposure_reasons ?? [];
  const assessmentProgress = packetAssessments?.assessment_progress ?? vendor?.assessment_progress ?? 0;
  const owner = ownerLabel(vendor);

  return (
    <main className="mx-auto max-w-[1440px] space-y-6">
      {detailQuery.error && (
        <ErrorBlock
          error={detailQuery.error}
          onRetry={() => { void detailQuery.reload(); }}
          recoveryDetail="Vendor detail appears when the API is reachable."
        />
      )}

      {detailQuery.loading && !data ? (
        <LoadingBlock label="Loading vendor..." />
      ) : vendor ? (
        <>
          <VendorHero
            actions={actions}
            assessmentProgress={assessmentProgress}
            exposureDriverCount={exposureReasons.length}
            exposureLevel={exposureLevel}
            onOpenReview={() => setActiveTab("questionnaire")}
            onRefresh={() => { void detailQuery.reload(); }}
            owner={owner}
            pageTitle={pageTitle}
            riskScore={riskScore}
            riskTier={riskTier}
            vendor={vendor}
            vendorLifecycle={vendorLifecycle}
          />

          <VendorTabBar activeTab={activeTab} onChange={setActiveTab} />

          {activeTab === "overview" && (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_390px]">
              <div className="space-y-4">
                <PriorityIssuesPanel findings={findings} />
                <RequiredDocumentsPanel packetControls={packetControls} packetMissingItems={packetMissingItems} packetReadyItems={packetReadyItems} vendor={vendor} />
              </div>
              <aside className="space-y-4">
                <ReviewWorkflowPanel assessmentState={assessmentState} monitoringSignals={monitoringSignals} monitoringState={monitoringState} remediationState={remediationState} vendor={vendor} vendorLifecycle={vendorLifecycle} />
                <CommercialPanel commercial={packetCommercial} vendor={vendor} />
                <VendorContextPanel
                  exposureLevel={exposureLevel}
                  packetControls={packetControls}
                  packetOperations={packetOperations}
                  packetState={packetState}
                  remediationState={remediationState}
                  vendor={vendor}
                  vendorLifecycle={vendorLifecycle}
                />
                <AskVendorPanel vendorName={pageTitle} />
              </aside>
            </div>
          )}

          {activeTab === "risks" && (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_390px]">
              <PriorityIssuesPanel findings={findings} />
              <div className="space-y-4">
                <Panel title="Risk score">
                  <ScoreFactorList factors={scoreFactors} />
                </Panel>
                <Panel title="Risk inputs">
                  <dl className="divide-y divide-[color:var(--border)]">
                    <DetailRow label="Data" value={humanize(packetRisk?.data_sensitivity || vendor.data_sensitivity)} />
                    <DetailRow label="Access" value={humanize(packetRisk?.access_level || vendor.access_level)} />
                    <DetailRow label="Criticality" value={humanize(packetRisk?.criticality || vendor.criticality)} />
                    <DetailRow label="Subprocessor" value={humanize(packetRisk?.subprocessor || vendor.subprocessor)} />
                    <DetailRow label="Geography" value={packetRisk?.geography || vendor.geography} />
                    <DetailRow label="Dependency" value={humanize(packetRisk?.system_dependency || vendor.system_dependency)} />
                  </dl>
                </Panel>
              </div>
            </div>
          )}

          {activeTab === "questionnaire" && (
            <QuestionnaireReviewsPanel tenantID={tenantID} vendorURN={vendor.urn} />
          )}

          {activeTab === "evidence" && (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_390px]">
              <div className="space-y-4">
                <RequiredDocumentsPanel packetControls={packetControls} packetMissingItems={packetMissingItems} packetReadyItems={packetReadyItems} vendor={vendor} />
                <Panel title="Evidence">
                  {evidence.length === 0 ? (
                    <div className="rounded-md border border-dashed border-[color:var(--border-strong)] p-4 text-[13px] text-[var(--text-muted)]">No evidence records returned for this vendor.</div>
                  ) : (
                    <div>
                      <ResultLimitNotice className="mb-3" loaded={boundedEvidence.rows.length} meta={boundedEvidence.meta} limit={GRC_DETAIL_LIMIT} noun="evidence items" />
                      <div className="overflow-x-auto">
                        <table className="data-table">
                          <thead><tr><th>Evidence</th><th>Finding</th><th>Rule</th><th>Created</th></tr></thead>
                          <tbody>
                            {boundedEvidence.rows.map((item) => (
                              <tr key={item.id}>
                                <td className="font-mono text-[12px]">{shortEntity(item.id)}</td>
                                <td>{item.finding_title || shortEntity(item.finding_id)}</td>
                                <td>{shortEntity(item.rule_id)}</td>
                                <td>{displayDate(item.created_at)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </Panel>
              </div>
              <Panel title="Evidence freshness">
                <FreshnessList clocks={packet?.evidence_freshness ?? vendor.evidence_freshness ?? []} />
              </Panel>
            </div>
          )}

          {activeTab === "graph" && (
            <VendorGraphPanel graph={data?.graph} vendorURN={vendor.urn} />
          )}

          {activeTab === "activity" && (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_300px] xl:grid-cols-[minmax(0,1fr)_390px]">
              <div className="space-y-4">
                <Panel title="Review packet">
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Next actions</h3>
                      <ActionList actions={actions} />
                    </div>
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Close conditions</h3>
                      <CloseActionList actions={closeActions} />
                    </div>
                  </div>
                </Panel>
                <Panel title="Operational posture">
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Packet missing</h3>
                      <BadgeList items={packetMissingItems} emptyLabel="No missing packet items." />
                    </div>
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Packet ready</h3>
                      <BadgeList items={packetReadyItems} emptyLabel="No ready packet items." />
                    </div>
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Exposure</h3>
                      <BadgeList items={exposureReasons} emptyLabel="No exposure drivers." />
                    </div>
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Remediation</h3>
                      <dl className="divide-y divide-[color:var(--border)]">
                        <DetailRow label="State" value={humanize(remediationState)} />
                        <DetailRow label="Due" value={displayDate(packetOperations?.remediation_due_at || vendor.remediation_due_at)} />
                        <DetailRow label="Open" value={String(packetOperations?.open_remediation_items ?? vendor.open_remediation_items ?? 0)} />
                        <DetailRow label="Overdue" value={String(packetOperations?.overdue_remediation_items ?? vendor.overdue_remediation_items ?? 0)} />
                      </dl>
                    </div>
                  </div>
                </Panel>
                <Panel title="Vendor records">
                  <div className="grid gap-6 lg:grid-cols-2">
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Contracts</h3>
                      <RelationshipList items={relationships.contracts ?? []} />
                    </div>
                    <div>
                      <h3 className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Reviews and assurance</h3>
                      <RelationshipList items={reviews} />
                    </div>
                  </div>
                </Panel>
                <div className="grid gap-4 lg:grid-cols-2">
                  <Panel title="Monitoring signals">
                    <MonitoringSignalList signals={monitoringSignals} />
                  </Panel>
                  <Panel title="Obligations">
                    <ObligationList obligations={packet?.obligations ?? []} />
                  </Panel>
                </div>
              </div>
              <aside className="space-y-4">
                <Panel title="Vendor detail">
                  <dl className="divide-y divide-[color:var(--border)]">
                    <DetailRow label="Owner" value={ownerLabel(vendor)} />
                    <DetailRow label="Owner state" value={vendor.owner_state === "missing" ? "Missing" : "Assigned"} />
                    <DetailRow label="Lifecycle" value={humanize(vendorLifecycle)} />
                    <DetailRow label="Source status" value={humanize(vendor.source_status || vendor.status)} />
                    <DetailRow label="Review state" value={humanize(vendor.review_state)} />
                    <DetailRow label="Review due" value={displayDate(vendor.review_due_at)} />
                    <DetailRow label="Last review" value={displayDate(vendor.last_review_completed_at)} />
                    <DetailRow label="Category" value={humanize(vendor.category)} />
                    <DetailRow label="Website" value={vendor.website_url} />
                    <DetailRow label="Services" value={vendor.services_provided} />
                    <DetailRow label="Packet" value={humanize(packetState)} />
                    <DetailRow label="Exposure" value={humanize(exposureLevel)} />
                    <DetailRow label="Remediation" value={humanize(remediationState)} />
                    <DetailRow label="Offboarding" value={humanize(offboardingState)} />
                    <DetailRow label="Data deletion" value={humanize(packetOperations?.data_deletion_state || vendor.data_deletion_state)} />
                    <DetailRow label="Source" value={vendor.provider || vendor.source_id} />
                    <DetailRow label="Runtime" value={shortEntity(vendor.runtime_id)} />
                  </dl>
                </Panel>
                <CommercialPanel commercial={packetCommercial} vendor={vendor} />
                <Panel title="Control posture">
                  <dl className="divide-y divide-[color:var(--border)]">
                    <DetailRow label="Security review" value={humanize(packetControls?.security_review_status || vendor.security_review_status)} />
                    <DetailRow label="Privacy review" value={humanize(packetControls?.privacy_review_status || vendor.privacy_review_status)} />
                    <DetailRow label="DPA" value={humanize(packetControls?.dpa_status || vendor.dpa_status)} />
                    <DetailRow label="BAA" value={humanize(packetControls?.baa_status || vendor.baa_status)} />
                    <DetailRow label="SOC 2" value={humanize(packetControls?.soc2_status || vendor.soc2_status)} />
                    <DetailRow label="ISO 27001" value={humanize(packetControls?.iso27001_status || vendor.iso27001_status)} />
                  </dl>
                </Panel>
                <Panel title="Linked identities">
                  <div className="space-y-4">
                    <div>
                      <div className="mb-2 text-[12px] font-semibold text-[var(--text-muted)]">Owners</div>
                      <RelationshipList items={relationships.owners ?? []} />
                    </div>
                    <div>
                      <div className="mb-2 text-[12px] font-semibold text-[var(--text-muted)]">Hosts</div>
                      <RelationshipList items={relationships.hosts ?? []} />
                    </div>
                    <div>
                      <div className="mb-2 text-[12px] font-semibold text-[var(--text-muted)]">Aliases</div>
                      <RelationshipList items={relationships.aliases ?? []} />
                    </div>
                    <div>
                      <div className="mb-2 text-[12px] font-semibold text-[var(--text-muted)]">Contacts</div>
                      <RelationshipList items={relationships.contacts ?? []} />
                    </div>
                    <div>
                      <div className="mb-2 text-[12px] font-semibold text-[var(--text-muted)]">Fourth parties</div>
                      <RelationshipList items={relationships.fourth_parties ?? []} />
                    </div>
                  </div>
                </Panel>
              </aside>
            </div>
          )}
        </>
      ) : (
        <div className="surface-panel p-8 text-center text-[13px] text-[var(--text-muted)]">Vendor not found.</div>
      )}
    </main>
  );
}

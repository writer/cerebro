"use client";

import { ArrowRight, Bell, CheckCircle2, ClipboardList, Download, FileCheck2, FileText, GitCompare, History, ListChecks, RefreshCw, Search, Send, ShieldCheck, Upload, Users, X, XCircle } from "lucide-react";
import Link from "next/link";
import type { FormEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import type { TableColumn } from "@/components/grc/DataTable";
import { WorklistTable } from "@/components/grc/DataTable";
import { AppliedFilterChips, Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { GRCUploadErrorActions, GRCUploadFileInput, GRCUploadHistoryList, GRCUploadProgress, GRCUploadReceipt } from "@/components/grc/GRCUpload";
import { useApiKey } from "@/components/providers";
import { countLabel } from "@/lib/format";
import type {
  GRCPolicyAcceptance,
  GRCPolicyLifecycleAction,
  GRCPolicyLifecycleActionDefinition,
  GRCPolicyLifecycleActionRequest,
  GRCPolicyLifecycleActionResponse,
  GRCPolicyLifecycleEvent,
  GRCPolicyApproval,
  GRCPolicyControlRef,
  GRCPolicyDocument,
  GRCPolicyDocumentWork,
  GRCPolicyException,
  GRCPolicyGovernanceGap,
  GRCPolicyGovernanceGapRollups,
  GRCPolicyGovernanceRule,
  GRCPolicyLifecycleMapping,
  GRCPolicyLifecyclePolicy,
  GRCPolicyLifecycleResponse,
  GRCPolicyLifecycleWork,
  GRCPolicyReminderPlan,
  GRCPolicyRiskRegisterItem,
  GRCPolicyReminder,
  GRCPolicyReview,
  GRCPolicyTemplate,
  GRCPolicyVersion,
  GRCPolicyVersionDiff,
  GRCUploadReplayResponse,
  GRCUploadResponse,
} from "@/lib/grc";
import { displayDate, humanize, shortEntity } from "@/lib/grc";
import { downloadGRCExport, grcExportFilename, grcPath, useDebouncedValue, useGRCFormMutation, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { useGRCFilterState } from "@/lib/grc-filters";
import { grcUploadFileError } from "@/lib/grc-upload-limits";
import { grcUploadHistoryKey, grcUploadHistoryWith, readGRCUploadHistory, writeGRCUploadHistory } from "@/lib/grc-upload-history";
import { useQueryParamState } from "@/lib/query-params";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const inputClass = "mt-1 w-full rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-slate-500";
const POLICY_LIFECYCLE_LIMIT = 300;
type PolicySection = "queues" | "register" | "records" | "history";

const policySectionTabs: { id: PolicySection; label: string }[] = [
  { id: "queues", label: "Work queues" },
  { id: "register", label: "Policy register" },
  { id: "records", label: "Documents and risks" },
  { id: "history", label: "History" },
];

const lifecycleStates = [
  { value: "", label: "All states" },
  { value: "draft", label: "Drafts" },
  { value: "approval", label: "Approvals" },
  { value: "attestation", label: "Attestations" },
  { value: "review", label: "Reviews" },
  { value: "exception", label: "Exceptions" },
];

const ruleProfiles = [
  { value: "baseline", label: "Baseline" },
  { value: "strict", label: "Strict evidence" },
];

const normalized = (value?: string) => (value ?? "").trim().toLowerCase();

const listLabel = (items?: string[], fallback = "-") => {
  const values = (items ?? []).filter(Boolean);
  if (values.length === 0) return fallback;
  if (values.length <= 2) return values.join(", ");
  return `${values.slice(0, 2).join(", ")} +${values.length - 2}`;
};

const controlLabel = (control: GRCPolicyControlRef) =>
  [control.framework, control.control_id || shortEntity(control.urn)].filter(Boolean).join(" ");

const policyMatchesState = (policy: GRCPolicyLifecyclePolicy, state: string) => {
  switch (state) {
    case "draft":
      return (policy.versions ?? []).some((version) => ["draft", "changes_requested"].includes(normalized(version.status)));
    case "approval":
      return (policy.approvals ?? []).some((approval) => ["", "pending", "requested", "in_review"].includes(normalized(approval.status)));
    case "attestation":
      return policy.acceptance_summary.pending > 0 || policy.acceptance_summary.overdue > 0;
    case "review":
      return (policy.reviews ?? []).some((review) => ["", "pending", "in_review", "overdue", "scheduled"].includes(normalized(review.status)));
    case "exception":
      return policy.exception_summary.active > 0 || policy.exception_summary.expiring > 0;
    default:
      return true;
  }
};

const policySearchText = (policy: GRCPolicyLifecyclePolicy) => [
  policy.id,
  policy.title,
  policy.status,
  policy.owner,
  policy.reviewer,
  policy.review_cadence,
  policy.latest_version,
  policy.approval_status,
  ...(policy.controls ?? []).flatMap((control) => [control.framework, control.control_id, control.title]),
].filter(Boolean).join("\n").toLowerCase();

const documentSearchText = (document: GRCPolicyDocument) => [
  document.id,
  document.title,
  document.document_type,
  document.document_class,
  document.status,
  document.owner,
  document.version,
  document.review_cadence,
  ...(document.policies ?? []).flatMap((policy) => [policy.id, policy.title]),
  ...(document.risks ?? []).flatMap((risk) => [risk.id, risk.title, risk.status]),
  ...(document.controls ?? []).flatMap((control) => [control.framework, control.control_id, control.title]),
].filter(Boolean).join("\n").toLowerCase();

const riskSearchText = (risk: GRCPolicyRiskRegisterItem) => [
  risk.id,
  risk.title,
  risk.status,
  risk.owner,
  risk.category,
  risk.inherent_risk,
  risk.residual_risk,
  risk.likelihood,
  risk.impact,
  risk.treatment,
  risk.source_document_id,
  risk.source_document_title,
  ...(risk.policies ?? []).flatMap((policy) => [policy.id, policy.title]),
  ...(risk.controls ?? []).flatMap((control) => [control.framework, control.control_id, control.title]),
].filter(Boolean).join("\n").toLowerCase();

const governanceGapSearchText = (gap: GRCPolicyGovernanceGap) => [
  gap.id,
  gap.subject,
  gap.subject_id,
  gap.title,
  gap.status,
  gap.owner,
  gap.severity,
  gap.reason,
  gap.action,
  gap.action_id,
  gap.rule_id,
  gap.gap_state,
  gap.due_at,
  ...(gap.missing_fields ?? []),
  gap.policy_id,
  gap.document_id,
  gap.risk_id,
].filter(Boolean).join("\n").toLowerCase();

const dateValue = (value?: string) => {
  if (!value) return Number.POSITIVE_INFINITY;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : Number.POSITIVE_INFINITY;
};

const displayPolicyDate = (value?: string) => {
  if (!value) return "-";
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      timeZone: "UTC",
    }).format(new Date(`${value}T00:00:00Z`));
  }
  return displayDate(value);
};

const dateInputValue = (value?: string) => {
  if (!value) return "";
  if (/^\d{4}-\d{2}-\d{2}/.test(value)) return value.slice(0, 10);
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString().slice(0, 10) : "";
};

const dueClassName = (value: string | undefined, generatedAt?: string) => {
  const due = dateValue(value);
  if (!Number.isFinite(due)) return "text-slate-500";
  const reference = dateValue(generatedAt);
  const now = Number.isFinite(reference) ? reference : Date.now();
  if (due < now) return "font-medium text-red-700";
  if (due - now <= 1000 * 60 * 60 * 24 * 14) return "font-medium text-amber-700";
  return "text-slate-600";
};

const statusIntent = (status?: string): "severity" | "status" => {
  const value = normalized(status);
  return ["overdue", "expired", "rejected"].includes(value) ? "severity" : "status";
};

const actionTone = (action: string) => {
  if (action.endsWith(".reject") || action.endsWith(".close")) return "danger";
  if (action.includes("reminder") || action.includes("renew") || action.includes("exception")) return "warning";
  return "primary";
};

const actionDateField = (action: string, field?: string): "due_at" | "effective_at" | "expires_at" | null => {
  if (field === "due_at" || field === "effective_at" || field === "expires_at") return field;
  if (action === "exception.renew") return "expires_at";
  if (action === "version.publish") return "effective_at";
  if (action === "governance_gap.set_review_date" || action === "governance_gap.set_treatment_date" || action === "governance_gap.snooze") return "due_at";
  if (action.includes("reminder") || action.includes("attestation") || action.includes("approval") || action.includes("review")) return "due_at";
  return null;
};

const actionDateLabel = (action: string, field?: string) => {
  const normalizedField = actionDateField(action, field);
  if (action === "governance_gap.snooze") return "Snooze until";
  if (action === "governance_gap.set_review_date") return "Review due";
  if (action === "governance_gap.set_treatment_date") return "Treatment due";
  if (normalizedField === "expires_at") return "Expires";
  if (normalizedField === "effective_at") return "Effective";
  if (normalizedField === "due_at") return "Due";
  return "Date";
};

const actionValueField = (action: GRCPolicyLifecycleAction) => {
  if (action.value_field) return action.value_field;
  switch (action.action) {
    case "governance_gap.assign_owner":
      return "assigned_user_ids";
    case "governance_gap.link_policy":
      return "target_policy_id";
    case "governance_gap.map_controls":
      return "control_ids";
    case "governance_gap.add_treatment":
      return "treatment";
    case "governance_gap.link_source_document":
      return "source_document_id";
    case "governance_gap.attach_evidence":
      return "evidence_urns";
    default:
      return "";
  }
};

const actionValueLabel = (action: GRCPolicyLifecycleAction) => {
  if (action.value_label) return action.value_label;
  switch (actionValueField(action)) {
    case "assigned_user_ids":
      return "Owner";
    case "target_policy_id":
    case "policy_id":
      return "Policy ID";
    case "control_ids":
      return "Control IDs";
    case "evidence_urns":
      return "Evidence URNs";
    case "source_document_id":
      return "Source document ID";
    case "treatment":
      return "Treatment";
    default:
      return "Value";
  }
};

const splitActionValues = (value: string) => value.split(/[,;\n]/).map((item) => item.trim()).filter(Boolean);

const actionIconElement = (action: string, className: string) => {
  if (action.includes("governance_gap")) return <ListChecks className={className} aria-hidden="true" />;
  if (action.includes("approval.approve") || action.includes("attestation.accept") || action.includes("review.complete")) return <CheckCircle2 className={className} aria-hidden="true" />;
  if (action.includes("approval.reject") || action.includes("exception.close")) return <XCircle className={className} aria-hidden="true" />;
  if (action.includes("reminder")) return <Send className={className} aria-hidden="true" />;
  if (action.includes("exception")) return <ShieldCheck className={className} aria-hidden="true" />;
  if (action.includes("draft") || action.includes("version")) return <GitCompare className={className} aria-hidden="true" />;
  return <ListChecks className={className} aria-hidden="true" />;
};

const actionButtonClass = (tone: string) => [
  "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[12px] font-medium transition",
  tone === "danger" ? "border-red-200 bg-red-50 text-red-700 hover:border-red-300 hover:bg-red-100" : "",
  tone === "warning" ? "border-amber-200 bg-amber-50 text-amber-800 hover:border-amber-300 hover:bg-amber-100" : "",
  tone === "primary" ? "border-indigo-200 bg-indigo-50 text-indigo-700 hover:border-indigo-300 hover:bg-indigo-100" : "",
].filter(Boolean).join(" ");

const workQueueActionForItem = (item: GRCPolicyLifecycleWork): GRCPolicyLifecycleAction | null => {
  const type = normalized(item.type);
  const status = normalized(item.status);
  let action = "";
  let label = item.action || "Record action";
  if (type === "version") {
    action = "draft.submit";
    label = "Submit draft";
  } else if (type === "approval") {
    action = "approval.approve";
    label = "Approve version";
  } else if (type === "review") {
    action = "review.complete";
    label = "Complete review";
  } else if (type === "attestation") {
    action = status === "overdue" ? "reminder.escalate" : "reminder.send";
    label = status === "overdue" ? "Escalate reminder" : "Send reminder";
  } else if (type === "exception") {
    action = item.action.toLowerCase().includes("renew") ? "exception.renew" : "exception.approve";
    label = item.action.toLowerCase().includes("renew") ? "Renew exception" : "Approve exception";
  }
  if (!action) return null;
  return {
    id: `${item.id}:${action}`,
    action,
    label,
    policy_id: item.policy_id,
    policy: item.policy,
    record_urn: item.record_urn,
    record_type: type ? `policy.${type}` : undefined,
    status: item.status,
    owner: item.owner,
    due_at: item.due_at,
    reason: item.action,
  };
};

const reminderPlanActionForItem = (item: GRCPolicyReminderPlan): GRCPolicyLifecycleAction => {
  const reminderAction = normalized(item.action);
  const recordType = normalized(item.record_type);
  let action = "reminder.send";
  let label = "Send reminder";
  if (recordType === "policy.exception" || reminderAction.includes("exception")) {
    action = "exception.renew";
    label = "Renew exception";
  } else if (reminderAction.includes("escalat")) {
    action = "reminder.escalate";
    label = "Escalate reminder";
  }
  return {
    id: `${item.id}:${action}`,
    action,
    label,
    policy_id: item.policy_id,
    policy: item.policy,
    record_urn: item.record_urn,
    record_type: item.record_type,
    status: "planned",
    owner: item.owner,
    due_at: item.due_at,
    reason: item.reason,
  };
};

const governanceGapFallbackActionID = (gap: GRCPolicyGovernanceGap) => {
  const reason = normalized(gap.reason);
  if (reason.includes("owner")) return "governance_gap.assign_owner";
  if (reason.includes("treatment date")) return "governance_gap.set_treatment_date";
  if (reason.includes("treatment")) return "governance_gap.add_treatment";
  if (reason.includes("review date")) return "governance_gap.set_review_date";
  if (reason.includes("source document")) return "governance_gap.link_source_document";
  if (reason.includes("linked policy")) return "governance_gap.link_policy";
  if (reason.includes("controls")) return "governance_gap.map_controls";
  if (reason.includes("evidence")) return "governance_gap.attach_evidence";
  return "governance_gap.acknowledge";
};

const governanceGapActionForItem = (
  gap: GRCPolicyGovernanceGap,
  definition?: GRCPolicyLifecycleActionDefinition,
): GRCPolicyLifecycleAction => {
  const action = definition?.id ?? gap.action_id ?? governanceGapFallbackActionID(gap);
  return {
    id: `${gap.id}:${action}`,
    action,
    label: definition?.label ?? gap.action ?? "Record action",
    policy_id: gap.policy_id,
    gap_id: gap.id,
    gap_state: gap.gap_state,
    record_urn: gap.id,
    record_type: "governance.gap",
    status: gap.gap_state ?? gap.status ?? "open",
    owner: gap.owner,
    due_at: gap.due_at,
    reason: gap.reason,
    date_field: definition?.date_field,
    value_field: definition?.value_field,
    value_label: definition?.value_label,
    attributes: {
      document_id: gap.document_id ?? "",
      risk_id: gap.risk_id ?? "",
      rule_id: gap.rule_id ?? "",
      subject: gap.subject,
      subject_id: gap.subject_id ?? "",
    },
  };
};

const governanceGapStateAction = (gap: GRCPolicyGovernanceGap, action: string, label: string): GRCPolicyLifecycleAction => ({
  id: `${gap.id}:${action}`,
  action,
  label,
  policy_id: gap.policy_id,
  gap_id: gap.id,
  gap_state: gap.gap_state,
  record_urn: gap.id,
  record_type: "governance.gap",
  status: gap.gap_state ?? gap.status ?? "open",
  owner: gap.owner,
  due_at: gap.due_at,
  reason: gap.reason,
  attributes: {
    document_id: gap.document_id ?? "",
    risk_id: gap.risk_id ?? "",
    rule_id: gap.rule_id ?? "",
    subject: gap.subject,
    subject_id: gap.subject_id ?? "",
  },
});

const rollupLabel = (key: string) => key === "unassigned" ? "Unassigned" : humanize(key);

const riskIntent = (risk?: string): "severity" | "status" => {
  const value = normalized(risk);
  return ["critical", "high", "very_high", "very high", "severe"].includes(value) ? "severity" : "status";
};

const selectedPolicyFallback = (
  policies: GRCPolicyLifecyclePolicy[],
  filteredPolicies: GRCPolicyLifecyclePolicy[],
  selectedPolicyID: string | null,
) =>
  policies.find((policy) => policy.id === selectedPolicyID) ??
  filteredPolicies[0] ??
  policies[0] ??
  null;

export default function PoliciesPage() {
  const { apiKey } = useApiKey();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [owner, setOwner] = useQueryParamState("owner");
  const [state, setState] = useQueryParamState("state");
  const [ruleProfile, setRuleProfile] = useQueryParamState("rule_profile");
  const [query, setQuery] = useQueryParamState("q");
  const [selectedPolicyID, setSelectedPolicyID] = useState<string | null>(null);
  const [policySection, setPolicySection] = useState<PolicySection>("queues");
  const [selectedAction, setSelectedAction] = useState<GRCPolicyLifecycleAction | null>(null);
  const [actionReason, setActionReason] = useState("");
  const [actionDate, setActionDate] = useState("");
  const [actionValue, setActionValue] = useState("");
  const [actionIdempotencyKey, setActionIdempotencyKey] = useState("");
  const [lastActionStatus, setLastActionStatus] = useState<string | null>(null);
  const [policyUploadFile, setPolicyUploadFile] = useState<File | null>(null);
  const [policyUploadTitle, setPolicyUploadTitle] = useState("");
  const [policyUploadID, setPolicyUploadID] = useState("");
  const [policyUploadOwner, setPolicyUploadOwner] = useState("");
  const [policyUploadReviewDue, setPolicyUploadReviewDue] = useState("");
  const [lastPolicyUpload, setLastPolicyUpload] = useState<GRCUploadResponse | null>(null);
  const [policyUploadHistory, setPolicyUploadHistory] = useState<GRCUploadResponse[]>([]);
  const [policyReplayMessage, setPolicyReplayMessage] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const actionIdempotencyCounterRef = useRef(0);
  const policyUploadFormRef = useRef<HTMLFormElement>(null);
  const policyUploadInputRef = useRef<HTMLInputElement>(null);
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedOwner = useDebouncedValue(owner.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const activeRuleProfile = normalized(ruleProfile) === "strict" ? "strict" : "baseline";
  const { mutate: recordAction, saving: actionSaving, error: actionError, setError: setActionError } =
    useGRCMutation<GRCPolicyLifecycleActionResponse>();
  const { mutate: uploadPolicyDocument, saving: policyUploadSaving, error: policyUploadError, setError: setPolicyUploadError, cancel: cancelPolicyUpload } =
    useGRCFormMutation<GRCUploadResponse>();
  const { mutate: replayPolicyUploadEvents, saving: policyReplaySaving, error: policyReplayError, setError: setPolicyReplayError } =
    useGRCMutation<GRCUploadReplayResponse>();
  const { data, error, loading, reload } = useGRCQuery<GRCPolicyLifecycleResponse>(
    grcPath("/grc/policy-lifecycle", { tenant_id: debouncedTenantID, rule_profile: activeRuleProfile, limit: POLICY_LIFECYCLE_LIMIT }),
  );
  const isInitialLoading = loading && !data;
  const isRefreshing = loading && Boolean(data);
  const runtimeState = runtimeStateForError(error);
  const metricState: RuntimeState = error ? runtimeState : isInitialLoading ? "loading" : "ready";
  const policies = useMemo(() => data?.policies ?? [], [data?.policies]);
  const documents = useMemo(() => data?.documents ?? [], [data?.documents]);
  const riskRegister = useMemo(() => data?.risk_register ?? [], [data?.risk_register]);
  const governanceGaps = useMemo(() => data?.governance_gaps ?? [], [data?.governance_gaps]);
  const availableActionDefinitions = useMemo(
    () => new Map((data?.available_actions ?? []).map((action) => [action.id, action])),
    [data?.available_actions],
  );
  const filteredPolicies = useMemo(() => {
    const ownerFilter = normalized(debouncedOwner);
    const textFilter = normalized(debouncedQuery);
    return policies.filter((policy) => {
      if (ownerFilter && !normalized([policy.owner, policy.reviewer].filter(Boolean).join(" ")).includes(ownerFilter)) return false;
      if (state && !policyMatchesState(policy, state)) return false;
      if (textFilter && !policySearchText(policy).includes(textFilter)) return false;
      return true;
    });
  }, [debouncedOwner, debouncedQuery, policies, state]);
  const filteredDocuments = useMemo(() => {
    const ownerFilter = normalized(debouncedOwner);
    const textFilter = normalized(debouncedQuery);
    return documents.filter((document) => {
      if (ownerFilter && !normalized(document.owner).includes(ownerFilter)) return false;
      if (textFilter && !documentSearchText(document).includes(textFilter)) return false;
      return true;
    });
  }, [debouncedOwner, debouncedQuery, documents]);
  const filteredRiskRegister = useMemo(() => {
    const ownerFilter = normalized(debouncedOwner);
    const textFilter = normalized(debouncedQuery);
    return riskRegister.filter((risk) => {
      if (ownerFilter && !normalized(risk.owner).includes(ownerFilter)) return false;
      if (textFilter && !riskSearchText(risk).includes(textFilter)) return false;
      return true;
    });
  }, [debouncedOwner, debouncedQuery, riskRegister]);
  const visiblePolicyIDs = useMemo(() => new Set(filteredPolicies.map((policy) => policy.id)), [filteredPolicies]);
  const visibleWorkQueue = useMemo(
    () => (data?.work_queue ?? []).filter((item) => !item.policy_id || visiblePolicyIDs.has(item.policy_id)),
    [data?.work_queue, visiblePolicyIDs],
  );
  const visibleDocumentIDs = useMemo(() => new Set(filteredDocuments.map((document) => document.id)), [filteredDocuments]);
  const visibleRiskIDs = useMemo(() => new Set(filteredRiskRegister.map((risk) => risk.id)), [filteredRiskRegister]);
  const visibleDocumentWorkQueue = useMemo(
    () => (data?.document_work_queue ?? []).filter((item) =>
      (!item.policy_id || visiblePolicyIDs.has(item.policy_id)) &&
      (!item.document_id || visibleDocumentIDs.has(item.document_id)) &&
      (!item.risk_id || visibleRiskIDs.has(item.risk_id)),
    ),
    [data?.document_work_queue, visibleDocumentIDs, visiblePolicyIDs, visibleRiskIDs],
  );
  const visibleGovernanceGaps = useMemo(() => {
    const ownerFilter = normalized(debouncedOwner);
    const textFilter = normalized(debouncedQuery);
    return governanceGaps.filter((gap) => {
      // Governance gaps use gap-level owner/search filters; lifecycle state filters target policy records.
      const ownerText = normalized(gap.owner);
      if (ownerFilter && !ownerText.includes(ownerFilter)) return false;
      if (textFilter && !governanceGapSearchText(gap).includes(textFilter)) return false;
      return true;
    });
  }, [debouncedOwner, debouncedQuery, governanceGaps]);
  const selectedPolicy = selectedPolicyFallback(policies, filteredPolicies, selectedPolicyID);
  const ownerOptions = useMemo(
    () => Array.from(new Set([
      ...policies.flatMap((policy) => [policy.owner, policy.reviewer]),
      ...documents.map((document) => document.owner),
      ...riskRegister.map((risk) => risk.owner),
      ...governanceGaps.map((gap) => gap.owner),
    ].filter((value): value is string => Boolean(value)))).sort(),
    [documents, governanceGaps, policies, riskRegister],
  );
  const filterState = useGRCFilterState([
    { key: "tenant_id", label: "Tenant", value: tenantID, setValue: setTenantID },
    { key: "owner", label: "Owner", value: owner, setValue: setOwner },
    { key: "state", label: "State", value: state, setValue: setState },
    { key: "rule_profile", label: "Rules", value: ruleProfile, setValue: setRuleProfile },
    { key: "q", label: "Search", value: query, setValue: setQuery },
  ]);
  const summary = data?.summary;
  const generatedAt = data?.generated_at;
  const activeGapCount = (summary?.open_governance_gaps ?? 0) + (summary?.in_progress_governance_gaps ?? 0) + (summary?.acknowledged_governance_gaps ?? 0) + (summary?.snoozed_governance_gaps ?? 0);
  const policyUploadStorageKey = useMemo(() => grcUploadHistoryKey("policy", tenantID), [tenantID]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setPolicyUploadHistory(readGRCUploadHistory(window.localStorage, policyUploadStorageKey));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [policyUploadStorageKey]);

  const rememberPolicyUpload = (upload: GRCUploadResponse) => {
    setPolicyUploadHistory((current) => {
      const next = grcUploadHistoryWith(current, upload);
      writeGRCUploadHistory(window.localStorage, policyUploadStorageKey, next);
      return next;
    });
  };

  const replayPolicyUpload = async (upload: GRCUploadResponse) => {
    setPolicyReplayMessage("");
    setPolicyReplayError(null);
    try {
      const response = await replayPolicyUploadEvents(
        grcPath(`/grc/policy-lifecycle/uploads/${encodeURIComponent(upload.upload_id)}/replay`, { tenant_id: tenantID.trim() }),
        {},
      );
      setPolicyReplayMessage(`${countLabel(response.events_projected ?? 0, "event")} replayed. ${countLabel((response.entities_projected ?? 0) + (response.links_projected ?? 0), "graph update")} projected.`);
      setLastPolicyUpload((current) => current?.upload_id === upload.upload_id ? {
        ...current,
        status: response.status || current.status,
        projection_status: response.status || current.projection_status,
        projection_failures: response.projection_failures ?? current.projection_failures,
      } : current);
      await reload();
    } catch {
      return;
    }
  };

  const openAction = (action: GRCPolicyLifecycleAction) => {
    actionIdempotencyCounterRef.current += 1;
    setSelectedAction(action);
    setActionReason(action.reason ?? "");
    setActionDate(dateInputValue(action.due_at));
    setActionValue("");
    setActionIdempotencyKey(`${action.id}:${globalThis.crypto?.randomUUID?.() ?? actionIdempotencyCounterRef.current}`);
    setLastActionStatus(null);
    setActionError(null);
  };

  const submitSelectedAction = async () => {
    if (!selectedAction) return;
    const dateField = actionDateField(selectedAction.action, selectedAction.date_field);
    const valueField = actionValueField(selectedAction);
    const value = actionValue.trim();
    const body: GRCPolicyLifecycleActionRequest = {
      action: selectedAction.action,
      tenant_id: tenantID.trim() || undefined,
      policy_id: selectedAction.policy_id,
      policy_version_id: selectedAction.policy_version_id,
      gap_id: selectedAction.gap_id,
      gap_ids: selectedAction.gap_ids,
      gap_state: selectedAction.gap_state,
      record_id: selectedAction.gap_id,
      record_urn: selectedAction.record_urn,
      reason: actionReason.trim() || selectedAction.reason,
      idempotency_key: actionIdempotencyKey || selectedAction.id,
      attributes: {
        source_surface: "cerebro-web",
        record_type: selectedAction.record_type ?? "",
        ...(selectedAction.attributes ?? {}),
      },
    };
    if (dateField && actionDate.trim()) {
      (body as Record<string, unknown>)[dateField] = actionDate.trim();
    }
    if (value) {
      if (valueField === "assigned_user_ids") body.assignees = splitActionValues(value);
      else if (valueField === "control_ids") body.control_ids = splitActionValues(value);
      else if (valueField === "evidence_urns") body.evidence_urns = splitActionValues(value);
      else if (selectedAction.action === "governance_gap.link_policy" && valueField === "policy_id") body.attributes = { ...(body.attributes ?? {}), target_policy_id: value };
      else if (valueField) body.attributes = { ...(body.attributes ?? {}), [valueField]: value };
    }
    try {
      const response = await recordAction(grcPath("/grc/policy-lifecycle/actions", { tenant_id: tenantID.trim() }), body);
      setLastActionStatus(`${humanize(response.action)} ${humanize(response.status)}`);
      setSelectedAction(null);
      setActionValue("");
      setActionIdempotencyKey("");
      await reload();
    } catch {
      return;
    }
  };

  const submitPolicyUpload = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!policyUploadFile) {
      setPolicyUploadError("Select a policy document.");
      return;
    }
    const fileError = grcUploadFileError(policyUploadFile);
    if (fileError) {
      setPolicyUploadError(fileError);
      setPolicyUploadFile(null);
      if (policyUploadInputRef.current) {
        policyUploadInputRef.current.value = "";
      }
      return;
    }
    const title = policyUploadTitle.trim() || policyUploadFile.name.replace(/\.[^.]+$/, "");
    const body = new FormData();
    body.set("file", policyUploadFile);
    body.set("title", title);
    body.set("document_title", title);
    body.set("document_type", "policy");
    body.set("document_class", "policy");
    body.set("status", "uploaded");
    if (tenantID.trim()) body.set("tenant_id", tenantID.trim());
    if (policyUploadID.trim()) body.set("policy_id", policyUploadID.trim());
    if (policyUploadOwner.trim()) body.set("owner_id", policyUploadOwner.trim());
    if (policyUploadReviewDue.trim()) body.set("next_review_due_at", policyUploadReviewDue.trim());
    try {
      const response = await uploadPolicyDocument(
        grcPath("/grc/policy-lifecycle/uploads", { tenant_id: tenantID.trim() }),
        body,
      );
      setLastPolicyUpload(response);
      rememberPolicyUpload(response);
      setPolicyUploadFile(null);
      setPolicyUploadTitle("");
      setPolicyUploadID("");
      setPolicyUploadOwner("");
      setPolicyUploadReviewDue("");
      if (policyUploadInputRef.current) {
        policyUploadInputRef.current.value = "";
      }
      await reload();
    } catch {
      return;
    }
  };

  const exportPolicies = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const result = await downloadGRCExport(
        grcPath("/grc/policy-lifecycle/export", { tenant_id: debouncedTenantID, rule_profile: activeRuleProfile }),
        apiKey,
        grcExportFilename("policy-lifecycle"),
      );
      if (!result.ok) setExportError(result.error);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const workColumns = useMemo<TableColumn<GRCPolicyLifecycleWork>[]>(() => [
    { key: "action", label: "Action", render: (_value, item) => <span className="font-medium text-slate-900">{item.action}</span> },
    { key: "policy", label: "Policy", render: (_value, item) => <span className="text-slate-700">{item.policy || item.policy_id || "-"}</span> },
    { key: "type", label: "Record", render: (_value, item) => <Badge value={item.type} /> },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "pending"} tone={statusIntent(item.status)} /> },
    { key: "owner", label: "Owner", render: (_value, item) => <span className="text-slate-600">{item.owner || "Unassigned"}</span> },
    { key: "due_at", label: "Due", render: (_value, item) => <span className={dueClassName(item.due_at, generatedAt)}>{displayPolicyDate(item.due_at)}</span> },
  ], [generatedAt]);

  const documentWorkColumns = useMemo<TableColumn<GRCPolicyDocumentWork>[]>(() => [
    { key: "action", label: "Action", render: (_value, item) => <span className="font-medium text-slate-900">{item.action}</span> },
    { key: "document", label: "Document", render: (_value, item) => <span className="text-slate-700">{item.document || item.document_id || item.risk_id || "-"}</span> },
    { key: "type", label: "Record", render: (_value, item) => <Badge value={item.type} /> },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "pending"} tone={statusIntent(item.status)} /> },
    { key: "owner", label: "Owner", render: (_value, item) => <span className="text-slate-600">{item.owner || "Unassigned"}</span> },
    { key: "due_at", label: "Due", render: (_value, item) => <span className={dueClassName(item.due_at, generatedAt)}>{displayPolicyDate(item.due_at)}</span> },
  ], [generatedAt]);

  const governanceGapColumns = useMemo<TableColumn<GRCPolicyGovernanceGap>[]>(() => [
    { key: "severity", label: "Severity", render: (_value, gap) => <Badge value={gap.severity || "medium"} tone="severity" /> },
    {
      key: "title",
      label: "Record",
      render: (_value, gap) => (
        <div className="min-w-[12rem]">
          <div className="font-medium text-slate-900">{gap.title || gap.subject_id || "-"}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">
            {humanize(gap.subject)} {gap.subject_id || gap.document_id || gap.risk_id || gap.policy_id || "-"}
          </div>
        </div>
      ),
    },
    { key: "reason", label: "Gap", render: (_value, gap) => <span className="font-medium text-slate-800">{gap.reason}</span> },
    {
      key: "missing_fields",
      label: "Fields",
      render: (_value, gap) => <span className="text-slate-600">{listLabel(gap.missing_fields, gap.rule_id || "-")}</span>,
    },
    { key: "owner", label: "Owner", render: (_value, gap) => <span className="text-slate-600">{gap.owner || "Unassigned"}</span> },
    { key: "due_at", label: "Due", render: (_value, gap) => <span className={dueClassName(gap.due_at, generatedAt)}>{displayPolicyDate(gap.due_at)}</span> },
    { key: "gap_state", label: "State", render: (_value, gap) => <Badge value={gap.gap_state || "open"} tone={statusIntent(gap.gap_state)} /> },
  ], [generatedAt]);

  const policyColumns = useMemo<TableColumn<GRCPolicyLifecyclePolicy>[]>(() => [
    {
      key: "title",
      label: "Policy",
      render: (_value, policy) => (
        <div>
          <div className="font-medium text-slate-900">{policy.title}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">{policy.id}</div>
        </div>
      ),
    },
    { key: "status", label: "State", render: (_value, policy) => <Badge value={policy.status || "unknown"} /> },
    {
      key: "owner",
      label: "Owner / reviewer",
      render: (_value, policy) => (
        <div className="text-[12px] text-slate-600">
          <div>{policy.owner || "Unassigned"}</div>
          <div>{policy.reviewer || "No reviewer"}</div>
        </div>
      ),
    },
    {
      key: "latest_version",
      label: "Version",
      render: (_value, policy) => (
        <div className="text-[12px] text-slate-600">
          <div className="font-medium text-slate-800">{policy.latest_version || "-"}</div>
          <div>{humanize(policy.version_status)}</div>
        </div>
      ),
    },
    { key: "approval_status", label: "Approval", render: (_value, policy) => <Badge value={policy.approval_status || "none"} /> },
    {
      key: "acceptance_summary",
      label: "Attestations",
      render: (_value, policy) => (
        <span className={policy.acceptance_summary.overdue > 0 ? "font-medium text-red-700" : "text-slate-600"}>
          {policy.acceptance_summary.accepted}/{policy.acceptance_summary.total}
        </span>
      ),
    },
    {
      key: "exception_summary",
      label: "Exceptions",
      render: (_value, policy) => (
        <span className={policy.exception_summary.active > 0 ? "font-medium text-amber-700" : "text-slate-600"}>
          {policy.exception_summary.active} active
        </span>
      ),
    },
    {
      key: "controls",
      label: "Controls",
      render: (_value, policy) => <span className="text-slate-600">{listLabel((policy.controls ?? []).map(controlLabel))}</span>,
    },
  ], []);

  const documentColumns = useMemo<TableColumn<GRCPolicyDocument>[]>(() => [
    {
      key: "title",
      label: "Document",
      render: (_value, document) => (
        <div>
          <div className="font-medium text-slate-900">{document.title}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">{document.id}</div>
        </div>
      ),
    },
    { key: "document_class", label: "Class", render: (_value, document) => <Badge value={document.document_class || document.document_type || "document"} /> },
    { key: "status", label: "State", render: (_value, document) => <Badge value={document.status || "unknown"} tone={statusIntent(document.status)} /> },
    { key: "owner", label: "Owner", render: (_value, document) => <span className="text-slate-600">{document.owner || "Unassigned"}</span> },
    { key: "version", label: "Version", render: (_value, document) => <span className="text-slate-600">{document.version || "-"}</span> },
    { key: "next_review_due_at", label: "Review", render: (_value, document) => <span className={dueClassName(document.next_review_due_at, generatedAt)}>{displayPolicyDate(document.next_review_due_at)}</span> },
    { key: "policies", label: "Policies", render: (_value, document) => <span className="text-slate-600">{listLabel((document.policies ?? []).map((policy) => policy.title || policy.id || shortEntity(policy.urn)))}</span> },
    { key: "controls", label: "Controls", render: (_value, document) => <span className="text-slate-600">{listLabel((document.controls ?? []).map(controlLabel))}</span> },
  ], [generatedAt]);

  const riskColumns = useMemo<TableColumn<GRCPolicyRiskRegisterItem>[]>(() => [
    {
      key: "title",
      label: "Risk",
      render: (_value, risk) => (
        <div>
          <div className="font-medium text-slate-900">{risk.title}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">{risk.id}</div>
        </div>
      ),
    },
    { key: "status", label: "State", render: (_value, risk) => <Badge value={risk.status || "unknown"} /> },
    { key: "residual_risk", label: "Residual", render: (_value, risk) => <Badge value={risk.residual_risk || risk.inherent_risk || "unknown"} tone={riskIntent(risk.residual_risk || risk.inherent_risk)} /> },
    { key: "owner", label: "Owner", render: (_value, risk) => <span className="text-slate-600">{risk.owner || "Unassigned"}</span> },
    { key: "category", label: "Category", render: (_value, risk) => <span className="text-slate-600">{risk.category || "-"}</span> },
    { key: "treatment", label: "Treatment", render: (_value, risk) => <span className="text-slate-600">{risk.treatment || "-"}</span> },
    { key: "review_due_at", label: "Review", render: (_value, risk) => <span className={dueClassName(risk.review_due_at, generatedAt)}>{displayPolicyDate(risk.review_due_at)}</span> },
    { key: "source_document_title", label: "Document", render: (_value, risk) => <span className="text-slate-600">{risk.source_document_title || risk.source_document_id || "-"}</span> },
  ], [generatedAt]);

  const templateColumns = useMemo<TableColumn<GRCPolicyTemplate>[]>(() => [
    { key: "title", label: "Template", render: (_value, item) => <span className="font-medium text-slate-900">{item.title}</span> },
    { key: "category", label: "Category", render: (_value, item) => <span className="text-slate-600">{item.category || "-"}</span> },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "unknown"} /> },
    { key: "owner", label: "Owner", render: (_value, item) => <span className="text-slate-600">{item.owner || "Unassigned"}</span> },
    { key: "frameworks", label: "Frameworks", render: (_value, item) => <span className="text-slate-600">{listLabel(item.frameworks)}</span> },
    { key: "controls", label: "Controls", render: (_value, item) => <span className="text-slate-600">{listLabel((item.controls ?? []).map(controlLabel))}</span> },
  ], []);

  const reminderColumns = useMemo<TableColumn<GRCPolicyReminder>[]>(() => [
    { key: "title", label: "Reminder", render: (_value, item) => <span className="font-medium text-slate-900">{item.title}</span> },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "unknown"} /> },
    { key: "channel", label: "Channel", render: (_value, item) => <span className="text-slate-600">{humanize(item.channel)}</span> },
    { key: "recipients", label: "Recipients", render: (_value, item) => <span className="text-slate-600">{listLabel(item.recipients)}</span> },
    { key: "escalated_to", label: "Escalated", render: (_value, item) => <span className="text-slate-600">{listLabel(item.escalated_to)}</span> },
    { key: "sent_at", label: "Sent", render: (_value, item) => <span className="text-slate-500">{displayPolicyDate(item.sent_at)}</span> },
    { key: "due_at", label: "Due", render: (_value, item) => <span className={dueClassName(item.due_at, generatedAt)}>{displayPolicyDate(item.due_at)}</span> },
  ], [generatedAt]);

  const reminderPlanColumns = useMemo<TableColumn<GRCPolicyReminderPlan>[]>(() => [
    { key: "action", label: "Action", render: (_value, item) => <span className="font-medium text-slate-900">{humanize(item.action)}</span> },
    { key: "policy", label: "Policy", render: (_value, item) => <span className="text-slate-700">{item.policy || item.policy_id || "-"}</span> },
    { key: "owner", label: "Owner", render: (_value, item) => <span className="text-slate-600">{item.owner || "Unassigned"}</span> },
    { key: "recipients", label: "Recipients", render: (_value, item) => <span className="text-slate-600">{listLabel(item.recipients)}</span> },
    { key: "due_at", label: "Due", render: (_value, item) => <span className={dueClassName(item.due_at, generatedAt)}>{displayPolicyDate(item.due_at)}</span> },
    { key: "escalate_at", label: "Escalate", render: (_value, item) => <span className={dueClassName(item.escalate_at, generatedAt)}>{displayPolicyDate(item.escalate_at)}</span> },
  ], [generatedAt]);

  const versionDiffColumns = useMemo<TableColumn<GRCPolicyVersionDiff>[]>(() => [
    {
      key: "policy_title",
      label: "Policy",
      render: (_value, item) => (
        <div className="min-w-[12rem]">
          <div className="font-medium text-slate-900">{item.policy_title || item.policy_id || "-"}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">
            {[item.from_version, item.to_version].filter(Boolean).join(" -> ") || item.to_version_id || "-"}
          </div>
        </div>
      ),
    },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "unknown"} /> },
    { key: "change_summary", label: "Change", render: (_value, item) => <span className="text-slate-600">{item.change_summary || item.diff_summary || "-"}</span> },
    { key: "approved_at", label: "Approved", render: (_value, item) => <span className="text-slate-500">{displayPolicyDate(item.approved_at)}</span> },
    {
      key: "diff_url",
      label: "Diff",
      render: (_value, item) => item.diff_url ? (
        <Link href={item.diff_url} className="inline-flex items-center gap-1 text-indigo-600 hover:text-indigo-800">
          Open
          <ArrowRight className="h-3 w-3" aria-hidden="true" />
        </Link>
      ) : <span className="text-slate-400">-</span>,
    },
  ], []);

  const eventColumns = useMemo<TableColumn<GRCPolicyLifecycleEvent>[]>(() => [
    {
      key: "action",
      label: "Event",
      render: (_value, item) => (
        <div className="min-w-[11rem]">
          <div className="font-medium text-slate-900">{humanize(item.action || item.event_kind || "event")}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">{humanize(item.record_type || "policy")}</div>
        </div>
      ),
    },
    { key: "status", label: "State", render: (_value, item) => <Badge value={item.status || "recorded"} tone={statusIntent(item.status)} /> },
    { key: "policy_id", label: "Policy", render: (_value, item) => <span className="text-slate-600">{item.policy_id || "-"}</span> },
    { key: "actor", label: "Actor", render: (_value, item) => <span className="text-slate-600">{item.actor || "System"}</span> },
    { key: "occurred_at", label: "Recorded", render: (_value, item) => <span className="text-slate-500">{displayPolicyDate(item.occurred_at)}</span> },
  ], []);

  const mappingColumns = useMemo<TableColumn<GRCPolicyLifecycleMapping>[]>(() => [
    {
      key: "policy_title",
      label: "Mapping",
      render: (_value, item) => (
        <div className="min-w-[12rem]">
          <div className="font-medium text-slate-900">{item.policy_title || item.policy_id || "-"}</div>
          <div className="mt-0.5 text-[12px] text-slate-500">
            {item.target.label || shortEntity(item.target.urn)} / {humanize(item.target.entity_type)}
          </div>
        </div>
      ),
    },
    { key: "source_type", label: "Source", render: (_value, item) => <Badge value={item.source_type} /> },
    { key: "controls", label: "Controls", render: (_value, item) => <span className="text-slate-600">{listLabel((item.controls ?? []).map(controlLabel))}</span> },
    { key: "evidence", label: "Evidence", render: (_value, item) => <span className="text-slate-600">{countLabel(item.evidence?.length ?? 0, "item")}</span> },
  ], []);

  return (
    <div className="space-y-6">
      <PageHeader
        contractId="policies"
        title="Policies"
        description="Policy documents, risk-register records, versions, approvals, attestations, exceptions, reminders, and control mappings."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={() => void exportPolicies()} disabled={exporting} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-indigo-200 hover:text-indigo-700 disabled:opacity-60">
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              {exporting ? "Exporting" : "Export"}
            </button>
            <button type="button" onClick={() => void reload()} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600">
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              Refresh
            </button>
          </div>
        }
      />

      <div className="rounded-lg border border-slate-200 bg-white px-5 py-4">
        <div className="grid gap-3 md:grid-cols-5">
          <label className={labelClass}>Tenant<input value={tenantID} onChange={(event) => setTenantID(event.target.value)} placeholder="All tenants" className={inputClass} /></label>
          <label className={labelClass}>
            Owner
            <input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="All owners" list="policy-owner-options" className={inputClass} />
            <datalist id="policy-owner-options">
              {ownerOptions.map((option) => <option key={option} value={option} />)}
            </datalist>
          </label>
          <label className={labelClass}>
            State
            <select value={state} onChange={(event) => setState(event.target.value)} className={inputClass}>
              {lifecycleStates.map((item) => <option key={item.value || "all"} value={item.value}>{item.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            Rules
            <select
              value={activeRuleProfile}
              onChange={(event) => setRuleProfile(event.target.value === "baseline" ? "" : event.target.value)}
              className={inputClass}
            >
              {ruleProfiles.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
            </select>
          </label>
          <label className={labelClass}>
            Search
            <span className="relative mt-1 block">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" aria-hidden="true" />
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Policy, document, risk, control" className={`${inputClass} mt-0 pl-8`} />
            </span>
          </label>
        </div>
        <AppliedFilterChips filters={filterState.chips} onClearAll={filterState.clearAll} />
      </div>

      <Panel
        title="Upload policy document"
        action={<Upload className="h-4 w-4 text-slate-400" aria-hidden="true" />}
      >
        <form ref={policyUploadFormRef} onSubmit={submitPolicyUpload} className="grid gap-3 lg:grid-cols-2 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,0.75fr)_minmax(0,0.8fr)_minmax(0,0.75fr)_auto]">
          <label className={labelClass}>
            File
            <GRCUploadFileInput
              file={policyUploadFile}
              inputClassName={inputClass}
              inputRef={policyUploadInputRef}
              disabled={policyUploadSaving}
              onAccepted={(file) => {
                setPolicyUploadFile(file);
                setPolicyUploadError(null);
                setPolicyReplayError(null);
                setPolicyReplayMessage("");
                setLastPolicyUpload(null);
              }}
              onRejected={(message) => {
                setPolicyUploadFile(null);
                setLastPolicyUpload(null);
                setPolicyUploadError(message);
                setPolicyReplayError(null);
                setPolicyReplayMessage("");
              }}
              onClear={() => {
                setPolicyUploadFile(null);
                setPolicyUploadError(null);
              }}
            />
          </label>
          <label className={labelClass}>
            Policy name
            <input value={policyUploadTitle} onChange={(event) => setPolicyUploadTitle(event.target.value)} placeholder="From file name" className={inputClass} />
          </label>
          <label className={labelClass}>
            Policy ID
            <input value={policyUploadID} onChange={(event) => setPolicyUploadID(event.target.value)} placeholder="Generated" className={inputClass} />
          </label>
          <label className={labelClass}>
            Owner
            <input value={policyUploadOwner} onChange={(event) => setPolicyUploadOwner(event.target.value)} placeholder="Unassigned" className={inputClass} />
          </label>
          <label className={labelClass}>
            Review due
            <input type="date" value={policyUploadReviewDue} onChange={(event) => setPolicyUploadReviewDue(event.target.value)} className={inputClass} />
          </label>
          <button
            type="submit"
            disabled={policyUploadSaving || !policyUploadFile}
            className="inline-flex items-center justify-center gap-1.5 self-end rounded-md border border-indigo-500 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Upload className="h-3.5 w-3.5" aria-hidden="true" />
            {policyUploadSaving ? "Uploading" : "Upload policy"}
          </button>
        </form>
        {policyUploadSaving && <GRCUploadProgress onCancel={cancelPolicyUpload} />}
        {policyUploadError && !policyUploadSaving && (
          <GRCUploadErrorActions
            error={policyUploadError}
            canRetry={Boolean(policyUploadFile)}
            onRetry={() => policyUploadFormRef.current?.requestSubmit()}
          />
        )}
        {lastPolicyUpload && (
          <GRCUploadReceipt
            upload={lastPolicyUpload}
            actions={(() => {
              const policyID = lastPolicyUpload.events.find((event) => event.event_kind === "grc.policy")?.record_id;
              return (
                <div className="flex flex-wrap gap-2">
                  {policyID && (
                    <button type="button" onClick={() => setSelectedPolicyID(policyID)} className="inline-flex items-center rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[12px] font-semibold text-[var(--text-primary)] transition hover:border-slate-300">
                      Open policy
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={policyReplaySaving || lastPolicyUpload.replayable === false}
                    onClick={() => replayPolicyUpload(lastPolicyUpload)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[color:var(--border)] bg-white px-3 py-1.5 text-[12px] font-semibold text-[var(--text-primary)] transition hover:border-slate-300 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    <RefreshCw className={`h-3.5 w-3.5 ${policyReplaySaving ? "animate-spin" : ""}`} aria-hidden="true" />
                    {policyReplaySaving ? "Replaying" : "Replay events"}
                  </button>
                </div>
              );
            })()}
          />
        )}
        {policyReplayMessage && !policyReplaySaving && (
          <div className="mt-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-[12px] font-medium text-emerald-800">
            {policyReplayMessage}
          </div>
        )}
        {policyReplayError && !policyReplaySaving && (
          <div className="mt-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] font-medium text-red-700">
            {policyReplayError}
          </div>
        )}
        <GRCUploadHistoryList uploads={policyUploadHistory} />
      </Panel>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-6">
        <MetricCard label="Policies" value={summary?.policies ?? 0} detail={`${summary?.templates ?? 0} templates`} state={metricState} />
        <MetricCard label="Documents" value={summary?.policy_documents ?? 0} detail={`${summary?.documents_due_for_review ?? 0} due for review`} intent={(summary?.documents_due_for_review ?? 0) > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Risks" value={summary?.risk_register_items ?? 0} detail={`${summary?.high_risks ?? 0} high`} intent={(summary?.high_risks ?? 0) > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Gaps" value={summary?.governance_gaps ?? 0} detail={`${activeGapCount} active / ${summary?.resolved_governance_gaps ?? 0} resolved`} intent={activeGapCount > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Mappings" value={summary?.mapped_controls ?? 0} detail={`${summary?.evidence_items ?? 0} evidence items`} state={metricState} />
        <MetricCard label="Pending Approvals" value={summary?.pending_approvals ?? 0} detail={`${summary?.draft_versions ?? 0} drafts`} intent={(summary?.pending_approvals ?? 0) > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Attestations" value={`${summary?.attestation_coverage_pct ?? 0}%`} detail={`${summary?.overdue_attestations ?? 0} overdue`} intent={(summary?.overdue_attestations ?? 0) > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Exceptions" value={summary?.open_exceptions ?? 0} detail={`${summary?.expiring_exceptions ?? 0} expiring`} intent={(summary?.expiring_exceptions ?? 0) > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="History" value={summary?.lifecycle_events ?? 0} detail={`${summary?.next_reminders ?? 0} reminders`} state={metricState} />
      </div>

      {error && <ErrorBlock error={error} onRetry={() => void reload()} />}
      {exportError && <ErrorBlock error={exportError} onRetry={() => void exportPolicies()} />}
      {actionError && <ErrorBlock error={actionError} onRetry={() => selectedAction && void submitSelectedAction()} />}
      {lastActionStatus && (
        <div className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-[13px] font-medium text-emerald-800">
          {lastActionStatus}
        </div>
      )}
      {isInitialLoading && <LoadingBlock label="Loading policies..." />}

      {data && (
        <>
          <div className="surface-panel p-2">
            <div className="grid gap-2 sm:grid-cols-4" role="tablist" aria-label="Policy lifecycle sections">
              {policySectionTabs.map((tab) => {
                const selected = policySection === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setPolicySection(tab.id)}
                    aria-pressed={selected}
                    className={`rounded-md px-3 py-2 text-[13px] font-semibold transition ${
                      selected
                        ? "bg-[var(--primary)] text-white"
                        : "text-[var(--text-secondary)] hover:bg-[var(--surface-muted)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>
          </div>

          {policySection === "queues" && (
            <>
              <WorklistTable
            title="Policy work queue"
            description={isRefreshing ? "Refreshing policy records..." : "Drafts, approvals, reviews, attestations, and exceptions ordered by due date."}
            rows={visibleWorkQueue}
            columns={workColumns}
            emptyMessage="No policy work matches the current filters."
            searchPlaceholder="Filter loaded work"
            filterKeys={["action", "policy", "type", "status", "owner", "due_at"]}
            pageSize={10}
            resultLimit={POLICY_LIFECYCLE_LIMIT}
            resultNoun="work items"
            getRowKey={(item) => item.id}
            refreshing={isRefreshing}
            rowActions={(item) => {
              const action = workQueueActionForItem(item);
              return (
                <div className="flex justify-end gap-2">
                  {action && (
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        openAction(action);
                      }}
                      disabled={actionSaving}
                      title={action.label}
                      className={actionButtonClass(actionTone(action.action))}
                    >
                      {actionIconElement(action.action, "h-3.5 w-3.5")}
                      {action.label}
                    </button>
                  )}
                  <button
                    type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        if (item.policy_id) {
                          setSelectedPolicyID(item.policy_id);
                          setPolicySection("register");
                        }
                      }}
                      title="Open policy"
                      className="inline-flex items-center rounded-md border border-slate-200 p-1.5 text-slate-500 transition hover:border-indigo-200 hover:text-indigo-700"
                  >
                    <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
              );
            }}
              />

              <WorklistTable
            title="Document work queue"
            description={isRefreshing ? "Refreshing document records..." : "Draft documents, stale reviews, and open risk treatments ordered by due date."}
            rows={visibleDocumentWorkQueue}
            columns={documentWorkColumns}
            emptyMessage="No document work matches the current filters."
            searchPlaceholder="Filter loaded document work"
            filterKeys={["action", "document", "type", "status", "owner", "due_at", "risk_id", "policy_id"]}
            pageSize={8}
            resultLimit={POLICY_LIFECYCLE_LIMIT}
            resultNoun="document work items"
            getRowKey={(item) => item.id}
            refreshing={isRefreshing}
            action={<ClipboardList className="h-4 w-4 text-slate-400" aria-hidden="true" />}
              />

              <WorklistTable
            title="Governance gaps"
            description={isRefreshing ? "Refreshing governance gaps..." : "Records missing owners, dates, mappings, treatment, or evidence."}
            rows={visibleGovernanceGaps}
            columns={governanceGapColumns}
            emptyMessage="No governance gaps match the current filters."
            searchPlaceholder="Filter loaded gaps"
            filterKeys={["subject", "subject_id", "title", "status", "owner", "severity", "reason", "action", "action_id", "rule_id", "gap_state", "due_at", "policy_id", "document_id", "risk_id"]}
            pageSize={8}
            resultLimit={POLICY_LIFECYCLE_LIMIT}
            resultNoun="gaps"
            getRowKey={(gap) => gap.id}
            refreshing={isRefreshing}
            rowActions={(gap) => {
              const recommended = governanceGapActionForItem(gap, availableActionDefinitions.get(gap.action_id ?? governanceGapFallbackActionID(gap)));
              const state = normalized(gap.gap_state);
              const acknowledge = governanceGapStateAction(gap, "governance_gap.acknowledge", "Acknowledge");
              return (
                <div className="flex flex-wrap justify-end gap-2">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      openAction(recommended);
                    }}
                    disabled={actionSaving}
                    title={recommended.label}
                    className={actionButtonClass(actionTone(recommended.action))}
                  >
                    {actionIconElement(recommended.action, "h-3.5 w-3.5")}
                    {recommended.label}
                  </button>
                  {(!state || state === "open") && (
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        openAction(acknowledge);
                      }}
                      disabled={actionSaving}
                      title="Acknowledge"
                      className={actionButtonClass("primary")}
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                      Acknowledge
                    </button>
                  )}
                </div>
              );
            }}
            action={<ListChecks className="h-4 w-4 text-slate-400" aria-hidden="true" />}
              />

              <GapRollupsPanel
                rollups={data.governance_gap_rollups}
                rules={data.governance_rules ?? []}
              />
            </>
          )}

          {policySection === "register" && (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,0.95fr)]">
            <WorklistTable
              title="Policy register"
              description="Policy records with owner, version, approval, attestation, review, and mapping counts."
              rows={filteredPolicies}
              columns={policyColumns}
              emptyMessage="No policies match the current filters."
              searchPlaceholder="Filter loaded policies"
              filterKeys={["id", "title", "status", "owner", "reviewer", "latest_version", "approval_status", "controls"]}
              pageSize={12}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="policies"
              getRowKey={(policy) => policy.id}
              onRowClick={(policy) => setSelectedPolicyID(policy.id)}
              selectedRowKey={selectedPolicy?.id ?? null}
              rowActions={(policy) => (
                <button
                  type="button"
                  onClick={(event) => {
                    event.stopPropagation();
                    setSelectedPolicyID(policy.id);
                  }}
                  title="Open policy"
                  className="inline-flex items-center rounded-md border border-slate-200 p-1.5 text-slate-500 transition hover:border-indigo-200 hover:text-indigo-700"
                >
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              )}
            />
            <PolicyDetail
              policy={selectedPolicy}
              generatedAt={generatedAt}
              onAction={openAction}
              savingActionID={actionSaving ? selectedAction?.id : undefined}
            />
            </div>
          )}

          {policySection === "records" && (
            <>
              <div className="grid gap-4 xl:grid-cols-2">
            <WorklistTable
              title="Document register"
              description="Policy documents with owner, class, state, review date, policies, and mapped controls."
              rows={filteredDocuments}
              columns={documentColumns}
              emptyMessage="No policy documents match the current filters."
              searchPlaceholder="Filter loaded documents"
              filterKeys={["id", "title", "document_type", "document_class", "status", "owner", "version", "policies", "risks", "controls"]}
              pageSize={8}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="documents"
              getRowKey={(document) => document.id || document.urn}
              getRowHref={(document) => document.source_url}
              action={<FileCheck2 className="h-4 w-4 text-slate-400" aria-hidden="true" />}
            />
            <WorklistTable
              title="Risk register"
              description="Risk scenarios with owner, residual risk, treatment, review date, and source document."
              rows={filteredRiskRegister}
              columns={riskColumns}
              emptyMessage="No risk register records match the current filters."
              searchPlaceholder="Filter loaded risks"
              filterKeys={["id", "title", "status", "owner", "category", "residual_risk", "inherent_risk", "treatment", "source_document_title", "controls"]}
              pageSize={8}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="risks"
              getRowKey={(risk) => risk.id || risk.urn}
              action={<ClipboardList className="h-4 w-4 text-slate-400" aria-hidden="true" />}
            />
              </div>

              <div className="grid gap-4 xl:grid-cols-2">
            <WorklistTable
              title="Template library"
              description="Published templates with owner, framework, and mapped control references."
              rows={data.templates ?? []}
              columns={templateColumns}
              emptyMessage="No policy templates are available."
              searchPlaceholder="Filter loaded templates"
              filterKeys={["id", "title", "status", "category", "owner", "frameworks", "controls"]}
              pageSize={8}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="templates"
              getRowKey={(item) => item.id}
              action={<FileText className="h-4 w-4 text-slate-400" aria-hidden="true" />}
            />

                <WorklistTable
                  title="Policy mappings"
                  description="Evidence, controls, and targets linked through policy, version, template, and exception records."
                  rows={data.mappings ?? []}
                  columns={mappingColumns}
                  emptyMessage="No policy mappings are available."
                  searchPlaceholder="Filter loaded mappings"
                  filterKeys={["policy_id", "policy_title", "source_type", "target", "controls", "evidence"]}
                  pageSize={10}
                  resultLimit={POLICY_LIFECYCLE_LIMIT}
                  resultNoun="mappings"
                  getRowKey={(item, index) => `${item.source_urn}:${item.target.urn}:${index}`}
                  action={<ShieldCheck className="h-4 w-4 text-slate-400" aria-hidden="true" />}
                />
              </div>
            </>
          )}

          {policySection === "history" && (
            <>
              <div className="grid gap-4 xl:grid-cols-2">
                <WorklistTable
                  title="Reminders and escalations"
                  description="Attestation and review notices with recipients, channels, and escalation owners."
                  rows={data.reminders ?? []}
                  columns={reminderColumns}
                  emptyMessage="No reminders are available."
                  searchPlaceholder="Filter loaded reminders"
                  filterKeys={["title", "status", "channel", "recipients", "escalated_to", "due_at"]}
                  pageSize={8}
                  resultLimit={POLICY_LIFECYCLE_LIMIT}
                  resultNoun="reminders"
                  getRowKey={(item) => item.id}
                  action={<Bell className="h-4 w-4 text-slate-400" aria-hidden="true" />}
                />
              </div>

              <div className="grid gap-4 xl:grid-cols-2">
            <WorklistTable
              title="Reminder plan"
              description="Scheduled notices and escalation dates for pending reviews and attestations."
              rows={data.reminder_plan ?? []}
              columns={reminderPlanColumns}
              emptyMessage="No reminder plan is available."
              searchPlaceholder="Filter loaded reminder plan"
              filterKeys={["policy", "policy_id", "action", "owner", "recipients", "due_at", "escalate_at"]}
              pageSize={8}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="reminder plan rows"
              getRowKey={(item) => item.id}
              rowActions={(item) => {
                const action = reminderPlanActionForItem(item);
                return (
                  <button
                    type="button"
                    onClick={() => openAction(action)}
                    disabled={actionSaving}
                    title={action.label}
                    className={actionButtonClass(actionTone(action.action))}
                  >
                    {actionIconElement(action.action, "h-3.5 w-3.5")}
                    {action.label}
                  </button>
                );
              }}
              action={<Bell className="h-4 w-4 text-slate-400" aria-hidden="true" />}
            />
            <WorklistTable
              title="Version diffs"
              description="Draft, published, and approved version changes with review status."
              rows={data.version_diffs ?? []}
              columns={versionDiffColumns}
              emptyMessage="No version diffs are available."
              searchPlaceholder="Filter loaded diffs"
              filterKeys={["policy_title", "policy_id", "from_version", "to_version", "status", "change_summary", "diff_summary"]}
              pageSize={8}
              resultLimit={POLICY_LIFECYCLE_LIMIT}
              resultNoun="diffs"
              getRowKey={(item, index) => `${item.policy_id ?? "policy"}:${item.from_version_id ?? "from"}:${item.to_version_id ?? index}`}
              action={<GitCompare className="h-4 w-4 text-slate-400" aria-hidden="true" />}
            />
              </div>

              <WorklistTable
            title="Lifecycle events"
            description="Policy actions recorded from templates, drafts, approvals, attestations, reviews, exceptions, and reminders."
            rows={data.events ?? []}
            columns={eventColumns}
            emptyMessage="No lifecycle events are available."
            searchPlaceholder="Filter loaded events"
            filterKeys={["id", "policy_id", "record_type", "event_kind", "action", "status", "actor", "reason", "occurred_at"]}
            pageSize={10}
            resultLimit={POLICY_LIFECYCLE_LIMIT}
            resultNoun="events"
            getRowKey={(item) => item.id}
            action={<History className="h-4 w-4 text-slate-400" aria-hidden="true" />}
              />
            </>
          )}
        </>
      )}
      <ActionModal
        action={selectedAction}
        reason={actionReason}
        dateValue={actionDate}
        value={actionValue}
        saving={actionSaving}
        onReasonChange={setActionReason}
        onDateChange={setActionDate}
        onValueChange={setActionValue}
        onClose={() => {
          if (!actionSaving) {
            setSelectedAction(null);
            setActionValue("");
            setActionIdempotencyKey("");
            setActionError(null);
          }
        }}
        onSubmit={() => void submitSelectedAction()}
      />
    </div>
  );
}

function GapRollupsPanel({
  rollups,
  rules,
}: {
  rollups?: GRCPolicyGovernanceGapRollups;
  rules: GRCPolicyGovernanceRule[];
}) {
  const groups = [
    { title: "State", items: rollups?.by_state ?? [] },
    { title: "Owner", items: rollups?.by_owner ?? [] },
    { title: "Severity", items: rollups?.by_severity ?? [] },
    { title: "Record", items: rollups?.by_subject ?? [] },
  ];
  return (
    <Panel
      title="Gap rollups"
      action={<span className="text-[12px] text-slate-500">{countLabel(rules.length, "rule")}</span>}
    >
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {groups.map((group) => (
          <div key={group.title} className="rounded-md border border-slate-200 px-3 py-2.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{group.title}</div>
            <div className="mt-2 space-y-1.5">
              {group.items.length === 0 ? (
                <div className="text-[12px] text-slate-500">No gaps</div>
              ) : group.items.slice(0, 4).map((item) => (
                <div key={`${group.title}:${item.key}`} className="flex items-center justify-between gap-3 text-[12px]">
                  <span className="truncate text-slate-700">{rollupLabel(item.key)}</span>
                  <span className="font-medium text-slate-900">{item.count}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function PolicyDetail({
  policy,
  generatedAt,
  onAction,
  savingActionID,
}: {
  policy: GRCPolicyLifecyclePolicy | null;
  generatedAt?: string;
  onAction: (action: GRCPolicyLifecycleAction) => void;
  savingActionID?: string;
}) {
  if (!policy) {
    return (
      <Panel title="Policy detail">
        <div className="rounded-md border border-dashed border-slate-300 bg-slate-50 px-3 py-4 text-[13px] text-slate-500">
          No policy selected.
        </div>
      </Panel>
    );
  }
  const latestVersion = policy.versions?.[0];
  const pendingApprovals = (policy.approvals ?? []).filter((approval) => ["", "pending", "requested", "in_review"].includes(normalized(approval.status)));
  const openReviews = (policy.reviews ?? []).filter((review) => ["", "pending", "scheduled", "in_review", "overdue"].includes(normalized(review.status)));
  const openExceptions = (policy.exceptions ?? []).filter((exception) => !["closed", "expired", "rejected"].includes(normalized(exception.status)));
  const policyActions = policy.actions ?? [];
  const policyVersionDiffs = policy.version_diffs ?? [];
  const policyReminderPlan = policy.reminder_plan ?? [];
  const policyEvents = policy.events ?? [];

  return (
    <Panel
      title="Policy detail"
      action={
        <div className="flex items-center gap-2 text-[12px] text-slate-500">
          <GitCompare className="h-3.5 w-3.5" aria-hidden="true" />
          {policy.latest_version || "No version"}
        </div>
      }
    >
      <div className="space-y-5">
        <div>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-[16px] font-semibold text-slate-900">{policy.title}</h2>
              <div className="mt-1 flex flex-wrap gap-1.5">
                <Badge value={policy.status || "unknown"} />
                <Badge value={policy.approval_status || "no approval"} />
                <Badge value={policy.review_cadence || "no cadence"} />
              </div>
            </div>
            <Link href={`/reports?policy=${encodeURIComponent(policy.id)}`} className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-2.5 py-1.5 text-[12px] font-medium text-indigo-600 transition hover:border-indigo-200 hover:bg-indigo-50">
              Report
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </div>
          <dl className="mt-4 grid gap-3 text-[12px] md:grid-cols-2">
            <DetailItem label="Owner" value={policy.owner || "Unassigned"} />
            <DetailItem label="Reviewer" value={policy.reviewer || "No reviewer"} />
            <DetailItem label="Next review" value={displayPolicyDate(policy.next_review_due_at)} valueClassName={dueClassName(policy.next_review_due_at, generatedAt)} />
            <DetailItem label="Assignments" value={listLabel((policy.assignments ?? []).map((item) => item.label))} />
          </dl>
        </div>

        <div className="grid gap-3 md:grid-cols-3">
          <DetailMetric icon={<GitCompare className="h-4 w-4" aria-hidden="true" />} label="Versions" value={policy.versions?.length ?? 0} detail={latestVersion?.status ? humanize(latestVersion.status) : "No status"} />
          <DetailMetric icon={<Users className="h-4 w-4" aria-hidden="true" />} label="Attestations" value={`${policy.acceptance_summary.accepted}/${policy.acceptance_summary.total}`} detail={`${policy.acceptance_summary.overdue} overdue`} />
          <DetailMetric icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} label="Controls" value={policy.controls?.length ?? 0} detail={countLabel(policy.evidence?.length ?? 0, "evidence item")} />
        </div>

        <DetailSection title="Actions">
          {policyActions.length === 0 ? (
            <EmptyDetail label="No actions available." />
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {policyActions.map((action) => (
                <PolicyActionButton
                  key={action.id}
                  action={action}
                  saving={savingActionID === action.id}
                  onAction={onAction}
                />
              ))}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Version history">
          {(policy.versions ?? []).length === 0 ? (
            <EmptyDetail label="No versions are linked." />
          ) : (
            <div className="space-y-3">
              {(policy.versions ?? []).map((version) => <VersionRow key={version.id} version={version} generatedAt={generatedAt} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Version diffs">
          {policyVersionDiffs.length === 0 ? (
            <EmptyDetail label="No diffs are linked." />
          ) : (
            <div className="space-y-3">
              {policyVersionDiffs.slice(0, 5).map((diff, index) => <VersionDiffRow key={`${diff.from_version_id ?? "from"}:${diff.to_version_id ?? index}`} diff={diff} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Approvals">
          {pendingApprovals.length === 0 ? (
            <EmptyDetail label="No pending approvals." />
          ) : (
            <div className="space-y-2">
              {pendingApprovals.map((approval) => <ApprovalRow key={approval.id} approval={approval} generatedAt={generatedAt} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Reviews">
          {openReviews.length === 0 ? (
            <EmptyDetail label="No open reviews." />
          ) : (
            <div className="space-y-2">
              {openReviews.map((review) => <ReviewRow key={review.id} review={review} generatedAt={generatedAt} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Attestations">
          {(policy.attestations ?? []).length === 0 ? (
            <EmptyDetail label="No attestations are linked." />
          ) : (
            <div className="space-y-2">
              {(policy.attestations ?? []).slice(0, 5).map((attestation) => <AttestationRow key={attestation.id} attestation={attestation} generatedAt={generatedAt} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Exceptions">
          {openExceptions.length === 0 ? (
            <EmptyDetail label="No open exceptions." />
          ) : (
            <div className="space-y-2">
              {openExceptions.map((exception) => <ExceptionRow key={exception.id} exceptionRecord={exception} generatedAt={generatedAt} />)}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Reminder plan">
          {policyReminderPlan.length === 0 ? (
            <EmptyDetail label="No reminders are scheduled." />
          ) : (
            <div className="space-y-2">
              {policyReminderPlan.slice(0, 5).map((item) => (
                <ReminderPlanRow
                  key={item.id}
                  item={item}
                  generatedAt={generatedAt}
                  onAction={onAction}
                  saving={savingActionID === reminderPlanActionForItem(item).id}
                />
              ))}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Controls and evidence">
          <div className="space-y-3 text-[12px]">
            <ChipList values={(policy.controls ?? []).map(controlLabel)} empty="No controls linked." />
            <ChipList values={(policy.evidence ?? []).map((item) => item.title || shortEntity(item.urn))} empty="No evidence linked." />
          </div>
        </DetailSection>

        <DetailSection title="Event history">
          {policyEvents.length === 0 ? (
            <EmptyDetail label="No events are linked." />
          ) : (
            <div className="space-y-2">
              {policyEvents.slice(0, 7).map((event) => <EventRow key={event.id} event={event} />)}
            </div>
          )}
        </DetailSection>
      </div>
    </Panel>
  );
}

function PolicyActionButton({
  action,
  saving,
  onAction,
}: {
  action: GRCPolicyLifecycleAction;
  saving?: boolean;
  onAction: (action: GRCPolicyLifecycleAction) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onAction(action)}
      disabled={saving}
      className={`${actionButtonClass(actionTone(action.action))} justify-between`}
    >
      <span className="inline-flex min-w-0 items-center gap-1.5">
        {actionIconElement(action.action, "h-3.5 w-3.5 shrink-0")}
        <span className="truncate">{action.label}</span>
      </span>
      {action.due_at && <span className="shrink-0 text-[11px] opacity-75">{displayPolicyDate(action.due_at)}</span>}
    </button>
  );
}

function VersionDiffRow({ diff }: { diff: GRCPolicyVersionDiff }) {
  return (
    <div className="rounded-md border border-slate-200 px-3 py-2.5 text-[12px]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="font-medium text-slate-900">
            {[diff.from_version, diff.to_version].filter(Boolean).join(" -> ") || diff.to_version_id || "Version diff"}
          </div>
          <div className="mt-0.5 text-slate-500">{diff.change_summary || diff.diff_summary || "No summary"}</div>
        </div>
        <Badge value={diff.status || "unknown"} />
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-slate-500">
        <span>Created {displayPolicyDate(diff.created_at)}</span>
        <span>Approved {displayPolicyDate(diff.approved_at)}</span>
        {diff.diff_url && <Link href={diff.diff_url} className="text-indigo-600 hover:text-indigo-800">Diff</Link>}
      </div>
    </div>
  );
}

function ReminderPlanRow({
  item,
  generatedAt,
  saving,
  onAction,
}: {
  item: GRCPolicyReminderPlan;
  generatedAt?: string;
  saving?: boolean;
  onAction: (action: GRCPolicyLifecycleAction) => void;
}) {
  const action = reminderPlanActionForItem(item);
  return (
    <div className="grid gap-2 rounded-md border border-slate-200 px-3 py-2.5 text-[12px] md:grid-cols-[minmax(0,1fr)_auto]">
      <div>
        <div className="font-medium text-slate-900">{humanize(item.action)}</div>
        <div className="mt-0.5 text-slate-500">{listLabel(item.recipients, "No recipient")}</div>
        <div className={`mt-1 ${dueClassName(item.due_at, generatedAt)}`}>Due {displayPolicyDate(item.due_at)}</div>
      </div>
      <button
        type="button"
        onClick={() => onAction(action)}
        disabled={saving}
        className={actionButtonClass(actionTone(action.action))}
      >
        {actionIconElement(action.action, "h-3.5 w-3.5")}
        {action.label}
      </button>
    </div>
  );
}

function EventRow({ event }: { event: GRCPolicyLifecycleEvent }) {
  return (
    <div className="grid gap-2 rounded-md border border-slate-200 px-3 py-2.5 text-[12px] md:grid-cols-[minmax(0,1fr)_auto]">
      <div>
        <div className="font-medium text-slate-900">{humanize(event.action || event.event_kind || "event")}</div>
        <div className="mt-0.5 text-slate-500">{event.actor || "System"} / {humanize(event.record_type || "policy")}</div>
        {event.reason && <div className="mt-1 text-slate-600">{event.reason}</div>}
      </div>
      <div className="text-right">
        <Badge value={event.status || "recorded"} tone={statusIntent(event.status)} />
        <div className="mt-1 text-slate-500">{displayPolicyDate(event.occurred_at)}</div>
      </div>
    </div>
  );
}

function ActionModal({
  action,
  reason,
  dateValue: currentDateValue,
  value,
  saving,
  onReasonChange,
  onDateChange,
  onValueChange,
  onClose,
  onSubmit,
}: {
  action: GRCPolicyLifecycleAction | null;
  reason: string;
  dateValue: string;
  value: string;
  saving: boolean;
  onReasonChange: (value: string) => void;
  onDateChange: (value: string) => void;
  onValueChange: (value: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  if (!action) return null;
  const dateField = actionDateField(action.action, action.date_field);
  const valueField = actionValueField(action);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/35 px-4 py-6">
      <div className="w-full max-w-lg rounded-lg border border-slate-200 bg-white shadow-xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div>
            <div className="flex items-center gap-2 text-[13px] font-semibold text-slate-900">
              {actionIconElement(action.action, "h-4 w-4 text-indigo-600")}
              {action.label}
            </div>
            <div className="mt-1 text-[12px] text-slate-500">{action.policy || action.policy_id || humanize(action.record_type || "policy")}</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            title="Close"
            className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition hover:border-slate-300 hover:text-slate-700 disabled:opacity-60"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          <dl className="grid gap-3 text-[12px] sm:grid-cols-2">
            <DetailItem label="Record" value={humanize(action.record_type || "policy")} />
            <DetailItem label="Owner" value={action.owner || "Unassigned"} />
            <DetailItem label="State" value={humanize(action.status || "pending")} />
            <DetailItem label="Due" value={displayPolicyDate(action.due_at)} valueClassName={dueClassName(action.due_at)} />
          </dl>
          {dateField && (
            <label className={labelClass}>
              {actionDateLabel(action.action, action.date_field)}
              <input
                type="date"
                value={currentDateValue}
                onChange={(event) => onDateChange(event.target.value)}
                className={inputClass}
              />
            </label>
          )}
          {valueField && (
            <label className={labelClass}>
              {actionValueLabel(action)}
              <input
                value={value}
                onChange={(event) => onValueChange(event.target.value)}
                placeholder={valueField === "control_ids" || valueField === "evidence_urns" ? "Comma-separated" : ""}
                className={inputClass}
              />
            </label>
          )}
          <label className={labelClass}>
            Reason
            <textarea
              value={reason}
              onChange={(event) => onReasonChange(event.target.value)}
              rows={4}
              placeholder="Decision note"
              className={`${inputClass} min-h-24 resize-y`}
            />
          </label>
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 transition hover:border-slate-300 hover:bg-slate-50 disabled:opacity-60"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={saving}
            className={actionButtonClass(actionTone(action.action))}
          >
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
            {saving ? "Saving" : "Record"}
          </button>
        </div>
      </div>
    </div>
  );
}

function DetailItem({ label, value, valueClassName = "text-slate-900" }: { label: string; value: string; valueClassName?: string }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={`mt-1 ${valueClassName}`}>{value}</dd>
    </div>
  );
}

function DetailMetric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: React.ReactNode; detail: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-500">
        {icon}
        {label}
      </div>
      <div className="mt-1.5 text-lg font-semibold text-slate-900">{value}</div>
      <div className="mt-0.5 text-[12px] text-slate-500">{detail}</div>
    </div>
  );
}

function DetailSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-slate-100 pt-4">
      <h3 className="text-[13px] font-semibold text-slate-900">{title}</h3>
      <div className="mt-3">{children}</div>
    </section>
  );
}

function EmptyDetail({ label }: { label: string }) {
  return <div className="rounded-md border border-dashed border-slate-300 bg-slate-50 px-3 py-3 text-[12px] text-slate-500">{label}</div>;
}

function VersionRow({ version, generatedAt }: { version: GRCPolicyVersion; generatedAt?: string }) {
  return (
    <div className="rounded-md border border-slate-200 px-3 py-2.5 text-[12px]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="font-medium text-slate-900">{version.title}</div>
          <div className="mt-0.5 text-slate-500">Version {version.version || version.id}</div>
        </div>
        <Badge value={version.status || "unknown"} />
      </div>
      {(version.change_summary || version.diff_summary) && (
        <div className="mt-2 space-y-1 text-slate-600">
          {version.change_summary && <div>{version.change_summary}</div>}
          {version.diff_summary && <div>{version.diff_summary}</div>}
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-slate-500">
        <span>Created {displayPolicyDate(version.created_at)}</span>
        <span className={dueClassName(version.effective_at, generatedAt)}>Effective {displayPolicyDate(version.effective_at)}</span>
        {version.diff_url && <Link href={version.diff_url} className="text-indigo-600 hover:text-indigo-800">Diff</Link>}
      </div>
    </div>
  );
}

function ApprovalRow({ approval, generatedAt }: { approval: GRCPolicyApproval; generatedAt?: string }) {
  return (
    <div className="grid gap-2 rounded-md border border-slate-200 px-3 py-2.5 text-[12px] md:grid-cols-[minmax(0,1fr)_auto]">
      <div>
        <div className="font-medium text-slate-900">{approval.step || approval.id}</div>
        <div className="mt-0.5 text-slate-500">{listLabel(approval.approvers, "No approver")}</div>
      </div>
      <div className="text-right">
        <Badge value={approval.status || "pending"} />
        <div className={`mt-1 ${dueClassName(approval.due_at, generatedAt)}`}>{displayPolicyDate(approval.due_at)}</div>
      </div>
    </div>
  );
}

function ReviewRow({ review, generatedAt }: { review: GRCPolicyReview; generatedAt?: string }) {
  return (
    <div className="grid gap-2 rounded-md border border-slate-200 px-3 py-2.5 text-[12px] md:grid-cols-[minmax(0,1fr)_auto]">
      <div>
        <div className="font-medium text-slate-900">{review.owner || "Unassigned"}</div>
        <div className="mt-0.5 text-slate-500">{listLabel(review.reviewers, "No reviewer")}</div>
      </div>
      <div className="text-right">
        <Badge value={review.status || "pending"} />
        <div className={`mt-1 ${dueClassName(review.review_due_at, generatedAt)}`}>{displayPolicyDate(review.review_due_at)}</div>
      </div>
    </div>
  );
}

function AttestationRow({ attestation, generatedAt }: { attestation: GRCPolicyAcceptance; generatedAt?: string }) {
  return (
    <div className="grid gap-2 rounded-md border border-slate-200 px-3 py-2.5 text-[12px] md:grid-cols-[minmax(0,1fr)_auto]">
      <div>
        <div className="font-medium text-slate-900">{attestation.person || listLabel(attestation.assignees, "Assignee")}</div>
        <div className="mt-0.5 text-slate-500">{listLabel(attestation.assignees, "No group")}</div>
      </div>
      <div className="text-right">
        <Badge value={attestation.status || "pending"} tone={statusIntent(attestation.status)} />
        <div className={`mt-1 ${dueClassName(attestation.accepted_at || attestation.due_at, generatedAt)}`}>{displayPolicyDate(attestation.accepted_at || attestation.due_at)}</div>
      </div>
    </div>
  );
}

function ExceptionRow({ exceptionRecord, generatedAt }: { exceptionRecord: GRCPolicyException; generatedAt?: string }) {
  return (
    <div className="rounded-md border border-slate-200 px-3 py-2.5 text-[12px]">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="font-medium text-slate-900">{exceptionRecord.title}</div>
          <div className="mt-0.5 text-slate-500">{exceptionRecord.owner || "Unassigned"} / {listLabel(exceptionRecord.targets?.map((target) => target.label), "No target")}</div>
        </div>
        <Badge value={exceptionRecord.status || "active"} />
      </div>
      {exceptionRecord.reason && <div className="mt-2 text-slate-600">{exceptionRecord.reason}</div>}
      <div className={`mt-2 ${dueClassName(exceptionRecord.expires_at, generatedAt)}`}>Expires {displayPolicyDate(exceptionRecord.expires_at)}</div>
    </div>
  );
}

function ChipList({ values, empty }: { values: string[]; empty: string }) {
  const cleanValues = values.filter(Boolean);
  if (cleanValues.length === 0) {
    return <div className="text-slate-500">{empty}</div>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {cleanValues.map((value) => (
        <span key={value} className="rounded-md border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600">
          {value}
        </span>
      ))}
    </div>
  );
}

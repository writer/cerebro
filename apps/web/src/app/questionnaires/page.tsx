"use client";

import Link from "next/link";
import { useCallback, useMemo, useState, type ChangeEvent, type DragEvent, type FormEvent, type ReactNode } from "react";
import { CheckCircle2, ClipboardPaste, FileUp, Link2, MessageSquare, Plus, RefreshCw, Send, UserPlus, X } from "lucide-react";

import DataTable, { type TableColumn } from "@/components/grc/DataTable";
import { Badge, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";
import { displayDate, humanize, shortEntity } from "@/lib/grc";
import type { GRCQuestionnaireAssignment, GRCQuestionnaireCitation, GRCQuestionnaireRun, GRCQuestionnaireRunAnswer, GRCQuestionnaireRunEvidenceGap, GRCQuestionnaireRunResponse, GRCQuestionnaireRunsResponse, GRCVendor, GRCVendorsResponse } from "@/lib/grc";
import { grcPath, useDebouncedValue, useGRCMutation, useGRCQuery } from "@/lib/grc-client";
import { useQueryParamState } from "@/lib/query-params";
import { inferQuestionnaireIntakeFormat, initialQuestionnaireRowID, isQuestionnaireBinaryIntakeFormat, primaryAnswerForRun, questionnaireDirectionLabel, questionnaireQueueRows, questionnaireRollups, questionnaireStateIntent, suggestQuestionnaireVendor, type QuestionnaireQueueRow } from "@/lib/questionnaires";
import { runtimeStateForError, type RuntimeState } from "@/lib/runtime-state";

const QUEUE_LIMIT = 100;
const EMPTY_RUNS: GRCQuestionnaireRun[] = [];
const EMPTY_VENDORS: GRCVendor[] = [];
const inputClass = "control-input w-full px-3 py-1.5 text-[13px]";
const labelClass = "text-[11px] font-medium uppercase tracking-wider text-[var(--text-muted)]";
const mutedText = "text-[var(--text-muted)]";
const monoText = "font-mono text-[12px] text-[var(--text-secondary)]";

const directionOptions = [
  { value: "", label: "All directions" },
  { value: "customer_security_review", label: "Customer reviews" },
  { value: "vendor_review", label: "Vendor reviews" },
];

const statusOptions = [
  { value: "", label: "All statuses" },
  { value: "needs_input", label: "Needs input" },
  { value: "ready_for_approval", label: "Ready for approval" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "intake", label: "Intake" },
  { value: "processing", label: "Processing" },
];

type IntakeMode = "paste" | "file" | "portal";

const intakeModeOptions = [
  { value: "paste", label: "Paste", Icon: ClipboardPaste },
  { value: "file", label: "File", Icon: FileUp },
  { value: "portal", label: "Portal", Icon: Link2 },
] satisfies Array<{ value: IntakeMode; label: string; Icon: typeof ClipboardPaste }>;

const pastedFormatOptions = [
  { value: "csv", label: "CSV" },
  { value: "tsv", label: "TSV" },
  { value: "json", label: "JSON" },
  { value: "text", label: "Text" },
];

export default function QuestionnairesPage() {
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [direction, setDirection] = useQueryParamState("direction");
  const [status, setStatus] = useQueryParamState("status");
  const [vendorURN, setVendorURN] = useQueryParamState("vendor_urn");
  const [ownerID, setOwnerID] = useQueryParamState("owner_id");
  const [requester, setRequester] = useQueryParamState("requester");
  const [customerName, setCustomerName] = useQueryParamState("customer_name");
  const [query, setQuery] = useQueryParamState("q");
  const [selectedRowID, setSelectedRowID] = useState<string | null>(null);
  const [assignmentOwner, setAssignmentOwner] = useState("");
  const [assignmentTeam, setAssignmentTeam] = useState("");
  const [assignmentReason, setAssignmentReason] = useState("");
  const [commentBody, setCommentBody] = useState("");
  const [decisionState, setDecisionState] = useState("needs_input");
  const [decisionReason, setDecisionReason] = useState("");
  const [mappingRowID, setMappingRowID] = useState<string | null>(null);
  const [slotMapping, setSlotMapping] = useState("");
  const [controlMapping, setControlMapping] = useState("");
  const [mappingOwner, setMappingOwner] = useState("");
  const [mappingReason, setMappingReason] = useState("");
  const [createDirectionDraft, setCreateDirectionDraft] = useState<string | null>(null);
  const [createTitle, setCreateTitle] = useState("Security questionnaire");
  const [createRequester, setCreateRequester] = useState("");
  const [createCustomer, setCreateCustomer] = useState("");
  const [createVendorURNDraft, setCreateVendorURNDraft] = useState<string | null>(null);
  const [createOwner, setCreateOwner] = useState("");
  const [createDueAt, setCreateDueAt] = useState("");
  const [linkVendorURN, setLinkVendorURN] = useState("");
  const [linkVendorRowID, setLinkVendorRowID] = useState<string | null>(null);
  const [linkVendorReason, setLinkVendorReason] = useState("");
  const [sourceFilename, setSourceFilename] = useState("");
  const [intakeMode, setIntakeMode] = useState<IntakeMode>("paste");
  const [intakeFormat, setIntakeFormat] = useState("csv");
  const [intakeText, setIntakeText] = useState("");
  const [intakeFileBase64, setIntakeFileBase64] = useState("");
  const [intakeContentType, setIntakeContentType] = useState("");
  const [portalURL, setPortalURL] = useState("");
  const [portalInstructions, setPortalInstructions] = useState("");
  const [fileReadError, setFileReadError] = useState("");
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const debouncedDirection = useDebouncedValue(direction.trim());
  const debouncedStatus = useDebouncedValue(status.trim());
  const debouncedVendorURN = useDebouncedValue(vendorURN.trim());
  const debouncedOwnerID = useDebouncedValue(ownerID.trim());
  const debouncedRequester = useDebouncedValue(requester.trim());
  const debouncedCustomerName = useDebouncedValue(customerName.trim());
  const debouncedQuery = useDebouncedValue(query.trim());
  const createDirection = createDirectionDraft ?? (direction === "vendor_review" || vendorURN.trim() ? "vendor_review" : "customer_security_review");
  const createVendorURN = createVendorURNDraft ?? vendorURN.trim();
  const setCreateDirection = (value: string) => setCreateDirectionDraft(value);
  const setCreateVendorURN = (value: string) => setCreateVendorURNDraft(value);
  const path = useMemo(
    () => grcPath("/grc/questionnaire-runs", {
      tenant_id: debouncedTenantID,
      direction: debouncedDirection,
      status: debouncedStatus,
      vendor_urn: debouncedVendorURN,
      owner_id: debouncedOwnerID,
      requester: debouncedRequester,
      customer_name: debouncedCustomerName,
      q: debouncedQuery,
      limit: QUEUE_LIMIT,
    }),
    [debouncedCustomerName, debouncedDirection, debouncedOwnerID, debouncedQuery, debouncedRequester, debouncedStatus, debouncedTenantID, debouncedVendorURN],
  );
  const vendorsPath = useMemo(
    () => grcPath("/grc/vendors", { tenant_id: debouncedTenantID, limit: QUEUE_LIMIT }),
    [debouncedTenantID],
  );
  const runsQuery = useGRCQuery<GRCQuestionnaireRunsResponse>(path);
  const vendorsQuery = useGRCQuery<GRCVendorsResponse>(vendorsPath);
  const actionMutation = useGRCMutation<GRCQuestionnaireRunResponse>();
  const createMutation = useGRCMutation<GRCQuestionnaireRunResponse>();
  const reloadQuestionnaireRuns = runsQuery.reload;
  const reloadVendors = vendorsQuery.reload;
  const runs = runsQuery.data?.runs ?? EMPTY_RUNS;
  const vendors = vendorsQuery.data?.vendors ?? EMPTY_VENDORS;
  const vendorsByURN = useMemo(() => new Map(vendors.map((vendor) => [vendor.urn, vendor])), [vendors]);
  const rows = useMemo(() => questionnaireQueueRows(runs), [runs]);
  const rollups = useMemo(() => questionnaireRollups(runs, runsQuery.data?.summary), [runs, runsQuery.data?.summary]);
  const selectedRow = rows.find((row) => row.id === selectedRowID) ?? rows[0] ?? null;
  const selectedRun = selectedRow ? runs.find((run) => run.run_id === selectedRow.runID) ?? null : null;
  const linkedVendor = selectedRun?.vendor_urn ? vendorsByURN.get(selectedRun.vendor_urn) ?? null : null;
  const selectedAnswer = primaryAnswerForRun(selectedRun, selectedRow?.questionID);
  const selectedQuestion = questionnaireQuestionForRun(selectedRun, selectedAnswer?.question_id ?? selectedRow?.questionID);
  const selectedQuestionID = selectedAnswer?.question_id ?? selectedRow?.questionID ?? null;
  const selectedGap = primaryGapForAssignment(selectedAnswer);
  const selectedSlotID = selectedGap ? selectedGap.slot_id || "" : firstOpenEvidenceSlotID(selectedAnswer);
  const selectedSlotMapping = joinMappingList(selectedQuestion?.required_evidence_slots ?? answerEvidenceSlotIDs(selectedAnswer));
  const selectedControlMapping = joinMappingList(selectedQuestion?.mapped_controls ?? selectedAnswer?.controls);
  const selectedMappingOwner = selectedQuestion?.owner_id ?? "";
  const activeSlotMapping = mappingRowID === selectedRow?.id ? slotMapping : selectedSlotMapping;
  const activeControlMapping = mappingRowID === selectedRow?.id ? controlMapping : selectedControlMapping;
  const activeMappingOwner = mappingRowID === selectedRow?.id ? mappingOwner : selectedMappingOwner;
  const activeMappingReason = mappingRowID === selectedRow?.id ? mappingReason : "";
  const activeLinkVendorURN = linkVendorRowID === selectedRow?.id ? linkVendorURN : selectedRun?.vendor_urn || "";
  const intakeLineCount = intakeText.split(/\r?\n/).filter((line) => line.trim()).length;
  const selectedFileDetail = sourceFilename ? [sourceFilename, intakeFormat ? intakeFormat.toUpperCase() : "", intakeContentType].filter(Boolean).join(" · ") : "";
  const metricState: RuntimeState = runsQuery.error ? runtimeStateForError(runsQuery.error) : runsQuery.loading && !runsQuery.data ? "loading" : "ready";
  const suggestedCreateVendor = useMemo(() => (
    createDirection === "vendor_review" && !createVendorURN
      ? suggestQuestionnaireVendor(vendors, {
        title: createTitle,
        requester: createRequester,
        sourceFilename,
        portalURL,
        intakeText,
      })
      : null
  ), [createDirection, createRequester, createTitle, createVendorURN, intakeText, portalURL, sourceFilename, vendors]);
  const createVendor = createVendorURN ? vendorsByURN.get(createVendorURN) ?? null : null;

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
    const row = rows.find((item) => item.id === rowID) ?? null;
    const run = row ? runs.find((item) => item.run_id === row.runID) ?? null : null;
    const answer = primaryAnswerForRun(run, row?.questionID);
    const question = questionnaireQuestionForRun(run, answer?.question_id ?? row?.questionID);
    setMappingRowID(rowID);
    setSlotMapping(joinMappingList(question?.required_evidence_slots ?? answerEvidenceSlotIDs(answer)));
    setControlMapping(joinMappingList(question?.mapped_controls ?? answer?.controls));
    setMappingOwner(question?.owner_id ?? "");
    setMappingReason("");
    setLinkVendorRowID(rowID);
    setLinkVendorURN(run?.vendor_urn ?? "");
    setLinkVendorReason("");
    resetRowActionForms();
  };

  const reloadRuns = useCallback(() => { void reloadQuestionnaireRuns(); }, [reloadQuestionnaireRuns]);

  const reloadQuestionnaireData = useCallback(() => {
    void reloadQuestionnaireRuns();
    void reloadVendors();
  }, [reloadQuestionnaireRuns, reloadVendors]);

  const clearIntakeFile = () => {
    setSourceFilename("");
    setIntakeContentType("");
    setIntakeFileBase64("");
    setIntakeText("");
  };

  const selectIntakeMode = (nextMode: IntakeMode) => {
    if (nextMode === intakeMode) return;
    setIntakeMode(nextMode);
    setFileReadError("");
    if (nextMode === "paste") {
      clearIntakeFile();
      setPortalURL("");
      setPortalInstructions("");
      if (intakeFormat === "portal" || isQuestionnaireBinaryIntakeFormat(intakeFormat)) setIntakeFormat("csv");
      return;
    }
    if (nextMode === "file") {
      setIntakeText("");
      setPortalURL("");
      setPortalInstructions("");
      if (intakeFormat === "portal") setIntakeFormat("pdf");
      return;
    }
    setIntakeText("");
    clearIntakeFile();
    setIntakeFormat("portal");
  };

  const updateSlotMapping = (value: string) => {
    if (mappingRowID !== selectedRow?.id) {
      setMappingRowID(selectedRow?.id ?? null);
      setControlMapping(selectedControlMapping);
      setMappingOwner(selectedMappingOwner);
      setMappingReason("");
    }
    setSlotMapping(value);
  };

  const updateControlMapping = (value: string) => {
    if (mappingRowID !== selectedRow?.id) {
      setMappingRowID(selectedRow?.id ?? null);
      setSlotMapping(selectedSlotMapping);
      setMappingOwner(selectedMappingOwner);
      setMappingReason("");
    }
    setControlMapping(value);
  };

  const updateMappingOwner = (value: string) => {
    if (mappingRowID !== selectedRow?.id) {
      setMappingRowID(selectedRow?.id ?? null);
      setSlotMapping(selectedSlotMapping);
      setControlMapping(selectedControlMapping);
      setMappingReason("");
    }
    setMappingOwner(value);
  };

  const updateMappingReason = (value: string) => {
    if (mappingRowID !== selectedRow?.id) {
      setMappingRowID(selectedRow?.id ?? null);
      setSlotMapping(selectedSlotMapping);
      setControlMapping(selectedControlMapping);
      setMappingOwner(selectedMappingOwner);
    }
    setMappingReason(value);
  };

  const updateLinkVendorURN = (value: string) => {
    setLinkVendorRowID(selectedRow?.id ?? null);
    setLinkVendorURN(value);
  };

  const submitCreateRun = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const response = await createMutation.mutate("/grc/questionnaire-runs", {
        tenant_id: tenantID || undefined,
        upload_id: newUploadID(),
        direction: createDirection,
        title: createTitle,
        requester: createRequester || undefined,
        customer_name: createDirection === "customer_security_review" ? createCustomer || createRequester || undefined : undefined,
        vendor_urn: createDirection === "vendor_review" ? createVendorURN || undefined : undefined,
        vendor_id: createDirection === "vendor_review" ? createVendor?.vendor_id || vendorIDFromURN(createVendorURN) || undefined : undefined,
        owner_id: createOwner || undefined,
        due_at: createDueAt || undefined,
        source_filename: intakeMode === "file" ? sourceFilename || undefined : undefined,
        source_format: intakeFormat,
        intake_format: intakeFormat,
        intake_text: intakeMode !== "portal" ? intakeText || undefined : undefined,
        intake_file_base64: intakeMode === "file" ? intakeFileBase64 || undefined : undefined,
        intake_content_type: intakeMode === "file" ? intakeContentType || undefined : undefined,
        portal_url: intakeFormat === "portal" ? portalURL || undefined : undefined,
        portal_instructions: intakeFormat === "portal" ? portalInstructions || undefined : undefined,
      });
      setSelectedRowID(initialQuestionnaireRowID(response.run));
      setMappingRowID(null);
      setMappingReason("");
      setLinkVendorRowID(null);
      resetRowActionForms();
      setIntakeText("");
      setIntakeMode("paste");
      setIntakeFileBase64("");
      setIntakeContentType("");
      setSourceFilename("");
      setPortalURL("");
      setPortalInstructions("");
      setFileReadError("");
      reloadRuns();
    } catch {
      return;
    }
  };

  const submitVendorLink = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextVendorURN = linkVendorURN.trim();
    if (!selectedRun || !nextVendorURN) return;
    const vendor = vendorsByURN.get(nextVendorURN);
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/vendor-link`, {
        tenant_id: tenantID || undefined,
        vendor_urn: nextVendorURN,
        vendor_id: vendor?.vendor_id || vendorIDFromURN(nextVendorURN) || undefined,
        reason: linkVendorReason || "Vendor matched to questionnaire.",
      });
      setLinkVendorRowID(selectedRow?.id ?? null);
      setLinkVendorURN(nextVendorURN);
      setLinkVendorReason("");
      reloadQuestionnaireData();
    } catch {
      return;
    }
  };

  const removeVendorLink = async () => {
    if (!selectedRun) return;
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/vendor-link`, {
        tenant_id: tenantID || undefined,
        unlink: true,
        reason: linkVendorReason || "Vendor link removed.",
      });
      setLinkVendorRowID(selectedRow?.id ?? null);
      setLinkVendorURN("");
      setLinkVendorReason("");
      reloadQuestionnaireData();
    } catch {
      return;
    }
  };

  const submitQuestionUpdate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun || !selectedQuestionID) return;
    const requiredSlots = splitMappingList(activeSlotMapping);
    const mappedControls = splitMappingList(activeControlMapping);
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/questions`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID,
        required_evidence_slots: requiredSlots,
        mapped_controls: mappedControls,
        owner_id: activeMappingOwner || undefined,
        reason: activeMappingReason || "Question mapping updated.",
        clear_required_evidence_slots: requiredSlots.length === 0,
        clear_mapped_controls: mappedControls.length === 0,
        clear_owner: !activeMappingOwner.trim(),
      });
      reloadRuns();
    } catch {
      return;
    }
  };

  const handleIntakeFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    await readIntakeFile(file);
    event.target.value = "";
  };

  const handleIntakeDrop = async (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    const file = event.dataTransfer.files?.[0];
    if (!file) return;
    await readIntakeFile(file);
  };

  const readIntakeFile = async (file: File) => {
    setIntakeMode("file");
    setSourceFilename(file.name);
    setIntakeContentType(file.type);
    setFileReadError("");
    setPortalURL("");
    setPortalInstructions("");
    const format = inferQuestionnaireIntakeFormat(file.name, file.type);
    setIntakeFormat(format);
    try {
      if (isQuestionnaireBinaryIntakeFormat(format)) {
        setIntakeFileBase64(await fileToBase64(file));
        setIntakeText("");
      } else {
        setIntakeText(await file.text());
        setIntakeFileBase64("");
      }
    } catch (error) {
      setIntakeFileBase64("");
      setIntakeText("");
      setFileReadError(error instanceof Error ? error.message : "Could not read file.");
    }
  };

  const processRun = async () => {
    if (!selectedRun) return;
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/process`, { tenant_id: tenantID || undefined });
      reloadRuns();
    } catch {
      return;
    }
  };

  const submitAssignment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun) return;
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/assignments`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        gap_id: selectedGap?.id || undefined,
        slot_id: selectedSlotID || undefined,
        owner_id: assignmentOwner,
        team: assignmentTeam,
        reason: assignmentReason,
      });
      reloadRuns();
    } catch {
      return;
    }
  };

  const submitDecision = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun) return;
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/decisions`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        state: decisionState,
        reason: decisionReason,
      });
      reloadRuns();
    } catch {
      return;
    }
  };

  const submitComment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedRun || !commentBody.trim()) return;
    try {
      await actionMutation.mutate(`/grc/questionnaire-runs/${encodeURIComponent(selectedRun.run_id)}/comments`, {
        tenant_id: tenantID || undefined,
        question_id: selectedQuestionID || undefined,
        body: commentBody,
      });
      setCommentBody("");
      reloadRuns();
    } catch {
      return;
    }
  };

  const columns = useMemo<TableColumn<QuestionnaireQueueRow>[]>(() => [
    {
      key: "question",
      label: "Question",
      render: (_value, row) => (
        <div>
          <div className="max-w-[28rem] truncate font-medium text-[var(--text-primary)]">{row.question}</div>
          <div className="mt-0.5 max-w-[28rem] truncate text-[11px] text-[var(--text-muted)]">{row.title}</div>
        </div>
      ),
    },
    { key: "direction", label: "Direction", render: (_value, row) => <span>{questionnaireDirectionLabel(row.direction)}</span> },
    { key: "requester", label: "Requester", render: (_value, row) => <span className="max-w-[12rem] truncate">{shortEntity(row.requester)}</span> },
    { key: "state", label: "State", render: (_value, row) => <Badge value={row.state} /> },
    { key: "blocker", label: "Blocker", render: (_value, row) => row.blocker ? <span className="max-w-[18rem] truncate">{row.blocker}</span> : <span className={mutedText}>—</span> },
    { key: "owner", label: "Owner", render: (_value, row) => row.owner ? <span>{row.owner}</span> : <span className={mutedText}>Unassigned</span> },
    { key: "dueAt", label: "Due", render: (_value, row) => <span className={mutedText}>{displayDate(row.dueAt)}</span> },
    { key: "mappedControls", label: "Controls", render: (_value, row) => <span className={monoText}>{row.mappedControls.slice(0, 2).join(", ") || "—"}</span> },
    { key: "citationCount", label: "Citations", render: (_value, row) => <span className="tabular-nums">{row.citationCount}</span> },
  ], []);
  const hasCreateIntake = intakeMode === "portal"
    ? Boolean(portalURL.trim())
    : intakeMode === "file"
      ? Boolean(intakeFileBase64 || (sourceFilename && intakeText.trim()))
      : Boolean(intakeText.trim());

  return (
    <main className="space-y-6">
      <PageHeader
        title="Questionnaires"
        description="Customer questionnaires and vendor reviews with evidence-backed answers, blockers, owners, and approvals."
        contractId="questionnaires"
        action={<button type="button" onClick={reloadRuns} className="secondary-button inline-flex items-center gap-2 px-3 py-1.5 text-[12px]"><RefreshCw className="h-3.5 w-3.5" />Refresh</button>}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-7">
        <MetricCard label="Due" value={rollups.due} detail="questionnaires past due" intent={rollups.due > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Blocked" value={rollups.blocked} detail="answers blocked" intent={rollups.blocked > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Needs review" value={rollups.needsReview} detail="answers queued" intent={rollups.needsReview > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Ready" value={rollups.ready} detail="answers with citations" intent="success" state={metricState} />
        <MetricCard label="Stale evidence" value={rollups.stale} detail="answers affected" intent={rollups.stale > 0 ? "warning" : "success"} state={metricState} />
        <MetricCard label="Missing evidence" value={rollups.missingEvidence} detail="open gaps" intent={rollups.missingEvidence > 0 ? "danger" : "success"} state={metricState} />
        <MetricCard label="Unassigned" value={rollups.unassigned} detail="questions without owner" intent={rollups.unassigned > 0 ? "warning" : "success"} state={metricState} />
      </div>

      <Panel title="Add questionnaire">
        <form onSubmit={submitCreateRun} className="space-y-4">
          {createMutation.error && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-100">{createMutation.error}</div>}
          <div className="grid gap-3 lg:grid-cols-4">
            <label htmlFor="create-direction">
              <span className={labelClass}>Direction</span>
              <select id="create-direction" value={createDirection} onChange={(event) => setCreateDirection(event.target.value)} className={inputClass}>
                <option value="customer_security_review">Customer review</option>
                <option value="vendor_review">Vendor review</option>
              </select>
            </label>
            <label htmlFor="create-title">
              <span className={labelClass}>Questionnaire name</span>
              <input id="create-title" value={createTitle} onChange={(event) => setCreateTitle(event.target.value)} className={inputClass} placeholder="Security questionnaire" />
            </label>
            <label htmlFor="create-requester">
              <span className={labelClass}>Requester</span>
              <input id="create-requester" value={createRequester} onChange={(event) => setCreateRequester(event.target.value)} className={inputClass} placeholder="customer or team" />
            </label>
            <label htmlFor="create-owner">
              <span className={labelClass}>Owner</span>
              <input id="create-owner" value={createOwner} onChange={(event) => setCreateOwner(event.target.value)} className={inputClass} placeholder="owner@example.com" />
            </label>
            {createDirection === "customer_security_review" ? (
              <label htmlFor="create-customer">
                <span className={labelClass}>Customer</span>
                <input id="create-customer" value={createCustomer} onChange={(event) => setCreateCustomer(event.target.value)} className={inputClass} placeholder="Acme Corp" />
              </label>
            ) : (
              <div className="lg:col-span-2">
                <VendorPicker
                  id="create-vendor"
                  label="Vendor"
                  vendors={vendors}
                  value={createVendorURN}
                  onChange={setCreateVendorURN}
                  loading={vendorsQuery.loading && !vendorsQuery.data}
                />
                {suggestedCreateVendor && (
                  <button type="button" onClick={() => setCreateVendorURN(suggestedCreateVendor.urn)} className="mt-2 text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
                    Use {suggestedCreateVendor.name}
                  </button>
                )}
              </div>
            )}
            <label htmlFor="create-due">
              <span className={labelClass}>Due date</span>
              <input id="create-due" type="date" value={createDueAt} onChange={(event) => setCreateDueAt(event.target.value)} className={inputClass} />
            </label>
          </div>

          <div className="space-y-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap items-center gap-2">
                <span className={labelClass}>Question source</span>
                <div className="inline-flex rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-0.5">
                  {intakeModeOptions.map(({ value, label, Icon }) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => selectIntakeMode(value)}
                      className={`inline-flex min-w-[5.25rem] items-center justify-center gap-1.5 rounded-[5px] px-2.5 py-1.5 text-[12px] font-semibold transition ${intakeMode === value ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-sm" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"}`}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="text-[12px] text-[var(--text-muted)]">
                {intakeMode === "paste" ? `${intakeLineCount} non-empty lines` : intakeMode === "file" ? selectedFileDetail || "No file selected." : portalURL || "Portal URL required."}
              </div>
            </div>

            {intakeMode === "paste" && (
              <div className="space-y-2">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                  <label htmlFor="intake-text">
                    <span className={labelClass}>Questions</span>
                  </label>
                  <label htmlFor="create-format" className="w-full sm:w-48">
                    <span className={labelClass}>Format</span>
                    <select id="create-format" value={intakeFormat} onChange={(event) => setIntakeFormat(event.target.value)} className={inputClass}>
                      {pastedFormatOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                    </select>
                  </label>
                </div>
                <textarea
                  id="intake-text"
                  value={intakeText}
                  onChange={(event) => setIntakeText(event.target.value)}
                  className={`${inputClass} min-h-[220px] resize-y font-mono text-[12px] leading-5`}
                  placeholder={"question,section,required_evidence_slots,mapped_controls\nDo you enforce MFA?,Access,identity_mfa,SOC2-CC6.1"}
                />
              </div>
            )}

            {intakeMode === "file" && (
              <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px]">
                <label
                  htmlFor="intake-file"
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={handleIntakeDrop}
                  className="flex min-h-[190px] cursor-pointer flex-col items-center justify-center rounded-md border border-dashed border-[color:var(--border-strong)] bg-[var(--surface-muted)] px-4 py-6 text-center transition hover:border-[color:var(--primary)] hover:bg-[var(--surface)]"
                >
                  <FileUp className="h-6 w-6 text-[var(--text-muted)]" />
                  <span className="mt-3 text-[13px] font-semibold text-[var(--text-primary)]">Upload questionnaire file</span>
                  <span className="mt-1 text-[12px] text-[var(--text-muted)]">CSV, TSV, JSON, TXT, PDF, XLSX, XLSM</span>
                </label>
                <div className="space-y-2">
                  <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                    <div className={labelClass}>Selected file</div>
                    <div className="mt-1 break-words text-[13px] text-[var(--text-secondary)]">{selectedFileDetail || "No file selected."}</div>
                  </div>
                  {sourceFilename && (
                    <button type="button" onClick={clearIntakeFile} className="secondary-button inline-flex w-full items-center justify-center gap-2 px-3 py-1.5 text-[12px]">
                      <X className="h-3.5 w-3.5" />
                      Clear file
                    </button>
                  )}
                  {fileReadError && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-100">{fileReadError}</div>}
                </div>
                <input
                  id="intake-file"
                  type="file"
                  accept=".csv,.tsv,.json,.txt,.pdf,.xlsx,.xlsm,text/csv,text/tab-separated-values,application/json,text/plain,application/pdf,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel.sheet.macroenabled.12"
                  onChange={handleIntakeFile}
                  className="sr-only"
                />
              </div>
            )}

            {intakeMode === "portal" && (
              <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
              <label htmlFor="portal-url">
                <span className={labelClass}>Portal URL</span>
                <input id="portal-url" value={portalURL} onChange={(event) => setPortalURL(event.target.value)} className={`${inputClass} py-2`} placeholder="https://portal.example.com/review" />
              </label>
              <label htmlFor="portal-instructions">
                <span className={labelClass}>Portal notes</span>
                <textarea
                  id="portal-instructions"
                  value={portalInstructions}
                  onChange={(event) => setPortalInstructions(event.target.value)}
                  className={`${inputClass} min-h-[86px] resize-y leading-5`}
                  placeholder="Login, workspace, owner, or access notes"
                />
              </label>
            </div>
            )}
          </div>

          <div className="flex justify-end">
            <button type="submit" disabled={createMutation.saving || !hasCreateIntake} className="primary-button inline-flex w-full items-center justify-center gap-2 px-3 py-2 text-[12px] sm:w-auto">
              <Plus className="h-3.5 w-3.5" />
              Create questionnaire
            </button>
          </div>
        </form>
      </Panel>

      <Panel title="Filters">
        <div className="grid gap-3 md:grid-cols-4 xl:grid-cols-8">
          <label htmlFor="filter-tenant">
            <span className={labelClass}>Tenant</span>
            <input id="filter-tenant" value={tenantID} onChange={(event) => setTenantID(event.target.value)} className={inputClass} placeholder="tenant id" />
          </label>
          <label htmlFor="filter-direction">
            <span className={labelClass}>Direction</span>
            <select id="filter-direction" value={direction} onChange={(event) => setDirection(event.target.value)} className={inputClass}>
              {directionOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label htmlFor="filter-status">
            <span className={labelClass}>Status</span>
            <select id="filter-status" value={status} onChange={(event) => setStatus(event.target.value)} className={inputClass}>
              {statusOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
            </select>
          </label>
          <label htmlFor="filter-owner">
            <span className={labelClass}>Owner</span>
            <input id="filter-owner" value={ownerID} onChange={(event) => setOwnerID(event.target.value)} className={inputClass} placeholder="owner" />
          </label>
          <label htmlFor="filter-requester">
            <span className={labelClass}>Requester</span>
            <input id="filter-requester" value={requester} onChange={(event) => setRequester(event.target.value)} className={inputClass} placeholder="requester" />
          </label>
          <label htmlFor="filter-customer">
            <span className={labelClass}>Customer</span>
            <input id="filter-customer" value={customerName} onChange={(event) => setCustomerName(event.target.value)} className={inputClass} placeholder="customer" />
          </label>
          <label htmlFor="filter-vendor">
            <span className={labelClass}>Vendor</span>
            <input id="filter-vendor" list="filter-vendor-options" value={vendorURN} onChange={(event) => setVendorURN(event.target.value)} className={inputClass} placeholder="vendor URN" />
            <datalist id="filter-vendor-options">
              {vendors.map((vendor) => <option key={vendor.urn} value={vendor.urn}>{vendor.name}</option>)}
            </datalist>
          </label>
          <label htmlFor="filter-search">
            <span className={labelClass}>Search</span>
            <input id="filter-search" value={query} onChange={(event) => setQuery(event.target.value)} className={inputClass} placeholder="question, owner, control" />
          </label>
        </div>
      </Panel>

      {runsQuery.error && <ErrorBlock error={runsQuery.error} onRetry={reloadRuns} recoveryDetail="The questionnaire queue needs the GRC questionnaire API." />}
      {runsQuery.loading && !runsQuery.data ? <LoadingBlock label="Loading questionnaires..." /> : (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1.55fr)_minmax(360px,0.9fr)]">
          <Panel title="Queue">
            <DataTable
              rows={rows}
              columns={columns}
              emptyMessage="No questionnaire answers match these filters."
              searchPlaceholder="Search loaded answers"
              pageSize={12}
              selectedRowKey={selectedRow?.id}
              getRowKey={(row) => row.id}
              onRowClick={(row) => selectQueueRow(row.id)}
              resultLimit={QUEUE_LIMIT}
              resultNoun="answers"
            />
          </Panel>
          <QuestionnaireDetail
            actionError={actionMutation.error}
            actionSaving={actionMutation.saving}
            answer={selectedAnswer}
            assignmentOwner={assignmentOwner}
            assignmentReason={assignmentReason}
            assignmentTeam={assignmentTeam}
            commentBody={commentBody}
            decisionReason={decisionReason}
            decisionState={decisionState}
            linkedVendor={linkedVendor}
            linkVendorReason={linkVendorReason}
            linkVendorURN={activeLinkVendorURN}
            mappingOwner={activeMappingOwner}
            mappingReason={activeMappingReason}
            mappedControls={activeControlMapping}
            requiredSlots={activeSlotMapping}
            onAssignmentOwnerChange={setAssignmentOwner}
            onAssignmentReasonChange={setAssignmentReason}
            onAssignmentTeamChange={setAssignmentTeam}
            onCommentBodyChange={setCommentBody}
            onDecisionReasonChange={setDecisionReason}
            onDecisionStateChange={setDecisionState}
            onLinkVendorReasonChange={setLinkVendorReason}
            onLinkVendorURNChange={updateLinkVendorURN}
            onMappingOwnerChange={updateMappingOwner}
            onMappingReasonChange={updateMappingReason}
            onMappedControlsChange={updateControlMapping}
            onProcess={processRun}
            onRemoveVendorLink={removeVendorLink}
            onRequiredSlotsChange={updateSlotMapping}
            onSubmitAssignment={submitAssignment}
            onSubmitComment={submitComment}
            onSubmitDecision={submitDecision}
            onSubmitQuestionUpdate={submitQuestionUpdate}
            onSubmitVendorLink={submitVendorLink}
            row={selectedRow}
            run={selectedRun}
            vendors={vendors}
          />
        </div>
      )}
    </main>
  );
}

function QuestionnaireDetail({
  actionError,
  actionSaving,
  answer,
  assignmentOwner,
  assignmentReason,
  assignmentTeam,
  commentBody,
  decisionReason,
  decisionState,
  linkedVendor,
  linkVendorReason,
  linkVendorURN,
  mappingOwner,
  mappingReason,
  mappedControls,
  onAssignmentOwnerChange,
  onAssignmentReasonChange,
  onAssignmentTeamChange,
  onCommentBodyChange,
  onDecisionReasonChange,
  onDecisionStateChange,
  onLinkVendorReasonChange,
  onLinkVendorURNChange,
  onMappingOwnerChange,
  onMappingReasonChange,
  onMappedControlsChange,
  onProcess,
  onRemoveVendorLink,
  onRequiredSlotsChange,
  onSubmitAssignment,
  onSubmitComment,
  onSubmitDecision,
  onSubmitQuestionUpdate,
  onSubmitVendorLink,
  requiredSlots,
  row,
  run,
  vendors,
}: {
  actionError: string | null;
  actionSaving: boolean;
  answer: ReturnType<typeof primaryAnswerForRun>;
  assignmentOwner: string;
  assignmentReason: string;
  assignmentTeam: string;
  commentBody: string;
  decisionReason: string;
  decisionState: string;
  linkedVendor: GRCVendor | null;
  linkVendorReason: string;
  linkVendorURN: string;
  mappingOwner: string;
  mappingReason: string;
  mappedControls: string;
  onAssignmentOwnerChange: (value: string) => void;
  onAssignmentReasonChange: (value: string) => void;
  onAssignmentTeamChange: (value: string) => void;
  onCommentBodyChange: (value: string) => void;
  onDecisionReasonChange: (value: string) => void;
  onDecisionStateChange: (value: string) => void;
  onLinkVendorReasonChange: (value: string) => void;
  onLinkVendorURNChange: (value: string) => void;
  onMappingOwnerChange: (value: string) => void;
  onMappingReasonChange: (value: string) => void;
  onMappedControlsChange: (value: string) => void;
  onProcess: () => Promise<void>;
  onRemoveVendorLink: () => Promise<void>;
  onRequiredSlotsChange: (value: string) => void;
  onSubmitAssignment: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitComment: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitDecision: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitQuestionUpdate: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onSubmitVendorLink: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  requiredSlots: string;
  row: QuestionnaireQueueRow | null;
  run: GRCQuestionnaireRun | null;
  vendors: GRCVendor[];
}) {
  if (!run || !row) {
    return (
      <Panel title="Answer detail">
        <div className="rounded-md border border-dashed border-[color:var(--border)] p-4 text-[13px] text-[var(--text-muted)]">No questionnaire answer selected.</div>
      </Panel>
    );
  }
  const intakeFacts = questionnaireIntakeFacts(run);
  const linkedVendorURN = run.vendor_urn ?? "";
  const linkedVendorName = linkedVendor?.name || (linkedVendorURN ? shortEntity(linkedVendorURN) : "");
  const assignmentGap = primaryGapForAssignment(answer);
  const assignmentSlotID = assignmentGap ? assignmentGap.slot_id || "" : firstOpenEvidenceSlotID(answer);
  return (
    <Panel
      title="Answer detail"
      action={<button type="button" onClick={() => { void onProcess(); }} disabled={actionSaving} className="secondary-button inline-flex items-center gap-2 px-3 py-1.5 text-[12px]"><RefreshCw className="h-3.5 w-3.5" />Process</button>}
    >
      <div className="space-y-5">
        {actionError && <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-100">{actionError}</div>}
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge value={answer?.answer_state ?? run.status} />
            <span className={`rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${intentClass(questionnaireStateIntent(answer?.answer_state ?? run.status))}`}>{questionnaireDirectionLabel(run.direction)}</span>
          </div>
          <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">{answer?.question ?? row.question ?? run.title}</h2>
          <div className="text-[12px] text-[var(--text-muted)]">{run.title} · {shortEntity(run.vendor_urn || run.customer_name || run.requester || "")}</div>
        </div>

        <DetailSection title="Draft answer">
          <p className="text-[13px] leading-5 text-[var(--text-secondary)]">{answer?.draft_answer || "No draft answer is ready."}</p>
        </DetailSection>

        <DetailSection title="Intake">
          {intakeFacts.length === 0 ? <EmptyDetail label="No intake source recorded." /> : (
            <div className="grid gap-2 sm:grid-cols-2">
              {intakeFacts.map((fact) => (
                <div key={fact.label} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                  <div className={labelClass}>{fact.label}</div>
                  <div className="mt-1 break-words text-[var(--text-secondary)]">{fact.value}</div>
                </div>
              ))}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Vendor">
          <div className="space-y-3">
            {linkedVendorURN ? (
              <div className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <Link href={`/vendors/${encodeURIComponent(linkedVendorURN)}`} className="text-[13px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
                      {linkedVendorName}
                    </Link>
                    <div className="mt-1 text-[var(--text-muted)]">{linkedVendor?.owner || linkedVendor?.security_owner_user_id || linkedVendor?.business_owner_user_id || "Owner missing"}</div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <Badge value={linkedVendor?.risk_level || "vendor"} />
                    <Badge value={linkedVendor?.review_state || "linked"} />
                  </div>
                </div>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  <div>
                    <div className={labelClass}>Review due</div>
                    <div className="mt-1 text-[var(--text-secondary)]">{displayDate(linkedVendor?.review_due_at)}</div>
                  </div>
                  <div>
                    <div className={labelClass}>Questionnaires</div>
                    <div className="mt-1 text-[var(--text-secondary)]">{linkedVendor?.questionnaire_count ?? 0}</div>
                  </div>
                </div>
              </div>
            ) : (
              <EmptyDetail label="No vendor linked." />
            )}
            <form onSubmit={onSubmitVendorLink} className="space-y-2">
              <VendorPicker
                id="detail-vendor"
                label={linkedVendorURN ? "Change vendor" : "Link vendor"}
                vendors={vendors}
                value={linkVendorURN}
                onChange={onLinkVendorURNChange}
              />
              <div className="grid gap-2 sm:grid-cols-[1fr_auto_auto]">
                <input
                  aria-label="Vendor link reason"
                  value={linkVendorReason}
                  onChange={(event) => onLinkVendorReasonChange(event.target.value)}
                  className={inputClass}
                  placeholder="reason"
                />
                <button type="submit" disabled={actionSaving || !linkVendorURN || linkVendorURN === linkedVendorURN} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]">
                  <Link2 className="h-3.5 w-3.5" />
                  {linkedVendorURN ? "Change vendor" : "Link vendor"}
                </button>
                <button type="button" onClick={() => { void onRemoveVendorLink(); }} disabled={actionSaving || !linkedVendorURN} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]">
                  <X className="h-3.5 w-3.5" />
                  Remove link
                </button>
              </div>
            </form>
          </div>
        </DetailSection>

        <DetailSection title="Question mapping">
          <form onSubmit={onSubmitQuestionUpdate} className="space-y-2">
            <div className="grid gap-2 sm:grid-cols-2">
              <label htmlFor="required-slots">
                <span className={labelClass}>Required slots</span>
                <input id="required-slots" value={requiredSlots} onChange={(event) => onRequiredSlotsChange(event.target.value)} className={inputClass} placeholder="identity_mfa, audit_report" />
              </label>
              <label htmlFor="mapped-controls">
                <span className={labelClass}>Mapped controls</span>
                <input id="mapped-controls" value={mappedControls} onChange={(event) => onMappedControlsChange(event.target.value)} className={inputClass} placeholder="SOC2-CC6.1, ISO-A.5.15" />
              </label>
              <label htmlFor="mapping-owner">
                <span className={labelClass}>Owner</span>
                <input id="mapping-owner" value={mappingOwner} onChange={(event) => onMappingOwnerChange(event.target.value)} className={inputClass} placeholder="owner@example.com" />
              </label>
              <label htmlFor="mapping-reason">
                <span className={labelClass}>Reason</span>
                <input id="mapping-reason" value={mappingReason} onChange={(event) => onMappingReasonChange(event.target.value)} className={inputClass} placeholder="evidence slot or owner change" />
              </label>
            </div>
            <button type="submit" disabled={actionSaving || !row.questionID} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]">
              <CheckCircle2 className="h-3.5 w-3.5" />
              Save mapping
            </button>
          </form>
        </DetailSection>

        <DetailSection title="Evidence slots">
          <div className="space-y-2">
            {(answer?.evidence_slots ?? []).length === 0 ? <EmptyDetail label="No evidence slots recorded." /> : (answer?.evidence_slots ?? []).map((slot) => (
              <div key={slot.id} className="rounded-md border border-[color:var(--border)] p-3">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-[13px] font-medium text-[var(--text-primary)]">{slot.label || humanize(slot.id)}</span>
                  <Badge value={slot.state} />
                </div>
                {(slot.missing_reasons ?? []).length > 0 && <div className="mt-2 text-[12px] text-[var(--text-muted)]">{slot.missing_reasons?.join("; ")}</div>}
              </div>
            ))}
          </div>
        </DetailSection>

        <DetailSection title="Citations">
          {(answer?.citations ?? []).length === 0 ? <EmptyDetail label="No citations linked." /> : (
            <div className="space-y-2">
              {(answer?.citations ?? []).map((citation) => (
                <div key={citation.id} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                  <div className="font-medium text-[var(--text-primary)]">{citation.label || shortEntity(citation.id)}</div>
                  <div className="mt-1 text-[var(--text-muted)]">{citationDetail(citation, answer?.freshness?.status)}</div>
                </div>
              ))}
            </div>
          )}
        </DetailSection>

        <DetailSection title="Blockers">
          <GapList gaps={[...(answer?.missing_evidence ?? []), ...(answer?.conflicts ?? [])]} />
        </DetailSection>

        <DetailSection title="Owner and decision">
          <form onSubmit={onSubmitAssignment} className="grid gap-2 sm:grid-cols-3">
            <input aria-label="Assignment owner" value={assignmentOwner} onChange={(event) => onAssignmentOwnerChange(event.target.value)} className={inputClass} placeholder="owner@example.com" />
            <input aria-label="Assignment team" value={assignmentTeam} onChange={(event) => onAssignmentTeamChange(event.target.value)} className={inputClass} placeholder="team" />
            <button type="submit" disabled={actionSaving || (!assignmentOwner.trim() && !assignmentTeam.trim())} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]"><UserPlus className="h-3.5 w-3.5" />Assign</button>
            <input aria-label="Assignment note" value={assignmentReason} onChange={(event) => onAssignmentReasonChange(event.target.value)} className={`${inputClass} sm:col-span-3`} placeholder="what the owner needs to provide" />
            {(assignmentGap || assignmentSlotID) && <div className="sm:col-span-3 text-[12px] text-[var(--text-muted)]">Assigning {assignmentGap ? humanize(assignmentGap.code) : humanize(assignmentSlotID)}.</div>}
          </form>
          <form onSubmit={onSubmitDecision} className="mt-3 grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
            <select aria-label="Decision" value={decisionState} onChange={(event) => onDecisionStateChange(event.target.value)} className={inputClass}>
              <option value="needs_input">Needs input</option>
              <option value="approved">Approved</option>
              <option value="approved_with_conditions">Approved with conditions</option>
              <option value="rejected">Rejected</option>
            </select>
            <input aria-label="Decision reason" value={decisionReason} onChange={(event) => onDecisionReasonChange(event.target.value)} className={inputClass} placeholder="decision reason" />
            <button type="submit" disabled={actionSaving} className="primary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]"><CheckCircle2 className="h-3.5 w-3.5" />Record</button>
          </form>
        </DetailSection>

        <DetailSection title="Comment">
          <form onSubmit={onSubmitComment} className="grid gap-2 sm:grid-cols-[1fr_auto]">
            <textarea
              aria-label="Comment body"
              value={commentBody}
              onChange={(event) => onCommentBodyChange(event.target.value)}
              className={`${inputClass} min-h-[72px] resize-y leading-5`}
              placeholder="note, blocker update, or handoff"
            />
            <button type="submit" disabled={actionSaving || !commentBody.trim()} className="secondary-button inline-flex items-center justify-center gap-2 px-3 py-1.5 text-[12px]">
              <MessageSquare className="h-3.5 w-3.5" />
              Add comment
            </button>
          </form>
        </DetailSection>

        <div className="grid gap-4 md:grid-cols-3">
          <DetailSection title="Assignments">
            {(run.assignments ?? []).length === 0 ? <EmptyDetail label="No assignments." /> : (
              <div className="space-y-2">
                {(run.assignments ?? []).map((assignment) => (
                  <div key={assignment.id} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-medium text-[var(--text-primary)]">{assignment.owner_id || assignment.team || "Unassigned"}</span>
                      <Badge value={assignment.status} />
                    </div>
                    <div className="mt-1 text-[var(--text-muted)]">{assignmentDetail(assignment)}</div>
                  </div>
                ))}
              </div>
            )}
          </DetailSection>

          <DetailSection title="Decisions">
            {(run.decisions ?? []).length === 0 ? <EmptyDetail label="No decisions." /> : (
              <div className="space-y-2">
                {(run.decisions ?? []).map((decision) => (
                  <div key={decision.id} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-medium text-[var(--text-primary)]">{decision.actor_id || "Reviewer"}</span>
                      <Badge value={decision.decision} />
                    </div>
                    <div className="mt-1 text-[var(--text-muted)]">{decision.reason || displayDate(decision.created_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </DetailSection>

          <DetailSection title="Comments">
            {(run.comments ?? []).length === 0 ? <EmptyDetail label="No comments." /> : (
              <div className="space-y-2">
                {(run.comments ?? []).map((comment) => (
                  <div key={comment.id} className="rounded-md border border-[color:var(--border)] p-3 text-[12px]">
                    <div className="font-medium text-[var(--text-primary)]">{comment.actor_id || "Comment"}</div>
                    <div className="mt-1 text-[var(--text-secondary)]">{comment.body}</div>
                    <div className="mt-1 text-[var(--text-muted)]">{displayDate(comment.created_at)}</div>
                  </div>
                ))}
              </div>
            )}
          </DetailSection>
        </div>

        <DetailSection title="Timeline">
          {(run.timeline ?? []).length === 0 ? <EmptyDetail label="No timeline events recorded." /> : (
            <div className="space-y-2">
              {(run.timeline ?? []).slice(0, 6).map((event) => (
                <div key={event.id} className="flex gap-3 text-[12px]">
                  <Send className="mt-0.5 h-3.5 w-3.5 text-[var(--text-muted)]" />
                  <div>
                    <div className="font-medium text-[var(--text-primary)]">{event.summary || humanize(event.event_type)}</div>
                    <div className="text-[var(--text-muted)]">{displayDate(event.created_at)} {event.actor_id ? `· ${event.actor_id}` : ""}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </DetailSection>
      </div>
    </Panel>
  );
}

function DetailSection({ children, title }: { children: ReactNode; title: string }) {
  return (
    <section>
      <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">{title}</h3>
      {children}
    </section>
  );
}

function VendorPicker({
  id,
  label,
  loading = false,
  onChange,
  value,
  vendors,
}: {
  id: string;
  label: string;
  loading?: boolean;
  onChange: (value: string) => void;
  value: string;
  vendors: GRCVendor[];
}) {
  const [search, setSearch] = useState("");
  const selectedVendor = vendors.find((vendor) => vendor.urn === value) ?? null;
  const filteredVendors = useMemo(() => {
    const query = search.trim().toLowerCase();
    return vendors.filter((vendor) => vendorMatchesPickerSearch(vendor, query)).slice(0, 8);
  }, [search, vendors]);

  return (
    <div>
      <label htmlFor={`${id}-search`}>
        <span className={labelClass}>{label}</span>
        <input
          id={`${id}-search`}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          className={inputClass}
          placeholder={selectedVendor?.name || (value ? shortEntity(value) : "Search vendors")}
        />
      </label>
      {selectedVendor || value ? (
        <div className="mt-2 flex flex-wrap items-center gap-2 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
          <span className="font-semibold text-[var(--text-primary)]">{selectedVendor?.name || shortEntity(value)}</span>
          <Badge value={selectedVendor?.risk_level || "linked"} />
          <button type="button" onClick={() => onChange("")} className="ml-auto text-[var(--text-muted)] hover:text-[var(--text-primary)]">
            Clear
          </button>
        </div>
      ) : null}
      <div className="mt-2 max-h-48 overflow-auto rounded-md border border-[color:var(--border)]">
        {loading ? (
          <div className="p-3 text-[12px] text-[var(--text-muted)]">Loading vendors...</div>
        ) : filteredVendors.length === 0 ? (
          <div className="p-3 text-[12px] text-[var(--text-muted)]">No vendors match.</div>
        ) : (
          filteredVendors.map((vendor) => (
            <button
              key={vendor.urn}
              type="button"
              onClick={() => {
                onChange(vendor.urn);
                setSearch("");
              }}
              className={`flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-[12px] transition hover:bg-[var(--surface-muted)] ${value === vendor.urn ? "bg-[var(--surface-muted)]" : ""}`}
            >
              <span className="min-w-0">
                <span className="block truncate font-semibold text-[var(--text-primary)]">{vendor.name}</span>
                <span className="block truncate text-[var(--text-muted)]">{vendor.owner || vendor.security_owner_user_id || vendor.business_owner_user_id || "Owner missing"}</span>
              </span>
              <Badge value={vendor.risk_level || "vendor"} />
            </button>
          ))
        )}
      </div>
    </div>
  );
}

function GapList({ gaps }: { gaps: GRCQuestionnaireRunEvidenceGap[] }) {
  if (gaps.length === 0) return <EmptyDetail label="No blockers recorded." />;
  return (
    <div className="space-y-2">
      {gaps.map((gap) => (
        <div key={gap.id} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-900 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-100">
          <div className="font-medium">{humanize(gap.code)}</div>
          <div className="mt-1">{gap.reason || gap.slot_id || "Reviewer follow-up required."}</div>
          <div className="mt-1 text-amber-800/80 dark:text-amber-100/80">{gapDetail(gap)}</div>
        </div>
      ))}
    </div>
  );
}

const primaryGapForAssignment = (answer?: GRCQuestionnaireRunAnswer | null) =>
  [...(answer?.missing_evidence ?? []), ...(answer?.conflicts ?? [])][0] ?? null;

const firstOpenEvidenceSlotID = (answer?: GRCQuestionnaireRunAnswer | null) =>
  (answer?.evidence_slots ?? []).find((slot) => slot.state !== "satisfied")?.id ?? "";

const citationDetail = (citation: GRCQuestionnaireCitation, fallbackFreshness?: string) =>
  [
    citation.source || "source",
    citation.evidence_type ? humanize(citation.evidence_type) : "",
    citation.resource_urn ? shortEntity(citation.resource_urn) : citation.evidence_packet_id || citation.evidence_id ? shortEntity(citation.evidence_packet_id || citation.evidence_id || "") : "",
    citation.freshness_status || fallbackFreshness || "unknown",
  ].filter(Boolean).join(" · ");

const gapDetail = (gap: GRCQuestionnaireRunEvidenceGap) =>
  [
    gap.slot_id ? `Slot ${humanize(gap.slot_id)}` : "",
    gap.control_id ? `Control ${gap.control_id}` : "",
    gap.evidence_packet_id ? `Packet ${shortEntity(gap.evidence_packet_id)}` : "",
    gap.review_state ? humanize(gap.review_state) : "",
  ].filter(Boolean).join(" · ");

const assignmentDetail = (assignment: GRCQuestionnaireAssignment) =>
  [
    assignment.reason,
    assignment.gap_id ? `Gap ${shortEntity(assignment.gap_id)}` : "",
    assignment.slot_id ? `Slot ${humanize(assignment.slot_id)}` : "",
    assignment.question_id ? `Question ${shortEntity(assignment.question_id)}` : "",
  ].filter(Boolean).join(" · ") || "No reason";

function EmptyDetail({ label }: { label: string }) {
  return <div className="rounded-md border border-dashed border-[color:var(--border)] p-3 text-[12px] text-[var(--text-muted)]">{label}</div>;
}

const intentClass = (intent: "neutral" | "danger" | "warning" | "success") => {
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

const fileToBase64 = (file: File) =>
  new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const value = typeof reader.result === "string" ? reader.result : "";
      const comma = value.indexOf(",");
      resolve(comma >= 0 ? value.slice(comma + 1) : value);
    };
    reader.onerror = () => reject(reader.error ?? new Error("Could not read file."));
    reader.readAsDataURL(file);
  });

const questionnaireQuestionForRun = (run: GRCQuestionnaireRun | null, questionID?: string | null) => {
  if (!run || !questionID) return undefined;
  return (run.questions ?? []).find((question) => question.id === questionID);
};

const questionnaireIntakeFacts = (run: GRCQuestionnaireRun) => {
  const attributes = run.attributes ?? {};
  return [
    { label: "File", value: run.source_filename },
    { label: "Format", value: attributes.intake_format || run.source_format },
    { label: "Attachment", value: attributes.intake_file_attached === "true" ? "Attached" : "" },
    { label: "Content type", value: attributes.intake_content_type },
    { label: "Portal URL", value: attributes.portal_url },
    { label: "Portal status", value: attributes.portal_status },
    { label: "Portal notes", value: attributes.portal_instructions },
  ].filter((item): item is { label: string; value: string } => typeof item.value === "string" && item.value.trim() !== "");
};

const answerEvidenceSlotIDs = (answer: ReturnType<typeof primaryAnswerForRun>) =>
  (answer?.evidence_slots ?? []).map((slot) => slot.id).filter(Boolean);

const joinMappingList = (values?: string[]) =>
  Array.from(new Set((values ?? []).map((value) => value.trim()).filter(Boolean))).join(", ");

const splitMappingList = (value: string) =>
  Array.from(new Set(value.split(/[,\n;]/).map((item) => item.trim()).filter(Boolean)));

const vendorMatchesPickerSearch = (vendor: GRCVendor, query: string) => {
  if (!query) return true;
  return [
    vendor.name,
    vendor.vendor_id,
    vendor.owner,
    vendor.security_owner_user_id,
    vendor.business_owner_user_id,
    vendor.category,
    vendor.provider,
    vendor.website_url,
  ].some((value) => value?.toLowerCase().includes(query));
};

const vendorIDFromURN = (value: string) => {
  const parts = value.split(":").map((part) => part.trim()).filter(Boolean);
  return parts[parts.length - 1] ?? "";
};

const newUploadID = () => {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return `web-${crypto.randomUUID()}`;
  return `web-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
};

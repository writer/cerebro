"use client";

import { AlertTriangle, CheckCircle2, FileText, ListChecks, RefreshCw, X } from "lucide-react";
import type { ReactNode, RefObject } from "react";

import type { GRCUploadResponse } from "@/lib/grc";
import { displayDate, humanize } from "@/lib/grc";
import { GRC_UPLOAD_ACCEPT, GRC_UPLOAD_FILE_HELP, grcUploadFileError, grcUploadFileSizeLabel } from "@/lib/grc-upload-limits";
import { countLabel } from "@/lib/format";

type UploadInputProps = {
  disabled?: boolean;
  file: File | null;
  inputClassName: string;
  inputRef: RefObject<HTMLInputElement | null>;
  onAccepted: (file: File | null) => void;
  onClear: () => void;
  onRejected: (message: string) => void;
};

export function GRCUploadFileInput({
  disabled = false,
  file,
  inputClassName,
  inputRef,
  onAccepted,
  onClear,
  onRejected,
}: UploadInputProps) {
  const clearFile = () => {
    if (inputRef.current) inputRef.current.value = "";
    onClear();
  };

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept={GRC_UPLOAD_ACCEPT}
        disabled={disabled}
        onChange={(event) => {
          const selected = event.currentTarget.files?.[0] ?? null;
          const fileError = grcUploadFileError(selected);
          if (fileError) {
            event.currentTarget.value = "";
            onRejected(fileError);
            return;
          }
          onAccepted(selected);
        }}
        className={inputClassName}
      />
      <span className="mt-1 block text-[12px] normal-case tracking-normal text-[var(--text-muted)]">{GRC_UPLOAD_FILE_HELP}</span>
      {file && (
        <div className="mt-2 flex min-h-9 items-center justify-between gap-2 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-2.5 py-1.5 text-[12px] normal-case tracking-normal text-[var(--text-secondary)]">
          <span className="flex min-w-0 items-center gap-2">
            <FileText className="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" aria-hidden="true" />
            <span className="truncate font-medium text-[var(--text-primary)]">{file.name}</span>
            <span className="shrink-0 text-[var(--text-muted)]">{grcUploadFileSizeLabel(file.size)}</span>
          </span>
          <button
            type="button"
            onClick={clearFile}
            title="Clear file"
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-[var(--text-muted)] transition hover:bg-white hover:text-[var(--text-primary)]"
          >
            <X className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>
      )}
    </>
  );
}

export function GRCUploadProgress({ onCancel }: { onCancel: () => void }) {
  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[13px] text-[var(--text-secondary)]">
      <span className="inline-flex items-center gap-2">
        <RefreshCw className="h-3.5 w-3.5 animate-spin text-[var(--text-muted)]" aria-hidden="true" />
        Reducto is parsing the document and extracting structured fields.
      </span>
      <button type="button" onClick={onCancel} className="text-[12px] font-semibold text-[var(--primary)] hover:text-[var(--primary-hover)]">
        Cancel upload
      </button>
    </div>
  );
}

export function GRCUploadErrorActions({
  canRetry,
  error,
  onRetry,
}: {
  canRetry: boolean;
  error: string;
  onRetry: () => void;
}) {
  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[13px] font-medium text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300">
      <span className="inline-flex items-center gap-2">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        {error}
      </span>
      {canRetry && (
        <button type="button" onClick={onRetry} className="text-[12px] font-semibold text-red-700 hover:text-red-900 dark:text-red-200 dark:hover:text-red-100">
          Retry upload
        </button>
      )}
    </div>
  );
}

export function GRCUploadReceipt({
  actions,
  upload,
}: {
  actions?: ReactNode;
  upload: GRCUploadResponse;
}) {
  const fields = uploadFieldRows(upload);
  const eventCount = upload.events?.length ?? 0;
  const reviewItems = (upload.review_items ?? []).filter((item) => item.reason || item.action || item.field);
  const qualityChecks = (upload.quality_checks ?? []).filter((check) => check.id || check.message);
  const matchHints = (upload.entity_match_hints ?? []).filter((hint) => hint.match_key);
  const parseChunks = upload.parse_artifact?.chunks ?? [];
  const parsePreview = upload.parse_artifact?.text_preview || upload.text_preview;
  const projectionStatus = upload.projection_status || upload.status || (eventCount > 0 ? "projected" : "accepted");
  const reviewState = upload.review_state || (reviewItems.length > 0 ? "needs_review" : "ready_to_project");
  const qualityStatus = upload.quality_status || (qualityChecks.some((check) => check.status === "needs_review") ? "needs_review" : "passed");
  const hasProjectionWarning = Boolean(upload.projection_failures && upload.projection_failures > 0);
  const hasReviewWarning = reviewState === "needs_review" || reviewItems.length > 0;
  const StatusIcon = hasProjectionWarning || hasReviewWarning ? AlertTriangle : CheckCircle2;
  return (
    <div className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-3 py-3 text-[13px] text-[var(--text-primary)]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2 font-semibold">
            <StatusIcon className={`h-4 w-4 shrink-0 ${hasProjectionWarning || hasReviewWarning ? "text-amber-600" : "text-emerald-600"}`} aria-hidden="true" />
            <span className="truncate">Uploaded {upload.file_name}.</span>
          </div>
          <div className="mt-1 text-[12px] text-[var(--text-secondary)]">
            {countLabel(eventCount, "event")} recorded. {parseDetail(upload, fields.length)}
            {reviewItems.length > 0 ? ` ${countLabel(reviewItems.length, "review item")} open.` : ""}
          </div>
        </div>
        {actions}
      </div>

      <div className="mt-3 grid gap-2 md:grid-cols-4">
        <ReceiptMetric label="Parse" value={humanize(upload.parse_status || "parsed")} />
        <ReceiptMetric label="Quality" value={humanize(qualityStatus)} warning={qualityStatus !== "passed"} />
        <ReceiptMetric label="Review" value={humanize(reviewState)} warning={hasReviewWarning} />
        <ReceiptMetric label="Projection" value={humanize(projectionStatus)} warning={hasProjectionWarning} />
        <ReceiptMetric label="Job" value={upload.job?.id ? `${humanize(upload.job.status || "recorded")} ${shortJobID(upload.job.id)}` : displayDate(upload.generated_at)} />
      </div>

      {upload.structured_summary && (
        <div className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5 text-[var(--text-primary)]">
          <div className="mb-1 font-semibold">Structured summary</div>
          {upload.structured_summary}
        </div>
      )}

      {reviewItems.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Review items ({reviewItems.length})</summary>
          <ul className="mt-2 grid gap-2">
            {reviewItems.map((item, index) => (
              <li key={item.id || `${item.record_id}-${item.field}-${index}`} className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] text-amber-950 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-100">
                <div className="font-semibold">{item.reason || humanize(item.field || "review item")}</div>
                {item.action && <div className="mt-1">{item.action}</div>}
                <div className="mt-1 text-amber-800 dark:text-amber-200">
                  {[item.record_kind && humanize(item.record_kind), item.record_id, item.field && humanize(item.field)].filter(Boolean).join(" / ")}
                </div>
              </li>
            ))}
          </ul>
        </details>
      )}

      {fields.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Extracted fields ({fields.length})</summary>
          <dl className="mt-2 grid gap-2 md:grid-cols-2">
            {fields.map((field, index) => (
              <div key={`${field.name}-${index}`} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
                <dt className="text-[11px] font-semibold text-[var(--text-secondary)]">{field.label}</dt>
                <dd className="mt-1 break-words text-[12px] leading-5">{field.value}</dd>
                {field.meta && <dd className="mt-1 text-[11px] text-[var(--text-muted)]">{field.meta}</dd>}
                {field.sourceSnippet && <dd className="mt-1 max-h-16 overflow-auto text-[11px] leading-5 text-[var(--text-secondary)]">{field.sourceSnippet}</dd>}
              </div>
            ))}
          </dl>
        </details>
      )}

      {qualityChecks.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Quality checks ({qualityChecks.length})</summary>
          <ul className="mt-2 grid gap-2">
            {qualityChecks.map((check, index) => (
              <li key={check.id || index} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                <div className="flex flex-wrap items-center gap-2 font-semibold">
                  <span>{humanize(check.id || "quality check")}</span>
                  {check.status && <span className={check.status === "passed" ? "text-emerald-700" : "text-amber-700"}>{humanize(check.status)}</span>}
                </div>
                {check.message && <div className="mt-1 text-[var(--text-secondary)]">{check.message}</div>}
                {check.action && <div className="mt-1 text-[var(--text-muted)]">{check.action}</div>}
              </li>
            ))}
          </ul>
        </details>
      )}

      {parsePreview && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Parsed text preview</summary>
          <p className="mt-2 max-h-28 overflow-auto rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px] leading-5">
            {parsePreview}
          </p>
        </details>
      )}

      {parseChunks.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Parser chunks ({parseChunks.length})</summary>
          <ul className="mt-2 grid gap-2">
            {parseChunks.map((chunk) => (
              <li key={`${chunk.index}-${chunk.page ?? 0}`} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                <div className="mb-1 font-semibold text-[var(--text-secondary)]">
                  Chunk {chunk.index}{chunk.page ? `, page ${chunk.page}` : ""}
                </div>
                <div className="max-h-20 overflow-auto leading-5">{chunk.text_preview}</div>
              </li>
            ))}
          </ul>
        </details>
      )}

      {matchHints.length > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Match hints ({matchHints.length})</summary>
          <ul className="mt-2 grid gap-2 md:grid-cols-2">
            {matchHints.map((hint, index) => (
              <li key={`${hint.record_id}-${hint.match_key}-${index}`} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                <div className="break-words font-mono text-[11px] text-[var(--text-primary)]">{hint.match_key}</div>
                <div className="mt-1 text-[var(--text-muted)]">{[hint.record_kind && humanize(hint.record_kind), hint.strategy && humanize(hint.strategy)].filter(Boolean).join(" / ")}</div>
              </li>
            ))}
          </ul>
        </details>
      )}

      {eventCount > 0 && (
        <details className="mt-3">
          <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Created records ({eventCount})</summary>
          <ul className="mt-2 grid gap-2">
            {upload.events.map((event) => (
              <li key={event.event_id} className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[12px]">
                <div className="flex flex-wrap items-center gap-2 font-semibold">
                  <ListChecks className="h-3.5 w-3.5 text-[var(--text-secondary)]" aria-hidden="true" />
                  <span>{humanize(event.event_kind)}</span>
                  {event.record_id && <span className="font-mono text-[11px] text-[var(--text-muted)]">{event.record_id}</span>}
                </div>
                <div className="mt-1 break-all font-mono text-[11px] text-[var(--text-muted)]">{event.record_urn || event.event_id}</div>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export function GRCUploadHistoryList({ uploads }: { uploads: GRCUploadResponse[] }) {
  if (uploads.length <= 1) return null;
  return (
    <details className="mt-3 rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2 text-[13px] text-[var(--text-secondary)]">
      <summary className="cursor-pointer font-semibold text-[var(--text-primary)]">Recent uploads ({uploads.length})</summary>
      <ul className="mt-2 grid gap-2">
        {uploads.slice(1).map((upload) => (
          <li key={upload.upload_id} className="flex flex-wrap items-center justify-between gap-2 border-t border-[color:var(--border)] pt-2 text-[12px]">
            <span className="min-w-0 truncate font-medium text-[var(--text-primary)]">{upload.file_name}</span>
            <span className="text-[var(--text-muted)]">{humanize(upload.status || upload.parse_status || "parsed")}, {countLabel(upload.events?.length ?? 0, "event")}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

function ReceiptMetric({
  label,
  value,
  warning = false,
}: {
  label: string;
  value: ReactNode;
  warning?: boolean;
}) {
  return (
    <div className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-3 py-2">
      <div className="text-[11px] font-semibold text-[var(--text-secondary)]">{label}</div>
      <div className={`mt-1 break-words text-[12px] font-semibold ${warning ? "text-amber-700 dark:text-amber-300" : "text-[var(--text-primary)]"}`}>{value}</div>
    </div>
  );
}

type UploadFieldRow = {
  name: string;
  label: string;
  value: string;
  meta?: string;
  sourceSnippet?: string;
};

function uploadFieldRows(upload: GRCUploadResponse): UploadFieldRow[] {
  const extracted = (upload.extracted_fields ?? [])
    .filter((field) => field.name && field.value)
    .map((field) => ({
      name: field.name ?? "field",
      label: humanize(field.name ?? "field"),
      value: field.value ?? "",
      meta: fieldMeta(field.source, field.confidence, field.review_state),
      sourceSnippet: field.source_snippet,
    }));
  if (extracted.length > 0) return extracted;
  return (upload.structured_fields ?? [])
    .filter((field) => field.key && field.value)
    .map((field) => ({
      name: field.key ?? "field",
      label: field.label || humanize(field.key || "field"),
      value: field.value ?? "",
    }));
}

function fieldMeta(source?: string, confidence?: number, reviewState?: string) {
  return [
    source ? `Source: ${humanize(source)}` : "",
    typeof confidence === "number" ? `Confidence: ${Math.round(confidence * 100)}%` : "",
    reviewState ? `Review: ${humanize(reviewState)}` : "",
  ].filter(Boolean).join(" / ");
}

function shortJobID(jobID: string) {
  return jobID.length > 12 ? jobID.slice(0, 12) : jobID;
}

function parseDetail(upload: GRCUploadResponse, fieldCount: number) {
  const details = [];
  if (upload.page_count) details.push(countLabel(upload.page_count, "page"));
  if (upload.chunk_count) details.push(countLabel(upload.chunk_count, "chunk"));
  if (fieldCount > 0) details.push(countLabel(fieldCount, "field"));
  return details.length > 0 ? `${details.join(", ")} parsed.` : `${humanize(upload.parse_status || "parsed")}.`;
}

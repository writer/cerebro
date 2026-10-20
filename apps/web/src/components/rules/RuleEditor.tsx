"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Badge } from "@/components/grc/Primitives";
import { useApiKey } from "@/components/providers";
import { RuleChip } from "@/components/rules/RuleDetail";
import { fetchCerebro } from "@/lib/cerebro-client";
import {
  convertRuleDocument,
  customRulePath,
  hasBlockingIssues,
  type RuleCatalogDetail,
  type RuleFormat,
  ruleDomains,
  ruleIDFromDocument,
  rulePostureLabels,
  type RuleTestResult,
  ruleTemplates,
  RULE_TEST_PATH,
  RULE_VALIDATE_PATH,
  type RuleValidationResult,
} from "@/lib/finding-rules";
import { useDebouncedValue } from "@/lib/grc-client";

const textareaClass =
  "w-full rounded-md border border-[color:var(--border)] bg-[var(--surface)] p-3 font-mono text-[12px] leading-relaxed text-[var(--text-primary)] outline-none focus:border-[color:var(--primary)]";

const errorMessage = (status: number, data: unknown) => {
  if (data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string") {
    return (data as { error: string }).error;
  }
  if (status === 403) return "You do not have permission to change finding rules.";
  return `Request failed (HTTP ${status}).`;
};

type EditorProps = {
  mode: "create" | "edit";
  initialContent: string;
  initialSample?: Record<string, unknown>;
  tenantID: string;
  onCancel: () => void;
  onSaved: (rule: RuleCatalogDetail) => void;
  onDeleted?: (ruleID: string) => void;
};

export function RuleEditor({ mode, initialContent, initialSample, tenantID, onCancel, onSaved, onDeleted }: EditorProps) {
  const { apiKey } = useApiKey();
  const [format, setFormat] = useState<RuleFormat>("yaml");
  const [content, setContent] = useState(initialContent);
  const [sample, setSample] = useState(() => JSON.stringify(initialSample ?? {}, null, 2));
  const [notice, setNotice] = useState<string | null>(null);
  const [rejected, setRejected] = useState<{ content: string; result: RuleValidationResult } | null>(null);
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const originalID = mode === "edit" ? ruleIDFromDocument(initialContent, "yaml") : "";

  const debouncedContent = useDebouncedValue(content, 500);
  const debouncedFormat = useDebouncedValue(format, 500);

  const validationQuery = useQuery<RuleValidationResult, Error>({
    enabled: debouncedContent.trim() !== "",
    queryKey: ["finding-rule-validate", apiKey ?? "", debouncedFormat, debouncedContent],
    queryFn: async ({ signal }) => {
      const response = await fetchCerebro<RuleValidationResult>(RULE_VALIDATE_PATH, apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: debouncedFormat, content: debouncedContent }),
        signal,
      });
      if (!response.ok || !response.data || typeof response.data !== "object") {
        throw new Error(errorMessage(response.status, response.data));
      }
      return response.data;
    },
    retry: false,
    staleTime: Infinity,
  });
  const pendingDebounce = debouncedContent !== content || debouncedFormat !== format;
  const validating = pendingDebounce || validationQuery.isFetching;

  const switchFormat = (next: RuleFormat) => {
    if (next === format) return;
    const converted = convertRuleDocument(content, format, next);
    if (!converted.ok) {
      setNotice(converted.error);
      return;
    }
    setNotice(null);
    setFormat(next);
    setContent(converted.content);
  };

  const applyTemplate = (templateID: string) => {
    const template = ruleTemplates.find((item) => item.id === templateID);
    if (!template) return;
    const converted = convertRuleDocument(template.document, "yaml", format);
    setContent(converted.ok ? converted.content : template.document);
    setSample(JSON.stringify(template.sampleResource, null, 2));
    setTestResult(null);
  };

  const runTest = async () => {
    let resource: Record<string, unknown>;
    try {
      const parsed: unknown = sample.trim() ? JSON.parse(sample) : {};
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("The sample resource must be a JSON object.");
      resource = parsed as Record<string, unknown>;
    } catch (error) {
      setTestResult({ valid: true, issues: [], evaluated: false, matched: false, message: error instanceof Error ? error.message : String(error) });
      return;
    }
    setTesting(true);
    try {
      const response = await fetchCerebro<RuleTestResult>(RULE_TEST_PATH, apiKey, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format, content, resource }),
      });
      if (response.ok && response.data) {
        setTestResult(response.data);
      } else {
        setRequestError(errorMessage(response.status, response.data));
      }
    } finally {
      setTesting(false);
    }
  };

  const ruleID = ruleIDFromDocument(content, format);
  const idChanged = mode === "edit" && ruleID !== "" && ruleID !== originalID;
  const currentValidation = !content.trim()
    ? null
    : rejected?.content === content
      ? rejected.result
      : pendingDebounce ? null : validationQuery.data ?? null;
  const blocking = !currentValidation || !currentValidation.valid || hasBlockingIssues(currentValidation.issues);

  const save = async () => {
    if (!ruleID) {
      setRequestError("Set metadata.id before saving.");
      return;
    }
    setSaving(true);
    setRequestError(null);
    try {
      const response = await fetchCerebro<RuleCatalogDetail | RuleValidationResult>(customRulePath(ruleID), apiKey, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...(tenantID ? { tenant_id: tenantID } : {}), format, content }),
      });
      const payload = response.data && typeof response.data === "object" ? response.data : null;
      if (response.ok && payload && "id" in payload) {
        onSaved(payload);
        return;
      }
      if (response.status === 422 && payload && "issues" in payload) {
        setRejected({ content, result: payload });
        return;
      }
      setRequestError(errorMessage(response.status, response.data));
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!originalID || !onDeleted) return;
    if (!window.confirm(`Delete custom rule ${originalID}? Findings it already opened are not removed.`)) return;
    setSaving(true);
    setRequestError(null);
    try {
      const response = await fetchCerebro(customRulePath(originalID, tenantID), apiKey, { method: "DELETE" });
      if (response.ok) {
        onDeleted(originalID);
        return;
      }
      setRequestError(errorMessage(response.status, response.data));
    } finally {
      setSaving(false);
    }
  };

  const preview = currentValidation?.preview;
  const issues = currentValidation?.issues ?? [];

  return (
    <div className="space-y-4" data-rule-editor={mode}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[16px] font-semibold text-[var(--text-primary)]">
            {mode === "create" ? "New custom rule" : `Edit ${originalID}`}
          </h2>
          <p className="text-[12px] text-[var(--text-muted)]">
            PolicyFindingRule document. Saved rules are stored as canonical YAML.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {mode === "create" && (
            <select
              aria-label="Start from a template"
              defaultValue=""
              onChange={(event) => {
                applyTemplate(event.target.value);
                event.target.value = "";
              }}
              className="rounded-md border border-[color:var(--border)] bg-[var(--surface)] px-2 py-1.5 text-[12px] text-[var(--text-primary)]"
            >
              <option value="" disabled>Start from a template</option>
              {ruleTemplates.map((template) => (
                <option key={template.id} value={template.id}>{template.label}</option>
              ))}
            </select>
          )}
          <div role="group" aria-label="Document format" className="inline-flex overflow-hidden rounded-md border border-[color:var(--border)]">
            {(["yaml", "json"] as const).map((option) => (
              <button
                key={option}
                type="button"
                aria-pressed={format === option}
                onClick={() => switchFormat(option)}
                className={`px-3 py-1.5 text-[12px] font-medium ${format === option ? "bg-[var(--primary)] text-white" : "bg-[var(--surface)] text-[var(--text-muted)]"}`}
              >
                {option.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {notice && <div className="rounded-md bg-[var(--tone-warning-soft)] px-3 py-2 text-[12px] text-[var(--tone-warning)]">{notice}</div>}

      <textarea
        aria-label={`Rule document (${format.toUpperCase()})`}
        value={content}
        onChange={(event) => setContent(event.target.value)}
        spellCheck={false}
        rows={24}
        className={textareaClass}
      />

      <div className="space-y-2" aria-live="polite">
        <div className="flex items-center gap-2 text-[12px]">
          {validating ? (
            <span className="text-[var(--text-muted)]">Validating...</span>
          ) : currentValidation ? (
            currentValidation.valid ? (
              <span className="font-medium text-[var(--tone-success)]">Valid{issues.length > 0 ? ` with ${issues.length} warning${issues.length === 1 ? "" : "s"}` : ""}</span>
            ) : (
              <span className="font-medium text-[var(--tone-danger)]">Invalid</span>
            )
          ) : (
            <span className="text-[var(--text-muted)]">Write or paste a rule to validate it.</span>
          )}
        </div>
        {issues.length > 0 && (
          <ul className="space-y-1 text-[12px]">
            {issues.map((issue, index) => (
              <li
                key={`${issue.severity}-${index}`}
                className={issue.severity === "error" ? "text-[var(--tone-danger)]" : "text-[var(--tone-warning)]"}
              >
                <span className="font-semibold uppercase">{issue.severity}</span> {issue.message}
              </li>
            ))}
          </ul>
        )}
        {idChanged && (
          <div className="text-[12px] text-[var(--tone-warning)]">
            Changing metadata.id saves a new rule; the original {originalID} stays until you delete it.
          </div>
        )}
      </div>

      {preview && (
        <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[12px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge value={preview.severity || "info"} tone="severity" />
            <RuleChip tone="primary">{ruleDomains.find((domain) => domain.id === preview.domain)?.label ?? preview.domain}</RuleChip>
            <RuleChip>{rulePostureLabels[preview.posture] ?? preview.posture}</RuleChip>
            {preview.provider && <RuleChip>{preview.provider}</RuleChip>}
          </div>
          {preview.attack_description && <p className="mt-2 text-[var(--text-primary)]">{preview.attack_description}</p>}
          {preview.remediation && <p className="mt-1 text-[var(--text-muted)]">Remediation: {preview.remediation}</p>}
        </div>
      )}

      <details className="rounded-lg border border-[color:var(--border)] p-3" open={mode === "create"}>
        <summary className="cursor-pointer text-[12px] font-semibold text-[var(--text-primary)]">Test against a sample resource</summary>
        <div className="mt-3 space-y-2">
          <textarea
            aria-label="Sample resource (JSON)"
            value={sample}
            onChange={(event) => setSample(event.target.value)}
            spellCheck={false}
            rows={6}
            className={textareaClass}
          />
          <div className="flex items-center gap-3">
            <button type="button" onClick={() => void runTest()} disabled={testing || !content.trim()} className="secondary-button px-3 py-1.5 text-[12px] disabled:opacity-50">
              {testing ? "Testing..." : "Run test"}
            </button>
            {testResult && (
              <span
                data-rule-test-result={testResult.evaluated ? (testResult.matched ? "match" : "no-match") : "not-evaluated"}
                className={`text-[12px] ${testResult.evaluated ? (testResult.matched ? "text-[var(--tone-danger)]" : "text-[var(--tone-success)]") : "text-[var(--text-muted)]"}`}
              >
                {testResult.message}
              </span>
            )}
          </div>
        </div>
      </details>

      {(requestError ?? validationQuery.error?.message) && <div className="rounded-md bg-[var(--tone-danger-soft)] px-3 py-2 text-[12px] text-[var(--tone-danger)]">{requestError ?? validationQuery.error?.message}</div>}

      <div className="flex items-center justify-between gap-2 border-t border-[color:var(--border)] pt-3">
        <div>
          {mode === "edit" && onDeleted && (
            <button type="button" onClick={() => void remove()} disabled={saving} className="px-3 py-1.5 text-[12px] font-medium text-[var(--tone-danger)] disabled:opacity-50">
              Delete rule
            </button>
          )}
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={onCancel} className="secondary-button px-3 py-1.5 text-[12px]">Cancel</button>
          <button
            type="button"
            onClick={() => void save()}
            disabled={saving || validating || blocking}
            className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save rule"}
          </button>
        </div>
      </div>
    </div>
  );
}

"use client";

import type { ReactNode } from "react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock } from "@/components/grc/Primitives";
import {
  type RuleCatalogDetail,
  ruleDetectionLabels,
  ruleDomains,
  ruleEvaluationLabels,
  ruleOriginLabels,
  rulePostureLabels,
} from "@/lib/finding-rules";

export function RuleChip({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "primary" | "warning" }) {
  const toneClass =
    tone === "primary"
      ? "border-[color:var(--primary)] text-[var(--primary)]"
      : tone === "warning"
        ? "border-[color:var(--tone-warning)] bg-[var(--tone-warning-soft)] text-[var(--tone-warning)]"
        : "border-[color:var(--border)] text-[var(--text-muted)]";
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${toneClass}`}>
      {children}
    </span>
  );
}

const domainLabel = (domain: string) => ruleDomains.find((item) => item.id === domain)?.label ?? domain;

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-1.5">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{title}</h3>
      <div className="text-[13px] leading-relaxed text-[var(--text-primary)]">{children}</div>
    </section>
  );
}

function CodeBlock({ value }: { value: string }) {
  return (
    <pre className="max-h-96 overflow-auto whitespace-pre rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 font-mono text-[12px] leading-relaxed text-[var(--text-primary)]">
      {value}
    </pre>
  );
}

const alertingExplanation = (rule: RuleCatalogDetail) => {
  switch (rule.detection) {
    case "posture":
      return "Probing: evaluated against the current state of each collected resource. The finding resolves when the resource no longer matches.";
    case "event":
      return "Event stream: evaluated as source events arrive, then held open only while the risky state persists.";
    default:
      return "Correlation: opens when related facts or findings line up across sources in the security graph.";
  }
};

export function RuleDetailView({
  rule,
  loading,
  error,
  onRetry,
  onEdit,
  onDuplicate,
}: {
  rule: RuleCatalogDetail | null;
  loading: boolean;
  error: string | null;
  onRetry: () => void;
  onEdit?: () => void;
  onDuplicate?: () => void;
}) {
  if (loading && !rule) return <LoadingBlock label="Loading rule..." />;
  if (error && !rule) return <ErrorBlock error={error} onRetry={onRetry} />;
  if (!rule) return <EmptyBlock label="Select a rule to see its attack description, remediation, and logic." />;

  const steps = rule.remediation_steps ?? [];
  const controls = rule.control_refs ?? [];
  const mitre = rule.mitre_attack ?? [];
  const conditions = rule.conditions ?? [];

  return (
    <div className="space-y-5" data-rule-detail={rule.id}>
      <div className="space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-[16px] font-semibold text-[var(--text-primary)]">{rule.name || rule.id}</h2>
            <div className="mt-0.5 break-all font-mono text-[12px] text-[var(--text-muted)]">{rule.id}</div>
          </div>
          <div className="flex shrink-0 gap-2">
            {onDuplicate && (
              <button type="button" onClick={onDuplicate} className="secondary-button px-3 py-1.5 text-[12px]">
                Duplicate as custom
              </button>
            )}
            {onEdit && (
              <button type="button" onClick={onEdit} className="rounded-md bg-[var(--primary)] px-3 py-1.5 text-[12px] font-medium text-white">
                Edit
              </button>
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge value={rule.severity || "info"} tone="severity" />
          <RuleChip tone="primary">{domainLabel(rule.domain)}</RuleChip>
          <RuleChip>{rulePostureLabels[rule.posture] ?? rule.posture}</RuleChip>
          {rule.provider && <RuleChip>{rule.provider}</RuleChip>}
          <RuleChip>{ruleOriginLabels[rule.origin] ?? rule.origin}</RuleChip>
          {!rule.enabled && <RuleChip tone="warning">Disabled</RuleChip>}
        </div>
      </div>

      {(rule.description || rule.summary) && <Section title="Description">{rule.description || rule.summary}</Section>}

      <Section title="Attack description">
        {rule.attack_description || <span className="text-[var(--text-muted)]">No attack narrative is authored for this rule.</span>}
      </Section>

      <Section title="Remediation">
        {rule.remediation ? <p>{rule.remediation}</p> : <span className="text-[var(--text-muted)]">No remediation is authored for this rule.</span>}
        {steps.length > 0 && (
          <ol className="mt-2 list-decimal space-y-1 pl-5">
            {steps.map((step) => <li key={step}>{step}</li>)}
          </ol>
        )}
        {rule.runbook && rule.runbook !== rule.remediation && (
          <p className="mt-2 text-[12px] text-[var(--text-muted)]">Runbook: {rule.runbook}</p>
        )}
      </Section>

      <Section title="Alerting">
        <p>{alertingExplanation(rule)}</p>
        <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12px]">
          <dt className="text-[var(--text-muted)]">Detection</dt>
          <dd>{ruleDetectionLabels[rule.detection] ?? rule.detection}</dd>
          <dt className="text-[var(--text-muted)]">Evaluation</dt>
          <dd>{ruleEvaluationLabels[rule.evaluation] ?? rule.evaluation}</dd>
          {rule.resource_type && (
            <>
              <dt className="text-[var(--text-muted)]">Resource</dt>
              <dd className="font-mono">{rule.resource_type}</dd>
            </>
          )}
          {rule.lifecycle && (
            <>
              <dt className="text-[var(--text-muted)]">Lifecycle</dt>
              <dd>{rule.lifecycle}</dd>
            </>
          )}
          {(rule.fingerprint_fields ?? []).length > 0 && (
            <>
              <dt className="text-[var(--text-muted)]">Fingerprint</dt>
              <dd className="font-mono">{(rule.fingerprint_fields ?? []).join(", ")}</dd>
            </>
          )}
          {rule.correlation_window && (
            <>
              <dt className="text-[var(--text-muted)]">Window</dt>
              <dd>{rule.correlation_window}</dd>
            </>
          )}
        </dl>
      </Section>

      {(controls.length > 0 || (rule.frameworks ?? []).length > 0) && (
        <Section title="Compliance mapping">
          <div className="flex flex-wrap gap-1.5">
            {controls.length > 0
              ? controls.map((ref) => (
                <RuleChip key={`${ref.framework}:${ref.control}`}>
                  {ref.framework} {ref.control}
                </RuleChip>
              ))
              : (rule.frameworks ?? []).map((framework) => <RuleChip key={framework}>{framework}</RuleChip>)}
          </div>
        </Section>
      )}

      {(mitre.length > 0 || (rule.mitre_techniques ?? []).length > 0) && (
        <Section title="MITRE ATT&CK">
          <div className="flex flex-wrap gap-1.5">
            {mitre.length > 0
              ? mitre.map((ref) => (
                <RuleChip key={`${ref.tactic}:${ref.technique}`}>
                  {ref.tactic ? `${ref.tactic} · ` : ""}{ref.technique}
                </RuleChip>
              ))
              : (rule.mitre_techniques ?? []).map((technique) => <RuleChip key={technique}>{technique}</RuleChip>)}
          </div>
        </Section>
      )}

      {(rule.false_positives ?? []).length > 0 && (
        <Section title="False positives">
          <ul className="list-disc space-y-1 pl-5">
            {(rule.false_positives ?? []).map((item) => <li key={item}>{item}</li>)}
          </ul>
        </Section>
      )}

      {conditions.length > 0 && (
        <Section title="Conditions (all must match)">
          <CodeBlock value={conditions.join("\n")} />
        </Section>
      )}
      {rule.query && <Section title="SQL query"><CodeBlock value={rule.query} /></Section>}
      {rule.graph_query && <Section title="Graph query"><CodeBlock value={rule.graph_query} /></Section>}
      {(rule.correlated_rule_ids ?? []).length > 0 && (
        <Section title="Correlated rules">
          <div className="flex flex-wrap gap-1.5">
            {(rule.correlated_rule_ids ?? []).map((id) => <RuleChip key={id}>{id}</RuleChip>)}
          </div>
          {(rule.correlation_dimensions ?? []).length > 0 && (
            <p className="mt-2 text-[12px] text-[var(--text-muted)]">Joined on {(rule.correlation_dimensions ?? []).join(", ")}.</p>
          )}
        </Section>
      )}

      {(rule.references ?? []).length > 0 && (
        <Section title="References">
          <ul className="space-y-1">
            {(rule.references ?? []).map((reference) => (
              <li key={reference} className="break-all">
                {/^https?:\/\//.test(reference) ? (
                  <a href={reference} target="_blank" rel="noreferrer" className="text-[var(--primary)] hover:underline">{reference}</a>
                ) : reference}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {rule.document && (
        <details className="group">
          <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">
            Rule document (YAML){rule.source_path ? ` · ${rule.source_path}` : ""}
          </summary>
          <div className="mt-2"><CodeBlock value={rule.document} /></div>
        </details>
      )}

      {(rule.updated_by || rule.created_by) && (
        <div className="text-[12px] text-[var(--text-muted)]">
          {rule.created_by && `Created by ${rule.created_by}`}
          {rule.updated_by && ` · last updated by ${rule.updated_by}`}
          {rule.updated_at && ` on ${new Date(rule.updated_at).toLocaleString()}`}
        </div>
      )}
    </div>
  );
}

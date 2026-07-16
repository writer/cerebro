"use client";

import Link from "next/link";
import { Suspense, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  Database,
  KeyRound,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";

import { CoverageMetadata, CoverageMetadataList } from "@/components/connectors/CoverageMetadata";
import ConnectorSetupForm from "@/components/connectors/ConnectorSetupForm";
import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, PageHeader, Panel, ResultLimitNotice } from "@/components/grc/Primitives";
import { useApiKey } from "@/components/providers";
import { fetchCerebro } from "@/lib/cerebro-client";
import { withQuery } from "@/lib/cerebro-data";
import { connectorPath, connectorResourceTypes, connectorResourceTypeStats } from "@/lib/connector-view";
import {
  ConnectorCatalogEntry,
  ConnectorConnectedContext,
  ConnectorConnectionSummary,
  ConnectorDefinition,
  ConnectorDefinitionPlanResponse,
  ConnectorDefinitionListResponse,
  ConnectorDefinitionResourceFamily,
  ConnectorDetailResponse,
  ConnectorLibraryResponse,
  SourceActivationPromotionPlan,
  connectorDisplayName,
  connectorDepositsPath,
  connectorDefinitionBlockingChecks,
  connectorDefinitionNextStage,
  connectorDefinitionStageLabels,
  connectorDefinitionStages,
  connectorDefinitionStatus,
  connectorRuntimeSurfaceLabel,
  connectorSetupAllowed,
  normalizeCredentialStores,
  sourceActivationPlanCategoryCounts,
  sourceActivationPlanPath,
  sourceActivationPlanStatusLabel,
  sourceRuntimeSyncPath,
} from "@/lib/connectors";
import { useGRCQuery } from "@/lib/grc-client";
import { GRC_DETAIL_LIMIT, GRC_WORKLIST_LIMIT, grcBoundedRows } from "@/lib/grc-list";
import { useQueryParamState } from "@/lib/query-params";

const resourceTypeLabels: Record<string, string> = {
  identity_user: "User identities",
  identity_group: "Groups",
  group_membership: "Group memberships",
  app_entitlement: "App entitlements",
  asset: "Assets",
  cloud_resource: "Cloud resources",
  endpoint_device: "Devices",
  repository: "Repositories",
  deployment: "Deployments",
  finding: "Security findings",
  vulnerability: "Vulnerabilities",
  alert: "Alerts",
  audit_event: "Audit events",
  policy: "Policies",
  compliance_control: "Compliance controls",
  secret: "Secret references",
};

const authModelLabels: Record<string, string> = {
  none: "No sign-in required",
  api_key: "API key",
  bearer_token: "Bearer token",
  basic: "Username and password",
  oauth_client_credentials: "OAuth (client credentials)",
  oauth_authorization_code: "OAuth",
  jwt: "Signed token (JWT)",
};

const storeLabels: Record<string, string> = {
  cerebro_vault: "Cerebro managed vault",
  hashicorp_vault: "HashiCorp Vault",
  aws_secrets_manager: "AWS Secrets Manager",
  infisical: "Infisical",
};

const stageMeaning: Record<string, string> = {
  draft: "You are still describing the source and the data it should bring in.",
  sandbox: "Checked with bounded sample pulls to confirm the data looks right.",
  pilot: "In use with one workspace under visible limits.",
  approved: "Available in your organization's connector library.",
  certified: "Trusted for audit-grade reliance.",
};

const gateLabels: Record<string, string> = {
  definition_validation: "Pass the setup checks",
  sandbox_probe: "Run a sandbox test pull",
  admin_review: "Get an admin to approve",
  pilot_signoff: "Sign off on the pilot",
  certification_review: "Pass certification review",
};

const SOURCE_ACTIVATION_SOURCE_LIMIT = 75;
const SOURCE_ACTIVATION_REVIEW_SCOPE_LIMIT = 24;
const SOURCE_ACTIVATION_CHECK_LIMIT = 24;
const SOURCE_ACTIVATION_BLOCKER_LIMIT = 24;

function humanize(value?: string) {
  if (!value) return "";
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function stageLabel(stage?: string) {
  if (!stage) return "Draft";
  return connectorDefinitionStageLabels[stage as keyof typeof connectorDefinitionStageLabels] ?? humanize(stage);
}

function authModelLabel(model?: string) {
  if (!model) return "Not set";
  return authModelLabels[model] ?? humanize(model);
}

function storeLabel(id: string) {
  return storeLabels[id] ?? humanize(id);
}

function gateLabel(id: string) {
  return gateLabels[id] ?? humanize(id);
}

function planCategoryLabel(category: string) {
  if (category === "source_cdk" || category === "source_activation") return "Activation";
  return humanize(category);
}

function resourceTypeLabel(family: ConnectorDefinitionResourceFamily) {
  const template = family.projection?.template;
  if (template && resourceTypeLabels[template]) return resourceTypeLabels[template];
  return family.label || humanize(family.id);
}

function isMapped(family: ConnectorDefinitionResourceFamily) {
  return Boolean(family.projection?.template);
}

function distinctResourceTypes(families: ConnectorDefinitionResourceFamily[]) {
  return new Set(families.map((family) => family.projection?.template).filter(Boolean) as string[]);
}

function readinessWord(definition?: ConnectorDefinition) {
  const status = connectorDefinitionStatus(definition);
  if (status === "blocked") return "Not ready yet";
  if (status === "warning") return "Almost ready";
  if (status === "ready") return definition?.stage === "certified" ? "Trusted" : "Ready to advance";
  return "Not set up yet";
}

function readinessTone(definition?: ConnectorDefinition): "blocked" | "warning" | "ready" | "empty" {
  const status = connectorDefinitionStatus(definition);
  if (status === "blocked") return "blocked";
  if (status === "warning") return "warning";
  if (status === "ready") return "ready";
  return "empty";
}

function toneBorder(tone: string) {
  if (tone === "blocked") return "border-l-red-500";
  if (tone === "warning") return "border-l-amber-500";
  if (tone === "ready") return "border-l-emerald-500";
  return "border-l-[color:var(--border-strong)]";
}

function nextStepForOperator(definition?: ConnectorDefinition) {
  if (!definition) return "Pick one of your sources to see what it collects and whether it is ready to trust.";
  const checks = definition.validation?.checks ?? [];
  const blocking = checks.filter((check) => check.blocking || check.status === "blocked");
  if (blocking.length > 0) return blocking[0].next_action || "Finish the required setup before this source can be trusted.";
  const warnings = checks.filter((check) => check.status === "warning");
  const next = connectorDefinitionNextStage(definition);
  if (next === "sandbox") return "Run a sandbox test pull to confirm real data flows in correctly.";
  if (next === "pilot") return "Pilot this source with one workspace before rolling it out widely.";
  if (next === "approved") return "Request approval to add this source to your organization's library.";
  if (next === "certified") return "Request certification so you can rely on this source for audit evidence.";
  if (warnings.length > 0) return "Review the open items below, then you can rely on this source.";
  return "This source is certified and ready to rely on for audit evidence.";
}

function builderHref(definition: ConnectorDefinition) {
  const params = new URLSearchParams();
  if (definition.tenant_id) params.set("tenant_id", definition.tenant_id);
  if (definition.id) params.set("definition_id", definition.id);
  const query = params.toString();
  return `/connectors/builder${query ? `?${query}` : ""}`;
}

function KeyStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className="mt-1 text-[15px] font-semibold text-[var(--text-primary)]">{value}</div>
    </div>
  );
}

function SafetyRow({ ok, title, detail }: { ok?: boolean; title: string; detail: string }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
      {ok ? (
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
      ) : (
        <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
      )}
      <div>
        <div className="text-[13px] font-semibold text-[var(--text-primary)]">{title}</div>
        <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{detail}</div>
      </div>
    </div>
  );
}

function ReadinessHero({ definition }: { definition?: ConnectorDefinition }) {
  const tone = readinessTone(definition);
  const families = definition?.resource_families ?? [];
  const resourceTypeCount = distinctResourceTypes(families).size || families.length;
  const blocking = definition ? connectorDefinitionBlockingChecks(definition) : 0;
  return (
    <section className={`surface-panel overflow-hidden border-l-[4px] p-0 ${toneBorder(tone)}`}>
      <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_minmax(280px,0.36fr)]">
        <div className="p-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge value={readinessWord(definition)} />
            {definition && <Badge value={stageLabel(definition.stage)} />}
          </div>
          <h2 className="mt-4 text-2xl font-semibold tracking-tight text-[var(--text-primary)]">
            {definition ? `Can you trust ${definition.display_name} yet?` : "Choose a source to review"}
          </h2>
          <p className="mt-2 max-w-3xl text-[13px] leading-6 text-[var(--text-secondary)]">
            {definition?.validation?.summary ||
              "This view shows what a source will collect, the access it needs, and whether it is ready to trust for your security and compliance program."}
          </p>
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--primary)]" />
            <div className="text-[13px] leading-5 text-[var(--text-primary)]">{nextStepForOperator(definition)}</div>
          </div>
          {definition && (
            <div className="mt-5 flex flex-wrap gap-2">
              <Link
                href={builderHref(definition)}
                className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]"
              >
                Edit this source
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>
          )}
        </div>
        <div className="border-t border-[color:var(--border)] bg-[var(--surface-muted)] p-5 lg:border-l lg:border-t-0">
          <div className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-muted)]">Trust snapshot</div>
          <div className="mt-3 space-y-3">
            <KeyStat label="Resource types collected" value={definition ? resourceTypeCount : "-"} />
            <KeyStat label="Access" value="Read-only" />
            <KeyStat label="Items to resolve" value={definition ? blocking : "-"} />
          </div>
        </div>
      </div>
    </section>
  );
}

function TrustLadder({ definition }: { definition?: ConnectorDefinition }) {
  const currentIndex = definition ? connectorDefinitionStages.indexOf(definition.stage as (typeof connectorDefinitionStages)[number]) : -1;
  const next = definition ? connectorDefinitionNextStage(definition) : undefined;
  const gates = definition?.promotion?.required_gates ?? [];
  return (
    <Panel title="Trust ladder" action={definition ? <Badge value={stageLabel(definition.stage)} /> : undefined}>
      <ol className="space-y-2">
        {connectorDefinitionStages.map((stage, index) => {
          const done = currentIndex > index;
          const current = currentIndex === index;
          return (
            <li
              key={stage}
              className={`flex items-start gap-3 rounded-lg border p-3 ${
                current ? "border-[color:var(--ring)] bg-[var(--primary-soft)]" : "border-[color:var(--border)] bg-[var(--surface)]"
              }`}
            >
              <div
                className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ${
                  done
                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-200"
                    : current
                      ? "bg-[var(--primary)] text-white"
                      : "bg-[var(--surface-muted)] text-[var(--text-muted)]"
                }`}
              >
                {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : index + 1}
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">{stageLabel(stage)}</span>
                  {current && <Badge value="You are here" />}
                </div>
                <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{stageMeaning[stage]}</div>
              </div>
            </li>
          );
        })}
      </ol>
      {next && gates.length > 0 && (
        <div className="mt-4 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">To reach {stageLabel(next)}:</div>
          <ul className="mt-2 space-y-1">
            {gates.map((gate) => (
              <li key={gate} className="flex items-start gap-2 text-[12px] leading-5 text-[var(--text-secondary)]">
                <ArrowRight className="mt-0.5 h-3 w-3 shrink-0 text-[var(--primary)]" />
                <span>{gateLabel(gate)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}

function DataCoveragePanel({ definition }: { definition?: ConnectorDefinition }) {
  const families = definition?.resource_families ?? [];
  const boundedFamilies = grcBoundedRows({ rows: families, limit: GRC_DETAIL_LIMIT });
  const typeCount = distinctResourceTypes(families).size || families.length;
  return (
    <Panel title="What this source collects" action={<Database className="h-4 w-4 text-[var(--primary)]" />}>
      {families.length === 0 ? (
        <EmptyBlock label={definition ? "No resource types are defined for this source yet." : "Choose a source to see what it collects."} />
      ) : (
        <>
          <p className="text-[13px] leading-6 text-[var(--text-muted)]">
            Collects {typeCount} resource type{typeCount === 1 ? "" : "s"} across {families.length} endpoint{families.length === 1 ? "" : "s"}, added to
            your security graph for findings, evidence, and audit.
          </p>
          <ResultLimitNotice className="mt-3" loaded={boundedFamilies.rows.length} meta={boundedFamilies.meta} limit={GRC_DETAIL_LIMIT} noun="resource families" />
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            {boundedFamilies.rows.map((family) => (
              <div key={family.id} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 truncate text-[13px] font-semibold text-[var(--text-primary)]">
                    {family.label || humanize(family.id)}
                  </div>
                  <Badge value={family.default_enabled === false ? "Optional" : "On"} />
                </div>
                <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
                  Appears as {resourceTypeLabel(family)}
                  {isMapped(family) ? "." : " (stored, not yet mapped to resource types)."}
                </div>
                {family.coverage && family.coverage.length > 0 && (
                  <div className="mt-3 border-t border-[color:var(--border)] pt-2">
                    <CoverageMetadataList items={family.coverage} compact showNotes />
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </Panel>
  );
}

function AccessSafetyPanel({ definition }: { definition?: ConnectorDefinition }) {
  const auth = definition?.auth;
  const credFields = auth?.credential_fields ?? [];
  const referenceOnly = Boolean(auth?.requires_references) || (credFields.length > 0 && credFields.every((field) => field.reference_only));
  const stores = auth?.supported_store_ids ?? [];
  const reviewScopes = (definition?.scope_options ?? []).filter((scope) => scope.needs_user_review);
  const boundedReviewScopes = grcBoundedRows({ rows: reviewScopes, limit: SOURCE_ACTIVATION_REVIEW_SCOPE_LIMIT });
  const ingestMode = definition?.ingest?.mode === "deposit" ? "deposit" : "pull";
  if (!definition) {
    return (
      <Panel title="Access and safety" action={<KeyRound className="h-4 w-4 text-[var(--primary)]" />}>
        <EmptyBlock label="Choose a source to see the access it needs." />
      </Panel>
    );
  }
  return (
    <Panel title="Access and safety" action={<KeyRound className="h-4 w-4 text-[var(--primary)]" />}>
      <div className="space-y-2">
        <SafetyRow
          ok
          title={ingestMode === "deposit" ? "Typed deposit ingest" : "Read-only pull access"}
          detail={
            ingestMode === "deposit"
              ? "Customers post records that match this manifest. Cerebro appends typed events and projects them through the same graph pipeline."
              : "Cerebro only reads from this source. It never writes back or changes anything."
          }
        />
        <SafetyRow
          ok={referenceOnly}
          title={referenceOnly ? "Credentials stay in your vault" : "Credentials provided directly"}
          detail={
            referenceOnly
              ? "Cerebro stores a reference to your secret store, not the secret value itself."
              : "You provide credentials when connecting. Use a reference to keep the secret in your own vault."
          }
        />
        <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">Sign-in method</div>
          <div className="mt-1 text-[12px] text-[var(--text-muted)]">{authModelLabel(auth?.model)}</div>
          {credFields.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {credFields.map((field) => (
                <Badge key={field.key} value={field.label || humanize(field.key)} />
              ))}
            </div>
          )}
        </div>
        {stores.length > 0 && (
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3">
            <div className="text-[12px] font-semibold text-[var(--text-primary)]">Credentials can be stored in</div>
            <div className="mt-2 flex flex-wrap gap-2">
              {stores.map((store) => (
                <Badge key={store} value={storeLabel(store)} />
              ))}
            </div>
          </div>
        )}
        {reviewScopes.length > 0 && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 dark:border-amber-500/25 dark:bg-amber-500/10">
            <div className="text-[12px] font-semibold text-[var(--text-primary)]">Review what you are granting</div>
            <ResultLimitNotice className="mt-2" loaded={boundedReviewScopes.rows.length} meta={boundedReviewScopes.meta} limit={SOURCE_ACTIVATION_REVIEW_SCOPE_LIMIT} noun="review scopes" />
            <ul className="mt-2 space-y-1">
              {boundedReviewScopes.rows.map((scope) => (
                <li key={scope.id ?? scope.label} className="rounded-md bg-white/55 p-2 text-[12px] leading-5 text-[var(--text-secondary)] dark:bg-white/5">
                  <div>
                    <span className="font-semibold text-[var(--text-primary)]">{scope.label || humanize(scope.id ?? "")}</span>
                    {": "}
                    {scope.permission_note || "Confirm this access is appropriate for your program."}
                  </div>
                  <div className="mt-2">
                    <CoverageMetadata item={scope} compact showNotes />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}

function RuntimeActivationPlanPanel({ plan }: { plan?: SourceActivationPromotionPlan }) {
  const counts = sourceActivationPlanCategoryCounts(plan);
  const blockers = plan?.blockers ?? [];
  const boundedBlockers = grcBoundedRows({ rows: blockers, limit: SOURCE_ACTIVATION_BLOCKER_LIMIT });
  return (
    <Panel title="Runtime activation plan" action={<Badge value={sourceActivationPlanStatusLabel(plan?.status)} />}>
      {!plan ? (
        <EmptyBlock label="Choose a saved source to compute the runtime activation plan." />
      ) : (
        <div className="space-y-3">
          <p className="text-[13px] leading-6 text-[var(--text-muted)]">{plan.summary}</p>
          <div className="grid gap-2 md:grid-cols-3">
            <KeyStat label="Runtime resource types" value={plan.metrics?.resource_families ?? 0} />
            <KeyStat label="Scope options" value={plan.metrics?.scope_options ?? 0} />
            <KeyStat label="Blocking checks" value={plan.metrics?.blocked_checks ?? blockers.length} />
          </div>
          {Object.keys(counts).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(counts).map(([category, count]) => (
                <Badge key={category} value={`${planCategoryLabel(category)}: ${count}`} />
              ))}
            </div>
          )}
          {blockers.length > 0 && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3 dark:border-red-500/25 dark:bg-red-500/10">
              <div className="text-[12px] font-semibold text-[var(--text-primary)]">Blocked by</div>
              <ResultLimitNotice className="mt-2" loaded={boundedBlockers.rows.length} meta={boundedBlockers.meta} limit={SOURCE_ACTIVATION_BLOCKER_LIMIT} noun="blockers" />
              <div className="mt-2 flex flex-wrap gap-2">
                {boundedBlockers.rows.map((blocker) => <Badge key={blocker} value={blocker} />)}
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function ReadinessChecklist({ definition }: { definition?: ConnectorDefinition }) {
  const checks = definition?.validation?.checks ?? [];
  const open = checks.filter((check) => check.blocking || check.status === "blocked" || check.status === "warning");
  const boundedOpen = grcBoundedRows({ rows: open, limit: SOURCE_ACTIVATION_CHECK_LIMIT });
  const confidenceSteps = [
    "Run a test pull and confirm the sample data looks right.",
    "Confirm only the data you intend is collected.",
    "Confirm updates arrive often enough for your needs.",
  ];
  return (
    <Panel title="What's left before you can rely on it" action={definition ? <Badge value={`${open.length} open`} /> : undefined}>
      <div className="space-y-2">
        {open.length > 0 && <ResultLimitNotice loaded={boundedOpen.rows.length} meta={boundedOpen.meta} limit={SOURCE_ACTIVATION_CHECK_LIMIT} noun="open checks" />}
        {boundedOpen.rows.map((check) => {
          const blocking = check.blocking || check.status === "blocked";
          return (
            <div
              key={check.id}
              className={`flex items-start gap-3 rounded-lg border border-l-[3px] border-[color:var(--border)] p-3 ${
                blocking ? "border-l-red-500 bg-red-50/70 dark:bg-red-500/10" : "border-l-amber-500 bg-amber-50/70 dark:bg-amber-500/10"
              }`}
            >
              <CircleAlert className={`mt-0.5 h-4 w-4 shrink-0 ${blocking ? "text-red-500" : "text-amber-500"}`} />
              <div className="min-w-0">
                <div className="text-[13px] font-semibold text-[var(--text-primary)]">{check.label}</div>
                <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{check.next_action || check.detail}</div>
              </div>
            </div>
          );
        })}
        {definition && open.length === 0 && (
          <div className="flex items-start gap-3 rounded-lg border border-l-[3px] border-[color:var(--border)] border-l-emerald-500 bg-emerald-50/70 p-3 dark:bg-emerald-500/10">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
            <div className="text-[13px] leading-5 text-[var(--text-primary)]">
              Setup checks pass. Confirm the data with a test pull, then advance it up the trust ladder.
            </div>
          </div>
        )}
        {!definition && <EmptyBlock label="Choose a source to see what is left." />}
      </div>
      {definition && (
        <div className="mt-4 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
          <div className="text-[12px] font-semibold text-[var(--text-primary)]">Confirm before you rely on it</div>
          <ul className="mt-2 space-y-1">
            {confidenceSteps.map((step) => (
              <li key={step} className="flex items-start gap-2 text-[12px] leading-5 text-[var(--text-muted)]">
                <ArrowRight className="mt-0.5 h-3 w-3 shrink-0 text-[var(--primary)]" />
                <span>{step}</span>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex items-start gap-2 text-[12px] leading-5 text-[var(--text-secondary)]">
            <Activity className="mt-0.5 h-3 w-3 shrink-0 text-[var(--primary)]" />
            <span>Once connected, track freshness and collection errors on the source page in your connector library.</span>
          </div>
        </div>
      )}
    </Panel>
  );
}

function SourcesQueue({
  definitions,
  selectedID,
  tenantID,
}: {
  definitions: ConnectorDefinition[];
  selectedID: string;
  tenantID: string;
}) {
  const boundedDefinitions = grcBoundedRows({ rows: definitions, limit: SOURCE_ACTIVATION_SOURCE_LIMIT });
  return (
    <Panel title="Your sources" action={<Badge value={`${boundedDefinitions.rows.length} shown`} />}>
      <div className="space-y-2">
        <ResultLimitNotice loaded={boundedDefinitions.rows.length} meta={boundedDefinitions.meta} limit={SOURCE_ACTIVATION_SOURCE_LIMIT} noun="sources" />
        {boundedDefinitions.rows.map((definition) => {
          const definitionID = definition.id ?? "";
          const familyCount = definition.resource_families?.length ?? 0;
          return (
            <Link
              key={definitionID || definition.source_id}
              href={sourceActivationPlanPath(definitionID, tenantID)}
              className={`block rounded-lg border border-l-[3px] p-3 transition ${toneBorder(readinessTone(definition))} ${
                definitionID && definitionID === selectedID
                  ? "border-[color:var(--ring)] bg-[var(--primary-soft)]"
                  : "border-[color:var(--border)] bg-[var(--surface)] hover:border-[color:var(--border-strong)]"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{definition.display_name}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                    {familyCount} resource type{familyCount === 1 ? "" : "s"}
                  </div>
                </div>
                <Badge value={stageLabel(definition.stage)} />
              </div>
              <div className="mt-2 text-[11px] text-[var(--text-muted)]">{readinessWord(definition)}</div>
            </Link>
          );
        })}
        {definitions.length === 0 && <EmptyBlock label="No sources yet. Create one in the connector builder." />}
      </div>
    </Panel>
  );
}

function CatalogSourcesPanel({ connectors, tenantID }: { connectors: ConnectorCatalogEntry[]; tenantID: string }) {
  const boundedConnectors = grcBoundedRows({ rows: connectors, limit: GRC_WORKLIST_LIMIT });
  const rows = boundedConnectors.rows
    .map((connector) => ({
      connector,
      resourceTypes: connectorResourceTypes(connector, 3),
      stats: connectorResourceTypeStats(connector),
    }))
    .filter((row) => row.stats.catalogResourceTypes > 0 || row.stats.resourceTypes > 0)
    .sort((left, right) =>
      right.stats.resourceTypes - left.stats.resourceTypes ||
      connectorDisplayName(left.connector).localeCompare(connectorDisplayName(right.connector)),
    );
  const resourceTypeSourceCount = rows.filter((row) => row.stats.resourceTypes > 0).length;

  return (
    <Panel title="Catalog sources" action={<Badge value={`${resourceTypeSourceCount} with resource types`} />}>
      <div className="space-y-2">
        <ResultLimitNotice loaded={boundedConnectors.rows.length} meta={boundedConnectors.meta} limit={GRC_WORKLIST_LIMIT} noun="catalog sources" />
        {rows.slice(0, 8).map(({ connector, resourceTypes, stats }) => {
          const setupAllowed = connectorSetupAllowed(connector);
          const href = connectorPath(connector.source_id, { tenant_id: tenantID, tab: setupAllowed ? "setup" : undefined });
          return (
            <Link key={connector.source_id} href={href} className="block rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-3 transition hover:border-[color:var(--border-strong)]">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-semibold text-[var(--text-primary)]">{connectorDisplayName(connector)}</div>
                  <div className="mt-1 text-[11px] text-[var(--text-muted)]">
                    {stats.resourceTypes}/{Math.max(stats.catalogResourceTypes, stats.resourceTypes)} resource types
                  </div>
                </div>
                <Badge value={connectorRuntimeSurfaceLabel(connector)} />
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {resourceTypes.length > 0 ? resourceTypes.map((item) => (
                  <span key={item.template} title={item.template} className="rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]">
                    {item.label}
                  </span>
                )) : <span className="text-[11px] text-[var(--text-muted)]">No resource type mapping</span>}
              </div>
            </Link>
          );
        })}
        {rows.length > 8 && (
          <Link href={`/connectors${tenantID ? `?tenant_id=${encodeURIComponent(tenantID)}&tab=available` : "?tab=available"}`} className="secondary-button inline-flex w-full justify-center px-3 py-2 text-[12px]">
            Open {rows.length - 8} more
          </Link>
        )}
        {rows.length === 0 && <EmptyBlock label="No catalog sources advertise resource types yet." />}
      </div>
    </Panel>
  );
}

function firstConnection(connections: ConnectorConnectionSummary[] | undefined, tenantID: string) {
  const cleanTenant = tenantID.trim();
  return (connections ?? []).find((connection) => !cleanTenant || connection.tenant_id === cleanTenant) ?? connections?.[0];
}

function depositSample(definition: ConnectorDefinition, runtimeID: string, tenantID: string) {
  const family = definition.ingest?.deposit?.resource_families?.[0] || definition.resource_families?.[0]?.id || "assets";
  return JSON.stringify({
    tenant_id: tenantID || definition.tenant_id,
    runtime_id: runtimeID || `${tenantID || definition.tenant_id || "tenant"}-${definition.source_id}-connection`,
    family_id: family,
    batch_id: "snapshot-2026-06-23",
    full_state: definition.ingest?.deposit?.full_state_sync ?? false,
    records: [{ id: "record-1", name: "Example record" }],
  }, null, 2);
}

function RuntimeActivationPanel({
  definition,
  connector,
  credentialStores,
  tenantID,
  apiKey,
  existingConnection,
  loading,
  error,
  onConnected,
  onRunSync,
  syncStatus,
  syncing,
}: {
  definition?: ConnectorDefinition;
  connector?: ConnectorCatalogEntry;
  credentialStores: ReturnType<typeof normalizeCredentialStores>;
  tenantID: string;
  apiKey?: string;
  existingConnection?: ConnectorConnectionSummary;
  loading: boolean;
  error?: string | null;
  onConnected: (context: ConnectorConnectedContext) => Promise<void>;
  onRunSync: (runtimeID: string) => void;
  syncStatus: { type: "success" | "error"; message: string } | null;
  syncing: boolean;
}) {
  const runtimeID = existingConnection?.runtime_id ?? "";
  const isDeposit = definition?.ingest?.mode === "deposit";
  return (
    <Panel title="Activate runtime" action={definition ? <Badge value={isDeposit ? "Deposit ingest" : "Pull runtime"} /> : undefined}>
      {!definition && <EmptyBlock label="Choose a source to activate its runtime." />}
      {definition && (
        <div className="space-y-4">
          <p className="text-[13px] leading-6 text-[var(--text-muted)]">
            Save a runtime connection for this source, then {isDeposit ? "send typed records to its deposit endpoint." : "run a bounded initial sync to confirm events enter the graph."}
          </p>
          {loading && !connector && <LoadingBlock label="Loading connector setup metadata..." />}
          {error && <ErrorBlock error={error} recoveryDetail="Refresh the connector library, then try activation again." />}
          {connector ? (
            <ConnectorSetupForm
              connector={connector}
              tenantID={tenantID || definition.tenant_id || ""}
              apiKey={apiKey}
              credentialStores={credentialStores}
              onConnected={onConnected}
            />
          ) : !loading && !error ? (
            <EmptyBlock label="Connector setup metadata is not available for this definition yet." />
          ) : null}
          {runtimeID && !isDeposit && (
            <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-[13px] font-semibold text-[var(--text-primary)]">Initial sync</div>
                  <div className="mt-1 text-[12px] text-[var(--text-muted)]">Run one page for {runtimeID} to verify runtime collection.</div>
                </div>
                <button type="button" disabled={syncing} onClick={() => onRunSync(runtimeID)} className="primary-button inline-flex items-center gap-2 px-3 py-2 text-[13px] disabled:opacity-60">
                  <RefreshCw className={`h-4 w-4 ${syncing ? "animate-spin" : ""}`} />
                  {syncing ? "Running..." : "Run initial sync"}
                </button>
              </div>
            </div>
          )}
          {definition && isDeposit && (
            <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface)] p-4">
              <div className="text-[13px] font-semibold text-[var(--text-primary)]">Deposit endpoint</div>
              <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">
                Post JSON records to <code className="rounded bg-[var(--surface-muted)] px-1 py-0.5">{connectorDepositsPath(definition.source_id)}</code>. Use a stable batch_id or idempotency_key when retrying.
              </div>
              <pre className="mt-3 max-h-64 overflow-auto rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3 text-[11px] leading-5 text-[var(--text-secondary)]">{depositSample(definition, runtimeID, tenantID)}</pre>
            </div>
          )}
          {syncStatus && (
            <div className={`rounded-lg border p-3 text-[12px] ${syncStatus.type === "success" ? "border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100" : "border-red-200 bg-red-50 text-red-800 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-100"}`}>
              {syncStatus.message}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function SourceReadinessContent() {
  const { apiKey } = useApiKey();
  const [tenantID, setTenantID] = useQueryParamState("tenant_id");
  const [requestedDefinitionID] = useQueryParamState("definition_id");
  const scopedTenantID = tenantID.trim();
  const [syncing, setSyncing] = useState(false);
  const [syncStatus, setSyncStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const definitionsQuery = useGRCQuery<ConnectorDefinitionListResponse>(withQuery("/connector-definitions", { tenant_id: scopedTenantID, limit: SOURCE_ACTIVATION_SOURCE_LIMIT }));
  const definitions = useMemo(() => definitionsQuery.data?.definitions ?? [], [definitionsQuery.data?.definitions]);
  const selectedDefinitionID = requestedDefinitionID || definitions[0]?.id || "";
  const selectedListDefinition = definitions.find((definition) => definition.id === selectedDefinitionID) ?? definitions[0];
  const planQuery = useGRCQuery<ConnectorDefinitionPlanResponse>(
    selectedDefinitionID ? `/connector-definitions/${encodeURIComponent(selectedDefinitionID)}/promotion-plan` : null,
  );
  const planDefinition = planQuery.data?.plan?.definition;
  const selectedDefinition = (planDefinition?.id && planDefinition.id === selectedDefinitionID ? planDefinition : undefined) ?? selectedListDefinition;
  useEffect(() => {
    const responseTenantID = definitionsQuery.data?.tenant_id?.trim() || selectedDefinition?.tenant_id?.trim() || "";
    if (!scopedTenantID && responseTenantID) {
      setTenantID(responseTenantID);
    }
  }, [definitionsQuery.data?.tenant_id, scopedTenantID, selectedDefinition?.tenant_id, setTenantID]);
  const libraryQuery = useGRCQuery<ConnectorLibraryResponse>(withQuery("/connectors", { tenant_id: scopedTenantID, view: "full", limit: GRC_WORKLIST_LIMIT }));
  const detailQuery = useGRCQuery<ConnectorDetailResponse>(
    selectedDefinition?.source_id ? withQuery(`/connectors/${encodeURIComponent(selectedDefinition.source_id)}`, { tenant_id: scopedTenantID }) : null,
  );
  const plan = planQuery.data?.plan;
  const credentialStores = useMemo(() => normalizeCredentialStores(libraryQuery.data), [libraryQuery.data]);
  const catalogConnectors = libraryQuery.data?.connectors ?? [];
  const connector = detailQuery.data?.connector ?? libraryQuery.data?.connectors?.find((entry) => entry.source_id === selectedDefinition?.source_id);
  const existingConnection = firstConnection(detailQuery.data?.connections, scopedTenantID);
  const reloadActivation = async () => {
    await Promise.all([
      definitionsQuery.reload(),
      planQuery.reload(),
      libraryQuery.reload(),
      detailQuery.reload(),
    ]);
  };
  const handleConnected = async (context: ConnectorConnectedContext) => {
    setSyncStatus({ type: "success", message: `Saved runtime ${context.runtimeID}.` });
    await reloadActivation();
  };
  const runInitialSync = async (runtimeID: string) => {
    setSyncing(true);
    setSyncStatus(null);
    try {
      const response = await fetchCerebro(sourceRuntimeSyncPath(runtimeID, 1), apiKey, { method: "POST" });
      if (!response.ok) {
        throw new Error(`Initial sync failed (${response.status}).`);
      }
      setSyncStatus({ type: "success", message: `Initial sync started for ${runtimeID}.` });
      await reloadActivation();
    } catch (syncError) {
      setSyncStatus({ type: "error", message: syncError instanceof Error ? syncError.message : "Initial sync failed." });
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Runtime source activation"
        description="Promote a source definition, preview the data it emits, and connect it at runtime without a GitHub handoff."
        action={
          <div className="flex flex-wrap gap-2">
            <Link
              href={`/connectors${scopedTenantID ? `?tenant_id=${encodeURIComponent(scopedTenantID)}` : ""}`}
              className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]"
            >
              <ArrowLeft className="h-4 w-4" />
              Library
            </Link>
            <button
              type="button"
              onClick={() => { void reloadActivation(); }}
              className="secondary-button inline-flex items-center gap-2 px-3 py-2 text-[13px]"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        }
      />

      <ReadinessHero definition={selectedDefinition} />

      {definitionsQuery.error && (
        <ErrorBlock
          error={definitionsQuery.error}
          onRetry={() => void definitionsQuery.reload()}
          recoveryDetail="Runtime activation needs the connector definitions service."
        />
      )}
      {definitionsQuery.loading && !definitionsQuery.data && <LoadingBlock label="Loading your sources..." />}
      {planQuery.error && <ErrorBlock error={planQuery.error} onRetry={() => void planQuery.reload()} recoveryDetail="Save or select a connector definition, then refresh the runtime activation plan." />}
      {planQuery.loading && selectedDefinitionID && !planQuery.data && <LoadingBlock label="Computing runtime activation plan..." />}

      <div className="grid items-start gap-5 xl:grid-cols-[minmax(260px,0.3fr)_minmax(0,0.7fr)]">
        <div className="xl:sticky xl:top-4 xl:max-h-[calc(100vh-8rem)] xl:overflow-y-auto">
          <div className="space-y-5">
            <SourcesQueue definitions={definitions} selectedID={selectedDefinitionID} tenantID={scopedTenantID} />
            <CatalogSourcesPanel connectors={catalogConnectors} tenantID={scopedTenantID} />
          </div>
        </div>
        <div className="space-y-5">
          <div className="grid gap-5 xl:grid-cols-2">
            <DataCoveragePanel definition={selectedDefinition} />
            <AccessSafetyPanel definition={selectedDefinition} />
          </div>
          <RuntimeActivationPlanPanel plan={plan} />
          <RuntimeActivationPanel
            definition={selectedDefinition}
            connector={connector}
            credentialStores={credentialStores}
            tenantID={scopedTenantID}
            apiKey={apiKey}
            existingConnection={existingConnection}
            loading={detailQuery.loading || libraryQuery.loading}
            error={detailQuery.error || libraryQuery.error}
            onConnected={handleConnected}
            onRunSync={(runtimeID) => { void runInitialSync(runtimeID); }}
            syncStatus={syncStatus}
            syncing={syncing}
          />
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.5fr)]">
            <TrustLadder definition={selectedDefinition} />
            <ReadinessChecklist definition={selectedDefinition} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default function SourceReadinessPage() {
  return (
    <Suspense fallback={<LoadingBlock label="Loading runtime activation..." />}>
      <SourceReadinessContent />
    </Suspense>
  );
}

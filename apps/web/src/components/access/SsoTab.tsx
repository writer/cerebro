"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Loader2, Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { AttentionBanner, EmptyBlock, ErrorBlock, LoadingBlock, Panel } from "@/components/grc/Primitives";
import { useCurrentUser } from "@/components/providers";
import {
  canActivate,
  connectionStatusLabel,
  connectionToInput,
  durationLabel,
  enforcementBlocker,
  enforcementBlockerCopy,
  identityAdminFetch,
  jsonBody,
  newConnectionDraft,
  protocolLabel,
  SSO_PROVIDER_PRESETS,
  testLoginHref,
  validatePolicy,
  type SSOConnection,
  type SSOConnectionInput,
  type SSOPolicy,
  type SSOProviderPreset,
  type SSOServiceProviderInfo,
  type SSOStatus,
} from "@/lib/sso-admin";

import { ConnectionEditor } from "./ConnectionEditor";
import { Chip, Field, inputClass, shortDateTime, StatusDot, Toggle } from "./fields";

export const identityQueryKeys = {
  connections: ["identity-admin", "connections"] as const,
  policy: ["identity-admin", "policy"] as const,
  status: ["identity-admin", "status"] as const,
  spInfo: (connectionId?: string) => ["identity-admin", "sp-info", connectionId ?? ""] as const,
};

type EditorState =
  | { mode: "closed" }
  | { mode: "pick" }
  | { mode: "edit"; connection: SSOConnection | null; draft: SSOConnectionInput; preset: SSOProviderPreset };

const statusTone = { draft: "warning", tested: "neutral", active: "success", disabled: "neutral" } as const;

function presetFor(connection: SSOConnection): SSOProviderPreset {
  const issuer = connection.oidc?.issuer ?? connection.saml?.idpSsoUrl ?? "";
  let host = "";
  try {
    host = new URL(issuer).hostname.toLowerCase();
  } catch {
    host = "";
  }
  const under = (...domains: string[]) => domains.some((domain) => host === domain || host.endsWith(`.${domain}`));
  if (under("okta.com", "oktapreview.com", "okta-emea.com")) return SSO_PROVIDER_PRESETS[0];
  if (under("microsoftonline.com", "microsoft.com")) return SSO_PROVIDER_PRESETS[1];
  if (under("google.com")) return SSO_PROVIDER_PRESETS[2];
  return SSO_PROVIDER_PRESETS[3];
}

export function SsoTab({ roles, testedConnectionId, testOk, testReason }: { roles: string[]; testedConnectionId?: string; testOk?: boolean; testReason?: string }) {
  const queryClient = useQueryClient();
  const { user } = useCurrentUser();
  const [editor, setEditor] = useState<EditorState>({ mode: "closed" });

  const connectionsQuery = useQuery<{ connections: SSOConnection[] }, Error>({
    queryKey: identityQueryKeys.connections,
    queryFn: () => identityAdminFetch("/connections"),
  });
  const statusQuery = useQuery<SSOStatus, Error>({ queryKey: identityQueryKeys.status, queryFn: () => identityAdminFetch("/status") });
  const editingId = editor.mode === "edit" ? editor.connection?.id : undefined;
  const spInfoQuery = useQuery<SSOServiceProviderInfo, Error>({
    queryKey: identityQueryKeys.spInfo(editingId),
    queryFn: () => identityAdminFetch(`/sp-info${editingId ? `?connection=${encodeURIComponent(editingId)}` : ""}`),
    enabled: editor.mode === "edit",
  });

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ["identity-admin"] });

  const setStatus = useMutation<SSOConnection, Error, { connection: SSOConnection; status: SSOConnection["status"] }>({
    mutationFn: ({ connection, status }) =>
      identityAdminFetch(`/connections/${encodeURIComponent(connection.id)}`, {
        method: "PUT",
        ...jsonBody({ ...connectionToInput(connection), status }),
      }),
    onSettled: invalidate,
  });
  const remove = useMutation<void, Error, SSOConnection>({
    mutationFn: (connection) => identityAdminFetch(`/connections/${encodeURIComponent(connection.id)}`, { method: "DELETE" }),
    onSettled: invalidate,
  });

  const connections = connectionsQuery.data?.connections ?? [];
  const status = statusQuery.data ?? null;
  const tested = testedConnectionId ? connections.find((connection) => connection.id === testedConnectionId) : undefined;

  return (
    <div className="space-y-6">
      {status?.breakGlass && (
        <AttentionBanner>
          Break-glass is on (CEREBRO_SSO_BREAK_GLASS). SSO is not required right now, and proxy or local sign-in works. Turn it off once access is restored.
        </AttentionBanner>
      )}
      {status?.state === "unavailable" && (
        <AttentionBanner>
          SSO is unavailable: the web service has no Cerebro API credential, or the API has no identity store configured. The stored
          sign-in policy cannot be read or enforced.
        </AttentionBanner>
      )}
      {status && !status.sessionSecretConfigured && (
        <AttentionBanner>Set CEREBRO_WEB_SESSION_SECRET (32+ random bytes) on the web service before anyone can sign in with SSO.</AttentionBanner>
      )}
      {status && !status.publicUrlConfigured && (
        <AttentionBanner>Set CEREBRO_WEB_PUBLIC_URL to the console&apos;s external address so redirect and ACS URLs are stable.</AttentionBanner>
      )}
      {testedConnectionId && (
        <div
          role="status"
          className={`rounded-xl border px-4 py-3 text-[13px] ${
            testOk
              ? "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-100"
              : "border-red-200 bg-red-50 text-red-900 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-100"
          }`}
        >
          {testOk
            ? `Test sign-in with ${tested?.name ?? "the connection"} worked. You can turn it on.`
            : `Test sign-in with ${tested?.name ?? "the connection"} failed${testReason ? `: ${testReason.replaceAll("_", " ")}` : ""}.`}
        </div>
      )}

      <EnforcementPanel connections={connections} status={status} currentSource={user?.source} onChanged={invalidate} />

      {editor.mode === "edit" ? (
        <ConnectionEditor
          key={editor.connection?.id ?? `new-${editor.preset.id}`}
          connection={editor.connection}
          draft={editor.draft}
          preset={editor.preset}
          roles={roles}
          spInfo={spInfoQuery.data ?? null}
          onCancel={() => setEditor({ mode: "closed" })}
          onSaved={(saved) => {
            invalidate();
            setEditor({ mode: "edit", connection: saved, draft: connectionToInput(saved), preset: editor.preset });
          }}
        />
      ) : (
        <Panel
          title="Identity providers"
          description="People sign in through the connection that matches their email domain. Test each connection before turning it on."
          action={
            <button type="button" onClick={() => setEditor({ mode: "pick" })} className="primary-button inline-flex h-9 items-center gap-2 px-3 text-[13px]">
              <Plus className="h-4 w-4" /> Add connection
            </button>
          }
        >
          {editor.mode === "pick" && (
            <div className="mb-5 rounded-lg border border-[color:var(--border)] p-4">
              <div className="mb-3 text-[13px] font-semibold text-[var(--text-primary)]">Choose your identity provider</div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {SSO_PROVIDER_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => setEditor({ mode: "edit", connection: null, draft: newConnectionDraft(preset, preset.protocols[0]), preset })}
                    className="surface-panel is-interactive flex items-center gap-3 p-3 text-left"
                  >
                    <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--surface-muted)] text-[12px] font-bold text-[var(--text-primary)]">
                      {preset.label.slice(0, 2)}
                    </span>
                    <span>
                      <span className="block text-[13px] font-semibold text-[var(--text-primary)]">{preset.label}</span>
                      <span className="block text-[11px] text-[var(--text-muted)]">{preset.protocols.map((protocol) => protocolLabel[protocol]).join(" or ")}</span>
                    </span>
                  </button>
                ))}
              </div>
              <button type="button" onClick={() => setEditor({ mode: "closed" })} className="mt-3 text-[12px] font-semibold text-[var(--text-muted)]">
                Cancel
              </button>
            </div>
          )}

          {connectionsQuery.isPending && <LoadingBlock label="Loading connections..." />}
          {connectionsQuery.error && <ErrorBlock error={connectionsQuery.error.message} onRetry={() => void connectionsQuery.refetch()} />}
          {(setStatus.error || remove.error) && (
            <p className="mb-3 rounded-md bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:bg-red-500/10 dark:text-red-200" role="alert">
              {(setStatus.error ?? remove.error)?.message}
            </p>
          )}
          {connectionsQuery.data && connections.length === 0 && editor.mode !== "pick" && (
            <EmptyBlock label="No identity providers yet. Add Okta or another provider to turn on single sign-on." />
          )}
          <div className="space-y-3">
            {connections.map((connection) => (
              <div key={connection.id} className="flex flex-wrap items-center gap-4 rounded-lg border border-[color:var(--border)] p-4">
                <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-[var(--surface-muted)]">
                  <KeyRound className="h-4 w-4 text-[var(--text-secondary)]" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[14px] font-semibold text-[var(--text-primary)]">{connection.name}</span>
                    <span className="rounded bg-[var(--surface-muted)] px-1.5 py-0.5 text-[11px] font-semibold text-[var(--text-secondary)]">
                      {protocolLabel[connection.protocol]}
                    </span>
                    <StatusDot tone={statusTone[connection.status]} label={connectionStatusLabel[connection.status]} />
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px] text-[var(--text-muted)]">
                    {connection.domains.map((domain) => (
                      <Chip key={domain} value={domain} />
                    ))}
                    <span className="ml-1">
                      {connection.lastTest
                        ? `Last test ${connection.lastTest.ok ? "passed" : "failed"} ${shortDateTime(connection.lastTest.at)}`
                        : "Never tested"}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {/* Test sign-in is a full-page navigation to the identity provider, so it stays a plain link. */}
                  <a href={testLoginHref(connection.id)} className="secondary-button inline-flex h-8 items-center px-3 text-[12px]">
                    Test sign-in
                  </a>
                  {connection.managed ? (
                    <span className="text-[12px] text-[var(--text-muted)]">Managed by deployment configuration</span>
                  ) : (
                  <>
                  {connection.status === "active" ? (
                    <button
                      type="button"
                      className="secondary-button inline-flex h-8 items-center px-3 text-[12px]"
                      disabled={setStatus.isPending}
                      onClick={() => setStatus.mutate({ connection, status: "disabled" })}
                    >
                      Turn off
                    </button>
                  ) : (
                    <button
                      type="button"
                      className="primary-button inline-flex h-8 items-center px-3 text-[12px]"
                      disabled={!canActivate(connection) || setStatus.isPending}
                      title={canActivate(connection) ? undefined : "Test sign-in first"}
                      onClick={() => setStatus.mutate({ connection, status: "active" })}
                    >
                      Turn on
                    </button>
                  )}
                  <button
                    type="button"
                    className="secondary-button inline-flex h-8 items-center px-3 text-[12px]"
                    onClick={() => setEditor({ mode: "edit", connection, draft: connectionToInput(connection), preset: presetFor(connection) })}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="secondary-button inline-flex h-8 items-center px-3 text-[12px] text-red-700 dark:text-red-300"
                    disabled={remove.isPending}
                    onClick={() => {
                      if (window.confirm(`Delete ${connection.name}? People signed in with it are signed out, and its SCIM tokens stop working.`)) {
                        remove.mutate(connection);
                      }
                    }}
                  >
                    Delete
                  </button>
                  </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function EnforcementPanel({
  connections,
  status,
  currentSource,
  onChanged,
}: {
  connections: SSOConnection[];
  status: SSOStatus | null;
  currentSource?: string;
  onChanged: () => void;
}) {
  const policyQuery = useQuery<SSOPolicy, Error>({ queryKey: identityQueryKeys.policy, queryFn: () => identityAdminFetch("/policy") });
  if (policyQuery.isPending) return <LoadingBlock label="Loading sign-in policy..." />;
  if (policyQuery.error) return <ErrorBlock error={policyQuery.error.message} onRetry={() => void policyQuery.refetch()} />;
  const policy = policyQuery.data;
  return (
    <PolicyForm
      key={`${policy.enforced}-${policy.sessionMaxLifetimeMinutes}-${policy.sessionIdleTimeoutMinutes}-${policy.updatedAt ?? ""}`}
      policy={policy}
      connections={connections}
      status={status}
      currentSource={currentSource}
      onChanged={onChanged}
    />
  );
}

function PolicyForm({
  policy,
  connections,
  status,
  currentSource,
  onChanged,
}: {
  policy: SSOPolicy;
  connections: SSOConnection[];
  status: SSOStatus | null;
  currentSource?: string;
  onChanged: () => void;
}) {
  const [draft, setDraft] = useState<SSOPolicy>(policy);

  const save = useMutation<SSOPolicy, Error, SSOPolicy>({
    mutationFn: (policy) =>
      identityAdminFetch("/policy", {
        method: "PUT",
        ...jsonBody({
          enforced: policy.enforced,
          sessionMaxLifetimeMinutes: policy.sessionMaxLifetimeMinutes,
          sessionIdleTimeoutMinutes: policy.sessionIdleTimeoutMinutes,
        }),
      }),
    onSettled: onChanged,
  });

  const blocker = enforcementBlocker({ connections, currentSource, status });
  const errors = validatePolicy(draft);
  const dirty =
    draft.sessionMaxLifetimeMinutes !== policy.sessionMaxLifetimeMinutes ||
    draft.sessionIdleTimeoutMinutes !== policy.sessionIdleTimeoutMinutes;
  const required = status?.required === true;
  const enforced = required || policy.enforced;

  const toggleEnforced = (next: boolean) => {
    const message = next
      ? "Require SSO? Everyone else is signed out and must sign in through an identity provider. Proxy and header sign-in stop working."
      : "Stop requiring SSO? The console falls back to proxy or header sign-in.";
    if (window.confirm(message)) save.mutate({ ...policy, enforced: next });
  };

  return (
    <Panel
      title="Sign-in policy"
      description="How people sign in to this console and how long a session lasts."
      action={
        status?.state === "unavailable" ? (
          <StatusDot tone="warning" label="SSO unavailable" />
        ) : (
          <StatusDot tone={enforced ? "success" : "warning"} label={enforced ? "SSO required" : "SSO optional"} />
        )
      }
    >
      <div className="space-y-5">
        <Toggle
          label="Require single sign-on"
          checked={enforced}
          disabled={required || save.isPending || (!enforced && blocker !== null)}
          onChange={toggleEnforced}
          description={
            required ? (
              <span className="inline-flex items-center gap-1">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" /> Required by deployment configuration (CEREBRO_SSO_REQUIRED). Break-glass is unavailable.
              </span>
            ) : !enforced && blocker ? (
              enforcementBlockerCopy[blocker]
            ) : enforced ? (
              <span className="inline-flex items-center gap-1">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" /> Only SSO sessions can use the console. If you get locked out, set CEREBRO_SSO_BREAK_GLASS=true on the web service.
              </span>
            ) : (
              "When on, proxy headers and the local developer identity are ignored."
            )
          }
        />
        <div className="grid gap-4 border-t border-[color:var(--border)] pt-5 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
          <Field label="Session lifetime (minutes)" error={errors.sessionMaxLifetimeMinutes} hint={`Sign in again after ${durationLabel(draft.sessionMaxLifetimeMinutes)}.`}>
            <input
              type="number"
              min={15}
              className={inputClass}
              value={draft.sessionMaxLifetimeMinutes}
              onChange={(event) => setDraft({ ...draft, sessionMaxLifetimeMinutes: Number(event.target.value) })}
            />
          </Field>
          <Field label="Idle timeout (minutes)" error={errors.sessionIdleTimeoutMinutes} hint={`Sign out after ${durationLabel(draft.sessionIdleTimeoutMinutes)} of inactivity.`}>
            <input
              type="number"
              min={5}
              className={inputClass}
              value={draft.sessionIdleTimeoutMinutes}
              onChange={(event) => setDraft({ ...draft, sessionIdleTimeoutMinutes: Number(event.target.value) })}
            />
          </Field>
          <button
            type="button"
            disabled={!dirty || Object.keys(errors).length > 0 || save.isPending}
            onClick={() => save.mutate({ ...policy, sessionMaxLifetimeMinutes: draft.sessionMaxLifetimeMinutes, sessionIdleTimeoutMinutes: draft.sessionIdleTimeoutMinutes })}
            className="primary-button mb-6 inline-flex h-9 items-center gap-2 px-4 text-[13px]"
          >
            {save.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Save
          </button>
        </div>
        {save.error && (
          <p className="rounded-md bg-red-50 px-3 py-2 text-[12px] text-red-800 dark:bg-red-500/10 dark:text-red-200" role="alert">
            {save.error.message}
          </p>
        )}
        <p className="text-[12px] text-[var(--text-muted)]">New limits apply to sessions created after you save.</p>
      </div>
    </Panel>
  );
}

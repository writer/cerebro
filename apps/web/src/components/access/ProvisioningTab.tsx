"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Plus } from "lucide-react";
import { useState } from "react";

import { EmptyBlock, ErrorBlock, LoadingBlock, Panel } from "@/components/grc/Primitives";
import {
  identityAdminFetch,
  jsonBody,
  type SCIMToken,
  type SSOConnection,
  type SSOServiceProviderInfo,
} from "@/lib/sso-admin";

import { Chip, CopyField, Field, inputClass, shortDateTime } from "./fields";
import { identityQueryKeys } from "./SsoTab";

type CreatedToken = SCIMToken & { token: string };

const scimTokensKey = ["identity-admin", "scim-tokens"] as const;

export function ProvisioningTab() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("Okta SCIM");
  const [connectionId, setConnectionId] = useState("");
  const [created, setCreated] = useState<CreatedToken | null>(null);

  const spInfoQuery = useQuery<SSOServiceProviderInfo, Error>({ queryKey: identityQueryKeys.spInfo(), queryFn: () => identityAdminFetch("/sp-info") });
  const connectionsQuery = useQuery<{ connections: SSOConnection[] }, Error>({
    queryKey: identityQueryKeys.connections,
    queryFn: () => identityAdminFetch("/connections"),
  });
  const tokensQuery = useQuery<{ tokens: SCIMToken[] }, Error>({ queryKey: scimTokensKey, queryFn: () => identityAdminFetch("/scim/tokens") });

  const connections = connectionsQuery.data?.connections ?? [];
  const selectedConnection = connectionId || connections[0]?.id || "";
  const connectionName = (id?: string) => connections.find((connection) => connection.id === id)?.name ?? id ?? "";

  const create = useMutation<CreatedToken, Error>({
    mutationFn: () => identityAdminFetch("/scim/tokens", { method: "POST", ...jsonBody({ name: name.trim(), connectionId: selectedConnection }) }),
    onSuccess: (token) => {
      setCreated(token);
      void queryClient.invalidateQueries({ queryKey: scimTokensKey });
    },
  });
  const revoke = useMutation<void, Error, SCIMToken>({
    mutationFn: (token) => identityAdminFetch(`/scim/tokens/${encodeURIComponent(token.id)}`, { method: "DELETE" }),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: scimTokensKey }),
  });

  return (
    <div className="space-y-6">
      <Panel
        title="Automatic provisioning (SCIM 2.0)"
        description="Let your identity provider create, update, and deactivate Cerebro users and groups. Deactivated users are signed out right away."
      >
        <div className="grid gap-5 lg:grid-cols-2">
          <div className="space-y-3">
            <CopyField
              label="SCIM base URL"
              value={spInfoQuery.data?.scimBaseUrl ?? ""}
              hint="In Okta: the app's Provisioning tab → Integration → SCIM connector base URL. Unique identifier field: userName. Authentication mode: HTTP Header."
            />
            <ul className="list-disc space-y-1 pl-5 text-[12px] leading-5 text-[var(--text-secondary)]">
              <li>Turn on Create Users, Update User Attributes, and Deactivate Users.</li>
              <li>Use Push Groups for the groups you map to roles on the Single sign-on tab.</li>
              <li>When a connection has a SCIM token, only provisioned, active users can sign in through it, unless it also creates accounts on first sign-in.</li>
            </ul>
          </div>
          <div className="space-y-3 rounded-lg border border-[color:var(--border)] p-4">
            <div className="text-[13px] font-semibold text-[var(--text-primary)]">New SCIM token</div>
            {connections.length === 0 ? (
              <p className="text-[12px] text-[var(--text-muted)]">Add an identity provider on the Single sign-on tab first.</p>
            ) : (
              <>
                <Field label="Name" htmlFor="scim-token-name">
                  <input id="scim-token-name" className={inputClass} value={name} onChange={(event) => setName(event.target.value)} />
                </Field>
                <Field label="Connection" htmlFor="scim-token-connection">
                  <select id="scim-token-connection" className={inputClass} value={selectedConnection} onChange={(event) => setConnectionId(event.target.value)}>
                    {connections.map((connection) => (
                      <option key={connection.id} value={connection.id}>
                        {connection.name}
                      </option>
                    ))}
                  </select>
                </Field>
                <button
                  type="button"
                  disabled={!name.trim() || !selectedConnection || create.isPending}
                  onClick={() => create.mutate()}
                  className="primary-button inline-flex h-9 items-center gap-2 px-3 text-[13px]"
                >
                  {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                  Generate token
                </button>
                {create.error && <p className="text-[12px] text-red-700 dark:text-red-300">{create.error.message}</p>}
              </>
            )}
          </div>
        </div>

        {created && (
          <div className="mt-5 space-y-2 rounded-lg border border-emerald-200 bg-emerald-50 p-4 dark:border-emerald-500/25 dark:bg-emerald-500/10" role="status">
            <div className="text-[13px] font-semibold text-emerald-900 dark:text-emerald-100">Copy this token now. Cerebro won&apos;t show it again.</div>
            <CopyField label="API token (Bearer)" value={created.token} hint="Paste it into the identity provider's provisioning settings." />
            <button type="button" className="text-[12px] font-semibold text-emerald-900 dark:text-emerald-100" onClick={() => setCreated(null)}>
              I&apos;ve copied it
            </button>
          </div>
        )}
      </Panel>

      <Panel title="SCIM tokens" description="Each token is tied to one connection. Revoke a token to stop that provider from provisioning.">
        {tokensQuery.isPending && <LoadingBlock label="Loading tokens..." />}
        {tokensQuery.error && <ErrorBlock error={tokensQuery.error.message} onRetry={() => void tokensQuery.refetch()} />}
        {revoke.error && <p className="mb-3 text-[12px] text-red-700 dark:text-red-300">{revoke.error.message}</p>}
        {tokensQuery.data && tokensQuery.data.tokens.length === 0 && <EmptyBlock label="No SCIM tokens yet." />}
        {tokensQuery.data && tokensQuery.data.tokens.length > 0 && (
          <table className="w-full text-left text-[13px]">
            <thead className="text-[12px] text-[var(--text-muted)]">
              <tr>
                <th className="pb-2 pr-4 font-medium">Name</th>
                <th className="pb-2 pr-4 font-medium">Connection</th>
                <th className="pb-2 pr-4 font-medium">Token</th>
                <th className="pb-2 pr-4 font-medium">Last used</th>
                <th className="pb-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {tokensQuery.data.tokens.map((token) => (
                <tr key={token.id} className="border-t border-[color:var(--border)]">
                  <td className="py-2.5 pr-4 font-medium text-[var(--text-primary)]">{token.name}</td>
                  <td className="py-2.5 pr-4 text-[var(--text-secondary)]">{connectionName(token.connectionId)}</td>
                  <td className="py-2.5 pr-4">
                    <Chip value={`${token.prefix}…`} />
                  </td>
                  <td className="py-2.5 pr-4 text-[var(--text-secondary)]">{shortDateTime(token.lastUsedAt)}</td>
                  <td className="py-2.5 text-right">
                    <button
                      type="button"
                      className="secondary-button inline-flex h-8 items-center px-3 text-[12px] text-red-700 dark:text-red-300"
                      disabled={revoke.isPending}
                      onClick={() => {
                        if (window.confirm(`Revoke ${token.name}? Provisioning with it stops immediately.`)) revoke.mutate(token);
                      }}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

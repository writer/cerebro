"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useDeferredValue, useState } from "react";

import { EmptyBlock, ErrorBlock, LoadingBlock, Panel } from "@/components/grc/Primitives";
import { identityAdminFetch, type DirectoryGroup, type DirectoryUser, type SSOConnection } from "@/lib/sso-admin";

import { Chip, shortDateTime, StatusDot } from "./fields";
import { identityQueryKeys } from "./SsoTab";

export function PeopleTab() {
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query.trim());
  const [signedOut, setSignedOut] = useState<string | null>(null);

  const usersQuery = useQuery<{ users: DirectoryUser[] }, Error>({
    queryKey: ["identity-admin", "directory-users", deferredQuery],
    queryFn: () => identityAdminFetch(`/directory/users?${new URLSearchParams({ query: deferredQuery, limit: "200" })}`),
  });
  const groupsQuery = useQuery<{ groups: DirectoryGroup[] }, Error>({
    queryKey: ["identity-admin", "directory-groups"],
    queryFn: () => identityAdminFetch("/directory/groups"),
  });
  const connectionsQuery = useQuery<{ connections: SSOConnection[] }, Error>({
    queryKey: identityQueryKeys.connections,
    queryFn: () => identityAdminFetch("/connections"),
  });
  const connectionName = (id: string) => connectionsQuery.data?.connections.find((connection) => connection.id === id)?.name ?? id;

  const signOut = useMutation<{ revoked: number }, Error, DirectoryUser>({
    mutationFn: (user) => identityAdminFetch(`/sessions?${new URLSearchParams({ email: user.email })}`, { method: "DELETE" }),
    onSuccess: (result, user) => setSignedOut(`${user.name || user.email}: ${result?.revoked ?? 0} session(s) ended.`),
  });

  const users = usersQuery.data?.users ?? [];

  return (
    <div className="space-y-6">
      <Panel
        title="People"
        description="Everyone who has signed in with SSO or was provisioned through SCIM. Change roles through groups in your identity provider."
        action={
          <label className="relative block w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              className="control-input h-9 w-full rounded-md pl-9 pr-3 text-[13px]"
              placeholder="Search people"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              aria-label="Search people"
            />
          </label>
        }
      >
        {signedOut && <p className="mb-3 text-[12px] text-emerald-700 dark:text-emerald-300" role="status">{signedOut}</p>}
        {signOut.error && <p className="mb-3 text-[12px] text-red-700 dark:text-red-300">{signOut.error.message}</p>}
        {usersQuery.isPending && <LoadingBlock label="Loading people..." />}
        {usersQuery.error && <ErrorBlock error={usersQuery.error.message} onRetry={() => void usersQuery.refetch()} />}
        {usersQuery.data && users.length === 0 && (
          <EmptyBlock label={deferredQuery ? "No one matches that search." : "No one has signed in with SSO yet."} />
        )}
        {users.length > 0 && (
          <table className="w-full text-left text-[13px]">
            <thead className="text-[12px] text-[var(--text-muted)]">
              <tr>
                <th className="pb-2 pr-4 font-medium">Person</th>
                <th className="pb-2 pr-4 font-medium">Status</th>
                <th className="pb-2 pr-4 font-medium">Groups</th>
                <th className="pb-2 pr-4 font-medium">Added by</th>
                <th className="pb-2 pr-4 font-medium">Last sign-in</th>
                <th className="pb-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-t border-[color:var(--border)] align-top">
                  <td className="py-2.5 pr-4">
                    <div className="font-medium text-[var(--text-primary)]">{user.name || user.userName}</div>
                    <div className="text-[12px] text-[var(--text-muted)]">{user.email}</div>
                  </td>
                  <td className="py-2.5 pr-4">
                    <StatusDot tone={user.active ? "success" : "neutral"} label={user.active ? "Active" : "Deactivated"} />
                  </td>
                  <td className="py-2.5 pr-4">
                    <span className="flex max-w-xs flex-wrap gap-1">
                      {user.groups.length > 0 ? user.groups.map((group) => <Chip key={group} value={group} />) : <span className="text-[12px] text-[var(--text-muted)]">none</span>}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 text-[12px] text-[var(--text-secondary)]">
                    {user.source === "scim" ? "SCIM" : "First sign-in"} · {connectionName(user.connectionId)}
                  </td>
                  <td className="py-2.5 pr-4 text-[12px] text-[var(--text-secondary)]">{shortDateTime(user.lastLoginAt)}</td>
                  <td className="py-2.5 text-right">
                    <button
                      type="button"
                      className="secondary-button inline-flex h-8 items-center whitespace-nowrap px-3 text-[12px]"
                      disabled={signOut.isPending || !user.email}
                      onClick={() => signOut.mutate(user)}
                    >
                      Sign out everywhere
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Groups" description="Groups pushed from your identity provider through SCIM.">
        {groupsQuery.isPending && <LoadingBlock label="Loading groups..." />}
        {groupsQuery.error && <ErrorBlock error={groupsQuery.error.message} onRetry={() => void groupsQuery.refetch()} />}
        {groupsQuery.data && groupsQuery.data.groups.length === 0 && <EmptyBlock label="No groups provisioned yet." />}
        {groupsQuery.data && groupsQuery.data.groups.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {groupsQuery.data.groups.map((group) => (
              <span key={group.id} className="inline-flex items-center gap-2 rounded-md border border-[color:var(--border)] px-2.5 py-1.5 text-[12px]">
                <span className="font-mono text-[var(--text-primary)]">{group.displayName}</span>
                <span className="text-[var(--text-muted)]">
                  {group.memberCount} member{group.memberCount === 1 ? "" : "s"}
                </span>
              </span>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

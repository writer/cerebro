"use client";

import { useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldCheck, UserPlus, Users } from "lucide-react";
import type { ReactNode } from "react";

import { Chip, SegmentedTabs } from "@/components/access/fields";
import { PeopleTab } from "@/components/access/PeopleTab";
import { ProvisioningTab } from "@/components/access/ProvisioningTab";
import { SsoTab } from "@/components/access/SsoTab";
import { AttentionBanner, Badge, ErrorBlock, LoadingBlock, PageHeader, Panel } from "@/components/grc/Primitives";
import { accessRoleRows, deniedPermissions, type AccessControl } from "@/lib/access-control";
import { useQueryParamState } from "@/lib/query-params";

type AccessTab = "roles" | "sso" | "provisioning" | "people";

const accessTabs: { id: AccessTab; label: string; icon: ReactNode }[] = [
  { id: "roles", label: "Roles", icon: <ShieldCheck className="h-3.5 w-3.5" /> },
  { id: "sso", label: "Single sign-on", icon: <KeyRound className="h-3.5 w-3.5" /> },
  { id: "provisioning", label: "Provisioning", icon: <UserPlus className="h-3.5 w-3.5" /> },
  { id: "people", label: "People", icon: <Users className="h-3.5 w-3.5" /> },
];

export default function AdminAccessControlPage() {
  const [tabValue, setTab] = useQueryParamState("tab", "roles");
  const [tested] = useQueryParamState("tested");
  const [testOk] = useQueryParamState("ok");
  const [testReason] = useQueryParamState("reason");
  const tab = (accessTabs.some((item) => item.id === tabValue) ? tabValue : "roles") as AccessTab;
  const query = useQuery<AccessControl, Error>({
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/admin/access", { cache: "no-store", signal });
      if (!response.ok) {
        throw new Error(
          response.status === 403
            ? "You do not have the admin:read permission for this console."
            : `Access control is unavailable (HTTP ${response.status}).`,
        );
      }
      return (await response.json()) as AccessControl;
    },
    queryKey: ["admin-access-control"],
  });

  const data = query.data ?? null;
  const roleRows = data ? accessRoleRows(data) : [];
  const yourRoles = roleRows.filter((row) => row.yours);
  const denied = data ? deniedPermissions(data) : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Access Control"
        description="How people sign in, how they're provisioned, and which identity-provider groups get which Cerebro roles."
      />

      <SegmentedTabs tabs={accessTabs} active={tab} onChange={setTab} />

      {tab === "sso" && (
        <SsoTab
          roles={data?.roles.map((role) => role.role) ?? []}
          testedConnectionId={tested || undefined}
          testOk={testOk === "1"}
          testReason={testReason || undefined}
        />
      )}
      {tab === "provisioning" && <ProvisioningTab />}
      {tab === "people" && <PeopleTab />}

      {tab === "roles" && query.isPending && <LoadingBlock label="Loading access control..." />}
      {tab === "roles" && query.error && <ErrorBlock error={query.error.message} onRetry={() => void query.refetch()} />}

      {tab === "roles" && data && (
        <div className="space-y-6" id="access-control">
          {data.sampleMappings && (
            <AttentionBanner>
              These group mappings are samples for local development. A deployment sets its own in stack config.
            </AttentionBanner>
          )}
          {!data.sampleMappings && !data.deployment.builtinRbacRequired && (
            <AttentionBanner>
              Roles are not enforced in this deployment. Any signed-in user may take every action that has no group
              policy of its own.
            </AttentionBanner>
          )}

          <Panel title="Your Access">
            <div className="space-y-3 text-[13px]">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="min-w-[110px] text-[12px] font-medium text-[var(--text-muted)]">Your roles</span>
                {yourRoles.length > 0 ? (
                  yourRoles.map((row) => <Chip key={row.role} value={row.role} />)
                ) : (
                  <span className="text-[var(--text-muted)]">none</span>
                )}
              </div>
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="min-w-[110px] text-[12px] font-medium text-[var(--text-muted)]">You can&apos;t</span>
                {denied.length > 0 ? (
                  denied.map((permission) => <Chip key={permission} value={permission} />)
                ) : (
                  <span className="text-[var(--text-muted)]">
                    nothing is blocked; you hold all {data.permissions.length} permissions
                  </span>
                )}
              </div>
              {data.deployment.globalRequiredGroups.length > 0 && (
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="min-w-[110px] text-[12px] font-medium text-[var(--text-muted)]">Everyone needs</span>
                  {data.deployment.globalRequiredGroups.map((group) => (
                    <Chip key={group} value={group} />
                  ))}
                </div>
              )}
            </div>
          </Panel>

          <Panel title="Who Gets What">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[12px] text-[var(--text-muted)]">
                <tr>
                  <th className="pb-2 pr-4 font-medium">Role</th>
                  <th className="pb-2 pr-4 font-medium">Granted to</th>
                  <th className="pb-2 font-medium">Allows</th>
                </tr>
              </thead>
              <tbody>
                {roleRows.map((row) => (
                  <tr key={row.role} className="border-t border-[color:var(--border)] align-top">
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2 font-medium text-[var(--text-primary)]">
                        {row.role}
                        {row.yours && <Badge value="you" />}
                      </div>
                      {row.description && (
                        <p className="mt-1 max-w-xs text-[12px] leading-5 text-[var(--text-muted)]">{row.description}</p>
                      )}
                    </td>
                    <td className="py-3 pr-4">
                      {row.grantedTo.length > 0 ? (
                        <span className="flex flex-wrap gap-1.5">
                          {row.grantedTo.map((group) => (
                            <Chip key={group} value={group} />
                          ))}
                        </span>
                      ) : (
                        <span className="text-[12px] text-[var(--text-muted)]">no group</span>
                      )}
                    </td>
                    <td className="py-3">
                      <span className="flex flex-wrap gap-1.5">
                        {row.permissions.map((permission) => (
                          <Chip key={permission} value={permission} />
                        ))}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </div>
      )}
    </div>
  );
}

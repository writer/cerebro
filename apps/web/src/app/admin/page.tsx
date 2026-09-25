"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { KeyRound, Plug, ShieldCheck, UserCog } from "lucide-react";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";

type PermissionRow = {
  permission: string;
  requiredGroups: string[];
  requiredRoles: string[];
  requiredScopes: string[];
  restricted: boolean;
  granted: boolean;
};

type RoleRow = { description: string; permissions: string[]; role: string };

type ClaimMappingRow = { claim: string; value: string; roles: string[] };

type AccessControl = {
  deployment: {
    builtinRbacRequired: boolean;
    globalRequiredGroups: string[];
    identityRequired: boolean;
  };
  permissions: PermissionRow[];
  roleClaimMappings: ClaimMappingRow[];
  roles: RoleRow[];
  viewer: {
    confidence: string;
    entitlements: { groups?: string[]; roles?: string[]; scopes?: string[] };
    mappedRoles: string[];
    permissions: string[];
    provider: string;
  };
};

const adminSections = [
  {
    description: "Roles, claim mappings, and the permissions each console action requires.",
    href: "#access-control",
    icon: ShieldCheck,
    label: "Access control",
  },
  {
    description: "Source setup, ingestion scope, and connector health.",
    href: "/connectors",
    icon: Plug,
    label: "Integrations",
  },
  {
    description: "Credential store defaults and accepted reference formats.",
    href: "/credential-stores",
    icon: KeyRound,
    label: "Credential stores",
  },
  {
    description: "Organizations, users, and login history discovered by ingestion.",
    href: "/identity",
    icon: UserCog,
    label: "Members",
  },
];

function ClaimList({ label, values }: { label: string; values: string[] | undefined }) {
  return (
    <div className="flex flex-wrap items-baseline gap-2">
      <span className="text-[12px] font-medium text-[var(--text-muted)]">{label}</span>
      {values && values.length > 0 ? (
        values.map((value) => <Badge key={value} value={value} />)
      ) : (
        <span className="text-[12px] text-[var(--text-muted)]">none</span>
      )}
    </div>
  );
}

export default function AdminPage() {
  const query = useQuery<AccessControl, Error>({
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/admin/access-control", { cache: "no-store", signal });
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
  const loading = query.isPending;
  const error = query.error?.message ?? "";
  const load = () => {
    void query.refetch();
  };

  const restrictedCount = data?.permissions.filter((row) => row.restricted).length ?? 0;
  const grantedCount = data?.viewer.permissions.length ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Admin"
        description="Console settings that govern who may sign in, what they may do, and which systems Cerebro ingests from."
      />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {adminSections.map((section) => (
          <Link
            key={section.label}
            href={section.href}
            className="surface-panel flex flex-col gap-2 p-4 transition hover:border-[color:var(--primary)]"
          >
            <span className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
              <section.icon className="h-4 w-4 text-[var(--primary)]" />
              {section.label}
            </span>
            <span className="text-[12px] leading-5 text-[var(--text-muted)]">{section.description}</span>
          </Link>
        ))}
      </div>

      {loading && <LoadingBlock label="Loading access control..." />}
      {!loading && error && <ErrorBlock error={error} onRetry={load} />}

      {!loading && data && (
        <div className="space-y-6" id="access-control">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard label="Permissions" value={String(data.permissions.length)} />
            <MetricCard label="Restricted" value={String(restrictedCount)} />
            <MetricCard label="Your permissions" value={String(grantedCount)} />
            <MetricCard label="Claim mappings" value={String(data.roleClaimMappings.length)} />
          </div>

          <Panel title="Your access">
            <div className="space-y-3">
              <div className="flex flex-wrap gap-4 text-[12px] text-[var(--text-muted)]">
                <span>
                  provider <span className="text-[var(--text-primary)]">{data.viewer.provider}</span>
                </span>
                <span>
                  confidence <span className="text-[var(--text-primary)]">{data.viewer.confidence}</span>
                </span>
                <span>
                  identity required{" "}
                  <span className="text-[var(--text-primary)]">{String(data.deployment.identityRequired)}</span>
                </span>
                <span>
                  builtin rbac{" "}
                  <span className="text-[var(--text-primary)]">{String(data.deployment.builtinRbacRequired)}</span>
                </span>
              </div>
              <ClaimList label="groups" values={data.viewer.entitlements.groups} />
              <ClaimList label="roles" values={data.viewer.entitlements.roles} />
              <ClaimList label="scopes" values={data.viewer.entitlements.scopes} />
              <ClaimList label="roles from mappings" values={data.viewer.mappedRoles} />
              <ClaimList label="required for every action" values={data.deployment.globalRequiredGroups} />
            </div>
          </Panel>

          <Panel title="Claim to role mappings">
            {data.roleClaimMappings.length === 0 ? (
              <EmptyBlock label="No claim mappings are configured, so identity claims grant no roles." />
            ) : (
              <table className="w-full text-left text-[13px]">
                <thead className="text-[12px] text-[var(--text-muted)]">
                  <tr>
                    <th className="pb-2 font-medium">Claim</th>
                    <th className="pb-2 font-medium">Value</th>
                    <th className="pb-2 font-medium">Roles granted</th>
                  </tr>
                </thead>
                <tbody>
                  {data.roleClaimMappings.map((mapping) => (
                    <tr key={`${mapping.claim}:${mapping.value}`} className="border-t border-[color:var(--border)]">
                      <td className="py-2 text-[var(--text-muted)]">{mapping.claim}</td>
                      <td className="py-2 text-[var(--text-primary)]">{mapping.value}</td>
                      <td className="py-2">
                        <span className="flex flex-wrap gap-1.5">
                          {mapping.roles.map((role) => (
                            <Badge key={role} value={role} />
                          ))}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          <Panel title="Roles">
            <div className="space-y-3">
              {data.roles.map((role) => (
                <div
                  key={role.role}
                  className="space-y-1.5 border-b border-[color:var(--border)] pb-3 last:border-0 last:pb-0"
                >
                  <div className="text-[13px] font-medium text-[var(--text-primary)]">{role.role}</div>
                  {role.description && (
                    <p className="text-[12px] leading-5 text-[var(--text-muted)]">{role.description}</p>
                  )}
                  <span className="flex flex-wrap gap-1.5">
                    {role.permissions.map((permission) => (
                      <Badge key={permission} value={permission} />
                    ))}
                  </span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Permissions">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[12px] text-[var(--text-muted)]">
                <tr>
                  <th className="pb-2 font-medium">Permission</th>
                  <th className="pb-2 font-medium">Required groups</th>
                  <th className="pb-2 font-medium">Restricted</th>
                  <th className="pb-2 font-medium">You</th>
                </tr>
              </thead>
              <tbody>
                {data.permissions.map((row) => (
                  <tr key={row.permission} className="border-t border-[color:var(--border)]">
                    <td className="py-2 text-[var(--text-primary)]">{row.permission}</td>
                    <td className="py-2">
                      {row.requiredGroups.length === 0 ? (
                        <span className="text-[var(--text-muted)]">any</span>
                      ) : (
                        <span className="flex flex-wrap gap-1.5">
                          {row.requiredGroups.map((group) => (
                            <Badge key={group} value={group} />
                          ))}
                        </span>
                      )}
                    </td>
                    <td className="py-2 text-[var(--text-muted)]">{row.restricted ? "yes" : "open"}</td>
                    <td className="py-2 text-[var(--text-muted)]">{row.granted ? "allowed" : "denied"}</td>
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

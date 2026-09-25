"use client";

import { useQuery } from "@tanstack/react-query";

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

type IdentityHealth = {
  config: {
    audienceConfigured: boolean;
    fallbackEnabled: boolean;
    issuerConfigured: boolean;
    jwksConfigured: boolean;
    profile: string;
    required: boolean;
    trustedHeaders: string[];
  };
  current: { source: string };
  issues: string[];
  status: "ready" | "degraded" | "blocked";
};

// Phrased as requirements so "met" and "missing" read the same way down the
// column, and each says what is accepted while it is unmet.
const requirementRows = (config: IdentityHealth["config"]) => [
  {
    detail: "A request carrying no recognised identity is still served.",
    label: "Identity required",
    met: config.required,
  },
  {
    detail: "An unauthenticated request becomes a local developer account.",
    label: "Local fallback disabled",
    met: !config.fallbackEnabled,
  },
  {
    detail: "Token signatures are accepted without being checked.",
    label: "JWKS configured",
    met: config.jwksConfigured,
  },
  {
    detail: "A token from any issuer is accepted.",
    label: "Issuer pinned",
    met: config.issuerConfigured,
  },
  {
    detail: "A token minted for another audience is accepted.",
    label: "Audience pinned",
    met: config.audienceConfigured,
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

export default function AdminAccessControlPage() {
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

  // Separate endpoint and separate permission, so a viewer who may read
  // authorization but not identity still gets the rest of the page.
  const identityQuery = useQuery<IdentityHealth, Error>({
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/identity/health", { cache: "no-store", signal });
      if (!response.ok) {
        throw new Error(
          response.status === 403
            ? "You do not have the identity:read permission."
            : `Sign-in posture is unavailable (HTTP ${response.status}).`,
        );
      }
      return (await response.json()) as IdentityHealth;
    },
    queryKey: ["admin-identity-health"],
  });

  const data = query.data ?? null;
  const loading = query.isPending;
  const error = query.error?.message ?? "";
  const load = () => {
    void query.refetch();
  };
  const identity = identityQuery.data ?? null;

  const restrictedCount = data?.permissions.filter((row) => row.restricted).length ?? 0;
  const grantedCount = data?.viewer.permissions.length ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Access control"
        description="How Cerebro establishes who you are, how much of that claim it has verified, and what that identity is allowed to do."
      />

      <Panel title="Sign-in">
        {identityQuery.isPending && <LoadingBlock label="Loading sign-in posture..." />}
        {identityQuery.error && (
          <ErrorBlock error={identityQuery.error.message} onRetry={() => void identityQuery.refetch()} />
        )}
        {identity && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-x-6 gap-y-2 text-[12px] text-[var(--text-muted)]">
              <span>
                status <Badge value={identity.status} />
              </span>
              <span>
                profile <span className="text-[var(--text-primary)]">{identity.config.profile}</span>
              </span>
              <span>
                source <span className="text-[var(--text-primary)]">{identity.current.source}</span>
              </span>
              <span>
                trusted headers{" "}
                <span className="text-[var(--text-primary)]">
                  {identity.config.trustedHeaders.length > 0 ? identity.config.trustedHeaders.join(", ") : "none"}
                </span>
              </span>
            </div>
            {requirementRows(identity.config).map((row) => (
              <div
                key={row.label}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-[color:var(--border)] pb-3 last:border-0 last:pb-0"
              >
                <span className="min-w-[170px] text-[13px] font-medium text-[var(--text-primary)]">{row.label}</span>
                <Badge value={row.met ? "ok" : "missing"} />
                {!row.met && <span className="text-[12px] leading-5 text-[var(--text-muted)]">{row.detail}</span>}
              </div>
            ))}
          </div>
        )}
      </Panel>

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

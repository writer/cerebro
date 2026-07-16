"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { useCurrentUser } from "@/components/providers";
import { currentUserConfidenceLabel, identityPosture, type IdentityHealth } from "@/lib/identity";
import { currentUserWriteFieldForPath } from "@/lib/identity-write-stamp";
import { authorizationRoleLabelsForUser, effectiveAuthorizationPermissionsForUser } from "@/lib/rbac";

const writeStampRows = [
  { path: "grc/inventory/asset-reports", label: "Asset report create" },
  { path: "grc/inventory/asset-reports/{id}/triage", label: "Asset report triage" },
];

function IdentityRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border)] py-2.5 last:border-b-0">
      <span className="text-[12px] text-[var(--text-muted)]">{label}</span>
      <span className="max-w-[70%] break-words text-right font-mono text-[12px] text-[var(--text-primary)]">{value || "—"}</span>
    </div>
  );
}

const joinValues = (values: string[] | undefined) => values?.filter(Boolean).join(", ") ?? "";

export default function IdentityContractPanel({ compact = false }: { compact?: boolean }) {
  const { actor, error, loading, user } = useCurrentUser();
  const [health, setHealth] = useState<IdentityHealth | null>(null);
  const identity = identityPosture({ error, loading, user });
  const effectivePermissions = effectiveAuthorizationPermissionsForUser(user);
  const recognizedRoles = authorizationRoleLabelsForUser(user);
  const attentionItems = [
    ...(user?.conflicts ?? []),
    ...(user?.warnings ?? []),
    ...(health?.issues ?? []),
  ];

  useEffect(() => {
    let mounted = true;
    const loadHealth = async () => {
      try {
        const response = await fetch("/api/identity/health", { cache: "no-store" });
        if (!response.ok) return;
        const payload = await response.json() as IdentityHealth;
        if (mounted) setHealth(payload);
      } catch {
        return;
      }
    };
    void loadHealth();
    return () => { mounted = false; };
  }, []);

  return (
    <section className="surface-panel">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border)] px-5 py-3.5">
        <div>
          <h2 className="text-[13px] font-semibold text-[var(--text-primary)]">Identity Contract</h2>
          <p className="mt-1 text-[12px] text-[var(--text-muted)]">Current user source, actor value, initials, and write-stamp fields.</p>
        </div>
        <span className="rounded-md border border-[color:var(--border)] bg-[var(--surface-muted)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
          {identity.label}
        </span>
      </div>
      <div className="grid gap-5 p-5 lg:grid-cols-[minmax(0,1fr)_minmax(260px,0.8fr)]">
        <div>
          <div className="mb-3 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--surface-muted)] text-[13px] font-semibold text-[var(--text-primary)]">
              {identity.initials}
            </div>
            <div>
              <div className="text-[14px] font-semibold text-[var(--text-primary)]">{identity.displayName}</div>
              <div className="text-[12px] text-[var(--text-muted)]">{identity.sourceLabel}</div>
            </div>
          </div>
          <div className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2">
            <IdentityRow label="Actor ID" value={actor} />
            <IdentityRow label="Actor label" value={user?.actorLabel ?? ""} />
            <IdentityRow label="Email" value={user?.email ?? ""} />
            <IdentityRow label="Username" value={user?.username ?? ""} />
            <IdentityRow label="Subject" value={user?.subject ?? ""} />
            <IdentityRow label="Provider" value={user?.provider ?? ""} />
            <IdentityRow label="Confidence" value={user ? currentUserConfidenceLabel(user.confidence) : ""} />
            <IdentityRow label="Source" value={identity.sourceLabel} />
            <IdentityRow label="Groups" value={joinValues(user?.entitlements?.groups)} />
            <IdentityRow label="Roles" value={joinValues(user?.entitlements?.roles)} />
            <IdentityRow label="RBAC roles" value={joinValues(recognizedRoles)} />
            <IdentityRow label="Permissions" value={joinValues(effectivePermissions)} />
            <IdentityRow label="Scopes" value={joinValues(user?.entitlements?.scopes)} />
          </div>
          <p className="mt-3 text-[12px] leading-5 text-[var(--text-muted)]">{identity.detail}</p>
          <div className="mt-3 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2">
            <IdentityRow label="Headers" value={joinValues(user?.evidence?.headers)} />
            <IdentityRow label="Claims" value={joinValues(user?.evidence?.claims)} />
            <IdentityRow label="Inferred" value={joinValues(user?.evidence?.inferred)} />
            <IdentityRow label="JWT algorithm" value={user?.evidence?.jwt?.algorithm ?? ""} />
            <IdentityRow label="JWT key ID" value={user?.evidence?.jwt?.keyId ?? ""} />
            <IdentityRow label="JWT signature" value={user?.evidence?.jwt?.signature ?? ""} />
            <IdentityRow label="Issuer" value={user?.evidence?.jwt?.issuer ?? ""} />
            <IdentityRow label="Audience" value={user?.evidence?.jwt?.audience ?? ""} />
            <IdentityRow label="Expires" value={user?.evidence?.jwt?.expiresAt ?? ""} />
          </div>
          {attentionItems.length > 0 && (
            <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-[12px] leading-5 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
              {attentionItems.join("; ")}
            </div>
          )}
        </div>
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Deployment Contract</div>
          <div className="mt-2 rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] px-4 py-2">
            <IdentityRow label="Status" value={health?.status ?? "loading"} />
            <IdentityRow label="Profile" value={health?.config.profile ?? ""} />
            <IdentityRow label="Required" value={health ? String(health.config.required) : ""} />
            <IdentityRow label="Fallback" value={health ? String(health.config.fallbackEnabled) : ""} />
            <IdentityRow label="Issuer" value={health ? (health.config.issuerConfigured ? "configured" : "not configured") : ""} />
            <IdentityRow label="Audience" value={health ? (health.config.audienceConfigured ? "configured" : "not configured") : ""} />
            <IdentityRow label="JWKS" value={health ? (health.config.jwksConfigured ? "configured" : "not configured") : ""} />
            <IdentityRow label="Trusted headers" value={health ? joinValues(health.config.trustedHeaders) || "all recognized headers" : ""} />
          </div>
          {health?.status === "blocked" && (
            <div className="mt-3 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-[12px] leading-5 text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-100">
              Identity enforcement is blocking requests that require a verified current user.
            </div>
          )}
          <div className="mt-5 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Write Stamps</div>
          <div className="mt-2 space-y-2">
            {writeStampRows.map((row) => (
              <div key={row.path} className="rounded-lg border border-[color:var(--border)] bg-[var(--surface-muted)] p-3">
                <div className="text-[12px] font-medium text-[var(--text-primary)]">{row.label}</div>
                <div className="mt-1 break-all font-mono text-[11px] text-[var(--text-muted)]">{row.path}</div>
                <div className="mt-2 inline-flex rounded-md bg-[var(--surface)] px-2 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
                  {currentUserWriteFieldForPath(row.path) ?? "not stamped"}
                </div>
              </div>
            ))}
          </div>
          {!compact && (
            <Link href="/developer" className="mt-3 inline-flex text-[12px] font-medium text-[var(--primary)] hover:text-[var(--primary-hover)]">
              Back to Developer Tools
            </Link>
          )}
        </div>
      </div>
    </section>
  );
}

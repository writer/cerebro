"use client";

import { useQuery } from "@tanstack/react-query";

import { Badge, EmptyBlock, ErrorBlock, LoadingBlock, MetricCard, PageHeader, Panel } from "@/components/grc/Primitives";

type IdentityHealth = {
  checkedAt: string;
  config: {
    audienceConfigured: boolean;
    fallbackEnabled: boolean;
    issuerConfigured: boolean;
    jwksConfigured: boolean;
    profile: string;
    required: boolean;
    trustedHeaders: string[];
  };
  current: {
    authenticated: boolean;
    claimCount: number;
    confidence: string;
    conflictCount: number;
    headerCount: number;
    provider: string;
    source: string;
    warningCount: number;
  };
  issues: string[];
  status: "ready" | "degraded" | "blocked";
};

const statusIntent = (status: IdentityHealth["status"]) =>
  status === "ready" ? "success" : status === "degraded" ? "warning" : "danger";

// Each row is phrased as a requirement so "met" and "missing" read the same way
// down the column, and each says what is accepted while it is unmet.
const requirementRows = (config: IdentityHealth["config"]) => [
  {
    detail: "While unmet, a request carrying no recognised identity is still served.",
    label: "Identity required",
    met: config.required,
  },
  {
    detail: "While unmet, an unauthenticated request becomes a local developer account.",
    label: "Local fallback disabled",
    met: !config.fallbackEnabled,
  },
  {
    detail: "While unmet, token signatures are accepted without being checked.",
    label: "JWKS configured",
    met: config.jwksConfigured,
  },
  {
    detail: "While unmet, a token from any issuer is accepted.",
    label: "Issuer pinned",
    met: config.issuerConfigured,
  },
  {
    detail: "While unmet, a token minted for another audience is accepted.",
    label: "Audience pinned",
    met: config.audienceConfigured,
  },
];

export default function AdminIdentityPage() {
  const query = useQuery<IdentityHealth, Error>({
    queryFn: async ({ signal }) => {
      const response = await fetch("/api/identity/health", { cache: "no-store", signal });
      if (!response.ok) {
        throw new Error(
          response.status === 403
            ? "You do not have the identity:read permission for this console."
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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Sign-in"
        description="How Cerebro establishes who you are, and how much of that claim it has actually verified."
      />

      {loading && <LoadingBlock label="Loading sign-in posture..." />}
      {!loading && error && <ErrorBlock error={error} onRetry={load} />}

      {!loading && data && (
        <div className="space-y-6">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard label="Status" value={data.status} intent={statusIntent(data.status)} />
            <MetricCard label="Profile" value={data.config.profile} />
            <MetricCard label="Confidence" value={data.current.confidence} />
            <MetricCard label="Open issues" value={String(data.issues.length)} />
          </div>

          <Panel title="Verification requirements">
            <div className="space-y-3">
              {requirementRows(data.config).map((row) => (
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
          </Panel>

          <Panel title="This session">
            <div className="flex flex-wrap gap-x-6 gap-y-2 text-[12px] text-[var(--text-muted)]">
              <span>
                provider <span className="text-[var(--text-primary)]">{data.current.provider}</span>
              </span>
              <span>
                source <span className="text-[var(--text-primary)]">{data.current.source}</span>
              </span>
              <span>
                authenticated <span className="text-[var(--text-primary)]">{String(data.current.authenticated)}</span>
              </span>
              <span>
                claims <span className="text-[var(--text-primary)]">{data.current.claimCount}</span>
              </span>
              <span>
                headers <span className="text-[var(--text-primary)]">{data.current.headerCount}</span>
              </span>
              <span>
                conflicts <span className="text-[var(--text-primary)]">{data.current.conflictCount}</span>
              </span>
              <span>
                warnings <span className="text-[var(--text-primary)]">{data.current.warningCount}</span>
              </span>
            </div>
          </Panel>

          <Panel title="Trusted headers">
            {data.config.trustedHeaders.length === 0 ? (
              <EmptyBlock label="No identity headers are trusted, so identity comes from the token alone." />
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {data.config.trustedHeaders.map((header) => (
                  <Badge key={header} value={header} />
                ))}
              </div>
            )}
          </Panel>

          <Panel title="Issues">
            {data.issues.length === 0 ? (
              <EmptyBlock label="No identity issues reported." />
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {data.issues.map((issue) => (
                  <Badge key={issue} value={issue} />
                ))}
              </div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}

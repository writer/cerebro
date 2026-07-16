"use client";

import { useEffect, useMemo, useState } from "react";

import { useApiKey } from "@/components/providers";
import { fetchCachedGRC, grcDashboardPath, grcTimeoutMessage } from "@/lib/grc-client";
import {
  displayDate,
  GRCDashboard,
  GRCConnector,
  GRCControl,
  GRCEvidence,
  GRCFinding,
  riskSort,
  shortEntity,
} from "@/lib/grc";

export type LiveSearchSection = "Finding" | "Control" | "Evidence" | "Connector" | "Entity";

export type LiveSearchCommand = {
  id: string;
  label: string;
  href: string;
  description: string;
  section: LiveSearchSection;
  keywords: string[];
  rank: number;
};

type LiveSearchState = {
  commands: LiveSearchCommand[];
  loading: boolean;
  error: string | null;
  searched: boolean;
};

type LiveSearchLoadState = {
  dashboard: GRCDashboard | null;
  loading: boolean;
  error: string | null;
  fetchedAt: number | null;
};

type DashboardCache = {
  data: GRCDashboard;
  fetchedAt: number;
};

type SharedDashboardState = {
  owner: string;
  cache: DashboardCache | null;
  request: Promise<GRCDashboard> | null;
};

declare global {
  interface Window {
    __cerebroLiveSearchDashboard?: SharedDashboardState;
  }
}

const emptySearchState: LiveSearchState = {
  commands: [],
  loading: false,
  error: null,
  searched: false,
};

const emptyLoadState: LiveSearchLoadState = {
  dashboard: null,
  loading: false,
  error: null,
  fetchedAt: null,
};

const LIVE_SEARCH_CACHE_TTL_MS = 60_000;
export const LIVE_SEARCH_TIMEOUT_MS = 8_000;
export const LIVE_SEARCH_UNAVAILABLE_COPY = "Page actions are ready. Live search is unavailable.";

const fallbackSharedDashboard: SharedDashboardState = {
  owner: "",
  cache: null,
  request: null,
};

const sharedDashboardState = () => {
  if (typeof window === "undefined") {
    return fallbackSharedDashboard;
  }
  window.__cerebroLiveSearchDashboard ??= { owner: "", cache: null, request: null };
  return window.__cerebroLiveSearchDashboard;
};

const normalize = (value: unknown) => String(value ?? "").trim().toLowerCase();

const compactKeywords = (values: unknown[]) =>
  values
    .flatMap((value) => Array.isArray(value) ? value : [value])
    .filter((value): value is string | number => typeof value === "string" || typeof value === "number")
    .map((value) => String(value))
    .filter(Boolean);

const searchableText = (values: unknown[]) => normalize(compactKeywords(values).join(" "));

const queryTokens = (query: string) => normalize(query).split(/\s+/).filter(Boolean);

const matchesQuery = (query: string, values: unknown[]) => {
  const text = searchableText(values);
  return queryTokens(query).every((token) => text.includes(token));
};

const scoreMatch = (query: string, primary: string, values: unknown[]) => {
  const normalizedQuery = normalize(query);
  const normalizedPrimary = normalize(primary);
  const text = searchableText(values);

  if (!normalizedQuery || !text.includes(normalizedQuery)) {
    return matchesQuery(query, values) ? 35 : 0;
  }
  if (normalizedPrimary === normalizedQuery) return 100;
  if (normalizedPrimary.startsWith(normalizedQuery)) return 80;
  if (normalizedPrimary.includes(normalizedQuery)) return 65;
  return 45;
};

const findingKeywords = (finding: GRCFinding) =>
  compactKeywords([
    finding.id,
    finding.title,
    finding.summary,
    finding.severity,
    finding.status,
    finding.owner,
    finding.sla_status,
    finding.entity,
    finding.runtime_id,
    finding.source_id,
    finding.rule_id,
    finding.policy_id,
    finding.policy_name,
    finding.risk_score,
    finding.likelihood_score,
    finding.impact_score,
    finding.confidence_score,
    finding.likelihood_level,
    finding.impact_level,
    finding.risk_reasons,
    finding.resource_urns,
    finding.controls?.map((control) => `${control.framework_name} ${control.control_id}`),
  ]);

const findingCommand = (query: string, finding: GRCFinding): LiveSearchCommand | null => {
  const keywords = findingKeywords(finding);
  if (!matchesQuery(query, keywords)) {
    return null;
  }
  const risk = typeof finding.risk_score === "number" ? `Risk ${finding.risk_score}` : finding.severity;
  return {
    id: `live:finding:${finding.id}`,
    label: finding.title || finding.id,
    href: `/findings/${encodeURIComponent(finding.id)}`,
    description: `${risk} · ${finding.owner || "Unassigned"} · ${shortEntity(finding.entity)} · ${finding.evidence_count} evidence`,
    section: "Finding",
    keywords,
    rank: 500 + scoreMatch(query, finding.title || finding.id, keywords) + (finding.risk_score ?? 0),
  };
};

const controlCommand = (query: string, control: GRCControl): LiveSearchCommand | null => {
  const controlLabel = `${control.framework_name} ${control.control_id}`;
  const keywords = compactKeywords([
    control.framework_name,
    control.control_id,
    control.status,
    control.open_findings,
    control.critical_findings,
    control.high_findings,
    control.findings?.flatMap(findingKeywords),
  ]);
  if (!matchesQuery(query, keywords)) {
    return null;
  }
  return {
    id: `live:control:${control.framework_name}:${control.control_id}`,
    label: controlLabel,
    href: `/controls?framework=${encodeURIComponent(control.framework_name)}&control=${encodeURIComponent(control.control_id)}`,
    description: `${control.status} · ${control.open_findings} open findings · ${control.evidence_items} evidence items`,
    section: "Control",
    keywords,
    rank: 420 + scoreMatch(query, controlLabel, keywords) + control.critical_findings * 8 + control.high_findings * 4,
  };
};

const evidenceCommand = (query: string, evidence: GRCEvidence): LiveSearchCommand | null => {
  const keywords = compactKeywords([
    evidence.id,
    evidence.finding_id,
    evidence.finding_title,
    evidence.runtime_id,
    evidence.rule_id,
    evidence.run_id,
    evidence.claim_ids,
    evidence.event_ids,
    evidence.graph_root_urns,
  ]);
  if (!matchesQuery(query, keywords)) {
    return null;
  }
  const href = evidence.finding_id
    ? `/evidence?finding_id=${encodeURIComponent(evidence.finding_id)}`
    : evidence.graph_root_urns?.[0]
      ? `/evidence?graph_root_urn=${encodeURIComponent(evidence.graph_root_urns[0])}`
      : `/evidence?run_id=${encodeURIComponent(evidence.run_id ?? evidence.id)}`;
  return {
    id: `live:evidence:${evidence.id}`,
    label: evidence.finding_title || evidence.id,
    href,
    description: `${evidence.claim_ids?.length ?? 0} claims · ${evidence.event_ids?.length ?? 0} events · ${displayDate(evidence.created_at)}`,
    section: "Evidence",
    keywords,
    rank: 340 + scoreMatch(query, evidence.finding_title || evidence.id, keywords),
  };
};

const connectorCommand = (query: string, connector: GRCConnector): LiveSearchCommand | null => {
  const keywords = compactKeywords([
    connector.runtime_id,
    connector.source_id,
    connector.tenant_id,
    connector.status,
    connector.freshness,
  ]);
  if (!matchesQuery(query, keywords)) {
    return null;
  }
  return {
    id: `live:connector:${connector.runtime_id}`,
    label: connector.source_id || connector.runtime_id,
    href: `/connectors?source_id=${encodeURIComponent(connector.source_id || connector.runtime_id)}`,
    description: `${connector.status} · ${connector.freshness} · last sync ${displayDate(connector.last_synced_at)}`,
    section: "Connector",
    keywords,
    rank: 300 + scoreMatch(query, connector.source_id || connector.runtime_id, keywords) + (connector.status === "stale" ? 20 : 0),
  };
};

const entityCommands = (query: string, dashboard: GRCDashboard): LiveSearchCommand[] => {
  const entities = new Map<string, { findings: number; evidence: number; labels: string[] }>();
  const addEntity = (urn: string | undefined, label: string, kind: "findings" | "evidence") => {
    if (!urn) return;
    const current = entities.get(urn) ?? { findings: 0, evidence: 0, labels: [] };
    current[kind] += 1;
    current.labels.push(label);
    entities.set(urn, current);
  };

  (dashboard.findings ?? []).forEach((finding) => {
    addEntity(finding.entity, finding.title, "findings");
    (finding.resource_urns ?? []).forEach((urn) => addEntity(urn, finding.title, "findings"));
  });
  (dashboard.evidence ?? []).forEach((evidence) => {
    (evidence.graph_root_urns ?? []).forEach((urn) => addEntity(urn, evidence.finding_title || evidence.id, "evidence"));
  });

  const commands: LiveSearchCommand[] = [];
  entities.forEach((details, urn) => {
    const keywords = compactKeywords([urn, shortEntity(urn), details.labels]);
    if (!matchesQuery(query, keywords)) {
      return;
    }
    commands.push({
      id: `live:entity:${urn}`,
      label: shortEntity(urn),
      href: `/impact?root_urn=${encodeURIComponent(urn)}`,
      description: `${details.findings} findings · ${details.evidence} evidence roots · ${urn}`,
      section: "Entity",
      keywords,
      rank: 360 + scoreMatch(query, urn, keywords) + details.findings * 5 + details.evidence,
    });
  });
  return commands;
};

export const buildLiveSearchCommands = (query: string, dashboard: GRCDashboard) => {
  const findings = (dashboard.findings ?? [])
    .slice()
    .sort(riskSort)
    .map((finding) => findingCommand(query, finding));
  const controls = (dashboard.controls ?? []).map((control) => controlCommand(query, control));
  const evidence = (dashboard.evidence ?? []).map((item) => evidenceCommand(query, item));
  const connectors = (dashboard.connectors ?? []).map((connector) => connectorCommand(query, connector));

  return [...findings, ...controls, ...entityCommands(query, dashboard), ...evidence, ...connectors]
    .filter((command): command is LiveSearchCommand => Boolean(command))
    .sort((left, right) => right.rank - left.rank)
    .slice(0, 12);
};

const errorMessage = (data: unknown, status: number) =>
  typeof data === "string" && data.trim() ? data : `Live search failed (${status})`;

export function useLiveSearchCommands(query: string, isOpen: boolean) {
  const { apiKey } = useApiKey();
  const trimmedQuery = query.trim();
  const shouldSearch = isOpen && trimmedQuery.length >= 2;
  const [loadState, setLoadState] = useState<LiveSearchLoadState>(emptyLoadState);

  useEffect(() => {
    if (!shouldSearch) {
      return;
    }

    let active = true;
    const timer = window.setTimeout(async () => {
      const shared = sharedDashboardState();
      if (shared.owner !== apiKey) {
        shared.owner = apiKey;
        shared.cache = null;
        shared.request = null;
      }

      const cached = shared.cache;
      const now = Date.now();
      if (cached && now - cached.fetchedAt < LIVE_SEARCH_CACHE_TTL_MS) {
        setLoadState({
          dashboard: cached.data,
          loading: false,
          error: null,
          fetchedAt: cached.fetchedAt,
        });
        return;
      }

      const requestOwner = apiKey;
      setLoadState((current) => ({
        dashboard: current.dashboard,
        loading: true,
        error: null,
        fetchedAt: current.fetchedAt,
      }));

      if (!shared.request) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), LIVE_SEARCH_TIMEOUT_MS);
        const request = fetchCachedGRC<GRCDashboard>(
          grcDashboardPath({ limit: 100 }),
          requestOwner,
          false,
          { signal: controller.signal },
        ).then((response) => {
          if (!response.ok) {
            throw new Error(errorMessage(response.data, response.status));
          }
          return response.data;
        }).catch((error: unknown) => {
          if (controller.signal.aborted) {
            throw new Error(grcTimeoutMessage("/grc/dashboard", LIVE_SEARCH_TIMEOUT_MS));
          }
          throw error;
        }).finally(() => {
          window.clearTimeout(timeout);
          if (shared.request === request) {
            shared.request = null;
          }
        });
        shared.request = request;
      }

      const dashboard = await shared.request.catch((error: unknown) => {
        if (!active) {
          return null;
        }
        return error instanceof Error ? error : new Error("Live search failed");
      });

      if (!active || shared.owner !== requestOwner) {
        return;
      }
      if (!dashboard) {
        return;
      }
      if (dashboard instanceof Error) {
        setLoadState((current) => ({
          dashboard: current.dashboard,
          loading: false,
          error: LIVE_SEARCH_UNAVAILABLE_COPY,
          fetchedAt: current.fetchedAt,
        }));
        return;
      }

      const fetchedAt = Date.now();
      shared.cache = { data: dashboard, fetchedAt };
      setLoadState({
        dashboard,
        loading: false,
        error: null,
        fetchedAt,
      });
    }, 0);

    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [apiKey, shouldSearch]);

  const commands = useMemo(
    () => shouldSearch && loadState.dashboard ? buildLiveSearchCommands(trimmedQuery, loadState.dashboard) : [],
    [loadState.dashboard, shouldSearch, trimmedQuery],
  );

  return useMemo(() => {
    if (!shouldSearch) {
      return emptySearchState;
    }
    return {
      commands,
      loading: loadState.loading,
      error: loadState.error,
      searched: Boolean(loadState.dashboard || loadState.error),
    };
  }, [commands, loadState.dashboard, loadState.error, loadState.loading, shouldSearch]);
}

"use client";

import { parseAsString, useQueryStates, type UrlKeys } from "nuqs";
import { useCallback, useMemo } from "react";

import {
  buildActionableControlOwnerRows,
  buildAuditExportManifestRows,
  buildAuditReadinessRows,
  buildAuditPackageSummary,
  buildAuditStatusLedgerRows,
  buildAuditorQuestionRows,
  buildControlOwnerRows,
  buildEvidenceCurationRows,
  buildFrameworkCoverageRows,
  buildScopeExceptionRows,
  buildSourceTrustRows,
  buildTeamQueueRows,
} from "@/lib/audit-packages";
import type { GRCDashboard, GRCControlEvidencePacketResponse, GRCEvidencePacketsResponse, GRCFrameworksResponse } from "@/lib/grc";
import { grcDashboardPath, grcPath, useDebouncedValue, useGRCQuery } from "@/lib/grc-client";
import { supportedGRCFrameworkNames } from "@/lib/grc-frameworks";
import { GRC_WORKLIST_LIMIT } from "@/lib/grc-list";

export const DEFAULT_CONTROL_PROFILE_ID = "soc2-security-core";

export const CONTROL_PROFILE_OPTIONS = [
  "soc2-security-core",
  "soc2-availability",
  "iso-technology-controls",
  "cloud-security-benchmarks",
  "pci-operational-security",
  "dora-operational-resilience",
  "fedramp-rev5-core",
  "nist-csf-20-core",
  "privacy-ai-governance",
];

const auditPackageSearchParams = {
  controlID: parseAsString.withDefault(""),
  framework: parseAsString.withDefault(""),
  profileID: parseAsString.withDefault(""),
  tenantID: parseAsString.withDefault(""),
};

const auditPackageUrlKeys: UrlKeys<typeof auditPackageSearchParams> = {
  controlID: "control",
  profileID: "profile",
  tenantID: "tenant_id",
};

const normalizeSearchParamValue = (value: string) => {
  const normalized = value.trim();
  return normalized ? normalized : null;
};

export function useAuditPackageParams() {
  const [params, setParams] = useQueryStates(auditPackageSearchParams, {
    clearOnDefault: true,
    history: "replace",
    scroll: false,
    shallow: true,
    urlKeys: auditPackageUrlKeys,
  });

  const setTenantID = useCallback((value: string) => {
    void setParams({ tenantID: normalizeSearchParamValue(value) });
  }, [setParams]);
  const setProfileID = useCallback((value: string) => {
    void setParams({ profileID: normalizeSearchParamValue(value) });
  }, [setParams]);
  const setFramework = useCallback((value: string) => {
    void setParams({ framework: normalizeSearchParamValue(value) });
  }, [setParams]);
  const setControlID = useCallback((value: string) => {
    void setParams({ controlID: normalizeSearchParamValue(value) });
  }, [setParams]);
  const clear = useCallback(() => {
    void setParams({
      controlID: null,
      framework: null,
      profileID: null,
      tenantID: null,
    });
  }, [setParams]);

  return {
    ...params,
    clear,
    setControlID,
    setFramework,
    setProfileID,
    setTenantID,
  };
}

export function useAuditPackageView({
  controlID,
  framework,
  profileID,
  tenantID,
}: {
  controlID: string;
  framework: string;
  profileID: string;
  tenantID: string;
}) {
  const debouncedTenantID = useDebouncedValue(tenantID.trim());
  const selectedProfileID = profileID.trim() || DEFAULT_CONTROL_PROFILE_ID;

  const controlPacketQuery = useGRCQuery<GRCControlEvidencePacketResponse>(
    grcPath("/grc/control-packets", {
      tenant_id: debouncedTenantID,
      profile: selectedProfileID,
      framework,
      control: controlID,
      limit: GRC_WORKLIST_LIMIT,
    }),
  );
  const evidencePacketsQuery = useGRCQuery<GRCEvidencePacketsResponse>(
    grcPath("/grc/evidence-packets", { tenant_id: debouncedTenantID, limit: GRC_WORKLIST_LIMIT }),
  );
  const dashboardQuery = useGRCQuery<GRCDashboard>(
    grcDashboardPath({ tenant_id: debouncedTenantID, limit: 100 }),
  );
  const frameworksQuery = useGRCQuery<GRCFrameworksResponse>(grcPath("/grc/frameworks", { tenant_id: debouncedTenantID }));

  const summary = useMemo(
    () => buildAuditPackageSummary({
      controlPacket: controlPacketQuery.data,
      dashboard: dashboardQuery.data,
      evidencePackets: evidencePacketsQuery.data,
    }),
    [controlPacketQuery.data, dashboardQuery.data, evidencePacketsQuery.data],
  );
  const metadata = controlPacketQuery.data?.metadata ?? evidencePacketsQuery.data?.metadata;
  const evidenceRows = useMemo(
    () => buildEvidenceCurationRows({ controlPacket: controlPacketQuery.data, evidencePackets: evidencePacketsQuery.data, limit: 25 }),
    [controlPacketQuery.data, evidencePacketsQuery.data],
  );
  const ownerRows = useMemo(
    () => buildControlOwnerRows(controlPacketQuery.data?.controls ?? dashboardQuery.data?.controls ?? [], 25),
    [controlPacketQuery.data?.controls, dashboardQuery.data?.controls],
  );
  const actionableOwnerRows = useMemo(() => buildActionableControlOwnerRows(ownerRows, 25), [ownerRows]);
  const teamRows = useMemo(() => buildTeamQueueRows(dashboardQuery.data, 25), [dashboardQuery.data]);
  const frameworkRows = useMemo(() => buildFrameworkCoverageRows(frameworksQuery.data?.frameworks ?? [], 25), [frameworksQuery.data?.frameworks]);
  const sourceRows = useMemo(
    () => buildSourceTrustRows({ dashboard: dashboardQuery.data, evidencePackets: evidencePacketsQuery.data, limit: 25 }),
    [dashboardQuery.data, evidencePacketsQuery.data],
  );
  const exceptionRows = useMemo(() => buildScopeExceptionRows(metadata, 25), [metadata]);
  const loaded = Boolean(controlPacketQuery.data || evidencePacketsQuery.data || dashboardQuery.data || frameworksQuery.data);
  const loading = controlPacketQuery.loading || evidencePacketsQuery.loading || dashboardQuery.loading || frameworksQuery.loading;
  const errors = [
    controlPacketQuery.error,
    evidencePacketsQuery.error,
    dashboardQuery.error,
    frameworksQuery.error,
  ].filter((error): error is string => Boolean(error));
  const snapshotID = evidencePacketsQuery.data?.snapshot?.id || controlPacketQuery.data?.packet.selection_id || `${selectedProfileID}-current`;
  const generatedAt = evidencePacketsQuery.data?.generated_at || controlPacketQuery.data?.generated_at || dashboardQuery.data?.generated_at || "";
  const readinessRows = useMemo(
    () => buildAuditReadinessRows(summary, snapshotID, generatedAt),
    [generatedAt, snapshotID, summary],
  );
  const auditorQuestionRows = useMemo(
    () => buildAuditorQuestionRows({ evidenceRows, ownerRows, sourceRows, limit: 10 }),
    [evidenceRows, ownerRows, sourceRows],
  );
  const exportManifestRows = useMemo(
    () => buildAuditExportManifestRows({ generatedAt, snapshotID, summary }),
    [generatedAt, snapshotID, summary],
  );
  const statusLedgerRows = useMemo(
    () => buildAuditStatusLedgerRows({
      evidenceRows,
      ownerRows: actionableOwnerRows,
      readinessRows,
      snapshotID,
      sourceRows,
      limit: 12,
    }),
    [actionableOwnerRows, evidenceRows, readinessRows, snapshotID, sourceRows],
  );
  const frameworkOptions = useMemo(
    () => Array.from(new Set([
      ...supportedGRCFrameworkNames,
      ...(frameworksQuery.data?.frameworks ?? []).map((item) => item.name),
      ...(controlPacketQuery.data?.controls ?? []).map((control) => control.framework_name),
    ].filter(Boolean))),
    [controlPacketQuery.data?.controls, frameworksQuery.data?.frameworks],
  );

  const reload = () => {
    void controlPacketQuery.reload();
    void evidencePacketsQuery.reload();
    void dashboardQuery.reload();
    void frameworksQuery.reload();
  };

  return {
    actionableOwnerRows,
    auditorQuestionRows,
    debouncedTenantID,
    errors,
    evidenceRows,
    exceptionRows,
    exportManifestRows,
    frameworkOptions,
    frameworkRows,
    generatedAt,
    loaded,
    loading,
    metadata,
    ownerRows,
    readinessRows,
    reload,
    selectedProfileID,
    snapshotID,
    sourceRows,
    statusLedgerRows,
    summary,
    teamRows,
  };
}

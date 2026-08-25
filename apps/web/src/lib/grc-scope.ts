"use client";

import { parseAsString, useQueryStates } from "nuqs";
import { useCallback, useMemo } from "react";

import { useDebouncedValue } from "@/lib/grc-client";

export type GRCScope = {
  tenantID: string;
  workspaceID: string;
};

export type GRCScopeQuery = {
  tenant_id?: string;
  workspace_id?: string;
};

const cleanScopeValue = (value: string | null | undefined) => value?.trim() ?? "";

export const grcScopeQuery = ({ tenantID, workspaceID }: GRCScope): GRCScopeQuery => ({
  tenant_id: cleanScopeValue(tenantID) || undefined,
  workspace_id: cleanScopeValue(workspaceID) || undefined,
});

export const withGRCScope = (path: string, scope: GRCScope) => {
  const params = new URLSearchParams();
  const query = grcScopeQuery(scope);
  if (query.tenant_id) params.set("tenant_id", query.tenant_id);
  if (query.workspace_id) params.set("workspace_id", query.workspace_id);
  const suffix = params.toString();
  if (!suffix) return path;
  const hashIndex = path.indexOf("#");
  const base = hashIndex >= 0 ? path.slice(0, hashIndex) : path;
  const hash = hashIndex >= 0 ? path.slice(hashIndex) : "";
  return `${base}${base.includes("?") ? "&" : "?"}${suffix}${hash}`;
};

const scopeParsers = {
  tenant_id: parseAsString.withDefault("").withOptions({ clearOnDefault: true }),
  workspace_id: parseAsString.withDefault("").withOptions({ clearOnDefault: true }),
};

export const useGRCScopeQueryState = () => {
  const [queryScope, setQueryScope] = useQueryStates(scopeParsers, {
    history: "replace",
    scroll: false,
    shallow: true,
  });
  const tenantID = queryScope.tenant_id;
  const workspaceID = queryScope.workspace_id;
  const setTenantID = useCallback((nextValue: string) => {
    const normalized = cleanScopeValue(nextValue);
    void setQueryScope({
      tenant_id: normalized || null,
      workspace_id: normalized === tenantID.trim() ? workspaceID.trim() || null : null,
    });
  }, [setQueryScope, tenantID, workspaceID]);
  const setWorkspaceID = useCallback((nextValue: string) => {
    const normalized = cleanScopeValue(nextValue);
    void setQueryScope({ workspace_id: normalized || null });
  }, [setQueryScope]);

  return { tenantID, workspaceID, setTenantID, setWorkspaceID };
};

export const useDebouncedGRCScope = (scope: GRCScope, delayMs = 300) => {
  const tenantID = useDebouncedValue(scope.tenantID.trim(), delayMs);
  const workspaceID = useDebouncedValue(scope.workspaceID.trim(), delayMs);
  return useMemo(() => ({ tenantID, workspaceID }), [tenantID, workspaceID]);
};

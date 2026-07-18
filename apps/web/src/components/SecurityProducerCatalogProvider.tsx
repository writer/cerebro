"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import {
  fetchSecurityProducers,
  type SecurityProducerCatalogResult,
} from "@/lib/security-producers-client";

export type SecurityProducerCatalogState =
  | { state: "loading" }
  | SecurityProducerCatalogResult;

type SecurityProducerCatalogContextValue = {
  catalog: SecurityProducerCatalogState;
  retry: () => void;
};

const SecurityProducerCatalogContext = createContext<SecurityProducerCatalogContextValue | undefined>(undefined);

export function SecurityProducerCatalogProvider({ children }: { children: React.ReactNode }) {
  const [catalog, setCatalog] = useState<SecurityProducerCatalogState>({ state: "loading" });
  const [request, setRequest] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    fetchSecurityProducers({ signal: controller.signal }).then((result) => {
      if (!cancelled) setCatalog(result);
    });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [request]);

  const retry = useCallback(() => {
    setCatalog({ state: "loading" });
    setRequest((value) => value + 1);
  }, []);
  const value = useMemo(() => ({ catalog, retry }), [catalog, retry]);

  return (
    <SecurityProducerCatalogContext.Provider value={value}>
      {children}
    </SecurityProducerCatalogContext.Provider>
  );
}

export function useSecurityProducerCatalog() {
  const context = useContext(SecurityProducerCatalogContext);
  if (!context) {
    throw new Error("useSecurityProducerCatalog must be used inside SecurityProducerCatalogProvider");
  }
  return context;
}

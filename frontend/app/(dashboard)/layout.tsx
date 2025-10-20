import { ReactNode, Suspense } from "react";

import { DashboardShell } from "@/components/layout/dashboard-shell";
import { LoadingState } from "@/components/layout/loading-state";
import { RouteErrorBoundary } from "@/components/layout/route-error-boundary";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <DashboardShell>
      <RouteErrorBoundary>
        <Suspense fallback={<LoadingState />}>{children}</Suspense>
      </RouteErrorBoundary>
    </DashboardShell>
  );
}

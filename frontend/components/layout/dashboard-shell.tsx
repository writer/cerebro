import { ReactNode } from "react";
import { Sidebar } from "@/components/navigation/sidebar";
import { TopBar } from "@/components/navigation/topbar";

type DashboardShellProps = {
  children: ReactNode;
};

export function DashboardShell({ children }: DashboardShellProps) {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="lg:flex">
        <Sidebar />
        <div className="flex-1">
          <TopBar />
          <main className="px-4 py-6 lg:px-10 lg:py-8">
            <div className="mx-auto max-w-6xl space-y-6">{children}</div>
          </main>
        </div>
      </div>
    </div>
  );
}

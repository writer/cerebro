"use client";

import dynamic from "next/dynamic";
import { ArrowUpRight, LoaderCircle, MessageSquare } from "lucide-react";

import { useCerebroAgent } from "@/components/agent/CerebroAgentProvider";
import { isDenseAgentRouteLabel } from "@/components/agent/dense-routes";

const CerebroAgentPanel = dynamic(() => import("@/components/agent/CerebroAgentPanel"), {
  ssr: false,
  loading: () => null,
});

export default function CerebroAgentPanelShell() {
  const { activeTurnId, isOpen, openAgent, pageContext, turns } = useCerebroAgent();
  const activeTurn = turns.find((turn) => turn.id === activeTurnId);
  const densePage = isDenseAgentRouteLabel(pageContext.routeLabel);
  const quietLauncher = !activeTurn && (densePage || pageContext.pageState === "api_unavailable" || pageContext.pageState === "empty");
  const launcherPosition = quietLauncher && densePage ? "bottom-16 left-5 right-auto" : "bottom-5 right-5";

  if (isOpen) {
    return <CerebroAgentPanel />;
  }

  return (
    <button
      type="button"
      onClick={() => openAgent()}
      className={`agent-surface agent-launcher fixed z-40 hidden items-center gap-3 rounded-lg border border-slate-200 bg-white text-left shadow-[0_18px_45px_rgba(15,23,42,0.15)] transition duration-200 hover:-translate-y-0.5 hover:border-indigo-200 hover:shadow-[0_22px_55px_rgba(15,23,42,0.18)] sm:flex ${launcherPosition} ${quietLauncher ? "w-[58px] justify-center px-2.5 py-2.5" : "w-[234px] px-3 py-3"}`}
      aria-label="Open Ask"
      title={quietLauncher ? `Ask about ${pageContext.routeLabel ?? "this page"}` : undefined}
    >
      <span className={`grid shrink-0 place-items-center rounded-md border border-slate-200 bg-slate-950 text-white ${quietLauncher ? "h-9 w-9" : "h-10 w-10"}`}>
        {activeTurn ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <MessageSquare className="h-4 w-4" />}
      </span>
      <span className={quietLauncher ? "sr-only" : "min-w-0 flex-1 max-sm:sr-only"}>
        <span className="block text-[14px] font-semibold text-slate-950">Ask</span>
        <span className="mt-0.5 block truncate text-[12px] text-slate-500">
          {activeTurn ? "Working" : pageContext.routeLabel ?? "Ask about current data"}
        </span>
      </span>
      {!quietLauncher && <ArrowUpRight className="h-4 w-4 text-slate-400 max-sm:hidden" />}
    </button>
  );
}

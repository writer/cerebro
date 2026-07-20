"use client";

import Link from "next/link";
import { type KeyboardEvent, useMemo } from "react";
import {
  Activity,
  ArrowUpRight,
  Copy,
  Database,
  ExternalLink,
  LoaderCircle,
  Maximize2,
  MessageSquare,
  RefreshCw,
  Search,
  Send,
  Square,
  Trash2,
  X,
} from "lucide-react";

import MarkdownSummary from "@/components/ask/MarkdownSummary";
import { useCerebroAgent } from "@/components/agent/CerebroAgentProvider";
import { type AskAgentTimelineEvent, type AskTurnState, shortUrn } from "@/lib/ask";

const iconClass = "h-4 w-4";

const statusTone = (turn?: AskTurnState) => {
  if (!turn) return "border-slate-200 bg-white text-slate-600";
  if (turn.status === "streaming") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (turn.status === "error" || turn.status === "aborted") return "border-rose-200 bg-rose-50 text-rose-700";
  return "border-indigo-200 bg-indigo-50 text-indigo-700";
};

const statusLabel = (turn?: AskTurnState) => {
  if (!turn) return "Ready";
  if (turn.status === "streaming") return "Working";
  if (turn.status === "completed") return "Complete";
  if (turn.status === "aborted") return "Stopped";
  return "Attention";
};

const latestEvent = (turn?: AskTurnState) => turn?.agentEvents?.at(-1);

const formatEvent = (event: AskAgentTimelineEvent) => {
  if (event.type === "tool") {
    const verb =
      event.status === "started"
        ? "Calling"
        : event.status === "completed"
          ? "Read"
          : "Tool error";
    return `${verb} ${event.name}`;
  }
  return event.label;
};

const samplePrompts = (routeLabel?: string, scope?: string, pageState?: string) => {
  if (pageState === "api_unavailable") {
    return [
      {
        label: "Check API health",
        prompt: `On the ${routeLabel ?? "current"} screen, explain why data is unavailable and what health checks I should run next.`,
        icon: Activity,
      },
      {
        label: "Plan recovery",
        prompt: "List the fastest recovery steps for restoring API access and validating that the UI is healthy again.",
        icon: RefreshCw,
      },
      {
        label: "Explain empty graph",
        prompt: scope
          ? `Explain what data should appear for ${scope} once the API is reachable.`
          : "Explain what data should appear here once the API is reachable.",
        icon: Database,
      },
    ];
  }
  if (pageState === "empty") {
    return [
      {
        label: "Why empty?",
        prompt: `Explain why ${routeLabel ?? "this page"} is empty and what filters or inputs I should check first.`,
        icon: Search,
      },
      {
        label: "Find a root",
        prompt: "Find a good entity or finding to use as the next investigation root.",
        icon: Activity,
      },
      {
        label: "Next query",
        prompt: "Suggest the next query or filter that would make this screen useful.",
        icon: Database,
      },
    ];
  }
  return [
    {
      label: "What needs attention?",
      prompt: `On ${routeLabel ?? "this page"}, identify the highest-risk item I should inspect next and why.`,
      icon: Search,
    },
    {
      label: "Gather evidence",
      prompt: scope
        ? `Find the strongest evidence, source freshness, and connected findings for ${scope}.`
        : "Find the strongest evidence and source freshness for the current investigation context.",
      icon: Database,
    },
    {
      label: "Map impact",
      prompt: scope
        ? `Map affected entities and likely impact paths for ${scope}.`
        : "Map the affected entities for the current screen's most important entity.",
      icon: Activity,
    },
  ];
};

const answerText = (turn: AskTurnState) => turn.summary?.markdown ?? turn.agentAnswerDraft ?? "";

export default function CerebroAgentPanel() {
  const {
    activeTurnId,
    clearThread,
    draft,
    isOpen,
    openAgent,
    pageContext,
    retryTurn,
    setDraft,
    setOpen,
    stopActiveTurn,
    submitDraft,
    turns,
  } = useCerebroAgent();

  const latestTurn = turns.at(-1);
  const activeTurn = turns.find((turn) => turn.id === activeTurnId);
  const currentStatus = latestEvent(latestTurn);
  const quietLauncher = !activeTurn && (pageContext.pageState === "api_unavailable" || pageContext.pageState === "empty");
  const prompts = useMemo(
    () => samplePrompts(pageContext.routeLabel, pageContext.scopeUrn ?? pageContext.entityUrn, pageContext.pageState),
    [pageContext.entityUrn, pageContext.pageState, pageContext.routeLabel, pageContext.scopeUrn],
  );

  const onComposerKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      submitDraft();
    }
  };

  if (!isOpen) {
    return (
      <button
        type="button"
        onClick={() => openAgent()}
        className={`agent-surface agent-launcher fixed bottom-5 right-5 z-40 hidden items-center gap-3 rounded-lg border border-slate-200 bg-white text-left shadow-[0_18px_45px_rgba(15,23,42,0.15)] transition duration-200 hover:-translate-y-0.5 hover:border-indigo-200 hover:shadow-[0_22px_55px_rgba(15,23,42,0.18)] sm:flex ${quietLauncher ? "w-[58px] justify-center px-2.5 py-2.5" : "w-[234px] px-3 py-3"}`}
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

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-slate-950/20 backdrop-blur-[1px] md:hidden"
        onClick={() => setOpen(false)}
      />
      <aside
        data-cerebro-agent-panel
        className="agent-panel agent-surface fixed inset-x-2 bottom-2 top-2 z-40 flex flex-col overflow-hidden rounded-lg border border-slate-200 bg-[#fbfaf7] text-slate-950 shadow-[0_28px_90px_rgba(15,23,42,0.22)] md:inset-x-auto md:right-4 md:w-[500px]"
      >
        <div className="agent-rail absolute left-0 top-0 h-full w-[4px]" />

        <header className="relative border-b border-slate-200 bg-white/90 px-5 py-4 backdrop-blur">
          <div className="flex items-start justify-between gap-4">
            <div className="flex min-w-0 items-center gap-3">
              <div className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-slate-200 bg-slate-950 text-white shadow-sm">
                <MessageSquare className="h-4.5 w-4.5" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h2 className="truncate text-[16px] font-semibold text-slate-950">Ask</h2>
                  <span className={`agent-mono rounded-full border px-2 py-0.5 text-[10px] uppercase ${statusTone(latestTurn)}`}>
                    {statusLabel(latestTurn)}
                  </span>
                </div>
                <p className="mt-1 truncate text-[12px] text-slate-500">
                  {currentStatus ? formatEvent(currentStatus) : `Working from ${pageContext.routeLabel ?? "this screen"}`}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              <Link
                href="/ask"
                className="grid h-9 w-9 place-items-center rounded-md border border-slate-200 bg-white text-slate-500 transition hover:border-slate-300 hover:text-slate-900"
                title="Open full Ask"
              >
                <Maximize2 className={iconClass} />
              </Link>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="grid h-9 w-9 place-items-center rounded-md border border-slate-200 bg-white text-slate-500 transition hover:border-slate-300 hover:text-slate-900"
                title="Close Ask"
              >
                <X className={iconClass} />
              </button>
            </div>
          </div>

          <div className="mt-4 flex gap-2 overflow-x-auto pb-1">
            {(pageContext.chips?.length ? pageContext.chips : [{ label: "Page", value: pageContext.routeLabel ?? "Current page" }]).map((chip) => (
              <span
                key={`${chip.label}:${chip.value}`}
                className="agent-mono inline-flex shrink-0 items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-[10px] text-slate-600"
                title={chip.value}
              >
                <span className="font-semibold text-indigo-700">{chip.label.toUpperCase()}</span>
                <span className="max-w-[230px] truncate">{shortUrn(chip.value)}</span>
              </span>
            ))}
          </div>
        </header>

        <div className="relative min-h-0 flex-1 overflow-y-auto px-5 py-5">
          {turns.length === 0 ? (
            <div className="space-y-5">
              <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
                <div className="agent-mono text-[10px] font-semibold uppercase text-indigo-700">
                  Ask
                </div>
                <h3 className="mt-3 text-[27px] font-semibold leading-tight tracking-normal text-slate-950">
                  Ask about this page.
                </h3>
                <p className="mt-3 text-[14px] leading-6 text-slate-600">
                  Use the current filters, selected entity, and page context to check findings, evidence, affected assets, source health, and next steps.
                </p>
              </section>

              <section className="rounded-lg border border-slate-200 bg-white shadow-sm">
                <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
                  <span className="text-[13px] font-semibold text-slate-900">Suggested questions</span>
                  <span className="agent-mono text-[10px] uppercase text-slate-400">{pageContext.routeLabel ?? "Global"}</span>
                </div>
                <div className="divide-y divide-slate-100">
                  {prompts.map((prompt) => {
                    const Icon = prompt.icon;
                    return (
                      <button
                        key={prompt.label}
                        type="button"
                        onClick={() => setDraft(prompt.prompt)}
                        className="group grid w-full grid-cols-[36px_1fr_20px] items-center gap-3 px-4 py-3.5 text-left transition hover:bg-indigo-50/50"
                      >
                        <span className="grid h-9 w-9 place-items-center rounded-md border border-slate-200 bg-slate-50 text-slate-600 group-hover:border-indigo-200 group-hover:text-indigo-700">
                          <Icon className={iconClass} />
                        </span>
                        <span className="min-w-0">
                          <span className="block text-[13px] font-semibold text-slate-900">{prompt.label}</span>
                          <span className="mt-0.5 block truncate text-[12px] text-slate-500">{prompt.prompt}</span>
                        </span>
                        <ExternalLink className="h-3.5 w-3.5 text-slate-300 group-hover:text-indigo-500" />
                      </button>
                    );
                  })}
                </div>
              </section>
            </div>
          ) : (
            <div className="space-y-4">
              {turns.map((turn) => (
                <AgentTurnCard
                  key={turn.id}
                  turn={turn}
                  isActive={turn.id === activeTurnId}
                  onRetry={() => retryTurn(turn)}
                  onStop={stopActiveTurn}
                />
              ))}
            </div>
          )}
        </div>

        <footer className="border-t border-slate-200 bg-white p-3">
          <div className="rounded-lg border border-slate-200 bg-white shadow-sm focus-within:border-indigo-300 focus-within:ring-2 focus-within:ring-indigo-100">
            <textarea
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={onComposerKeyDown}
              rows={3}
              placeholder="Ask about this page, a finding, evidence, ownership, or affected assets..."
              className="block max-h-36 min-h-20 w-full resize-none rounded-lg border-0 bg-transparent px-3 py-2.5 text-[14px] leading-5 text-slate-900 outline-none placeholder:text-slate-400"
            />
            <div className="flex items-center justify-between border-t border-slate-100 px-2.5 py-2">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={clearThread}
                  disabled={!turns.length && !draft}
                  className="rounded-md p-2 text-slate-400 transition hover:bg-slate-50 hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
                  title="Clear"
                >
                  <Trash2 className={iconClass} />
                </button>
                {activeTurnId && (
                  <button
                    type="button"
                    onClick={stopActiveTurn}
                    className="rounded-md p-2 text-rose-500 transition hover:bg-rose-50"
                    title="Stop"
                  >
                    <Square className={iconClass} />
                  </button>
                )}
                <span className="agent-mono hidden text-[10px] uppercase text-slate-400 sm:inline">
                  Cmd Enter to ask
                </span>
              </div>
              <button
                type="button"
                onClick={submitDraft}
                disabled={!draft.trim() || Boolean(activeTurnId)}
                className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-[13px] font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300"
              >
                {activeTurnId ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                Ask
              </button>
            </div>
          </div>
        </footer>
      </aside>
    </>
  );
}

function AgentTurnCard({
  isActive,
  onRetry,
  onStop,
  turn,
}: {
  isActive: boolean;
  onRetry: () => void;
  onStop: () => void;
  turn: AskTurnState;
}) {
  const answer = answerText(turn);
  const events = (turn.agentEvents ?? []).slice(-6);
  const copy = async () => {
    if (!answer) return;
    await navigator.clipboard.writeText(answer).catch(() => undefined);
  };

  return (
    <article className="rounded-lg border border-slate-200 bg-white shadow-sm">
      <header className="border-b border-slate-100 px-4 py-3">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 rounded-md border border-slate-200 bg-slate-50 p-1.5 text-slate-500">
            <MessageSquare className="h-3.5 w-3.5" />
          </div>
          <p className="min-w-0 flex-1 text-[13px] font-medium leading-5 text-slate-900">{turn.question}</p>
        </div>
      </header>

      <div className="space-y-3 px-4 py-3">
        {events.length > 0 && (
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div className="agent-mono mb-2 text-[10px] font-semibold uppercase text-slate-400">
              Agent progress
            </div>
            <div className="space-y-1.5">
              {events.map((event) => (
                <div key={`${event.at}:${formatEvent(event)}`} className="grid grid-cols-[10px_1fr] items-start gap-2 text-[12px] text-slate-500">
                  <span
                    className={`mt-1.5 h-1.5 w-1.5 rounded-full ${
                      event.type === "tool"
                        ? event.status === "completed"
                          ? "bg-emerald-500"
                          : "bg-amber-500"
                        : "bg-indigo-500"
                    }`}
                  />
                  <span className="min-w-0 truncate">{formatEvent(event)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {turn.error && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 p-3 text-[13px] leading-5 text-rose-800">
            {turn.error.message}
          </div>
        )}

        {answer ? (
          <div className="agent-markdown rounded-lg border border-indigo-100 bg-indigo-50/70 p-4">
            <MarkdownSummary markdown={answer} citations={turn.summary?.citations} />
          </div>
        ) : (
          !turn.error && (
            <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-[13px] text-slate-500">
              <LoaderCircle className="h-4 w-4 animate-spin text-emerald-600" />
              Reading current context...
            </div>
          )
        )}

        <div className="flex items-center justify-between border-t border-slate-100 pt-2">
          <div className="agent-mono text-[10px] uppercase text-slate-400">
            {turn.agentMode === "legacy" ? "Legacy Ask stream" : "Graph tools"}
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={copy}
              disabled={!answer}
              className="rounded-md p-1.5 text-slate-400 transition hover:bg-slate-50 hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
              title="Copy answer"
            >
              <Copy className="h-3.5 w-3.5" />
            </button>
            {isActive ? (
              <button
                type="button"
                onClick={onStop}
                className="rounded-md p-1.5 text-rose-500 transition hover:bg-rose-50"
                title="Stop"
              >
                <Square className="h-3.5 w-3.5" />
              </button>
            ) : (
              <button
                type="button"
                onClick={onRetry}
                className="rounded-md p-1.5 text-slate-400 transition hover:bg-slate-50 hover:text-slate-700"
                title="Retry"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>
    </article>
  );
}

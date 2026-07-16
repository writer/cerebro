"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useApiKey } from "@/components/providers";
import { PageHeader } from "@/components/grc/Primitives";
import AskInput from "@/components/ask/AskInput";
import AskThread from "@/components/ask/AskThread";
import SavedQuestions, { type SavedQuestionDraft } from "@/components/ask/SavedQuestions";
import type { AskAgentReadiness } from "@/lib/ask-agent-status";
import {
  type AskHistoryEntry,
  type AskRequest,
  type AskTurnState,
  askEmptyState,
  defaultAskModel,
  markAskTurnAborted,
  normalizeAskModel,
  reduceAskEvent,
  streamAgentAsk,
} from "@/lib/ask";
import {
  type AskQuery,
  type AskQueryListResponse,
  askQueryCreatePayload,
} from "@/lib/ask-queries";
import { useGRCMutation, useGRCQuery } from "@/lib/grc-client";

const sampleQuestions = [
  "Which risks are open?",
  "Which risks have no owner?",
  "Which controls are failing?",
  "Which evidence is missing or stale?",
  "Which sources are stale?",
  "What changed since last week?",
];

function AskPageInner() {
  const { apiKey } = useApiKey();
  const searchParams = useSearchParams();
  const [turns, setTurns] = useState<AskTurnState[]>([]);
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [readiness, setReadiness] = useState<AskAgentReadiness | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(true);
  const abortRef = useRef<AbortController | null>(null);
  const autoFiredRef = useRef(false);

  const seededQuestion = searchParams.get("q") ?? "";
  const seededScope = searchParams.get("scope_urn") ?? "";
  const seededModel = searchParams.get("model") ?? "";
  const seededTenant = searchParams.get("tenant_id") ?? "";

  const history = useMemo<AskHistoryEntry[]>(
    () =>
      turns.flatMap((turn) => {
        const entries: AskHistoryEntry[] = [{ role: "user", content: turn.question }];
        if (turn.summary?.markdown) {
          entries.push({ role: "assistant", content: turn.summary.markdown });
        }
        return entries;
      }),
    [turns],
  );

  const stopActiveTurn = useCallback(() => {
    const activeID = activeTurnId;
    abortRef.current?.abort();
    abortRef.current = null;
    setActiveTurnId(null);
    if (activeID) {
      setTurns((prev) => prev.map((turn) => (turn.id === activeID ? markAskTurnAborted(turn) : turn)));
    }
  }, [activeTurnId]);

  const runAsk = useCallback(
    async (input: { question: string; model: string; tenantId: string; scopeUrn: string }) => {
      const controller = new AbortController();
      abortRef.current?.abort();
      abortRef.current = controller;
      const turnId = typeof crypto !== "undefined" ? crypto.randomUUID() : `t-${Date.now()}`;
      const model = normalizeAskModel(input.model);
      const tenantId = input.tenantId || "writer";
      const initial = askEmptyState({
        id: turnId,
        question: input.question,
        startedAt: Date.now(),
        updatedAt: Date.now(),
        model,
        tenantId,
        scopeUrn: input.scopeUrn || undefined,
      });
      setTurns((prev) => [...prev, initial]);
      setActiveTurnId(turnId);
      const request: AskRequest = {
        tenant_id: tenantId,
        question: input.question,
        scope_urn: input.scopeUrn || undefined,
        model,
        history,
        context: {
          route: "/ask",
          routeLabel: "Ask",
          scopeUrn: input.scopeUrn || undefined,
          chips: [
            { label: "Screen", value: "Ask" },
            ...(input.scopeUrn ? [{ label: "Scope", value: input.scopeUrn }] : []),
          ],
        },
        surface: "ask_page",
      };
      try {
        for await (const event of streamAgentAsk(request, apiKey, controller.signal)) {
          setTurns((prev) =>
            prev.map((turn) => (turn.id === turnId ? reduceAskEvent(turn, event) : turn)),
          );
          if (event.type === "done" || event.type === "error") {
            setActiveTurnId(null);
          }
        }
      } catch (error) {
        if (controller.signal.aborted) {
          setActiveTurnId(null);
          setTurns((prev) => prev.map((turn) => (turn.id === turnId ? markAskTurnAborted(turn) : turn)));
          return;
        }
        setTurns((prev) =>
          prev.map((turn) =>
            turn.id === turnId
              ? {
                  ...turn,
                  status: "error",
                  updatedAt: Date.now(),
                  error: {
                    code: "client_exception",
                    message: error instanceof Error ? error.message : "Ask stream failed",
                  },
                }
              : turn,
          ),
        );
        setActiveTurnId(null);
      }
    },
    [apiKey, history],
  );

  const retryTurn = useCallback(
    (turn: AskTurnState) => {
      void runAsk({
        question: turn.question,
        model: normalizeAskModel(turn.model),
        tenantId: turn.tenantId ?? "writer",
        scopeUrn: turn.scopeUrn ?? "",
      });
    },
    [runAsk],
  );

  const savedQueriesQuery = useGRCQuery<AskQueryListResponse>("/ask-queries");
  const { mutate: mutateSavedQuery, saving: savingSavedQuery, error: savedQueryError, setError: setSavedQueryError } =
    useGRCMutation();
  const [saveDraft, setSaveDraft] = useState<SavedQuestionDraft | null>(null);
  const savedQueries = savedQueriesQuery.data?.queries ?? [];

  useEffect(() => {
    const controller = new AbortController();
    const loadReadiness = async () => {
      setReadinessLoading(true);
      try {
        const response = await fetch("/api/agent/ask/status", { cache: "no-store", signal: controller.signal });
        if (!response.ok) return;
        setReadiness(await response.json() as AskAgentReadiness);
      } catch {
        if (!controller.signal.aborted) {
          setReadiness(null);
        }
      } finally {
        if (!controller.signal.aborted) {
          setReadinessLoading(false);
        }
      }
    };
    void loadReadiness();
    return () => controller.abort();
  }, []);

  const requestSaveQuestion = useCallback(
    (input: SavedQuestionDraft) => {
      setSavedQueryError(null);
      setSaveDraft(input);
    },
    [setSavedQueryError],
  );

  const saveDraftAs = useCallback(
    async (name: string) => {
      if (!saveDraft) return;
      try {
        await mutateSavedQuery(
          "/ask-queries",
          askQueryCreatePayload({
            name,
            question: saveDraft.question,
            scopeUrn: saveDraft.scopeUrn,
            model: saveDraft.model,
          }),
        );
        setSaveDraft(null);
        void savedQueriesQuery.reload();
      } catch {
        // Surfaced via savedQueryError.
      }
    },
    [mutateSavedQuery, saveDraft, savedQueriesQuery],
  );

  const runSavedQuery = useCallback(
    (query: AskQuery) => {
      void runAsk({
        question: query.question,
        model: normalizeAskModel(query.model ?? ""),
        tenantId: query.tenant_id || "",
        scopeUrn: query.scope_urn ?? "",
      });
    },
    [runAsk],
  );

  const toggleSavedQueryPin = useCallback(
    async (query: AskQuery) => {
      setSavedQueryError(null);
      try {
        await mutateSavedQuery(`/ask-queries/${encodeURIComponent(query.id)}`, { pinned: !query.pinned }, "PATCH");
        void savedQueriesQuery.reload();
      } catch {
        // Surfaced via savedQueryError.
      }
    },
    [mutateSavedQuery, savedQueriesQuery, setSavedQueryError],
  );

  const deleteSavedQuery = useCallback(
    async (query: AskQuery) => {
      setSavedQueryError(null);
      try {
        await mutateSavedQuery(`/ask-queries/${encodeURIComponent(query.id)}`, undefined, "DELETE");
        void savedQueriesQuery.reload();
      } catch {
        // Surfaced via savedQueryError.
      }
    },
    [mutateSavedQuery, savedQueriesQuery, setSavedQueryError],
  );

  useEffect(() => {
    const question = seededQuestion.trim();
    if (autoFiredRef.current || !question) return;
    const timer = window.setTimeout(() => {
      if (autoFiredRef.current) return;
      autoFiredRef.current = true;
      void runAsk({
        question,
        model: seededModel || defaultAskModel,
        tenantId: seededTenant,
        scopeUrn: seededScope,
      });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [runAsk, seededModel, seededQuestion, seededScope, seededTenant]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Ask"
        description="Ask about risks, controls, evidence, owners, sources, reports, or affected assets."
        action={
          turns.length > 0 ? (
            <div className="flex flex-wrap items-center gap-2">
              {activeTurnId && (
                <button
                  type="button"
                  onClick={stopActiveTurn}
                  className="rounded-md border border-rose-200 px-3 py-1.5 text-[13px] font-medium text-rose-700 transition hover:border-rose-300 hover:bg-rose-50"
                >
                  Stop
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  abortRef.current?.abort();
                  setTurns([]);
                  setActiveTurnId(null);
                }}
                className="rounded-md border border-slate-200 px-3 py-1.5 text-[13px] font-medium text-slate-600 transition hover:border-slate-300"
              >
                Clear thread
              </button>
            </div>
          ) : undefined
        }
      />

      <AskInput
        onSubmit={runAsk}
        disabled={Boolean(activeTurnId)}
        initialScopeUrn={seededScope}
        onSaveQuestion={requestSaveQuestion}
        readiness={readiness}
        readinessLoading={readinessLoading}
      />

      <SavedQuestions
        queries={savedQueries}
        loading={savedQueriesQuery.loading}
        busy={savingSavedQuery}
        error={savedQueryError}
        draft={saveDraft}
        onSaveDraft={saveDraftAs}
        onDismissDraft={() => setSaveDraft(null)}
        onRun={runSavedQuery}
        onTogglePin={toggleSavedQueryPin}
        onDelete={deleteSavedQuery}
        disabled={Boolean(activeTurnId)}
      />

      {turns.length === 0 && (
        <section className="rounded-lg border border-dashed border-slate-300 bg-white p-4">
          <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Common questions</div>
          <div className="mt-3 flex flex-wrap gap-2">
            {sampleQuestions.map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() =>
                  void runAsk({ question: sample, model: defaultAskModel, tenantId: "", scopeUrn: "" })
                }
                className="rounded-full border border-slate-200 bg-white px-3 py-1 text-[13px] text-slate-700 transition hover:border-indigo-300 hover:text-indigo-700"
              >
                {sample}
              </button>
            ))}
          </div>
        </section>
      )}

      <AskThread turns={turns} activeTurnId={activeTurnId} onRetry={retryTurn} onStop={stopActiveTurn} />
    </div>
  );
}

export default function AskPage() {
  return (
    <Suspense fallback={null}>
      <AskPageInner />
    </Suspense>
  );
}

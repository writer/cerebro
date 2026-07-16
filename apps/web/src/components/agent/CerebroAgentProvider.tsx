"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useApiKey } from "@/components/providers";
import {
  type AskAgentContext,
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
import { routeLabelForPath } from "@/lib/route-labels";

type RunAgentInput = {
  question: string;
  tenantId?: string;
  scopeUrn?: string;
  model?: string;
  context?: AskAgentContext;
  surface?: string;
};

type OpenAgentOptions = {
  question?: string;
  scopeUrn?: string;
  context?: AskAgentContext;
  autoSubmit?: boolean;
};

type CerebroAgentContextValue = {
  isOpen: boolean;
  setOpen: (value: boolean) => void;
  draft: string;
  setDraft: (value: string) => void;
  turns: AskTurnState[];
  activeTurnId: string | null;
  pageContext: AskAgentContext;
  openAgent: (options?: OpenAgentOptions) => void;
  runAgent: (input: RunAgentInput) => Promise<void>;
  retryTurn: (turn: AskTurnState) => void;
  stopActiveTurn: () => void;
  clearThread: () => void;
  submitDraft: () => void;
};

const CerebroAgentContext = createContext<CerebroAgentContextValue | undefined>(undefined);

const capturePageContext = (): AskAgentContext => {
  if (typeof window === "undefined") {
    return { route: "/", routeLabel: "Cerebro", chips: [] };
  }
  const url = new URL(window.location.href);
  const pathname = url.pathname;
  const scopeUrn =
    url.searchParams.get("scope_urn") ??
    url.searchParams.get("root_urn") ??
    url.searchParams.get("urn") ??
    undefined;
  const findingFromQuery = url.searchParams.get("finding_id") ?? undefined;
  const findingFromPath = pathname.startsWith("/findings/")
    ? decodeURIComponent(pathname.split("/").filter(Boolean).at(-1) ?? "")
    : undefined;
  const resourceUrn = pathname.startsWith("/inventory/")
    ? decodeURIComponent(pathname.split("/").filter(Boolean).at(-1) ?? "")
    : undefined;
  const routeLabel = routeLabelForPath(pathname);
  const bodyText = document.body?.innerText?.toLowerCase() ?? "";
  const pageState = bodyText.includes("cerebro api unavailable")
    ? "api_unavailable"
    : /\b(no .*available|no .*match|enter .*to query)\b/.test(bodyText)
      ? "empty"
      : "ready";
  const chips = [
    { label: "Screen", value: routeLabel },
    pageState !== "ready" ? { label: "State", value: pageState === "api_unavailable" ? "API unavailable" : "Empty" } : null,
    scopeUrn ? { label: "Scope", value: scopeUrn } : null,
    findingFromQuery || findingFromPath
      ? { label: "Finding", value: findingFromQuery ?? findingFromPath ?? "" }
      : null,
    resourceUrn ? { label: "Resource", value: resourceUrn } : null,
  ].filter(Boolean) as NonNullable<AskAgentContext["chips"]>;

  return {
    route: pathname,
    routeLabel,
    href: `${url.pathname}${url.search}`,
    title: typeof document !== "undefined" ? document.title : undefined,
    scopeUrn,
    findingId: findingFromQuery ?? findingFromPath,
    entityUrn: scopeUrn,
    pageState,
    resourceUrn,
    chips,
  };
};

const mergeContext = (
  base: AskAgentContext,
  override?: AskAgentContext,
  scopeUrn?: string,
): AskAgentContext => {
  const chips = [
    ...(base.chips ?? []),
    ...(override?.chips ?? []),
    scopeUrn ? { label: "Scope", value: scopeUrn } : null,
  ].filter(Boolean) as NonNullable<AskAgentContext["chips"]>;
  const deduped = chips.filter(
    (chip, index) =>
      chips.findIndex((candidate) => candidate.label === chip.label && candidate.value === chip.value) === index,
  );
  return {
    ...base,
    ...override,
    scopeUrn: scopeUrn ?? override?.scopeUrn ?? base.scopeUrn,
    entityUrn: override?.entityUrn ?? scopeUrn ?? base.entityUrn,
    chips: deduped,
  };
};

function createConversationId() {
  return typeof crypto !== "undefined" ? crypto.randomUUID() : `c-${Date.now()}`;
}

export function CerebroAgentProvider({ children }: { children: React.ReactNode }) {
  const { apiKey } = useApiKey();
  const [isOpen, setOpen] = useState(false);
  const [draft, setDraft] = useState("");
  const [turns, setTurns] = useState<AskTurnState[]>([]);
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [pageContext, setPageContext] = useState<AskAgentContext>(() => ({
    route: "/",
    routeLabel: "Cerebro",
    chips: [],
  }));
  const abortRef = useRef<AbortController | null>(null);
  const conversationIdRef = useRef<string | null>(null);
  const getConversationId = useCallback(() => {
    conversationIdRef.current ??= createConversationId();
    return conversationIdRef.current;
  }, []);

  useEffect(() => {
    const refresh = () => setPageContext(capturePageContext());
    refresh();
    const originalPushState = window.history.pushState;
    const originalReplaceState = window.history.replaceState;
    window.history.pushState = function pushState(...args) {
      originalPushState.apply(this, args);
      window.setTimeout(refresh, 0);
    };
    window.history.replaceState = function replaceState(...args) {
      originalReplaceState.apply(this, args);
      window.setTimeout(refresh, 0);
    };
    window.addEventListener("popstate", refresh);
    return () => {
      window.history.pushState = originalPushState;
      window.history.replaceState = originalReplaceState;
      window.removeEventListener("popstate", refresh);
    };
  }, []);

  const history = useMemo<AskHistoryEntry[]>(
    () =>
      turns.flatMap((turn) => {
        const entries: AskHistoryEntry[] = [{ role: "user", content: turn.question }];
        const answer = turn.summary?.markdown ?? turn.agentAnswerDraft;
        if (answer) entries.push({ role: "assistant", content: answer });
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

  const runAgent = useCallback(
    async (input: RunAgentInput) => {
      const question = input.question.trim();
      if (!question) return;

      const context = mergeContext(capturePageContext(), input.context, input.scopeUrn);
      setPageContext(context);
      setOpen(true);
      setDraft("");

      const controller = new AbortController();
      abortRef.current?.abort();
      abortRef.current = controller;
      const turnId = typeof crypto !== "undefined" ? crypto.randomUUID() : `t-${Date.now()}`;
      const model = normalizeAskModel(input.model ?? defaultAskModel);
      const tenantId = input.tenantId || "writer";
      const scopeUrn = input.scopeUrn ?? context.scopeUrn ?? "";
      const initial = askEmptyState({
        id: turnId,
        question,
        model,
        tenantId,
        scopeUrn: scopeUrn || undefined,
      });
      setTurns((prev) => [...prev, initial]);
      setActiveTurnId(turnId);

      const request: AskRequest = {
        tenant_id: tenantId,
        question,
        scope_urn: scopeUrn || undefined,
        model,
        history,
        context,
        surface: input.surface ?? "agent_panel",
        conversation_id: getConversationId(),
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
                    message: error instanceof Error ? error.message : "Cerebro agent stream failed",
                  },
                }
              : turn,
          ),
        );
        setActiveTurnId(null);
      }
    },
    [apiKey, getConversationId, history],
  );

  const openAgent = useCallback(
    (options: OpenAgentOptions = {}) => {
      const context = mergeContext(capturePageContext(), options.context, options.scopeUrn);
      setPageContext(context);
      setOpen(true);
      if (options.question) {
        setDraft(options.question);
        if (options.autoSubmit) {
          void runAgent({
            question: options.question,
            scopeUrn: options.scopeUrn,
            context,
            surface: "agent_panel",
          });
        }
      }
    },
    [runAgent],
  );

  const retryTurn = useCallback(
    (turn: AskTurnState) => {
      void runAgent({
        question: turn.question,
        model: turn.model,
        tenantId: turn.tenantId,
        scopeUrn: turn.scopeUrn,
        context: pageContext,
        surface: "agent_panel_retry",
      });
    },
    [pageContext, runAgent],
  );

  const clearThread = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setTurns([]);
    setActiveTurnId(null);
    setDraft("");
    conversationIdRef.current = null;
  }, []);

  const submitDraft = useCallback(() => {
    if (!draft.trim() || activeTurnId) return;
    void runAgent({
      question: draft,
      context: pageContext,
      surface: "agent_panel",
    });
  }, [activeTurnId, draft, pageContext, runAgent]);

  const value = useMemo<CerebroAgentContextValue>(
    () => ({
      isOpen,
      setOpen,
      draft,
      setDraft,
      turns,
      activeTurnId,
      pageContext,
      openAgent,
      runAgent,
      retryTurn,
      stopActiveTurn,
      clearThread,
      submitDraft,
    }),
    [
      activeTurnId,
      clearThread,
      draft,
      isOpen,
      openAgent,
      pageContext,
      retryTurn,
      runAgent,
      stopActiveTurn,
      submitDraft,
      turns,
    ],
  );

  return (
    <CerebroAgentContext.Provider value={value}>
      {children}
    </CerebroAgentContext.Provider>
  );
}

export function useCerebroAgent() {
  const context = useContext(CerebroAgentContext);
  if (!context) {
    throw new Error("useCerebroAgent must be used within CerebroAgentProvider");
  }
  return context;
}

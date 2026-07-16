"use client";

import { Bookmark, Pin, PinOff, Play, Trash2, X } from "lucide-react";
import { useState } from "react";

import {
  type AskQuery,
  defaultAskQueryName,
  sortAskQueries,
  summarizeQuestion,
  validateAskQueryName,
} from "@/lib/ask-queries";

export type SavedQuestionDraft = {
  question: string;
  model: string;
  tenantId: string;
  scopeUrn: string;
};

type Props = {
  queries: AskQuery[];
  loading?: boolean;
  busy?: boolean;
  error?: string | null;
  draft: SavedQuestionDraft | null;
  onSaveDraft: (name: string) => void;
  onDismissDraft: () => void;
  onRun: (query: AskQuery) => void;
  onTogglePin: (query: AskQuery) => void;
  onDelete: (query: AskQuery) => void;
  disabled?: boolean;
};

const iconButtonClass =
  "inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1 text-[12px] font-medium text-slate-600 transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50";

export default function SavedQuestions({
  queries,
  loading = false,
  busy = false,
  error = null,
  draft,
  onSaveDraft,
  onDismissDraft,
  onRun,
  onTogglePin,
  onDelete,
  disabled = false,
}: Props) {
  const [name, setName] = useState("");
  const [nameError, setNameError] = useState<string | null>(null);
  const [seededQuestion, setSeededQuestion] = useState<string | null>(null);

  if (draft && draft.question !== seededQuestion) {
    setSeededQuestion(draft.question);
    setName(defaultAskQueryName(draft.question));
    setNameError(null);
  }
  if (!draft && seededQuestion !== null) {
    setSeededQuestion(null);
  }

  const sorted = sortAskQueries(queries);

  const confirmSave = () => {
    const validation = validateAskQueryName(name);
    if (!validation.ok) {
      setNameError(validation.error);
      return;
    }
    setNameError(null);
    onSaveDraft(validation.name);
  };

  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
          <Bookmark className="h-3.5 w-3.5" />
          Saved questions
        </div>
        <span className="text-[11px] text-slate-400">{sorted.length} saved</span>
      </div>

      {draft && (
        <div className="mt-3 rounded-md border border-indigo-200 bg-indigo-50/60 p-3">
          <div className="text-[12px] text-slate-600">
            Save: <span className="text-slate-900">{summarizeQuestion(draft.question, 120)}</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  confirmSave();
                }
              }}
              placeholder="Name this question"
              className="min-w-0 flex-1 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30"
            />
            <button
              type="button"
              onClick={confirmSave}
              disabled={busy}
              className="rounded-md bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Save
            </button>
            <button
              type="button"
              onClick={onDismissDraft}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-1.5 text-[12px] font-medium text-slate-600 transition hover:border-slate-300"
            >
              <X className="h-3.5 w-3.5" />
              Cancel
            </button>
          </div>
          {nameError && <div className="mt-2 text-[12px] text-rose-600">{nameError}</div>}
        </div>
      )}

      {error && <div className="mt-3 rounded-md border border-rose-200 bg-rose-50 p-2 text-[12px] text-rose-700">{error}</div>}

      {loading && sorted.length === 0 ? (
        <div className="mt-3 text-[13px] text-slate-400">Loading saved questions…</div>
      ) : sorted.length === 0 ? (
        <div className="mt-3 text-[13px] text-slate-500">
          No saved questions yet. Type a question above and choose <span className="font-medium text-slate-700">Save</span> to reuse it later.
        </div>
      ) : (
        <ul className="mt-3 space-y-2">
          {sorted.map((query) => (
            <li
              key={query.id}
              className="flex flex-wrap items-start justify-between gap-3 rounded-md border border-slate-100 bg-slate-50/60 p-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  {query.pinned && <Pin className="h-3 w-3 text-indigo-500" />}
                  <span className="truncate text-[13px] font-medium text-slate-900">{query.name}</span>
                </div>
                <div className="mt-1 text-[12px] text-slate-500">{summarizeQuestion(query.question)}</div>
                {query.scope_urn && (
                  <div className="mt-1 inline-block rounded bg-slate-200/70 px-1.5 py-0.5 text-[11px] text-slate-600">
                    {query.scope_urn}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => onRun(query)}
                  disabled={disabled}
                  className="inline-flex items-center gap-1 rounded-md bg-indigo-500 px-2.5 py-1 text-[12px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Play className="h-3 w-3" />
                  Run
                </button>
                <button
                  type="button"
                  onClick={() => onTogglePin(query)}
                  disabled={busy}
                  className={iconButtonClass}
                  aria-label={query.pinned ? "Unpin question" : "Pin question"}
                >
                  {query.pinned ? <PinOff className="h-3.5 w-3.5" /> : <Pin className="h-3.5 w-3.5" />}
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(query)}
                  disabled={busy}
                  className={iconButtonClass}
                  aria-label="Delete question"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

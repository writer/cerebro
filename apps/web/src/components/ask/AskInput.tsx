"use client";

import { useForm } from "@tanstack/react-form";
import { type KeyboardEvent, useEffect } from "react";

import type { AskAgentReadiness } from "@/lib/ask-agent-status";
import { askModelOptions, defaultAskModel } from "@/lib/ask";

type Props = {
  onSubmit: (input: { question: string; model: string; tenantId: string; scopeUrn: string }) => void;
  disabled?: boolean;
  initialScopeUrn?: string;
  onSaveQuestion?: (input: { question: string; model: string; tenantId: string; scopeUrn: string }) => void;
  readiness?: AskAgentReadiness | null;
  readinessLoading?: boolean;
};

type AskInputValues = {
  model: string;
  question: string;
  scopeUrn: string;
  tenantId: string;
};

const normalizeAskInput = (value: AskInputValues) => ({
  model: value.model,
  question: value.question.trim(),
  scopeUrn: value.scopeUrn.trim(),
  tenantId: value.tenantId.trim(),
});

export default function AskInput({
  onSubmit,
  disabled = false,
  initialScopeUrn = "",
  onSaveQuestion,
  readiness,
  readinessLoading = false,
}: Props) {
  const form = useForm({
    defaultValues: {
      model: defaultAskModel,
      question: "",
      scopeUrn: initialScopeUrn,
      tenantId: "",
    } satisfies AskInputValues,
    onSubmit: ({ value }) => {
      const input = normalizeAskInput(value);
      if (!input.question || disabled) return;
      onSubmit(input);
      form.setFieldValue("question", "");
    },
  });

  useEffect(() => {
    form.setFieldValue("scopeUrn", initialScopeUrn);
  }, [form, initialScopeUrn]);

  const submit = () => {
    void form.handleSubmit();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      submit();
    }
  };

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
      className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">Ask a question</div>
          <p className="mt-1 text-[13px] text-slate-500">
            Use a concrete risk, owner, evidence item, source, or affected asset.
          </p>
        </div>
        <div className="flex flex-col items-end gap-2 text-right">
          {disabled && (
            <span className="rounded-full border border-indigo-200 bg-indigo-50 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-indigo-700">
              Generating
            </span>
          )}
          <div className="max-w-sm rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-left text-[12px] text-slate-600">
            <div className="font-semibold text-slate-800">
              {readinessLoading ? "Checking Ask path" : readiness?.label ?? "Ask path unavailable"}
            </div>
            <div className="mt-0.5">{readinessLoading ? "Checking which path will handle the next question." : readiness?.detail ?? "Retry after the Ask status check completes."}</div>
          </div>
        </div>
      </div>
      <form.Field name="question">
        {(field) => (
          <textarea
            value={field.state.value}
            onBlur={field.handleBlur}
            onChange={(event) => field.handleChange(event.target.value)}
            onKeyDown={onKeyDown}
            rows={3}
            disabled={disabled}
            placeholder="Which risks changed? Who owns them? Which evidence is missing?"
            className="mt-3 w-full resize-none border-0 bg-transparent text-base text-slate-900 outline-none placeholder:text-slate-400 disabled:opacity-60"
          />
        )}
      </form.Field>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3 text-xs">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <form.Field name="tenantId">
            {(field) => (
              <label className="flex min-w-0 items-center gap-2 text-slate-500 max-sm:w-full max-sm:flex-col max-sm:items-start">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Tenant</span>
                <input
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  placeholder="writer"
                  disabled={disabled}
                  className="w-32 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30 disabled:opacity-60 max-sm:w-full"
                />
              </label>
            )}
          </form.Field>
          <form.Field name="scopeUrn">
            {(field) => (
              <label className="flex min-w-0 items-center gap-2 text-slate-500 max-sm:w-full max-sm:flex-col max-sm:items-start">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Scope URN</span>
                <input
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  placeholder="urn:cerebro:..."
                  disabled={disabled}
                  className="w-72 rounded-md border border-slate-200 bg-white px-2 py-1.5 text-[13px] text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30 disabled:opacity-60 max-sm:w-full"
                />
              </label>
            )}
          </form.Field>
          <form.Field name="model">
            {(field) => (
              <label className="flex min-w-0 items-center gap-2 text-slate-500 max-sm:w-full max-sm:flex-col max-sm:items-start">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Model</span>
                <select
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  disabled={disabled}
                  className="max-w-full rounded-md border border-slate-200 bg-white px-2 py-1.5 text-[13px] text-slate-900 disabled:opacity-60 max-sm:w-full"
                >
                  {askModelOptions.map((option) => (
                    <option key={option.id} value={option.id}>
                      {option.label} — {option.hint}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </form.Field>
        </div>
        <form.Subscribe selector={(state) => state.values}>
          {(value) => {
            const input = normalizeAskInput(value);
            return (
              <div className="flex items-center gap-3">
                <span className="text-[11px] text-slate-400">{disabled ? "Use Stop on the active turn to cancel" : "⌘+Enter to send"}</span>
                {onSaveQuestion && (
                  <button
                    type="button"
                    disabled={!input.question}
                    onClick={() => onSaveQuestion(input)}
                    className="rounded-md border border-slate-200 px-4 py-1.5 text-[13px] font-medium text-slate-600 transition hover:border-slate-300 hover:text-slate-900 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Save
                  </button>
                )}
                <button
                  type="submit"
                  disabled={disabled || !input.question}
                  className="rounded-md bg-indigo-500 px-4 py-1.5 text-[13px] font-medium text-white transition hover:bg-indigo-600 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Ask
                </button>
              </div>
            );
          }}
        </form.Subscribe>
      </div>
    </form>
  );
}

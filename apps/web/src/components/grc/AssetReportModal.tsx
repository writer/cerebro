"use client";

import { useForm } from "@tanstack/react-form";

import { GRCInventoryAsset, humanize, shortEntity } from "@/lib/grc";

export default function AssetReportModal({
  asset,
  error,
  onClose,
  onSubmit,
  saving,
}: {
  asset: GRCInventoryAsset;
  error?: string | null;
  onClose: () => void;
  onSubmit: (reason: string) => void;
  saving?: boolean;
}) {
  const form = useForm({
    defaultValues: { reason: "" },
    onSubmit: ({ value }) => {
      const trimmed = value.reason.trim();
      if (trimmed) onSubmit(trimmed);
    },
  });

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/40 px-4 py-12 backdrop-blur-sm" onClick={onClose}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void form.handleSubmit();
        }}
        className="mx-auto max-w-lg rounded-xl border border-slate-200 bg-white shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="border-b border-slate-200 px-5 py-4">
          <h2 className="text-[15px] font-semibold text-slate-900">Report inventory issue</h2>
          <p className="mt-1 text-[12px] text-slate-500">
            Capture a data quality or curation reason for {asset.label || shortEntity(asset.urn)}.
          </p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div className="rounded-lg border border-slate-100 bg-slate-50 p-3">
            <div className="text-[13px] font-medium text-slate-900">{asset.label || shortEntity(asset.urn)}</div>
            <div className="mt-1 font-mono text-[11px] text-slate-500">{humanize(asset.entity_type)}</div>
          </div>
          <label className="block text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Reason
            <form.Field name="reason">
              {(field) => (
                <textarea
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  placeholder="Example: owner is wrong, duplicate asset, stale source data, missing account metadata..."
                  className="mt-1 min-h-28 w-full rounded-md border border-slate-200 bg-white px-3 py-2 text-[13px] normal-case tracking-normal text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-1 focus:ring-indigo-400/30"
                />
              )}
            </form.Field>
          </label>
          {error && <div className="rounded-md border border-red-100 bg-red-50 px-3 py-2 text-[12px] text-red-700">{error}</div>}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-200 px-5 py-4">
          <button type="button" onClick={onClose} className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-[13px] font-medium text-slate-700 hover:border-slate-300">
            Cancel
          </button>
          <form.Subscribe selector={(state) => state.values.reason.trim().length > 0}>
            {(hasReason) => (
              <button type="submit" disabled={saving || !hasReason} className="rounded-md border border-indigo-500 bg-indigo-500 px-3 py-1.5 text-[13px] font-medium text-white hover:bg-indigo-600 disabled:opacity-50">
                {saving ? "Submitting" : "Submit report"}
              </button>
            )}
          </form.Subscribe>
        </div>
      </form>
    </div>
  );
}

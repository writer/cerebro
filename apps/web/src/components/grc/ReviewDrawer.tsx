"use client";

import type { ReactNode } from "react";

export default function ReviewDrawer({
  children,
  footer,
  onClose,
  open,
  subtitle,
  title,
}: {
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
  open: boolean;
  subtitle?: ReactNode;
  title: ReactNode;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30" role="dialog" aria-modal="true" aria-labelledby="review-drawer-title">
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Close review drawer" onClick={onClose} />
      <aside className="surface-raised relative flex h-full w-full max-w-xl flex-col border-l border-[color:var(--border)] shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-[color:var(--border)] px-5 py-4">
          <div className="min-w-0">
            <h2 id="review-drawer-title" className="break-words text-[15px] font-semibold text-[var(--text-primary)]">
              {title}
            </h2>
            {subtitle && <div className="mt-1 text-[12px] leading-5 text-[var(--text-muted)]">{subtitle}</div>}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--surface-muted)] hover:text-[var(--text-primary)]"
            aria-label="Close"
          >
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.7} stroke="currentColor" className="h-4 w-4">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-5">
          {children}
        </div>
        {footer && <div className="border-t border-[color:var(--border)] px-5 py-4">{footer}</div>}
      </aside>
    </div>
  );
}

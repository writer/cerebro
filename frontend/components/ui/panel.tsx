import { ReactNode } from "react";
import { cn } from "@/lib/utils";

type PanelProps = {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
};

export function Panel({ title, description, action, children, className }: PanelProps) {
  return (
    <section className={cn("rounded-xl border border-zinc-900 bg-black/80 shadow-lg", className)}>
      <div className="flex items-start justify-between gap-4 border-b border-zinc-900 px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          {description ? <p className="mt-1 text-xs text-zinc-500">{description}</p> : null}
        </div>
        {action}
      </div>
      <div className="px-5 py-4 text-zinc-200">{children}</div>
    </section>
  );
}

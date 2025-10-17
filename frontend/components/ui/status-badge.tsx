import { cn } from "@/lib/utils";
import { ReviewTaskStatus } from "@/lib/types";

const STATUS_STYLES: Record<ReviewTaskStatus, string> = {
  pending: "bg-amber-500/10 text-amber-300 border-amber-500/40",
  approved: "bg-emerald-500/10 text-emerald-300 border-emerald-500/40",
  rejected: "bg-rose-500/10 text-rose-300 border-rose-500/40",
  promoted: "bg-sky-500/10 text-sky-300 border-sky-500/40",
  escalated: "bg-purple-500/10 text-purple-300 border-purple-500/40"
};

type StatusBadgeProps = {
  status: ReviewTaskStatus | string;
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const normalized = (status as ReviewTaskStatus) ?? "pending";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize",
        STATUS_STYLES[normalized] ?? STATUS_STYLES.pending
      )}
    >
      {normalized.replace("_", " ")}
    </span>
  );
}

"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiGet, apiPost } from "@/lib/api";
import { ReviewTask, ReviewTaskStatus } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";
import { StatusBadge } from "@/components/ui/status-badge";

const STATUS_FILTERS: Array<{ label: string; value?: ReviewTaskStatus }> = [
  { label: "All" },
  { label: "Pending", value: "pending" },
  { label: "Promoted", value: "promoted" },
  { label: "Escalated", value: "escalated" },
  { label: "Approved", value: "approved" },
  { label: "Rejected", value: "rejected" }
];

type BulkAction = "approve" | "reject" | "promote" | "escalate";

export function ReviewTable() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<ReviewTaskStatus | undefined>();
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [notes, setNotes] = useState("");

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["reviewTasks", status],
    queryFn: () => apiGet<ReviewTask[]>("/agents/review-tasks", status ? { status } : undefined)
  });

  const tasks = useMemo(() => data ?? [], [data]);

  const toggleSelection = (taskId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(taskId)) {
        next.delete(taskId);
      } else {
        next.add(taskId);
      }
      return next;
    });
  };

  const selectAll = (checked: boolean) => {
    if (!checked) {
      setSelectedIds(new Set());
      return;
    }
    setSelectedIds(new Set(tasks.map((task) => task.id)));
  };

  const mutation = useMutation({
    mutationFn: async ({ action }: { action: BulkAction }) => {
      // Map high-level reviewer actions to the API status values expected by the bulk endpoint.
      const statusMapping: Record<BulkAction, ReviewTaskStatus> = {
        approve: "approved",
        reject: "rejected",
        promote: "promoted",
        escalate: "escalated"
      };

      return apiPost<ReviewTask[]>("/agents/review-tasks/bulk-update", {
        task_ids: Array.from(selectedIds),
        status: statusMapping[action],
        notes: notes || undefined,
        escalated_to: action === "escalate" ? "security_manager" : undefined
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reviewTasks"] });
      setSelectedIds(new Set());
      setNotes("");
    }
  });

  const hasSelection = selectedIds.size > 0;

  const selectedTasks = useMemo(
    () => tasks.filter((task) => selectedIds.has(task.id)),
    [tasks, selectedIds]
  );

  return (
    <Panel
      title="Review queue"
      description="Audit, approve, or escalate agent actions before they are finalized."
      action={
        <div className="flex items-center gap-2">
          <select
            value={status ?? ""}
            onChange={(event) => {
              setStatus((event.target.value as ReviewTaskStatus) || undefined);
              setSelectedIds(new Set());
            }}
            className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
          >
            {STATUS_FILTERS.map((filter) => (
              <option key={filter.label} value={filter.value ?? ""}>
                {filter.label}
              </option>
            ))}
          </select>
          <span className="text-[10px] uppercase tracking-wide text-slate-500">
            {isFetching ? "Refreshing…" : `${tasks.length} tasks`}
          </span>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="min-w-full divide-y divide-slate-800 text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase text-slate-400">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    checked={hasSelection && selectedIds.size === tasks.length}
                    onChange={(event) => selectAll(event.target.checked)}
                    className="h-4 w-4 rounded border border-slate-600 bg-slate-900"
                  />
                </th>
                <th className="px-4 py-3 text-left">Task</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Priority</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-left">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-950/40">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    Loading review tasks…
                  </td>
                </tr>
              ) : tasks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-500">
                    No tasks match this filter.
                  </td>
                </tr>
              ) : (
                tasks.map((task) => {
                  const checked = selectedIds.has(task.id);
                  return (
                    <tr key={task.id} className={cn(checked && "bg-slate-900/60")}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleSelection(task.id)}
                          className="h-4 w-4 rounded border border-slate-600 bg-slate-900"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-slate-100">{task.title}</div>
                        <div className="truncate text-xs text-slate-400">{task.summary || "—"}</div>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={task.status} />
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-300">{task.priority ?? "—"}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{formatRelative(task.created_at)}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{formatRelative(task.resolved_at)}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="rounded-lg border border-dashed border-slate-700 bg-slate-900/40 p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-sm font-medium text-slate-100">
                {hasSelection ? `${selectedIds.size} selected` : "Select tasks to take action"}
              </p>
              <textarea
                placeholder="Add reviewer notes (optional)"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                className="mt-2 w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200"
                rows={2}
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {(["approve", "reject", "promote", "escalate"] as BulkAction[]).map((action) => (
                <button
                  key={action}
                  type="button"
                  disabled={!hasSelection || mutation.isLoading}
                  onClick={() => mutation.mutate({ action })}
                  className={cn(
                    "rounded-md border px-3 py-2 text-xs font-semibold uppercase tracking-wide transition",
                    hasSelection
                      ? "border-slate-600 bg-slate-900 text-slate-200 hover:border-slate-500 hover:bg-slate-800"
                      : "cursor-not-allowed border-slate-800 bg-slate-950 text-slate-600"
                  )}
                >
                  {action}
                </button>
              ))}
            </div>
          </div>
          {selectedTasks.length > 0 ? (
            <div className="mt-3 rounded-md bg-slate-900/60 p-3 text-xs text-slate-300">
              <span className="font-semibold text-slate-200">Preview:</span>{" "}
              {selectedTasks.map((task) => task.title).join(" · ")}
            </div>
          ) : null}
        </div>
      </div>
    </Panel>
  );
}

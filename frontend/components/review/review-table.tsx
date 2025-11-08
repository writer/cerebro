"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Wifi, WifiOff } from "lucide-react";

import { apiGet, apiPost } from "@/lib/api";
import { ReviewTask, ReviewTaskStatus } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { useWebSocket } from "@/lib/websocket";
import { Panel } from "@/components/ui/panel";
import { StatusBadge } from "@/components/ui/status-badge";
import { ReviewDetail } from "@/components/review/review-detail";
import { showToast } from "@/components/review/review-notifications";

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
  const [focusedTaskId, setFocusedTaskId] = useState<string | null>(null);
  const [connectionState, setConnectionState] = useState<"connecting" | "connected" | "disconnected">("connecting");

  const websocketUrl = useMemo(() => {
    const wsBase = process.env.NEXT_PUBLIC_WS_BASE_URL;
    const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api/v1";
    const normalizedBase = wsBase ?? apiBase.replace(/\/api\/v1\/?$/, "");

    try {
      const target = new URL(normalizedBase || apiBase);
      target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
      if (!wsBase) {
        target.pathname = "/ws/events";
      } else if (!target.pathname || target.pathname === "/") {
        target.pathname = "/ws/events";
      }

      if (typeof window !== "undefined") {
        const token =
          localStorage.getItem("cerebro_access_token") ??
          process.env.NEXT_PUBLIC_API_TOKEN ??
          "";
        if (token) {
          target.searchParams.set("token", token);
        }
      }

      return target.toString();
    } catch {
      const protocolAdjusted = normalizedBase.startsWith("https")
        ? normalizedBase.replace(/^https/, "wss")
        : normalizedBase.replace(/^http/, "ws");
      const trimmed = protocolAdjusted.replace(/\/$/, "");
      const basePath = `${trimmed}/ws/events`;

      if (typeof window !== "undefined") {
        const token =
          localStorage.getItem("cerebro_access_token") ??
          process.env.NEXT_PUBLIC_API_TOKEN ??
          "";
        if (token) {
          return `${basePath}?token=${encodeURIComponent(token)}`;
        }
      }

      return basePath;
    }
  }, []);

  const handleWebSocketMessage = useCallback(
    (message: { type: string; payload: unknown }) => {
      const { type, payload } = message ?? {};
      if (!type) {
        return;
      }

      if (type === "connection_established") {
        return;
      }

      if (type.startsWith("review_task_")) {
        queryClient.invalidateQueries({ queryKey: ["reviewTasks"] });

        if (payload && typeof payload === "object") {
          const details = payload as Partial<ReviewTask> & { status?: string };
          const toastTitle = type === "review_task_created" ? "New review task" : "Review task updated";
          const statusLabel = typeof details.status === "string" ? details.status : undefined;
          const titleLabel = typeof details.title === "string" ? details.title : undefined;
          const toastMessage = titleLabel
            ? statusLabel
              ? `${titleLabel} • ${statusLabel}`
              : titleLabel
            : statusLabel;
          showToast(type === "review_task_created" ? "warning" : "info", toastTitle, toastMessage ?? undefined, 4000);
        }
      }
    },
    [queryClient]
  );

  useWebSocket({
    url: websocketUrl,
    onMessage: handleWebSocketMessage,
    onOpen: () => setConnectionState("connected"),
    onClose: () => setConnectionState("disconnected"),
    onError: () => setConnectionState("disconnected"),
  });

  const connectionLabel =
    connectionState === "connected" ? "Live updates" : connectionState === "connecting" ? "Connecting…" : "Reconnecting…";
  const ConnectionIcon = connectionState === "connected" ? Wifi : WifiOff;
  const connectionTextClass =
    connectionState === "connected"
      ? "text-emerald-400"
      : connectionState === "connecting"
      ? "text-zinc-500"
      : "text-amber-400";

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["reviewTasks", status],
    queryFn: () => apiGet<ReviewTask[]>("/agents/review-tasks", status ? { status } : undefined)
  });

  const tasks = useMemo(() => data ?? [], [data]);
  const focusedTask = useMemo(
    () => tasks.find((task) => task.id === focusedTaskId) ?? null,
    [focusedTaskId, tasks]
  );

  useEffect(() => {
    if (focusedTaskId && !focusedTask) {
      setFocusedTaskId(null);
    }
  }, [focusedTaskId, focusedTask]);

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

  const ACTION_COPY: Record<BulkAction, { label: string; helper: string }> = {
    approve: {
      label: "Approve & publish",
      helper: "Finalizes the agent output and marks tasks as approved.",
    },
    reject: {
      label: "Reject & block",
      helper: "Stops the action and records reviewer notes for audit.",
    },
    promote: {
      label: "Promote to automation",
      helper: "Queues tasks for automation follow-up by the tooling team.",
    },
    escalate: {
      label: "Escalate to Security Manager",
      helper: "Routes tasks to the Security Manager queue (escalated_to: security_manager).",
    },
  };

  return (
    <Panel
      title="Review queue"
      description="Audit, approve, or escalate agent actions before they are finalized."
      action={
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "flex items-center gap-1 text-[10px] uppercase tracking-wide",
              connectionTextClass
            )}
          >
            <ConnectionIcon className="h-3 w-3" aria-hidden />
            {connectionLabel}
          </span>
          <select
            value={status ?? ""}
            onChange={(event) => {
              setStatus((event.target.value as ReviewTaskStatus) || undefined);
              setSelectedIds(new Set());
            }}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
          >
            {STATUS_FILTERS.map((filter) => (
              <option key={filter.label} value={filter.value ?? ""}>
                {filter.label}
              </option>
            ))}
          </select>
          <span className="text-[10px] uppercase tracking-wide text-zinc-500">
            {isFetching ? "Refreshing…" : `${tasks.length} tasks`}
          </span>
        </div>
      }
    >
      <div className="space-y-4">
        <div className="overflow-hidden rounded-lg border border-zinc-900 bg-black/70">
          <table className="min-w-full divide-y divide-zinc-900 text-sm text-zinc-200">
            <thead className="bg-zinc-950 text-xs uppercase text-zinc-500">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    checked={hasSelection && selectedIds.size === tasks.length}
                    onChange={(event) => selectAll(event.target.checked)}
                    className="h-4 w-4 rounded border border-zinc-700 bg-black text-zinc-100 focus:border-zinc-500"
                  />
                </th>
                <th className="px-4 py-3 text-left">Task</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Priority</th>
                <th className="px-4 py-3 text-left">Created</th>
                <th className="px-4 py-3 text-left">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-900 bg-black">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-zinc-500">
                    Loading review tasks…
                  </td>
                </tr>
              ) : tasks.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-zinc-500">
                    No tasks match this filter.
                  </td>
                </tr>
              ) : (
                tasks.map((task) => {
                  const checked = selectedIds.has(task.id);
                  return (
                    <tr
                      key={task.id}
                      onClick={() => setFocusedTaskId(task.id)}
                      className={cn(
                        "group cursor-pointer transition",
                        checked && "bg-zinc-900/50",
                        focusedTaskId === task.id && "ring-1 ring-zinc-500"
                      )}
                    >
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          checked={checked}
                          onClick={(event) => event.stopPropagation()}
                          onChange={(event) => {
                            event.stopPropagation();
                            toggleSelection(task.id);
                          }}
                          className="h-4 w-4 rounded border border-zinc-700 bg-black text-zinc-100 focus:border-zinc-500"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-zinc-100">{task.title}</div>
                        <div className="truncate text-xs text-zinc-400">{task.summary || "—"}</div>
                        {task.escalated_to ? (
                          <div className="text-[11px] text-amber-300">
                            Escalated to {task.escalated_to.replace(/_/g, " ")}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={task.status} />
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-300">{task.priority ?? "—"}</td>
                      <td className="px-4 py-3 text-xs text-zinc-500">{formatRelative(task.created_at)}</td>
                      <td className="px-4 py-3 text-xs text-zinc-500">{formatRelative(task.resolved_at)}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="rounded-lg border border-dashed border-zinc-900 bg-black/80 p-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-sm font-medium text-zinc-100">
                {hasSelection ? `${selectedIds.size} selected` : "Select tasks to take action"}
              </p>
              <textarea
                placeholder="Add reviewer notes (optional)"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                className="mt-2 w-full rounded-md border border-zinc-800 bg-black px-3 py-2 text-xs text-zinc-200 focus:border-zinc-600 focus:outline-none"
                rows={2}
              />
              <p className="mt-2 text-[11px] text-zinc-500">
                Notes are appended to each task’s history when bulk actions run.
              </p>
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
                      ? "border-zinc-700 bg-black text-zinc-200 hover:border-zinc-500 hover:bg-zinc-900"
                      : "cursor-not-allowed border-zinc-900 bg-black/60 text-zinc-600"
                  )}
                  title={ACTION_COPY[action].helper}
                >
                  {ACTION_COPY[action].label}
                </button>
              ))}
            </div>
          </div>
          {selectedTasks.length > 0 ? (
            <div className="mt-3 rounded-md bg-black/70 p-3 text-xs text-zinc-300">
              <span className="font-semibold text-zinc-100">Preview:</span>{" "}
              {selectedTasks.map((task) => task.title).join(" · ")}
            </div>
          ) : null}
          <div className="mt-2 text-[11px] text-zinc-500">
            Approve publishes the agent action; reject blocks it and records the note.
          </div>
          <div className="text-[11px] text-amber-300">
            Escalations route to the Security Manager queue (escalated_to: security_manager).
          </div>
        </div>

      </div>

      {focusedTask ? (
        <div className="mt-6">
          <ReviewDetail task={focusedTask} onClose={() => setFocusedTaskId(null)} />
        </div>
      ) : null}
    </Panel>
  );
}

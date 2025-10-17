"use client";

import { useQuery } from "@tanstack/react-query";

import { apiGet } from "@/lib/api";
import { ReviewNotification } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { Panel } from "@/components/ui/panel";

const STATUS_COLORS: Record<string, string> = {
  pending: "text-amber-200",
  delivered: "text-emerald-200"
};

export function NotificationsPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["reviewNotifications"],
    queryFn: () => apiGet<ReviewNotification[]>("/agents/review-tasks/notifications")
  });

  const notifications = data ?? [];

  return (
    <Panel
      title="Notification dispatch"
      description="Track reviewer alerts sent to Slack, email, or other channels."
    >
      <div className="space-y-3">
        {isLoading ? (
          <p className="text-sm text-zinc-500">Loading notifications…</p>
        ) : notifications.length === 0 ? (
          <p className="text-sm text-zinc-500">No notifications have been queued yet.</p>
        ) : (
          <ul className="space-y-2">
            {notifications.map((notification) => (
              <li
                key={notification.id}
                className="rounded-lg border border-zinc-900 bg-black/75 px-4 py-3 text-sm"
              >
                <div className="flex items-center justify-between">
                  <div className="font-medium text-zinc-100">{notification.channel}</div>
                  <span className={STATUS_COLORS[notification.status] ?? "text-zinc-300"}>
                    {notification.status}
                  </span>
                </div>
                <div className="mt-1 text-xs text-zinc-500">
                  Created {formatRelative(notification.created_at)}
                  {notification.delivered_at
                    ? ` · Delivered ${formatRelative(notification.delivered_at)}`
                    : ""}
                </div>
                {notification.payload ? (
                  <pre className="mt-2 overflow-x-auto rounded-md bg-zinc-900/70 p-2 text-[11px] text-zinc-200">
                    {JSON.stringify(notification.payload, null, 2)}
                  </pre>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

"use client";

import { useMemo } from "react";
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { TrendingUp, TrendingDown, Clock, CheckCircle, XCircle, AlertTriangle } from "lucide-react";

import { ReviewTask, ReviewTaskStatus } from "@/lib/types";
import { formatRelative } from "@/lib/utils";

type ReviewMetricsProps = {
  tasks: ReviewTask[];
};

const STATUS_COLORS: Record<ReviewTaskStatus, string> = {
  pending: "#f59e0b",
  approved: "#10b981",
  rejected: "#ef4444",
  promoted: "#3b82f6",
  escalated: "#8b5cf6",
};

const PRIORITY_ORDER = ["critical", "high", "medium", "low"];

export function ReviewMetrics({ tasks }: ReviewMetricsProps) {
  const metrics = useMemo(() => {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const statusCounts = tasks.reduce(
      (acc, task) => {
        acc[task.status] = (acc[task.status] || 0) + 1;
        return acc;
      },
      {} as Record<ReviewTaskStatus, number>
    );

    const priorityCounts = tasks.reduce(
      (acc, task) => {
        const priority = task.priority || "none";
        acc[priority] = (acc[priority] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const recentTasks = tasks.filter(
      (task) => new Date(task.created_at) >= last24h
    );

    const weekTasks = tasks.filter(
      (task) => new Date(task.created_at) >= last7d
    );

    const resolvedTasks = tasks.filter((task) => task.resolved_at);
    const avgResolutionTime =
      resolvedTasks.length > 0
        ? resolvedTasks.reduce((sum, task) => {
            const created = new Date(task.created_at).getTime();
            const resolved = new Date(task.resolved_at!).getTime();
            return sum + (resolved - created);
          }, 0) / resolvedTasks.length
        : 0;

    const escalationRate =
      tasks.length > 0
        ? (statusCounts.escalated || 0) / tasks.length
        : 0;

    const approvalRate =
      resolvedTasks.length > 0
        ? (statusCounts.approved || 0) / resolvedTasks.length
        : 0;

    // Time series data (last 7 days)
    const timeSeriesData: Array<{ date: string; created: number; resolved: number }> = [];
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
      const dateStr = date.toISOString().split("T")[0];
      const created = tasks.filter(
        (task) => task.created_at.split("T")[0] === dateStr
      ).length;
      const resolved = tasks.filter(
        (task) => task.resolved_at?.split("T")[0] === dateStr
      ).length;
      timeSeriesData.push({
        date: new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(date),
        created,
        resolved,
      });
    }

    return {
      total: tasks.length,
      pending: statusCounts.pending || 0,
      recent24h: recentTasks.length,
      recent7d: weekTasks.length,
      avgResolutionTime,
      escalationRate,
      approvalRate,
      statusCounts,
      priorityCounts,
      timeSeriesData,
    };
  }, [tasks]);

  const statusChartData = Object.entries(metrics.statusCounts).map(([status, count]) => ({
    name: status.charAt(0).toUpperCase() + status.slice(1),
    value: count,
    color: STATUS_COLORS[status as ReviewTaskStatus],
  }));

  const priorityChartData = PRIORITY_ORDER
    .filter((priority) => metrics.priorityCounts[priority])
    .map((priority) => ({
      priority: priority.charAt(0).toUpperCase() + priority.slice(1),
      count: metrics.priorityCounts[priority],
    }));

  const formatDuration = (ms: number) => {
    const hours = Math.floor(ms / (1000 * 60 * 60));
    const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
    if (hours > 24) {
      return `${Math.floor(hours / 24)}d ${hours % 24}h`;
    }
    return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
  };

  return (
    <div className="space-y-6">
      {/* Key metrics cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Total tasks"
          value={metrics.total}
          subtitle={`${metrics.pending} pending`}
          icon={<Clock className="h-5 w-5 text-yellow-500" />}
        />
        <MetricCard
          title="Last 24 hours"
          value={metrics.recent24h}
          subtitle={`${metrics.recent7d} this week`}
          icon={<TrendingUp className="h-5 w-5 text-blue-500" />}
          trend={metrics.recent24h > metrics.recent7d / 7 ? "up" : "down"}
        />
        <MetricCard
          title="Avg resolution"
          value={formatDuration(metrics.avgResolutionTime)}
          subtitle="Time to resolve"
          icon={<CheckCircle className="h-5 w-5 text-green-500" />}
        />
        <MetricCard
          title="Escalation rate"
          value={`${(metrics.escalationRate * 100).toFixed(1)}%`}
          subtitle={`${(metrics.approvalRate * 100).toFixed(1)}% approval rate`}
          icon={<AlertTriangle className="h-5 w-5 text-purple-500" />}
        />
      </div>

      {/* Charts */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Time series chart */}
        <div className="rounded-xl border border-zinc-900 bg-black/75 p-5">
          <h3 className="mb-4 text-sm font-semibold text-zinc-200">Task Activity (7 days)</h3>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={metrics.timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="date" stroke="#71717a" style={{ fontSize: 11 }} />
              <YAxis stroke="#71717a" style={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#18181b",
                  border: "1px solid #27272a",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="created" stroke="#3b82f6" strokeWidth={2} name="Created" />
              <Line type="monotone" dataKey="resolved" stroke="#10b981" strokeWidth={2} name="Resolved" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Status distribution pie chart */}
        <div className="rounded-xl border border-zinc-900 bg-black/75 p-5">
          <h3 className="mb-4 text-sm font-semibold text-zinc-200">Status Distribution</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={statusChartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {statusChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "#18181b",
                  border: "1px solid #27272a",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Priority distribution bar chart */}
        {priorityChartData.length > 0 && (
          <div className="rounded-xl border border-zinc-900 bg-black/75 p-5 lg:col-span-2">
            <h3 className="mb-4 text-sm font-semibold text-zinc-200">Priority Distribution</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={priorityChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                <XAxis dataKey="priority" stroke="#71717a" style={{ fontSize: 11 }} />
                <YAxis stroke="#71717a" style={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#18181b",
                    border: "1px solid #27272a",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}

type MetricCardProps = {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ReactNode;
  trend?: "up" | "down";
};

function MetricCard({ title, value, subtitle, icon, trend }: MetricCardProps) {
  return (
    <div className="rounded-xl border border-zinc-900 bg-black/75 p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-zinc-500">{title}</p>
          <p className="mt-2 text-2xl font-bold text-zinc-100">{value}</p>
          <p className="mt-1 text-xs text-zinc-400">{subtitle}</p>
        </div>
        <div className="rounded-lg bg-zinc-900/70 p-2">{icon}</div>
      </div>
      {trend && (
        <div className="mt-3 flex items-center gap-1 text-xs">
          {trend === "up" ? (
            <>
              <TrendingUp className="h-3 w-3 text-green-500" />
              <span className="text-green-500">Trending up</span>
            </>
          ) : (
            <>
              <TrendingDown className="h-3 w-3 text-red-500" />
              <span className="text-red-500">Trending down</span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

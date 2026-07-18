"use client";

import type { Ref } from "react";
import { useCallback, useMemo } from "react";
import { Bar, CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { GRCTrendPoint, GRCTrendTargets } from "@/lib/grc";
import { formatTrendDate } from "@/lib/trends";

export type TrendsChartProps = {
  points: GRCTrendPoint[];
  height?: number;
  targets?: GRCTrendTargets;
  onBucketSelect?: (date: string, kind: "opened" | "closed") => void;
  containerRef?: Ref<HTMLDivElement>;
};

type ChartDatum = {
  date: string;
  label: string;
  opened: number;
  closed: number;
  open_total: number;
};

export default function TrendsChart({ points, height = 280, targets, onBucketSelect, containerRef }: TrendsChartProps) {
  const data = useMemo(() => points.map((point) => ({
    date: point.date,
    label: formatTrendDate(point.date),
    opened: point.opened,
    closed: point.closed,
    open_total: point.open_total,
  })), [points]);
  const selectBucket = useCallback((kind: "opened" | "closed") => (entry: unknown) => {
    const datum = (entry as { payload?: ChartDatum })?.payload;
    if (datum?.date) onBucketSelect?.(datum.date, kind);
  }, [onBucketSelect]);

  return (
    <div ref={containerRef} style={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
          <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#64748b" }} tickLine={false} axisLine={{ stroke: "#e2e8f0" }} minTickGap={16} />
          <YAxis yAxisId="flow" tick={{ fontSize: 11, fill: "#64748b" }} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
          <YAxis yAxisId="backlog" orientation="right" tick={{ fontSize: 11, fill: "#64748b" }} tickLine={false} axisLine={false} allowDecimals={false} width={32} />
          <Tooltip
            contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid #e2e8f0" }}
            labelStyle={{ color: "#0f172a", fontWeight: 600 }}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Bar yAxisId="flow" dataKey="opened" name="Opened" fill="#6366f1" radius={[3, 3, 0, 0]} maxBarSize={28} onClick={selectBucket("opened")} cursor={onBucketSelect ? "pointer" : undefined} />
          <Bar yAxisId="flow" dataKey="closed" name="Closed" fill="#10b981" radius={[3, 3, 0, 0]} maxBarSize={28} onClick={selectBucket("closed")} cursor={onBucketSelect ? "pointer" : undefined} />
          {targets?.backlog ? <ReferenceLine yAxisId="backlog" y={targets.backlog} stroke="#f97316" strokeDasharray="4 4" label={{ value: "Backlog target", fontSize: 11, fill: "#f97316" }} /> : null}
          <Line yAxisId="backlog" type="monotone" dataKey="open_total" name="Open backlog" stroke="#f59e0b" strokeWidth={2} dot={false} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

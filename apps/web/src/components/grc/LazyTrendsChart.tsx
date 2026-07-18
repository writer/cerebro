"use client";

import dynamic from "next/dynamic";
import { forwardRef } from "react";

import { LoadingBlock } from "@/components/grc/Primitives";
import type { TrendsChartProps } from "@/components/grc/TrendsChart";

type LazyTrendsChartProps = Omit<TrendsChartProps, "containerRef">;

const LoadedTrendsChart = dynamic<TrendsChartProps>(() => import("@/components/grc/TrendsChart"), {
  loading: () => <LoadingBlock label="Loading chart..." />,
  ssr: false,
});

const LazyTrendsChart = forwardRef<HTMLDivElement, LazyTrendsChartProps>(function LazyTrendsChart(props, ref) {
  return <LoadedTrendsChart {...props} containerRef={ref} />;
});

export default LazyTrendsChart;

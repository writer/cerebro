"use client";

import dynamic from "next/dynamic";

import { LoadingBlock } from "@/components/grc/Primitives";
import type { GraphViewerProps } from "@/components/grc/GraphViewer";

const LazyGraphViewer = dynamic<GraphViewerProps>(() => import("@/components/grc/GraphViewer"), {
  loading: () => <LoadingBlock label="Loading graph..." />,
  ssr: false,
});

export default LazyGraphViewer;

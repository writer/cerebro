import { RuntimeAnalyticsPanel } from "@/components/analytics/runtime-analytics-panel";
import { MemoryInsightsPanel } from "@/components/analytics/memory-insights-panel";

export default function AnalyticsPage() {
  return (
    <div className="space-y-6">
      <RuntimeAnalyticsPanel />
      <MemoryInsightsPanel />
    </div>
  );
}

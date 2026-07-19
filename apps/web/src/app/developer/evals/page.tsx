import EvalDashboard from "@/components/evals/EvalDashboard";
import { PageHeader, Panel } from "@/components/grc/Primitives";

export default function DeveloperEvalsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Ask Evals"
        description="Local-only Ask quality regression runs and rubric results."
      />

      <Panel title="Local Commands">
        <div className="grid gap-3 text-[13px] text-slate-600 md:grid-cols-2">
          <pre className="overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[12px] text-slate-800">
            npm run eval:ask:local
          </pre>
          <pre className="overflow-x-auto rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-[12px] text-slate-800">
            npm run eval:security-agent:local
          </pre>
        </div>
      </Panel>

      <EvalDashboard />
    </div>
  );
}

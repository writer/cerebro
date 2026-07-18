import AuditLogWorkbench from "@/components/developer/AuditLogWorkbench";
import { PageHeader } from "@/components/grc/Primitives";

export default function DeveloperAuditLogPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="Wide-event timeline for Cerebro API, graph, source runtime, and web console activity."
      />
      <AuditLogWorkbench />
    </div>
  );
}

import AuditLogWorkbench from "@/components/developer/AuditLogWorkbench";
import { PageHeader } from "@/components/grc/Primitives";

export default function DeveloperAuditLogPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Events"
        description="Review who changed what, which resource was affected, and whether the action succeeded."
      />
      <AuditLogWorkbench />
    </div>
  );
}

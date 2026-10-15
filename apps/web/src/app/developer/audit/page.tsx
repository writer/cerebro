import AuditLogWorkbench from "@/components/developer/AuditLogWorkbench";
import { PageHeader } from "@/components/grc/Primitives";

export default function DeveloperAuditLogPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Events"
        description="Who changed what, and whether it worked."
      />
      <AuditLogWorkbench />
    </div>
  );
}

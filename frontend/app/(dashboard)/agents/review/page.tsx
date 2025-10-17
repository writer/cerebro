import { ReviewTable } from "@/components/review/review-table";
import { NotificationsPanel } from "@/components/notifications/notifications-panel";
import { PolicyPanel } from "@/components/policy/policy-panel";

export default function ReviewPage() {
  return (
    <div className="space-y-6">
      <ReviewTable />
      <div className="grid gap-6 lg:grid-cols-2">
        <NotificationsPanel />
        <PolicyPanel />
      </div>
    </div>
  );
}

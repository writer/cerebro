import { Metadata } from "next";

import { OperationalHealthDashboard } from "@/components/admin/operational-health-dashboard";

export const metadata: Metadata = {
  title: "System Health",
  description: "Operational dashboard for integrations, jobs, and telemetry.",
};

export default function OperationalHealthPage() {
  return <OperationalHealthDashboard />;
}

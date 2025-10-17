import { redirect } from "next/navigation";

export default function DashboardIndex() {
  redirect("/agents/review");
}

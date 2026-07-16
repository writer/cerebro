import { redirect } from "next/navigation";

export default function LegacyMissionControlRedirectPage() {
  redirect("/connectors");
}

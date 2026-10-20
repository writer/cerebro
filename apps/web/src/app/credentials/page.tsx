import { redirect } from "next/navigation";

// Credential health now sits on each integration, so the old store page sends
// bookmarks to the connected integrations list.
export default function CredentialsRedirectPage() {
  redirect("/connectors?tab=connected");
}

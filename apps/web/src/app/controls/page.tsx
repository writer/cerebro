import { redirect } from "next/navigation";

import { complianceControlHref, withComplianceScope } from "@/lib/compliance-links";

type ControlsRedirectPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

const firstValue = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

// Older links (finding control chips, bookmarks) pointed at /controls?framework=&control=.
// Controls are now listed under their framework on the Compliance page.
export default async function ControlsRedirectPage({ searchParams }: ControlsRedirectPageProps) {
  const params = await searchParams;
  const scope = { tenantID: firstValue(params?.tenant_id), workspaceID: firstValue(params?.workspace_id) };
  redirect(withComplianceScope(complianceControlHref(firstValue(params?.framework), firstValue(params?.control)), scope));
}

import { redirect } from "next/navigation";

import { withComplianceScope } from "@/lib/compliance-links";

type FrameworksRedirectPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

const firstValue = (value: string | string[] | undefined) => (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

// Enabled frameworks and their violations live on the Compliance page.
export default async function FrameworksRedirectPage({ searchParams }: FrameworksRedirectPageProps) {
  const params = await searchParams;
  redirect(withComplianceScope("/grc", { tenantID: firstValue(params?.tenant_id), workspaceID: firstValue(params?.workspace_id) }));
}

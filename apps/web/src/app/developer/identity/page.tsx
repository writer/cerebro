"use client";

import IdentityContractPanel from "@/components/identity/IdentityContractPanel";
import { PageHeader } from "@/components/grc/Primitives";

export default function DeveloperIdentityPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity Contract"
        description="Current user, entitlements, and write attribution."
      />
      <IdentityContractPanel />
    </div>
  );
}

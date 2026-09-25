import Link from "next/link";
import { KeyRound, Plug, ShieldCheck, UserCog } from "lucide-react";

import { PageHeader, Panel } from "@/components/grc/Primitives";

const adminSections = [
  {
    description: "Roles, claim mappings, and the permissions each console action requires.",
    href: "/admin/access-control",
    icon: ShieldCheck,
    label: "Access control",
  },
  {
    description: "Identity provider wiring, trusted headers, and signature verification posture.",
    href: "/admin/identity",
    icon: UserCog,
    label: "Sign-in",
  },
];

const relatedSections = [
  {
    description: "Source setup, ingestion scope, and connector health.",
    href: "/connectors",
    icon: Plug,
    label: "Integrations",
  },
  {
    description: "Credential store defaults and accepted reference formats.",
    href: "/credential-stores",
    icon: KeyRound,
    label: "Credential stores",
  },
  {
    description: "Organizations, users, and login history discovered by ingestion.",
    href: "/identity",
    icon: UserCog,
    label: "Members",
  },
];

type Section = (typeof adminSections)[number];

function SectionGrid({ sections }: { sections: Section[] }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {sections.map((section) => (
        <Link
          key={section.href}
          href={section.href}
          className="surface-panel flex flex-col gap-2 p-4 transition hover:border-[color:var(--primary)]"
        >
          <span className="flex items-center gap-2 text-[13px] font-semibold text-[var(--text-primary)]">
            <section.icon className="h-4 w-4 text-[var(--primary)]" />
            {section.label}
          </span>
          <span className="text-[12px] leading-5 text-[var(--text-muted)]">{section.description}</span>
        </Link>
      ))}
    </div>
  );
}

export default function AdminPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Admin"
        description="Console settings that govern who may sign in, what they may do, and which systems Cerebro ingests from."
      />

      <Panel title="Console settings">
        <SectionGrid sections={adminSections} />
      </Panel>

      <Panel title="Managed elsewhere">
        <SectionGrid sections={relatedSections} />
      </Panel>
    </div>
  );
}

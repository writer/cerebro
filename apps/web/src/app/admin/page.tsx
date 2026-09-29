import Link from "next/link";
import { KeyRound, ScrollText, ShieldCheck } from "lucide-react";

import { PageHeader, Panel } from "@/components/grc/Primitives";

const adminSections = [
  {
    description:
      "Who may sign in, how much of that identity Cerebro has verified, and which console actions each role may take.",
    href: "/admin/access-control",
    icon: ShieldCheck,
    label: "Access control",
  },
  {
    description:
      "Where the credentials for connected sources are held, either sealed in Cerebro or referenced from your own secret manager.",
    href: "/credential-stores",
    icon: KeyRound,
    label: "Credential stores",
  },
  {
    description: "What changed in this console, who changed it, and when.",
    href: "/developer/audit-log",
    icon: ScrollText,
    label: "Audit events",
  },
];

export default function AdminPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Admin"
        description="Settings that govern this console: who may use it, what it may reach, and what it recorded."
      />

      <Panel title="Settings">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {adminSections.map((section) => (
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
      </Panel>

      <Panel title="Cerebro has no user list of its own">
        <div className="space-y-2 text-[13px] leading-6 text-[var(--text-muted)]">
          <p>
            Accounts are not created here. Your identity provider decides who reaches the console, and the group claims
            it sends decide what they may do.
          </p>
          <p>
            To change someone&apos;s access, change their group membership in the provider, then map that group to a
            role under <span className="text-[var(--text-primary)]">Access control</span>.
          </p>
          <p>
            <span className="text-[var(--text-primary)]">Members</span> is a different thing: the people and
            organizations discovered in your connected systems. It is inventory, not a roster of console users, which is
            why it sits with the rest of the ingested data.
          </p>
        </div>
      </Panel>
    </div>
  );
}

import Link from "next/link";
import type { ReactNode } from "react";

import { Badge } from "@/components/grc/Primitives";
import { connectorCoverageControlRefLabel, type ConnectorCoverageControlRef } from "@/lib/connectors";
import { humanize } from "@/lib/grc";

type CoverageLike = {
  id?: string;
  dimension_id?: string;
  label?: string;
  title?: string;
  type?: string;
  dimension_type?: string;
  support?: string;
  support_level?: string;
  state?: string;
  high_value?: boolean;
  blind_spot?: boolean;
  warning?: string;
  families?: string[];
  evidence_types?: string[];
  control_domains?: string[];
  control_refs?: ConnectorCoverageControlRef[];
  matched_control_refs?: ConnectorCoverageControlRef[];
  known_unsupported_fields?: string[];
  notes?: string[];
};

export type CoverageMetadataItem = string | CoverageLike;

const chipClass = "rounded-md bg-[var(--surface-muted)] px-2 py-1 text-[11px] font-semibold text-[var(--text-secondary)]";
const monoChipClass = "rounded-md bg-[var(--surface-muted)] px-2 py-1 font-mono text-[10px] text-[var(--text-secondary)]";

const cleanList = (values?: string[]) =>
  (values ?? []).map((value) => value.trim()).filter(Boolean);

const refHref = (ref: ConnectorCoverageControlRef) => {
  const framework = ref.framework_name || ref.framework_id;
  if (!framework || !ref.control_id) return "";
  return `/controls?framework=${encodeURIComponent(framework)}&control=${encodeURIComponent(ref.control_id)}`;
};

export const coverageMetadataTitle = (item: CoverageMetadataItem) => {
  if (typeof item === "string") return humanize(item);
  return item.title || item.label || item.dimension_id || item.id || humanize(item.dimension_type || item.type || "coverage");
};

export const coverageMetadataType = (item: CoverageMetadataItem) => {
  if (typeof item === "string") return item;
  return item.dimension_type || item.type || item.id || item.dimension_id || "";
};

function Pill({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return <span className={mono ? monoChipClass : chipClass}>{children}</span>;
}

function ControlRefPill({ refItem }: { refItem: ConnectorCoverageControlRef }) {
  const label = connectorCoverageControlRefLabel(refItem);
  if (!label) return null;
  const href = refHref(refItem);
  if (!href) return <Pill>{label}</Pill>;
  return (
    <Link href={href} className={`${chipClass} transition hover:text-[var(--primary)]`}>
      {label}
    </Link>
  );
}

export function CoverageMetadata({
  item,
  compact = false,
  maxItems = 4,
  showTitle = false,
  showNotes = false,
}: {
  item: CoverageMetadataItem;
  compact?: boolean;
  maxItems?: number;
  showTitle?: boolean;
  showNotes?: boolean;
}) {
  if (typeof item === "string") {
    return (
      <div className="flex flex-wrap gap-1.5">
        <Pill mono>{item}</Pill>
      </div>
    );
  }

  const support = item.support || item.support_level;
  const type = coverageMetadataType(item);
  const evidenceTypes = cleanList(item.evidence_types);
  const controlDomains = cleanList(item.control_domains);
  const refs = [...(item.control_refs ?? []), ...(item.matched_control_refs ?? [])].filter((ref) => connectorCoverageControlRefLabel(ref));
  const unsupported = cleanList(item.known_unsupported_fields);
  const notes = cleanList(item.notes);

  return (
    <div className={compact ? "space-y-1.5" : "space-y-2"}>
      {showTitle && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[12px] font-semibold text-[var(--text-primary)]">{coverageMetadataTitle(item)}</span>
          {type && <Pill mono>{type}</Pill>}
        </div>
      )}
      <div className="flex flex-wrap gap-1.5">
        {support && <Badge value={support} />}
        {item.state && <Badge value={item.state} />}
        {item.high_value && <Badge value="high value" />}
        {item.blind_spot && <Badge value="blind spot" />}
        {!showTitle && type && <Pill mono>{type}</Pill>}
        {evidenceTypes.slice(0, maxItems).map((evidenceType) => (
          <Pill key={`evidence-${evidenceType}`}>{humanize(evidenceType)}</Pill>
        ))}
        {controlDomains.slice(0, maxItems).map((domain) => (
          <Pill key={`domain-${domain}`}>{humanize(domain)}</Pill>
        ))}
        {refs.slice(0, maxItems).map((ref) => (
          <ControlRefPill key={`${ref.framework_name || ref.framework_id}-${ref.control_id}`} refItem={ref} />
        ))}
        {refs.length > maxItems && <Pill>+{refs.length - maxItems} controls</Pill>}
      </div>
      {item.warning && <div className="text-[11px] leading-4 text-amber-700 dark:text-amber-200">{item.warning}</div>}
      {unsupported.length > 0 && (
        <div className="text-[11px] leading-4 text-[var(--text-muted)]">
          Gaps: {unsupported.slice(0, maxItems).join(", ")}{unsupported.length > maxItems ? `, +${unsupported.length - maxItems} more` : ""}
        </div>
      )}
      {showNotes && notes.length > 0 && (
        <div className="text-[11px] leading-4 text-[var(--text-muted)]">
          {notes.slice(0, compact ? 1 : 2).join(" ")}
        </div>
      )}
    </div>
  );
}

export function CoverageMetadataList({
  items,
  compact = false,
  showNotes = false,
}: {
  items?: CoverageMetadataItem[];
  compact?: boolean;
  showNotes?: boolean;
}) {
  const visible = items?.filter(Boolean) ?? [];
  if (visible.length === 0) return null;
  return (
    <div className={compact ? "space-y-2" : "grid gap-2"}>
      {visible.map((item, index) => (
        <div key={typeof item === "string" ? item : item.id || item.dimension_id || `${item.type}-${index}`} className={compact ? "" : "rounded-md bg-[var(--surface-muted)] p-2"}>
          <CoverageMetadata item={item} compact={compact} showTitle={typeof item !== "string"} showNotes={showNotes} />
        </div>
      ))}
    </div>
  );
}

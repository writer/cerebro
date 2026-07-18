import {
  assertToolCatalogEntry,
  ToolContractError,
  type ToolCatalogEntryV1,
} from "./contracts.js";

export interface ToolCatalog {
  list(): readonly ToolCatalogEntryV1[];
  resolve(toolId: string, toolVersion: string): ToolCatalogEntryV1 | undefined;
}

/**
 * Creates an immutable catalog of public tool contracts.
 *
 * The catalog owns metadata only. Integration clients, credentials, endpoints,
 * provider payloads, and deployment configuration remain host-owned.
 */
export function createToolCatalog(
  entries: readonly ToolCatalogEntryV1[],
): ToolCatalog {
  const snapshots = entries.map(snapshotEntry).sort(compareEntries);
  const byCoordinate = new Map<string, ToolCatalogEntryV1>();
  for (const entry of snapshots) {
    const coordinate = toolCoordinate(entry.tool_id, entry.tool_version);
    if (byCoordinate.has(coordinate)) {
      throw new ToolContractError("tool coordinate is registered more than once");
    }
    byCoordinate.set(coordinate, entry);
  }
  const listed = Object.freeze(snapshots);

  return Object.freeze({
    list(): readonly ToolCatalogEntryV1[] {
      return listed;
    },
    resolve(
      toolId: string,
      toolVersion: string,
    ): ToolCatalogEntryV1 | undefined {
      return byCoordinate.get(toolCoordinate(toolId, toolVersion));
    },
  });
}

function snapshotEntry(entry: ToolCatalogEntryV1): ToolCatalogEntryV1 {
  assertToolCatalogEntry(entry);
  return Object.freeze({
    ...entry,
    required_capabilities: Object.freeze(
      [...entry.required_capabilities].sort((left, right) =>
        left.localeCompare(right),
      ),
    ),
  });
}

function compareEntries(
  left: ToolCatalogEntryV1,
  right: ToolCatalogEntryV1,
): number {
  return (
    left.tool_id.localeCompare(right.tool_id) ||
    left.tool_version.localeCompare(right.tool_version)
  );
}

function toolCoordinate(toolId: string, toolVersion: string): string {
  return `${toolId}\u0000${toolVersion}`;
}

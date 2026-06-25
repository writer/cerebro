from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _operation_urn(operation: dict[str, Any]) -> str:
    resource = operation.get("resource")
    if isinstance(resource, dict):
        urn = resource.get("urn")
        if isinstance(urn, str):
            return urn
    urn = operation.get("urn")
    return urn if isinstance(urn, str) else ""


def clear_pending_operation(state: dict[str, Any], urn: str) -> bool:
    deployment = state.get("deployment")
    if not isinstance(deployment, dict):
        return False

    changed = False
    for key in ("pending_operations", "pendingOperations"):
        pending = deployment.get(key)
        if not isinstance(pending, list):
            continue

        kept = [operation for operation in pending if not (isinstance(operation, dict) and _operation_urn(operation) == urn)]
        if len(kept) != len(pending):
            deployment[key] = kept
            changed = True

    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Clear a single pending Pulumi operation from an exported stack state.")
    parser.add_argument("--input", required=True, help="Path to the exported Pulumi stack JSON.")
    parser.add_argument("--output", required=True, help="Path to write the repaired Pulumi stack JSON.")
    parser.add_argument("--urn", required=True, help="Resource URN whose pending operation should be removed.")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    state = json.loads(input_path.read_text(encoding="utf-8"))
    changed = clear_pending_operation(state, args.urn)
    output_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print("changed=true" if changed else "changed=false")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Export the Cerebro FastAPI OpenAPI schema to disk."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from fastapi.encoders import jsonable_encoder


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export the Cerebro OpenAPI schema")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Destination file path for the OpenAPI JSON document.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        help="Indent level for pretty-printed JSON (default: 2).",
    )
    return parser


def export_openapi(output_path: Path, indent: int) -> None:
    os.environ.setdefault("ENVIRONMENT", "development")
    from cerebro.api.main import app  # Imported lazily to ensure settings are loaded

    schema = jsonable_encoder(app.openapi())
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(schema, indent=indent, sort_keys=True), encoding="utf-8")


def main() -> None:
    args = build_parser().parse_args()
    export_openapi(args.output, args.indent)


if __name__ == "__main__":
    main()

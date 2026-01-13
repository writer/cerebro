"""
OCSF Exporter

Export OCSF events to various formats for SIEM, data lakes, and analytics platforms.
"""

import json
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

from cerebro.ocsf.models import OCSFEvent

logger = structlog.get_logger(__name__)


class OCSFFormat(str, Enum):
    """Supported OCSF export formats."""

    JSON = "json"
    JSONL = "jsonl"  # JSON Lines (newline-delimited)
    PARQUET = "parquet"  # For AWS Security Lake
    CSV = "csv"  # Flattened CSV


class OCSFExporter:
    """
    Export OCSF events to various formats.

    Supports:
    - JSON: Standard JSON array or single object
    - JSONL: Newline-delimited JSON (ideal for streaming)
    - Parquet: Columnar format for AWS Security Lake
    - CSV: Flattened format for spreadsheet analysis
    """

    def __init__(self) -> None:
        self.exported_count = 0

    def export_to_file(
        self,
        events: OCSFEvent | list[OCSFEvent],
        output_path: Path,
        format: OCSFFormat = OCSFFormat.JSON,
        append: bool = False,
    ) -> int:
        """
        Export OCSF events to file.

        Args:
            events: Single event or list of events
            output_path: Output file path
            format: Export format
            append: Append to existing file (JSONL only)

        Returns:
            Number of events exported
        """

        # Ensure events is a list
        if not isinstance(events, list):
            events = [events]

        if format == OCSFFormat.JSON:
            return self._export_json(events, output_path, append)
        elif format == OCSFFormat.JSONL:
            return self._export_jsonl(events, output_path, append)
        elif format == OCSFFormat.PARQUET:
            return self._export_parquet(events, output_path)
        elif format == OCSFFormat.CSV:
            return self._export_csv(events, output_path, append)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def export_to_string(
        self,
        events: OCSFEvent | list[OCSFEvent],
        format: OCSFFormat = OCSFFormat.JSON,
        pretty: bool = True,
    ) -> str:
        """
        Export OCSF events to string.

        Args:
            events: Single event or list of events
            format: Export format (JSON or JSONL)
            pretty: Pretty-print JSON (JSON only)

        Returns:
            Serialized events as string
        """

        if not isinstance(events, list):
            events = [events]

        if format == OCSFFormat.JSON:
            indent = 2 if pretty else None
            return json.dumps(
                [event.model_dump(exclude_none=True) for event in events],
                indent=indent,
            )
        elif format == OCSFFormat.JSONL:
            return "\n".join(
                json.dumps(event.model_dump(exclude_none=True)) for event in events
            )
        else:
            raise ValueError(f"String export only supports JSON/JSONL, not {format}")

    def _export_json(
        self,
        events: list[OCSFEvent],
        output_path: Path,
        append: bool,
    ) -> int:
        """Export as standard JSON array."""

        if append and output_path.exists():
            # Load existing, append, write back
            with open(output_path) as f:
                existing = json.load(f)
                if not isinstance(existing, list):
                    existing = [existing]

            combined = existing + [
                event.model_dump(exclude_none=True) for event in events
            ]

            with open(output_path, "w") as f:
                json.dump(combined, f, indent=2)

            logger.info(
                "Appended OCSF events to JSON",
                output_path=str(output_path),
                events_added=len(events),
                total_events=len(combined),
            )
        else:
            with open(output_path, "w") as f:
                json.dump(
                    [event.model_dump(exclude_none=True) for event in events],
                    f,
                    indent=2,
                )

            logger.info(
                "Exported OCSF events to JSON",
                output_path=str(output_path),
                events_count=len(events),
            )

        self.exported_count += len(events)
        return len(events)

    def _export_jsonl(
        self,
        events: list[OCSFEvent],
        output_path: Path,
        append: bool,
    ) -> int:
        """Export as JSONL (newline-delimited JSON)."""

        mode = "a" if append else "w"

        with open(output_path, mode) as f:
            for event in events:
                f.write(json.dumps(event.model_dump(exclude_none=True)) + "\n")

        logger.info(
            "Exported OCSF events to JSONL",
            output_path=str(output_path),
            events_count=len(events),
            appended=append,
        )

        self.exported_count += len(events)
        return len(events)

    def _export_parquet(
        self,
        events: list[OCSFEvent],
        output_path: Path,
    ) -> int:
        """
        Export as Parquet for AWS Security Lake.

        Requires: pandas, pyarrow
        """

        try:
            import pandas as pd
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            raise ImportError(
                "Parquet export requires pandas and pyarrow: "
                "pip install pandas pyarrow"
            ) from None

        # Convert events to dict records
        records = [event.model_dump(exclude_none=True) for event in events]

        # Flatten nested structures for Parquet
        flattened_records = [self._flatten_dict(record) for record in records]

        # Create DataFrame
        df = pd.DataFrame(flattened_records)

        # Write to Parquet
        table = pa.Table.from_pandas(df)
        pq.write_table(table, output_path, compression="snappy")

        logger.info(
            "Exported OCSF events to Parquet",
            output_path=str(output_path),
            events_count=len(events),
            columns=len(df.columns),
        )

        self.exported_count += len(events)
        return len(events)

    def _export_csv(
        self,
        events: list[OCSFEvent],
        output_path: Path,
        append: bool,
    ) -> int:
        """Export as CSV (flattened)."""

        try:
            import pandas as pd
        except ImportError:
            raise ImportError("CSV export requires pandas: pip install pandas") from None


        # Flatten records
        records = [event.model_dump(exclude_none=True) for event in events]
        flattened_records = [self._flatten_dict(record) for record in records]

        # Create DataFrame
        df = pd.DataFrame(flattened_records)

        # Write CSV
        mode = "a" if append else "w"
        header = not append  # Write header only if not appending

        df.to_csv(output_path, mode=mode, header=header, index=False)

        logger.info(
            "Exported OCSF events to CSV",
            output_path=str(output_path),
            events_count=len(events),
            appended=append,
        )

        self.exported_count += len(events)
        return len(events)

    def _flatten_dict(
        self,
        d: dict[str, Any],
        parent_key: str = "",
        sep: str = ".",
    ) -> dict[str, Any]:
        """Flatten nested dictionary with dot notation."""

        items: list[tuple[str, Any]] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k

            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to JSON strings for CSV/Parquet
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))

        return dict(items)


class OCSFBatchExporter:
    """
    Batch exporter for streaming OCSF events to destinations.

    Useful for continuous export of findings as they're created.
    """

    def __init__(
        self,
        output_path: Path,
        format: OCSFFormat = OCSFFormat.JSONL,
        batch_size: int = 100,
    ):
        self.output_path = output_path
        self.format = format
        self.batch_size = batch_size
        self.exporter = OCSFExporter()
        self.buffer: list[OCSFEvent] = []

    def add(self, event: OCSFEvent) -> int | None:
        """
        Add event to buffer. Flush if batch size reached.

        Returns:
            Number of events flushed (if flush occurred)
        """

        self.buffer.append(event)

        if len(self.buffer) >= self.batch_size:
            return self.flush()

        return None

    def flush(self) -> int:
        """Flush buffered events to file."""

        if not self.buffer:
            return 0

        count = self.exporter.export_to_file(
            events=self.buffer,
            output_path=self.output_path,
            format=self.format,
            append=True,  # Always append in batch mode
        )

        self.buffer.clear()
        return count

    def __enter__(self) -> "OCSFBatchExporter":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: type[BaseException] | None, _exc_val: BaseException | None, _exc_tb: Any) -> None:
        """Context manager exit - flush remaining."""
        self.flush()

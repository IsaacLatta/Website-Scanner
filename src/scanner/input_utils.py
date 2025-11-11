from __future__ import annotations

from pathlib import Path
from typing import List
import csv

def load_domains_from_file(path: str | Path) -> list[str]:
    p = Path(path)
    domains: list[str] = []

    with p.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            domains.append(s)

    return domains


def load_column_from_csv(
    path: Path,
    column: str,
    offset: int = 0,
    limit: int | None = None,
) -> list[str]:
    values: list[str] = []

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if column not in reader.fieldnames:
            raise ValueError(
                f"Column {column!r} not found in CSV. "
                f"Columns={reader.fieldnames}"
            )

        skipped = 0
        seen_after_offset = 0

        for row in reader:
            if skipped < offset:
                skipped += 1
                continue

            # Stop once we've consumed `limit` rows after the offset
            if limit is not None and seen_after_offset >= limit:
                break
            seen_after_offset += 1

            raw = row.get(column, "")
            if not raw:
                continue
            values.append(raw.strip())

    return values

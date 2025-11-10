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
    path: str | Path,
    column: str,
    offset: int = 0,
) -> list[str]:
    if offset < 0:
        raise ValueError("offset must be non-negative")

    p = Path(path)
    values: list[str] = []

    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or column not in reader.fieldnames:
            raise ValueError(
                f"column {column!r} not found in CSV header: {reader.fieldnames}"
            )

        skipped = 0
        for row in reader:
            if skipped < offset:
                skipped += 1
                continue

            raw = row.get(column, "")
            if not raw:
                continue
            values.append(raw.strip())

    return values

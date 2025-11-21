#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Tuple, Iterator


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "error_leaks"

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

COUNTRIES = ["ca", "us", "uk"]


def load_error_summary(country: str, sector_folder: str) -> Dict | None:
    """
    Try to load:
      ../results/<country>/<sector_folder>/error_leak/error_leak_summary.json
    Returns dict or None if the file does not exist.
    """
    path = RESULTS_DIR / country / sector_folder / "error_leak" / "error_leak_summary.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_datasets() -> Iterator[tuple[str, str, str, str, Dict]]:
    """
    Yield (country, sector_code, sector_label, dataset_label, summary_dict)
    for every country/sector combination that has an error_leak_summary.json.
    """
    for country in COUNTRIES:
        for sector_code, (sector_folder, sector_label) in SECTORS.items():
            summary = load_error_summary(country, sector_folder)
            if summary is None:
                continue
            dataset_label = f"{country.upper()} {sector_label}"
            yield country, sector_code, sector_label, dataset_label, summary


def write_error_leaks_csv(out_dir: Path) -> None:
    """
    CSV: error_leaks_summary.csv

    Columns:
      dataset_label, country, sector_code, sector_label, n_scanned_origins,
      pct_any_tech_leak, pct_version_leak, pct_stacktrace
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "error_leaks_summary.csv"

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_scanned_origins",
        "pct_any_tech_leak",
        "pct_version_leak",
        "pct_stacktrace",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for country, sector_code, sector_label, dataset_label, summary in iter_datasets():
            meta = summary.get("meta", {})
            tech = summary.get("tech_overview", {})
            stack = summary.get("stacktrace_overview", {})

            n_scanned = int(meta.get("n_scanned_origins", 0))

            pct_any = float(tech.get("pct_origins_with_any_leak",
                                     tech.get("pct_origins_with_tech_leak", 0.0)))
            pct_ver = float(tech.get("pct_origins_with_version_leak", 0.0))
            pct_stack = float(stack.get("pct_origins_with_stacktrace", 0.0))

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_scanned_origins": n_scanned,
                "pct_any_tech_leak": f"{pct_any:.1f}",
                "pct_version_leak": f"{pct_ver:.1f}",
                "pct_stacktrace": f"{pct_stack:.1f}",
            })


def main() -> None:
    write_error_leaks_csv(OUT_DIR)


if __name__ == "__main__":
    main()

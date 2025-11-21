#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Tuple, Iterator


# ---------------------------------------------------------------------------
# Paths and configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "securitytxt"

# sector code -> (folder name, human-readable label)
SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

# Countries in the scan
COUNTRIES = ["ca", "us", "uk"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def load_securitytxt_summary(country: str, sector_folder: str) -> Dict | None:
    """
    Try to load:
      ../results/<country>/<sector_folder>/securitytxt/securitytxt_summary.json
    """
    path = RESULTS_DIR / country / sector_folder / "securitytxt" / "securitytxt_summary.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_datasets() -> Iterator[tuple[str, str, str, str, Dict]]:
    """
    Yield (country, sector_code, sector_label, dataset_label, summary_dict)
    for every country/sector combination that has a securitytxt_summary.json.
    """
    for country in COUNTRIES:
        for sector_code, (sector_folder, sector_label) in SECTORS.items():
            summary = load_securitytxt_summary(country, sector_folder)
            if summary is None:
                continue
            dataset_label = f"{country.upper()} {sector_label}"
            yield country, sector_code, sector_label, dataset_label, summary


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_securitytxt_csv(out_dir: Path) -> None:
    """
    CSV: securitytxt_summary.csv

    Columns:
      dataset_label, country, sector_code, sector_label,
      n_origins, n_with_securitytxt, pct_sites_with_securitytxt,
      pct_with_contact_among_present,
      pct_with_expires_among_present,
      pct_valid_expires_among_expires
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "securitytxt_summary.csv"

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_origins",
        "n_with_securitytxt",
        "pct_sites_with_securitytxt",
        "pct_with_contact_among_present",
        "pct_with_expires_among_present",
        "pct_valid_expires_among_expires",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for country, sector_code, sector_label, dataset_label, summary in iter_datasets():
            overview = summary.get("securitytxt_overview", {})
            expires_stats = summary.get("expires_stats", {})
            contact_canon = summary.get("contact_canonical", {})

            n_origins = int(overview.get("n_origins", 0))
            n_present = int(overview.get("n_present", 0))

            # % of all sites with any usable security.txt
            pct_sites_with = safe_pct(n_present, n_origins)

            # These are already percentages in the summary, but normalize/round
            pct_contact = float(contact_canon.get("pct_present_with_contact", 0.0))
            pct_expires = float(expires_stats.get("pct_present_with_expires", 0.0))
            pct_valid_among_expires = float(
                expires_stats.get("pct_valid_expires_among_expires", 0.0)
            )

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_origins": n_origins,
                "n_with_securitytxt": n_present,
                "pct_sites_with_securitytxt": f"{pct_sites_with:.1f}",
                "pct_with_contact_among_present": f"{pct_contact:.1f}",
                "pct_with_expires_among_present": f"{pct_expires:.1f}",
                "pct_valid_expires_among_expires": f"{pct_valid_among_expires:.1f}",
            })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    write_securitytxt_csv(OUT_DIR)


if __name__ == "__main__":
    main()

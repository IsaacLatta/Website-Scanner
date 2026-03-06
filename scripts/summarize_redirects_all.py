#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Tuple, Iterator


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "redirects"

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

COUNTRIES = ["ca", "us", "uk"]


def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def load_redirect_summary(country: str, sector_folder: str) -> dict | None:
    path = RESULTS_DIR / country / sector_folder / "redirects" / "redirect_summary.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_full_results(country: str, sector_folder: str) -> dict | None:
    """
    Full run_scan() output, e.g. results/ca/auth/ca_auth.json
    """
    filename = f"{country}_{sector_folder}.json"
    path = RESULTS_DIR / country / sector_folder / filename
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_datasets() -> Iterator[tuple[str, str, str, str, dict, dict]]:
    """
    Yield (country, sector_code, sector_label, dataset_label,
           redirect_summary, full_results)
    for every dataset that has both files available.
    """
    for country in COUNTRIES:
        for sector_code, (sector_folder, sector_label) in SECTORS.items():
            redirect_summary = load_redirect_summary(country, sector_folder)
            full_results = load_full_results(country, sector_folder)
            if redirect_summary is None or full_results is None:
                continue
            dataset_label = f"{country.upper()} {sector_label}"
            yield (
                country,
                sector_code,
                sector_label,
                dataset_label,
                redirect_summary,
                full_results,
            )


def write_redirects_csv(out_dir: Path) -> None:
    """
    Comparison CSV: redirects_summary.csv

    Columns:
      dataset_label, country, sector_code, sector_label,
      n_input_uris, n_final_uris,
      n_input_origins, n_final_origins,
      n_resolved_uris,
      pct_final_2xx, pct_final_4xx_5xx, pct_no_final,
      n_origins, pct_origins_all_unreachable
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "redirects_summary.csv"

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_input_uris",
        "n_final_uris",
        "n_input_origins",
        "n_final_origins",
        "n_resolved_uris",
        "pct_final_2xx",
        "pct_final_4xx_5xx",
        "pct_no_final",
        "n_origins",
        "pct_origins_all_unreachable",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for (
            country,
            sector_code,
            sector_label,
            dataset_label,
            redirect_summary,
            full_results,
        ) in iter_datasets():
            scan_targets = full_results.get("scan_targets", {})
            origin_targets = full_results.get("origin_targets", {})
            resolutions = full_results.get("resolutions", {})

            input_uris = scan_targets.get("uris", [])    
            input_origins = scan_targets.get("origins", [])
            final_origins = origin_targets.get("final_origins", [])

            n_input_uris = len(input_uris)
            n_input_origins = len(input_origins)
            n_final_origins = len(final_origins)

            final_urls = {
                res.get("final_url")
                for res in resolutions.values()
                if isinstance(res, dict) and res.get("final_url")
            }
            n_final_uris = len(final_urls)

            redirects = redirect_summary.get("redirects", {})
            origin_health = redirect_summary.get("origin_health", {})

            n_resolutions = int(redirects.get("n_resolutions", 0))
            outcome_counts = redirects.get("outcome_counts", {}) or {}

            n_2xx = int(outcome_counts.get("ok_final_2xx", 0))
            n_4xx = int(outcome_counts.get("ok_final_4xx_non_block", 0))
            n_5xx = int(outcome_counts.get("ok_final_5xx", 0))
            n_blocked = int(outcome_counts.get("blocked_403_503", 0))

            n_final_any = n_2xx + n_4xx + n_5xx + n_blocked
            n_resolved_uris = n_final_any  # inputs that reached a final URL

            n_final_2xx = n_2xx
            n_final_4xx_5xx = n_4xx + n_5xx + n_blocked

            pct_final_2xx = safe_pct(n_final_2xx, n_resolutions)
            pct_final_4xx_5xx = safe_pct(n_final_4xx_5xx, n_resolutions)
            n_no_final = max(0, n_resolutions - n_final_any)
            pct_no_final = safe_pct(n_no_final, n_resolutions)

            n_origins = int(origin_health.get("n_origins", 0))
            n_origins_all_unreachable = int(
                origin_health.get("n_origins_all_inputs_unreachable", 0)
            )
            pct_origins_all_unreachable = safe_pct(
                n_origins_all_unreachable, n_origins
            )

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_input_uris": n_input_uris,
                "n_final_uris": n_final_uris,
                "n_input_origins": n_input_origins,
                "n_final_origins": n_final_origins,
                "n_resolved_uris": n_resolved_uris,
                "pct_final_2xx": f"{pct_final_2xx:.1f}",
                "pct_final_4xx_5xx": f"{pct_final_4xx_5xx:.1f}",
                "pct_no_final": f"{pct_no_final:.1f}",
                "n_origins": n_origins,
                "pct_origins_all_unreachable": f"{pct_origins_all_unreachable:.1f}",
            })


def main() -> None:
    write_redirects_csv(OUT_DIR)


if __name__ == "__main__":
    main()

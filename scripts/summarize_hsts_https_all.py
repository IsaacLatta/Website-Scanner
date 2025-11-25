#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Tuple, List

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "https_hsts"

COUNTRIES = {
    "ca": "CA",
    "us": "US",
    "uk": "UK",
}

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}


def load_summary(country: str, sector: str) -> Dict:
    """
    Load https_hsts_summary.json for a given (country, sector) pair.

    Expected path:
      ../results/<country>/<sector>/hsts_https/https_hsts_summary.json
    """
    path = RESULTS_DIR / country / sector / "hsts_https" / "https_hsts_summary.json"
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def collect_datasets() -> List[tuple]:
    """
    Return a list of (country_code, country_label, sector_key, sector_path, sector_label)
    for which a https_hsts_summary.json exists.
    """
    datasets: List[tuple] = []
    for c_code, c_label in COUNTRIES.items():
        for s_key, (s_path, s_label) in SECTORS.items():
            try:
                _ = load_summary(c_code, s_path)
            except FileNotFoundError:
                continue
            datasets.append((c_code, c_label, s_key, s_path, s_label))
    return datasets


def build_enforcement_rows(datasets: List[tuple]) -> List[Dict[str, str]]:
    """
    Build rows for HTTPS/HSTS enforcement summary.

    Columns (per dataset):
      - dataset_label
      - sector_label
      - n_origins
      - pct_https_success (of all origins)
      - pct_https_unreachable (of all origins)
      - pct_http_probe_ok (of all origins)
      - pct_http_redirect_to_https (of HTTP-probed origins)
      - pct_http_no_redirect (of HTTP-probed origins)
    """
    rows: List[Dict[str, str]] = []

    for c_code, c_label, _s_key, s_path, s_label in datasets:
        summary = load_summary(c_code, s_path)

        https_conn = summary.get("https_connectivity", {})
        http_to_https = summary.get("http_to_https", {})
        enforcement = summary.get("enforcement_counts", {})

        n_origins = int(https_conn.get("n_origins", 0))
        n_https_success = int(https_conn.get("n_https_success", 0))

        n_http_probe_ok = int(http_to_https.get("n_http_probe_ok", 0))
        n_http_redirect_to_https = int(http_to_https.get("n_http_redirect_to_https", 0))
        n_http_no_redirect = int(http_to_https.get("n_http_no_redirect", 0))

        n_https_unreachable = int(enforcement.get("https_unreachable", 0))

        row = {
            "dataset_label": f"{c_label} {s_label}",
            "sector_label": s_label,
            "n_origins": str(n_origins),
            "pct_https_success": f"{safe_pct(n_https_success, n_origins):.2f}",
            "pct_https_unreachable": f"{safe_pct(n_https_unreachable, n_origins):.2f}",
            "pct_http_probe_ok": f"{safe_pct(n_http_probe_ok, n_origins):.2f}",
            "pct_http_redirect_to_https": f"{safe_pct(n_http_redirect_to_https, n_http_probe_ok):.2f}",
            "pct_http_no_redirect": f"{safe_pct(n_http_no_redirect, n_http_probe_ok):.2f}",
        }
        rows.append(row)

    return rows


def build_hsts_quality_rows(datasets: List[tuple]) -> List[Dict[str, str]]:
    """
    Build rows for HSTS configuration quality summary.

    Columns (per dataset):
      - dataset_label
      - sector_label
      - n_https_ok
      - n_has_hsts
      - pct_has_hsts_among_https_ok
      - pct_hsts_maxage_1yr_among_hsts
      - pct_hsts_include_subdomains_among_hsts
      - pct_hsts_preload_among_hsts
      - pct_hsts_strong_among_hsts
    """
    rows: List[Dict[str, str]] = []

    for c_code, c_label, _s_key, s_path, s_label in datasets:
        summary = load_summary(c_code, s_path)
        h = summary.get("hsts", {})

        n_https_ok = int(h.get("n_https_ok", 0))
        n_has_hsts = int(h.get("n_has_hsts", 0))
        n_maxage_1yr = int(h.get("n_hsts_maxage_1yr", 0))
        n_subdomains = int(h.get("n_hsts_include_subdomains", 0))
        n_preload = int(h.get("n_hsts_preload_flag", 0))
        n_strong = int(h.get("n_hsts_strong", 0))

        row = {
            "dataset_label": f"{COUNTRIES[c_code]} {s_label}",
            "sector_label": s_label,
            "n_https_ok": str(n_https_ok),
            "n_has_hsts": str(n_has_hsts),
            "pct_has_hsts_among_https_ok": f"{safe_pct(n_has_hsts, n_https_ok):.2f}",
            "pct_hsts_maxage_1yr_among_hsts": f"{safe_pct(n_maxage_1yr, n_has_hsts):.2f}",
            "pct_hsts_include_subdomains_among_hsts": f"{safe_pct(n_subdomains, n_has_hsts):.2f}",
            "pct_hsts_preload_among_hsts": f"{safe_pct(n_preload, n_has_hsts):.2f}",
            "pct_hsts_strong_among_hsts": f"{safe_pct(n_strong, n_has_hsts):.2f}",
        }
        rows.append(row)

    return rows


def write_csv(path: Path, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    print("CALLED")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    datasets = collect_datasets()
    if not datasets:
        raise SystemExit("No https_hsts_summary.json files found")

    # 1) Enforcement CSV
    enforcement_rows = build_enforcement_rows(datasets)
    enforcement_fields = [
        "dataset_label",
        "sector_label",
        "n_origins",
        "pct_https_success",
        "pct_https_unreachable",
        "pct_http_probe_ok",
        "pct_http_redirect_to_https",
        "pct_http_no_redirect",
    ]
    write_csv(
        OUT_DIR / "https_hsts_enforcement_summary.csv",
        enforcement_fields,
        enforcement_rows,
    )

    # 2) HSTS quality CSV
    hsts_rows = build_hsts_quality_rows(datasets)
    hsts_fields = [
        "dataset_label",
        "sector_label",
        "n_https_ok",
        "n_has_hsts",
        "pct_has_hsts_among_https_ok",
        "pct_hsts_maxage_1yr_among_hsts",
        "pct_hsts_include_subdomains_among_hsts",
        "pct_hsts_preload_among_hsts",
        "pct_hsts_strong_among_hsts",
    ]
    write_csv(
        OUT_DIR / "hsts_quality_summary.csv",
        hsts_fields,
        hsts_rows,
    )


if __name__ == "__main__":
    main()

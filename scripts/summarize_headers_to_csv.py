#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, Tuple, Iterator


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "headers"

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

COUNTRIES = ["ca", "us", "uk"]

SECURITY_HEADER_RULES = [
    ("referrer_policy", "Referrer-Policy"),
    ("x_content_type_options", "X-Content-Type-Options"),
    ("x_frame_options", "X-Frame-Options"),
    ("csp_frame_ancestors", "CSP frame-ancestors"),
    ("permissions_policy", "Permissions-Policy"),
]


def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def load_headers_summary(country: str, sector_folder: str) -> Dict | None:
    """
    Try to load ../results/<country>/<sector_folder>/headers/headers_summary.json.
    Returns dict or None if the file does not exist.
    """
    path = RESULTS_DIR / country / sector_folder / "headers" / "headers_summary.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def iter_datasets() -> Iterator[tuple[str, str, str, str, Dict]]:
    """
    Yield (country, sector_code, sector_label, dataset_label, summary_dict)
    for every country/sector combination that has a headers_summary.json file.
    """
    for country in COUNTRIES:
        for sector_code, (sector_folder, sector_label) in SECTORS.items():
            summary = load_headers_summary(country, sector_folder)
            if summary is None:
                continue
            dataset_label = f"{country.upper()} {sector_label}"
            yield country, sector_code, sector_label, dataset_label, summary


def write_revealing_headers_csv(out_dir: Path) -> None:
    """
    CSV 1: revealing_headers_summary.csv

    Columns:
      dataset_label, country, sector_code, sector_label, n_sites,
      pct_revealing_0, pct_revealing_1, pct_revealing_2, pct_revealing_3_plus,
      pct_with_any_revealing
    """
    out_path = out_dir / "revealing_headers_summary.csv"
    out_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_sites",
        "pct_revealing_0",
        "pct_revealing_1",
        "pct_revealing_2",
        "pct_revealing_3_plus",
        "pct_with_any_revealing",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for country, sector_code, sector_label, dataset_label, summary in iter_datasets():
            meta = summary.get("meta", {})
            n_sites = int(meta.get("n_sites", 0))

            rev = summary.get("revealing_headers", {})
            dist = rev.get("count_distribution", {})
            n_any = int(rev.get("n_sites_with_any_revealing", 0))

            pct_0 = safe_pct(int(dist.get("0", 0)), n_sites)
            pct_1 = safe_pct(int(dist.get("1", 0)), n_sites)
            pct_2 = safe_pct(int(dist.get("2", 0)), n_sites)
            pct_3p = safe_pct(int(dist.get("3+", 0)), n_sites)
            pct_any = safe_pct(n_any, n_sites)

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_sites": n_sites,
                "pct_revealing_0": f"{pct_0:.1f}",
                "pct_revealing_1": f"{pct_1:.1f}",
                "pct_revealing_2": f"{pct_2:.1f}",
                "pct_revealing_3_plus": f"{pct_3p:.1f}",
                "pct_with_any_revealing": f"{pct_any:.1f}",
            })


def write_security_headers_csv(out_dir: Path) -> None:
    """
    CSV 2: security_headers_presence.csv

    Columns:
      dataset_label, country, sector_code, sector_label, n_sites,
      pct_referrer_policy_present,
      pct_x_content_type_options_present,
      pct_x_frame_options_present,
      pct_csp_frame_ancestors_present,
      pct_permissions_policy_present
    """
    out_path = out_dir / "security_headers_presence.csv"
    out_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_sites",
        "pct_referrer_policy_present",
        "pct_x_content_type_options_present",
        "pct_x_frame_options_present",
        "pct_csp_frame_ancestors_present",
        "pct_permissions_policy_present",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for country, sector_code, sector_label, dataset_label, summary in iter_datasets():
            meta = summary.get("meta", {})
            n_sites = int(meta.get("n_sites", 0))

            rules = summary.get("security_rules", {})

            def pct_present(rule_key: str) -> float:
                r = rules.get(rule_key, {})
                n_present = int(r.get("n_present", 0))
                return safe_pct(n_present, n_sites)

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_sites": n_sites,
                "pct_referrer_policy_present": f"{pct_present('referrer_policy'):.1f}",
                "pct_x_content_type_options_present": f"{pct_present('x_content_type_options'):.1f}",
                "pct_x_frame_options_present": f"{pct_present('x_frame_options'):.1f}",
                "pct_csp_frame_ancestors_present": f"{pct_present('csp_frame_ancestors'):.1f}",
                "pct_permissions_policy_present": f"{pct_present('permissions_policy'):.1f}",
            })


def write_cookie_flags_csv(out_dir: Path) -> None:
    """
    CSV 3: cookie_security_flags_summary.csv

    Columns:
      dataset_label, country, sector_code, sector_label, n_sites,
      pct_sites_with_cookies,
      pct_secure_among_cookie_sites,
      pct_httponly_among_cookie_sites,
      pct_samesite_ge_lax_among_cookie_sites,
      pct_rec_suff_among_cookie_sites
    """
    out_path = out_dir / "cookie_security_flags_summary.csv"
    out_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "dataset_label",
        "country",
        "sector_code",
        "sector_label",
        "n_sites",
        "pct_sites_with_cookies",
        "pct_secure_among_cookie_sites",
        "pct_httponly_among_cookie_sites",
        "pct_samesite_ge_lax_among_cookie_sites",
        "pct_rec_suff_among_cookie_sites",
    ]

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for country, sector_code, sector_label, dataset_label, summary in iter_datasets():
            meta = summary.get("meta", {})
            n_sites = int(meta.get("n_sites", 0))

            cookies = summary.get("cookies", {})
            n_c = int(cookies.get("n_sites_with_cookies", 0))
            pct_sites_with_cookies = safe_pct(n_c, n_sites)

            flags = cookies.get("flag_counts", {})
            ratings = cookies.get("rating_counts", {})

            secure_pct = safe_pct(int(flags.get("secure", 0)), n_c)
            httponly_pct = safe_pct(int(flags.get("httponly", 0)), n_c)
            samesite_ge_lax_ct = int(flags.get("samesite_lax", 0)) + int(flags.get("samesite_strict", 0))
            samesite_ge_lax_pct = safe_pct(samesite_ge_lax_ct, n_c)
            rec_suff_ct = int(ratings.get("recommended", 0)) + int(ratings.get("sufficient", 0))
            rec_suff_pct = safe_pct(rec_suff_ct, n_c)

            writer.writerow({
                "dataset_label": dataset_label,
                "country": country.upper(),
                "sector_code": sector_code,
                "sector_label": sector_label,
                "n_sites": n_sites,
                "pct_sites_with_cookies": f"{pct_sites_with_cookies:.1f}",
                "pct_secure_among_cookie_sites": f"{secure_pct:.1f}",
                "pct_httponly_among_cookie_sites": f"{httponly_pct:.1f}",
                "pct_samesite_ge_lax_among_cookie_sites": f"{samesite_ge_lax_pct:.1f}",
                "pct_rec_suff_among_cookie_sites": f"{rec_suff_pct:.1f}",
            })


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_revealing_headers_csv(OUT_DIR)
    write_security_headers_csv(OUT_DIR)
    write_cookie_flags_csv(OUT_DIR)


if __name__ == "__main__":
    main()

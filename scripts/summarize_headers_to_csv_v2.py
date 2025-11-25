#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Dict, Tuple, Iterator, Any

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

# These keys must match the "name" field used by the headers module.
SECURITY_HEADER_RULES = [
    ("referrer_policy", "Referrer-Policy"),
    ("x_content_type_options", "X-Content-Type-Options"),
    ("x_frame_options", "X-Frame-Options"),
    ("csp_frame_ancestors", "CSP frame-ancestors"),
    ("permissions_policy", "Permissions-Policy"),
]
SECURITY_RULE_KEYS = [k for k, _ in SECURITY_HEADER_RULES]

COOKIE_RULE = "cookies"
TOP_N_REVEALING = 20


def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def load_full_results(country: str, sector_folder: str) -> Dict[str, Any] | None:
    """
    Load the full scan JSON produced by main/runner:

        results/<country>/<sector_folder>/<country>_<sector_folder>.json
    """
    path = RESULTS_DIR / country / sector_folder / f"{country}_{sector_folder}.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def summarise_headers_from_results(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a headers summary keyed by *final URIs*, so that n_sites matches the
    redirect summary's n_final_uris.

    We:
      * Use resolutions.final_url in exactly the same way as summarize_redirects_all.
      * Collapse multiple input URIs that end at the same final_url into one site.
      * If no header results exist for a final_url, we treat that site as having
        an empty header list (i.e., no headers observed).
    """
    modules = results.get("modules", {}) or {}
    header_module: Dict[str, list] = modules.get("headers", {}) or {}
    resolutions: Dict[str, Any] = results.get("resolutions", {}) or {}

    # Build final_url -> list-of-header-results mapping. We follow the same
    # final_url logic as summarize_redirects_all.py, and then associate one
    # header result list with each final URL (first non-empty we see).
    final_url_to_headers: Dict[str, list] = {}

    for input_url, res in resolutions.items():
        if not isinstance(res, dict):
            continue
        final_url = res.get("final_url")
        if not final_url:
            # No final URL; this URI contributes to "no final URL" in the
            # redirect table, and should not be counted as a site here.
            continue

        hdr_list = header_module.get(input_url)
        if hdr_list is None:
            hdr_list = []

        if final_url not in final_url_to_headers:
            final_url_to_headers[final_url] = hdr_list
        else:
            # If we already have headers for this final_url but they are empty
            # and this new hdr_list is non-empty, prefer the non-empty one.
            if not final_url_to_headers[final_url] and hdr_list:
                final_url_to_headers[final_url] = hdr_list

    n_input_uris = len(header_module)
    n_sites = len(final_url_to_headers)  # this should match n_final_uris

    baseline_enabled_counts: Counter[int] = Counter()
    baseline_all_enabled = 0

    posture_counts: Counter[str] = Counter()

    security_rating_counts: Dict[str, Counter[str]] = {
        name: Counter() for name in SECURITY_RULE_KEYS
    }
    security_presence_counts: Counter[str] = Counter()

    cookie_rating_counts: Counter[str] = Counter()
    cookie_flag_counts: Counter[str] = Counter()
    n_sites_with_cookies = 0

    revealing_presence_counts: Counter[str] = Counter()
    revealing_count_distribution: Counter[str] = Counter()
    n_sites_with_any_revealing = 0

    for final_url, results_list in final_url_to_headers.items():
        # Split into security headers, cookies, and revealing headers.
        security_results: Dict[str, Dict[str, Any]] = {}
        cookie_result: Dict[str, Any] | None = None
        revealing_results: list[Dict[str, Any]] = []

        for r in results_list:
            name = r.get("name")
            category = r.get("category", "security")
            if category == "revealing":
                revealing_results.append(r)
            else:
                if name == COOKIE_RULE:
                    cookie_result = r
                elif isinstance(name, str):
                    security_results[name] = r

        # --- Baseline CCCS-style headers ---
        enabled_count = 0
        insecure_or_obsolete = False

        for rule in SECURITY_RULE_KEYS:
            r = security_results.get(rule)
            if not r:
                continue
            rating = r.get("rating", "unknown")
            present = bool(r.get("present", False))

            security_rating_counts[rule][rating] += 1
            if present:
                security_presence_counts[rule] += 1

            if rating in ("recommended", "sufficient"):
                enabled_count += 1
            if rating in ("insecure", "obsolete"):
                insecure_or_obsolete = True

        baseline_enabled_counts[enabled_count] += 1
        if enabled_count == len(SECURITY_RULE_KEYS):
            baseline_all_enabled += 1

        if enabled_count == 0:
            posture = "weak"
        elif enabled_count >= 3 and not insecure_or_obsolete:
            posture = "strong"
        else:
            posture = "mixed"
        posture_counts[posture] += 1

        # --- Cookies ---
        if cookie_result and cookie_result.get("present", False):
            n_sites_with_cookies += 1
            rating = cookie_result.get("rating", "unknown")
            cookie_rating_counts[rating] += 1

            extra = cookie_result.get("additional_fields") or {}
            if extra.get("has_secure"):
                cookie_flag_counts["secure"] += 1
            if extra.get("has_httponly"):
                cookie_flag_counts["httponly"] += 1

            samesite = (extra.get("samesite") or "").strip().lower()
            if samesite == "strict":
                cookie_flag_counts["samesite_strict"] += 1
            elif samesite == "lax":
                cookie_flag_counts["samesite_lax"] += 1
            elif samesite == "none":
                cookie_flag_counts["samesite_none"] += 1
            else:
                cookie_flag_counts["samesite_missing_or_other"] += 1

            if extra.get("has_max_age") or extra.get("has_expires"):
                cookie_flag_counts["has_lifetime"] += 1

        # --- Revealing headers ---
        present_revealing = 0
        for r in revealing_results:
            display_name = r.get("name")
            if r.get("present", False):
                present_revealing += 1
                if isinstance(display_name, str):
                    revealing_presence_counts[display_name] += 1

        if present_revealing == 0:
            revealing_count_distribution["0"] += 1
        elif present_revealing == 1:
            revealing_count_distribution["1"] += 1
        elif present_revealing == 2:
            revealing_count_distribution["2"] += 1
        else:
            revealing_count_distribution["3+"] += 1

        if present_revealing > 0:
            n_sites_with_any_revealing += 1

    baseline_histogram = {
        "0": baseline_enabled_counts.get(0, 0),
        "1-2": sum(baseline_enabled_counts[k] for k in (1, 2)),
        "3-4": sum(baseline_enabled_counts[k] for k in (3, 4)),
        "5_all": baseline_enabled_counts.get(len(SECURITY_RULE_KEYS), 0),
    }

    security_rules_summary: Dict[str, Dict[str, Any]] = {}
    for rule in SECURITY_RULE_KEYS:
        ratings = security_rating_counts[rule]
        security_rules_summary[rule] = {
            "ratings": dict(ratings),
            "n_present": security_presence_counts.get(rule, 0),
        }

    top_revealing = sorted(
        revealing_presence_counts.items(),
        key=lambda kv: kv[1],
        reverse=True,
    )[:TOP_N_REVEALING]

    summary: Dict[str, Any] = {
        "meta": {
            "n_sites": n_sites,         # should align with n_final_uris
            "n_input_uris": n_input_uris,
        },
        "baseline_overview": {
            "security_rules": SECURITY_RULE_KEYS,
            "baseline_enabled_histogram": baseline_histogram,
            "n_sites_with_any_baseline": n_sites - baseline_enabled_counts.get(0, 0),
            "pct_sites_with_any_baseline": safe_pct(
                n_sites - baseline_enabled_counts.get(0, 0), n_sites
            ),
            "n_sites_with_all_baseline": baseline_all_enabled,
            "pct_sites_with_all_baseline": safe_pct(baseline_all_enabled, n_sites),
            "posture_counts": dict(posture_counts),
        },
        "security_rules": security_rules_summary,
        "cookies": {
            "n_sites_with_cookies": n_sites_with_cookies,
            "pct_sites_with_cookies": safe_pct(n_sites_with_cookies, n_sites),
            "flag_counts": dict(cookie_flag_counts),
            "rating_counts": dict(cookie_rating_counts),
        },
        "revealing_headers": {
            "n_sites_with_any_revealing": n_sites_with_any_revealing,
            "pct_sites_with_any_revealing": safe_pct(
                n_sites_with_any_revealing, n_sites
            ),
            "presence_counts": dict(revealing_presence_counts),
            "count_distribution": dict(revealing_count_distribution),
            "top_revealing": top_revealing,
        },
    }
    return summary


def iter_datasets() -> Iterator[tuple[str, str, str, str, Dict[str, Any]]]:
    """
    Yield (country, sector_code, sector_label, dataset_label, summary_dict)
    for every country/sector combination that has a full results JSON file.
    """
    for country in COUNTRIES:
        for sector_code, (sector_folder, sector_label) in SECTORS.items():
            full_results = load_full_results(country, sector_folder)
            if full_results is None:
                continue
            summary = summarise_headers_from_results(full_results)
            dataset_label = f"{country.upper()} {sector_label}"
            yield country, sector_code, sector_label, dataset_label, summary


def write_revealing_headers_csv(out_dir: Path) -> None:
    """
    CSV 1: revealing_headers_summary.csv
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

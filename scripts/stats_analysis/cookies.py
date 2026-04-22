#!/usr/bin/env python3

"""
Compute Wilson 95% confidence intervals for Table 7
(Cookie security flag adoption by country and sector).

This script reads the cookie-security summary CSV used by the paper and emits a
standardized long-form CSV for later aggregation across tables.

Denominator rules for this table:
- "Sites with cookies" is computed among all measured sites:
    numerator   = reconstructed from pct_sites_with_cookies
    denominator = n_sites

- The remaining columns are computed among cookie-setting sites only:
    denominator = n_cookie_sites
  where:
    n_cookie_sites = reconstructed from pct_sites_with_cookies * n_sites

Specifically:
- "Secure flag" is computed among cookie-setting sites
- "HttpOnly flag" is computed among cookie-setting sites
- "SameSite≥Lax" is computed among cookie-setting sites
- "Recommended/Sufficient" is computed among cookie-setting sites

Because the input stores rounded percentages, and because n_cookie_sites is
itself reconstructed from a rounded percentage, reconstructed counts may differ
slightly from the original raw counts. That is acceptable for the CI summary
workflow, but raw counts should be preferred if later available.

Output schema:
- source_table
- dataset_label
- metric
- claim_label
- success_count
- total_count
- proportion
- percent_reported
- ci_low
- ci_high
- ci_low_pct
- ci_high_pct
"""

import argparse
import math
from pathlib import Path

import pandas as pd

Z_95 = 1.96


def wilson_ci(x: int, n: int, z: float = Z_95) -> tuple[float, float, float]:
    if n <= 0:
        return float("nan"), float("nan"), float("nan")

    p = x / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half_width = (
        z
        * math.sqrt((p * (1.0 - p) / n) + ((z * z) / (4.0 * n * n)))
        / denom
    )

    return p, center - half_width, center + half_width


def pct_to_count(pct: float, n: int) -> int:
    return int(round((pct / 100.0) * n))


def require_columns(df: pd.DataFrame, required: list[str]) -> None:
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def build_rows(df: pd.DataFrame) -> list[dict]:
    out_rows: list[dict] = []

    for _, row in df.iterrows():
        dataset_label = str(row["dataset_label"]).strip()
        n_sites = int(row["n_sites"])

        pct_sites_with_cookies = float(row["pct_sites_with_cookies"])
        n_cookie_sites = pct_to_count(pct_sites_with_cookies, n_sites)

        # Sites with cookies among all sites
        sites_with_cookies_x = n_cookie_sites
        sites_with_cookies_n = n_sites
        prop, ci_low, ci_high = wilson_ci(sites_with_cookies_x, sites_with_cookies_n)

        out_rows.append(
            {
                "source_table": "table7_cookie_security_flags",
                "dataset_label": dataset_label,
                "metric": "sites_with_cookies",
                "claim_label": "Sites with cookies",
                "success_count": sites_with_cookies_x,
                "total_count": sites_with_cookies_n,
                "proportion": prop,
                "percent_reported": pct_sites_with_cookies,
                "ci_low": ci_low,
                "ci_high": ci_high,
                "ci_low_pct": ci_low * 100.0,
                "ci_high_pct": ci_high * 100.0,
            }
        )

        metric_specs = [
            {
                "metric": "secure_flag_present",
                "claim_label": "Secure flag",
                "pct_col": "pct_secure_among_cookie_sites",
            },
            {
                "metric": "httponly_flag_present",
                "claim_label": "HttpOnly flag",
                "pct_col": "pct_httponly_among_cookie_sites",
            },
            {
                "metric": "samesite_ge_lax_present",
                "claim_label": "SameSite≥Lax",
                "pct_col": "pct_samesite_ge_lax_among_cookie_sites",
            },
            {
                "metric": "recommended_sufficient",
                "claim_label": "Recommended/Sufficient",
                "pct_col": "pct_rec_suff_among_cookie_sites",
            },
        ]

        for spec in metric_specs:
            pct = float(row[spec["pct_col"]])
            x = pct_to_count(pct, n_cookie_sites)
            n = n_cookie_sites
            prop, ci_low, ci_high = wilson_ci(x, n)

            out_rows.append(
                {
                    "source_table": "table7_cookie_security_flags",
                    "dataset_label": dataset_label,
                    "metric": spec["metric"],
                    "claim_label": spec["claim_label"],
                    "success_count": x,
                    "total_count": n,
                    "proportion": prop,
                    "percent_reported": pct,
                    "ci_low": ci_low,
                    "ci_high": ci_high,
                    "ci_low_pct": ci_low * 100.0,
                    "ci_high_pct": ci_high * 100.0,
                }
            )

    return out_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compute Wilson 95% confidence intervals for Table 7 "
            "(Cookie security flag adoption by country and sector)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to cookie_security_flags_summary.csv",
    )
    parser.add_argument(
        "output_csv",
        type=Path,
        help="Path to write the long-form Wilson CI summary CSV",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    df = pd.read_csv(args.input_csv)

    require_columns(
        df,
        [
            "dataset_label",
            "n_sites",
            "pct_sites_with_cookies",
            "pct_secure_among_cookie_sites",
            "pct_httponly_among_cookie_sites",
            "pct_samesite_ge_lax_among_cookie_sites",
            "pct_rec_suff_among_cookie_sites",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

"""
Compute Wilson 95% confidence intervals for Table 5
(HSTS adoption and strength among HTTPS-capable origins).

This script reads the HSTS quality summary CSV used by the paper and emits a
standardized long-form CSV for later aggregation across tables.

Important denominator rules for this table:
- "Any HSTS" is computed among HTTPS-capable origins:
    numerator   = n_has_hsts
    denominator = n_https_ok

- "Strong HSTS" is computed among origins that already have HSTS:
    numerator   = reconstructed from pct_hsts_strong_among_hsts
    denominator = n_has_hsts

- "Preload signaling" is computed among origins that already have HSTS:
    numerator   = reconstructed from pct_hsts_preload_among_hsts
    denominator = n_has_hsts

Because some inputs are stored as rounded percentages, reconstructed counts may
differ by 1 from the original raw counts. That is acceptable for the CI summary
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

        n_https_ok = int(row["n_https_ok"])
        n_has_hsts = int(row["n_has_hsts"])

        # Any HSTS among HTTPS-ok
        any_hsts_x = n_has_hsts
        any_hsts_n = n_https_ok
        any_hsts_prop, any_hsts_low, any_hsts_high = wilson_ci(any_hsts_x, any_hsts_n)

        out_rows.append(
            {
                "source_table": "table5_hsts_quality",
                "dataset_label": dataset_label,
                "metric": "any_hsts",
                "claim_label": "Any HSTS",
                "success_count": any_hsts_x,
                "total_count": any_hsts_n,
                "proportion": any_hsts_prop,
                "percent_reported": float(row["pct_has_hsts_among_https_ok"]),
                "ci_low": any_hsts_low,
                "ci_high": any_hsts_high,
                "ci_low_pct": any_hsts_low * 100.0,
                "ci_high_pct": any_hsts_high * 100.0,
            }
        )

        # Strong HSTS among HSTS-present origins
        strong_pct = float(row["pct_hsts_strong_among_hsts"])
        strong_x = pct_to_count(strong_pct, n_has_hsts)
        strong_n = n_has_hsts
        strong_prop, strong_low, strong_high = wilson_ci(strong_x, strong_n)

        out_rows.append(
            {
                "source_table": "table5_hsts_quality",
                "dataset_label": dataset_label,
                "metric": "strong_hsts",
                "claim_label": "Strong HSTS",
                "success_count": strong_x,
                "total_count": strong_n,
                "proportion": strong_prop,
                "percent_reported": strong_pct,
                "ci_low": strong_low,
                "ci_high": strong_high,
                "ci_low_pct": strong_low * 100.0,
                "ci_high_pct": strong_high * 100.0,
            }
        )

        # Preload signaling among HSTS-present origins
        preload_pct = float(row["pct_hsts_preload_among_hsts"])
        preload_x = pct_to_count(preload_pct, n_has_hsts)
        preload_n = n_has_hsts
        preload_prop, preload_low, preload_high = wilson_ci(preload_x, preload_n)

        out_rows.append(
            {
                "source_table": "table5_hsts_quality",
                "dataset_label": dataset_label,
                "metric": "preload_signaling",
                "claim_label": "Preload signaling",
                "success_count": preload_x,
                "total_count": preload_n,
                "proportion": preload_prop,
                "percent_reported": preload_pct,
                "ci_low": preload_low,
                "ci_high": preload_high,
                "ci_low_pct": preload_low * 100.0,
                "ci_high_pct": preload_high * 100.0,
            }
        )

    return out_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compute Wilson 95% confidence intervals for Table 5 "
            "(HSTS adoption and strength among HTTPS-capable origins)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to hsts_quality_summary.csv",
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
            "n_https_ok",
            "n_has_hsts",
            "pct_has_hsts_among_https_ok",
            "pct_hsts_preload_among_hsts",
            "pct_hsts_strong_among_hsts",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
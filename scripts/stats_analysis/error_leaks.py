#!/usr/bin/env python3

"""
Compute Wilson 95% confidence intervals for Table 10
(Information leakage in HTTP error responses by dataset).

This script reads the error-leak summary CSV used by the paper and emits a
standardized long-form CSV for later aggregation across tables.

Denominator rule for this table:
- Every reported percentage is computed over the same denominator:
    denominator = n_scanned_origins
  where n_scanned_origins is the number of origins scanned for the error-path
  leakage measurement in that dataset.

For each dataset, the script computes Wilson 95% confidence intervals for:
- Any tech leak
- Version leak

The CSV also contains pct_stacktrace, but this script does not emit it because
it is not part of the current paper table. It can be added later if needed.

Because the input stores rounded percentages, reconstructed counts may differ by
1 from the original raw counts. That is acceptable for the CI summary workflow,
but raw counts should be preferred if later available.

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
    metric_specs = [
        {
            "metric": "any_tech_leak",
            "claim_label": "Any tech leak",
            "pct_col": "pct_any_tech_leak",
        },
        {
            "metric": "version_leak",
            "claim_label": "Version leak",
            "pct_col": "pct_version_leak",
        },
    ]

    out_rows: list[dict] = []

    for _, row in df.iterrows():
        dataset_label = str(row["dataset_label"]).strip()
        n = int(row["n_scanned_origins"])

        for spec in metric_specs:
            pct = float(row[spec["pct_col"]])
            x = pct_to_count(pct, n)
            prop, ci_low, ci_high = wilson_ci(x, n)

            out_rows.append(
                {
                    "source_table": "table10_error_leaks",
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
            "Compute Wilson 95% confidence intervals for Table 10 "
            "(Information leakage in HTTP error responses by dataset)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to error_leaks_summary.csv",
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
            "n_scanned_origins",
            "pct_any_tech_leak",
            "pct_version_leak",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
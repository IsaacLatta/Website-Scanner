#!/usr/bin/env python3

"""
Compute Wilson 95% confidence intervals for Table 9
(Distribution of technology-revealing headers by dataset).

This script reads the revealing-headers summary CSV used by the paper and emits
a standardized long-form CSV for later aggregation across tables.

Denominator rule for this table:
- Every reported percentage is computed over the same denominator:
    denominator = n_sites
  where n_sites is the number of measured sites for that dataset.

For each dataset, the script computes Wilson 95% confidence intervals for:
- 0 revealing headers
- 1 revealing header
- 2 revealing headers
- 3+ revealing headers
- Any revealing headers

Although the 0/1/2/3+ categories form a partition of sites, this script treats
each reported percentage as an individual displayed proportion and computes a
Wilson interval for that proportion separately. The "Any revealing headers"
column is taken directly from the CSV rather than recomputed from the 0-header
share.

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
            "metric": "revealing_headers_0",
            "claim_label": "0 revealing headers",
            "pct_col": "pct_revealing_0",
        },
        {
            "metric": "revealing_headers_1",
            "claim_label": "1 revealing header",
            "pct_col": "pct_revealing_1",
        },
        {
            "metric": "revealing_headers_2",
            "claim_label": "2 revealing headers",
            "pct_col": "pct_revealing_2",
        },
        {
            "metric": "revealing_headers_3_plus",
            "claim_label": "3+ revealing headers",
            "pct_col": "pct_revealing_3_plus",
        },
        {
            "metric": "revealing_headers_any",
            "claim_label": "Any revealing headers",
            "pct_col": "pct_with_any_revealing",
        },
    ]

    out_rows: list[dict] = []

    for _, row in df.iterrows():
        dataset_label = str(row["dataset_label"]).strip()
        n = int(row["n_sites"])

        for spec in metric_specs:
            pct = float(row[spec["pct_col"]])
            x = pct_to_count(pct, n)
            prop, ci_low, ci_high = wilson_ci(x, n)

            out_rows.append(
                {
                    "source_table": "table9_revealing_headers",
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
            "Compute Wilson 95% confidence intervals for Table 9 "
            "(Distribution of technology-revealing headers by dataset)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to revealing_headers_summary.csv",
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
            "pct_revealing_0",
            "pct_revealing_1",
            "pct_revealing_2",
            "pct_revealing_3_plus",
            "pct_with_any_revealing",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
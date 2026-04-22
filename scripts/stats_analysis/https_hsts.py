#!/usr/bin/env python3

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
            "metric": "https_ok",
            "pct_col": "pct_https_success",
            "claim_label": "HTTPS ok",
        },
        {
            "metric": "https_unreachable",
            "pct_col": "pct_https_unreachable",
            "claim_label": "HTTPS unreachable",
        },
        {
            "metric": "http_ok",
            "pct_col": "pct_http_probe_ok",
            "claim_label": "HTTP ok",
        },
        {
            "metric": "http_to_https",
            "pct_col": "pct_http_redirect_to_https",
            "claim_label": "HTTP→HTTPS",
        },
        {
            "metric": "http_no_redirect",
            "pct_col": "pct_http_no_redirect",
            "claim_label": "HTTP no redirect",
        },
    ]

    out_rows: list[dict] = []

    for _, row in df.iterrows():
        dataset_label = str(row["dataset_label"])
        n = int(row["n_origins"])

        for spec in metric_specs:
            pct = float(row[spec["pct_col"]])
            x = pct_to_count(pct, n)
            prop, ci_low, ci_high = wilson_ci(x, n)

            out_rows.append(
                {
                    "source_table": "table3_https_connectivity",
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
            "Compute Wilson 95% confidence intervals for Table 3 "
            "(HTTP/HTTPS connectivity outcomes by dataset)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to https_hsts_enforcement_summary.csv",
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
            "n_origins",
            "pct_https_success",
            "pct_https_unreachable",
            "pct_http_probe_ok",
            "pct_http_redirect_to_https",
            "pct_http_no_redirect",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
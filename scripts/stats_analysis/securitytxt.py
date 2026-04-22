#!/usr/bin/env python3

"""
Compute Wilson 95% confidence intervals for Table 8
(Security.txt adoption and field completeness by dataset).

This script reads the security.txt summary CSV used by the paper and emits a
standardized long-form CSV for later aggregation across tables.

Denominator rules for this table:
- "security.txt present" is computed among all measured origins:
    numerator   = n_with_securitytxt
    denominator = n_origins

- "Contact" is computed among origins with security.txt present:
    denominator = n_with_securitytxt
  The numerator is reconstructed from pct_with_contact_among_present.

- "Expires" is computed among origins with security.txt present:
    denominator = n_with_securitytxt
  The numerator is reconstructed from pct_with_expires_among_present.

- "Valid expires" is computed among origins with an Expires field present:
    denominator = n_with_expires
  where:
    n_with_expires = reconstructed from pct_with_expires_among_present * n_with_securitytxt
  The numerator is reconstructed from pct_valid_expires_among_expires.

Because the input stores rounded percentages, and because some intermediate
counts (such as n_with_expires) are themselves reconstructed from rounded
percentages, reconstructed counts may differ slightly from the original raw
counts. That is acceptable for the CI summary workflow, but raw counts should
be preferred if later available.

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

        n_origins = int(row["n_origins"])
        n_with_securitytxt = int(row["n_with_securitytxt"])

        # security.txt present among all origins
        present_x = n_with_securitytxt
        present_n = n_origins
        present_prop, present_low, present_high = wilson_ci(present_x, present_n)

        out_rows.append(
            {
                "source_table": "table8_securitytxt",
                "dataset_label": dataset_label,
                "metric": "securitytxt_present",
                "claim_label": "security.txt present",
                "success_count": present_x,
                "total_count": present_n,
                "proportion": present_prop,
                "percent_reported": float(row["pct_sites_with_securitytxt"]),
                "ci_low": present_low,
                "ci_high": present_high,
                "ci_low_pct": present_low * 100.0,
                "ci_high_pct": present_high * 100.0,
            }
        )

        # Contact among security.txt-present origins
        contact_pct = float(row["pct_with_contact_among_present"])
        contact_x = pct_to_count(contact_pct, n_with_securitytxt)
        contact_n = n_with_securitytxt
        contact_prop, contact_low, contact_high = wilson_ci(contact_x, contact_n)

        out_rows.append(
            {
                "source_table": "table8_securitytxt",
                "dataset_label": dataset_label,
                "metric": "contact_present",
                "claim_label": "Contact",
                "success_count": contact_x,
                "total_count": contact_n,
                "proportion": contact_prop,
                "percent_reported": contact_pct,
                "ci_low": contact_low,
                "ci_high": contact_high,
                "ci_low_pct": contact_low * 100.0,
                "ci_high_pct": contact_high * 100.0,
            }
        )

        # Expires among security.txt-present origins
        expires_pct = float(row["pct_with_expires_among_present"])
        expires_x = pct_to_count(expires_pct, n_with_securitytxt)
        expires_n = n_with_securitytxt
        expires_prop, expires_low, expires_high = wilson_ci(expires_x, expires_n)

        out_rows.append(
            {
                "source_table": "table8_securitytxt",
                "dataset_label": dataset_label,
                "metric": "expires_present",
                "claim_label": "Expires",
                "success_count": expires_x,
                "total_count": expires_n,
                "proportion": expires_prop,
                "percent_reported": expires_pct,
                "ci_low": expires_low,
                "ci_high": expires_high,
                "ci_low_pct": expires_low * 100.0,
                "ci_high_pct": expires_high * 100.0,
            }
        )

        # Valid Expires among origins with Expires present
        valid_pct = float(row["pct_valid_expires_among_expires"])
        valid_x = pct_to_count(valid_pct, expires_x)
        valid_n = expires_x
        valid_prop, valid_low, valid_high = wilson_ci(valid_x, valid_n)

        out_rows.append(
            {
                "source_table": "table8_securitytxt",
                "dataset_label": dataset_label,
                "metric": "valid_expires",
                "claim_label": "Valid expires",
                "success_count": valid_x,
                "total_count": valid_n,
                "proportion": valid_prop,
                "percent_reported": valid_pct,
                "ci_low": valid_low,
                "ci_high": valid_high,
                "ci_low_pct": valid_low * 100.0,
                "ci_high_pct": valid_high * 100.0,
            }
        )

    return out_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compute Wilson 95% confidence intervals for Table 8 "
            "(Security.txt adoption and field completeness by dataset)."
        )
    )
    parser.add_argument(
        "input_csv",
        type=Path,
        help="Path to securitytxt_summary.csv",
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
            "n_with_securitytxt",
            "pct_sites_with_securitytxt",
            "pct_with_contact_among_present",
            "pct_with_expires_among_present",
            "pct_valid_expires_among_expires",
        ],
    )

    out_rows = build_rows(df)
    out_df = pd.DataFrame(out_rows)

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} rows to {args.output_csv}")


if __name__ == "__main__":
    main()
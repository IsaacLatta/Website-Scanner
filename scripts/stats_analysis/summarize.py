#!/usr/bin/env python3

"""
Aggregate selected statistical-support rows for the paper's summary table.

This script reads the long-form Wilson CI CSVs generated for Tables 3-10 and
builds a compact comparison summary CSV for LaTeX.

Design goals:
- Use CA Authorities vs US Authorities as the primary cross-jurisdiction
  comparison throughout the summary table.
- Exclude UK Authorities from the summary comparisons.
- Retain selected CA Authorities vs CA Finance comparisons where they support
  the paper's domestic critical-sector argument.
- Reuse the precomputed success_count / total_count / CI values from the
  per-table Wilson outputs.
- Add a 2x2 statistical test for each selected comparison:
    * Fisher's exact test when counts are small
    * Chi-square test otherwise

Expected per-table input schema:
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

Output schema:
- order
- theme
- metric_label
- base_dataset
- comparator_dataset
- base_x
- base_n
- base_pct
- base_ci_low_pct
- base_ci_high_pct
- base_display
- comparator_x
- comparator_n
- comparator_pct
- comparator_ci_low_pct
- comparator_ci_high_pct
- comparator_display
- delta_pp
- delta_pp_display
- test_name
- p_value
- p_value_display
- rationale

Important formatting note:
- Display fields intentionally avoid commas inside the cell text
  (e.g., "59.7 [54.0--65.2]") so the CSV remains easy for LaTeX/csvsimple
  to parse.
"""

import argparse
from pathlib import Path
from typing import Dict, Tuple, List

import pandas as pd
from scipy.stats import fisher_exact, chi2_contingency


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Aggregate selected comparison rows from Table 3-10 Wilson CI CSVs."
    )
    parser.add_argument("--table-3", type=Path, required=True, help="Path to Table 3 Wilson CSV")
    parser.add_argument("--table-4", type=Path, required=True, help="Path to Table 4 Wilson CSV")
    parser.add_argument("--table-5", type=Path, required=True, help="Path to Table 5 Wilson CSV")
    parser.add_argument("--table-6", type=Path, required=True, help="Path to Table 6 Wilson CSV")
    parser.add_argument("--table-7", type=Path, required=True, help="Path to Table 7 Wilson CSV")
    parser.add_argument("--table-8", type=Path, required=True, help="Path to Table 8 Wilson CSV")
    parser.add_argument("--table-9", type=Path, required=True, help="Path to Table 9 Wilson CSV")
    parser.add_argument("--table-10", type=Path, required=True, help="Path to Table 10 Wilson CSV")
    parser.add_argument("--output-csv", type=Path, required=True, help="Output CSV for LaTeX summary table")
    return parser.parse_args()


def read_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {
        "source_table",
        "dataset_label",
        "metric",
        "claim_label",
        "success_count",
        "total_count",
        "proportion",
        "ci_low",
        "ci_high",
        "ci_low_pct",
        "ci_high_pct",
    }
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"{path} is missing required columns: {sorted(missing)}")
    return df


def build_index(dfs: List[pd.DataFrame]) -> Dict[Tuple[str, str, str], dict]:
    idx: Dict[Tuple[str, str, str], dict] = {}
    for df in dfs:
        for _, row in df.iterrows():
            key = (
                str(row["source_table"]).strip(),
                str(row["dataset_label"]).strip(),
                str(row["metric"]).strip(),
            )
            idx[key] = row.to_dict()
    return idx


def get_row(idx: Dict[Tuple[str, str, str], dict], source_table: str, dataset: str, metric: str) -> dict:
    key = (source_table, dataset, metric)
    if key not in idx:
        raise KeyError(f"Missing row for source_table={source_table}, dataset={dataset}, metric={metric}")
    return idx[key]


def choose_test(x1: int, n1: int, x2: int, n2: int) -> Tuple[str, float]:
    table = [[x1, n1 - x1], [x2, n2 - x2]]

    # Use Fisher if any observed cell is < 5
    if min(table[0] + table[1]) < 5:
        _, p_value = fisher_exact(table)
        return "fisher", float(p_value)

    # Otherwise use chi-square without Yates correction
    _, p_value, _, _ = chi2_contingency(table, correction=False)
    return "chi_square", float(p_value)


def fmt_pct_ci(pct: float, lo: float, hi: float) -> str:
    return f"{pct:.1f} [{lo:.1f}--{hi:.1f}]"


def fmt_p_value(p: float) -> str:
    if p < 0.001:
        return "<0.001"
    return f"{p:.3f}"


def comparison_row(
    idx: Dict[Tuple[str, str, str], dict],
    *,
    order: int,
    theme: str,
    metric_label: str,
    source_table: str,
    metric: str,
    base_dataset: str,
    comparator_dataset: str,
    rationale: str,
) -> dict:
    base = get_row(idx, source_table, base_dataset, metric)
    comp = get_row(idx, source_table, comparator_dataset, metric)

    x1 = int(base["success_count"])
    n1 = int(base["total_count"])
    x2 = int(comp["success_count"])
    n2 = int(comp["total_count"])

    p1 = float(base["proportion"]) * 100.0
    p2 = float(comp["proportion"]) * 100.0
    lo1 = float(base["ci_low_pct"])
    hi1 = float(base["ci_high_pct"])
    lo2 = float(comp["ci_low_pct"])
    hi2 = float(comp["ci_high_pct"])

    test_name, p_value = choose_test(x1, n1, x2, n2)
    delta_pp = p1 - p2

    return {
        "order": order,
        "theme": theme,
        "metric_label": metric_label,
        "base_dataset": base_dataset,
        "comparator_dataset": comparator_dataset,
        "base_x": x1,
        "base_n": n1,
        "base_pct": p1,
        "base_ci_low_pct": lo1,
        "base_ci_high_pct": hi1,
        "base_display": fmt_pct_ci(p1, lo1, hi1),
        "comparator_x": x2,
        "comparator_n": n2,
        "comparator_pct": p2,
        "comparator_ci_low_pct": lo2,
        "comparator_ci_high_pct": hi2,
        "comparator_display": fmt_pct_ci(p2, lo2, hi2),
        "delta_pp": delta_pp,
        "delta_pp_display": f"{delta_pp:+.1f}",
        "test_name": test_name,
        "p_value": p_value,
        "p_value_display": fmt_p_value(p_value),
        "rationale": rationale,
    }


def build_summary_rows(idx: Dict[Tuple[str, str, str], dict]) -> List[dict]:
    rows = [
        comparison_row(
            idx,
            order=1,
            theme="Transport",
            metric_label="HTTP→HTTPS upgrade",
            source_table="table3_https_connectivity",
            metric="http_to_https",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Primary cross-jurisdiction comparison for HTTPS upgrade behavior.",
        ),
        comparison_row(
            idx,
            order=2,
            theme="Transport",
            metric_label="Negotiated TLS 1.3",
            source_table="table4_tls_summary",
            metric="tls13_negotiated",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Primary cross-jurisdiction comparison for modern TLS negotiation.",
        ),
        comparison_row(
            idx,
            order=3,
            theme="Transport",
            metric_label="Any HSTS",
            source_table="table5_hsts_quality",
            metric="any_hsts",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Primary cross-jurisdiction HSTS comparison highlighted in paper and reviews.",
        ),
        comparison_row(
            idx,
            order=4,
            theme="Application",
            metric_label="CSP frame-ancestors",
            source_table="table6_security_headers",
            metric="csp_frame_ancestors_present",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Supports claim that Canadian authorities lag on modern browser policy controls.",
        ),
        comparison_row(
            idx,
            order=6,
            theme="Disclosure",
            metric_label="security.txt present",
            source_table="table8_securitytxt",
            metric="securitytxt_present",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Supports disclosure-readiness claim centered on standardized vulnerability reporting.",
        ),
        comparison_row(
            idx,
            order=7,
            theme="Reconnaissance",
            metric_label="Any revealing headers",
            source_table="table9_revealing_headers",
            metric="revealing_headers_any",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Cross-jurisdiction comparison for reconnaissance exposure.",
        ),
        # comparison_row(
        #     idx,
        #     order=8,
        #     theme="Reconnaissance",
        #     metric_label="Any revealing headers",
        #     source_table="table9_revealing_headers",
        #     metric="revealing_headers_any",
        #     base_dataset="CA Authorities",
        #     comparator_dataset="CA Finance",
        #     rationale="Domestic critical-sector comparison for reconnaissance exposure.",
        # ),
        comparison_row(
            idx,
            order=11,
            theme="Error leakage",
            metric_label="Version leak",
            source_table="table10_error_leaks",
            metric="version_leak",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Supports discussion of leakage surfaced by the 404-probe measurement.",
        ),
        comparison_row(
            idx,
            order=7,
            theme="Reconnaissance",
            metric_label="Any revealing headers",
            source_table="table9_revealing_headers",
            metric="revealing_headers_any",
            base_dataset="CA Authorities",
            comparator_dataset="CA Finance",
            rationale="Supports claim that Canadian authorities are more exposed than domestic finance.",
        ),
        comparison_row(
            idx,
            order=9,
            theme="Error leakage",
            metric_label="Version leak",
            source_table="table10_error_leaks",
            metric="version_leak",
            base_dataset="CA Authorities",
            comparator_dataset="US Authorities",
            rationale="Supports discussion of leakage surfaced by the 404-probe measurement.",
        ),
    ]
    return rows


def main() -> None:
    args = parse_args()

    dfs = [
        read_csv(args.table_3),
        read_csv(args.table_4),
        read_csv(args.table_5),
        read_csv(args.table_6),
        read_csv(args.table_7),
        read_csv(args.table_8),
        read_csv(args.table_9),
        read_csv(args.table_10),
    ]

    idx = build_index(dfs)
    summary_rows = build_summary_rows(idx)
    out_df = pd.DataFrame(summary_rows).sort_values("order")

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(args.output_csv, index=False)

    print(f"Wrote {len(out_df)} summary rows to {args.output_csv}")


if __name__ == "__main__":
    main()
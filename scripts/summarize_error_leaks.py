#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from collections import Counter, defaultdict

import matplotlib.pyplot as plt


TECH_NAME_IGNORE = [
    "Next.js",
    "Ruby on Rails"
]

STACKTRACE_DISPLAY_IGNORE = []

BIG_PLATFORM_TECH_NAMES = [
    "WordPress",
    "Cloudflare",
    "Drupal",
]

TOP_N_TECH = 15
TOP_N_STACKTRACE = 10


def load_results(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den == 0:
        return 0.0
    return 100.0 * num / den


def compute_error_leak_blocks(results: dict) -> dict:
    modules = results.get("modules", {})
    rows = modules.get("error_leak", []) or []

    origin_targets = results.get("origin_targets", {})
    n_scanned_origins = len(origin_targets.get("all_origins", []))

    tech_name_counts: Counter[str] = Counter()
    tech_name_version_counts: Counter[str] = Counter()
    category_origin_sets: dict[str, set[str]] = defaultdict(set)

    stack_display_counts: Counter[str] = Counter()
    stack_language_counts: Counter[str] = Counter()

    origins_with_tech_leak: set[str] = set()
    origins_with_version_leak: set[str] = set()
    origins_with_stacktrace: set[str] = set()
    origins_with_any_leak: set[str] = set()

    n_tech_rows = 0
    n_stack_rows = 0
    n_tech_rows_ignored = 0
    n_stack_rows_ignored = 0

    for row in rows:
        origin = row.get("origin")

        if "tech_name" in row:
            tech_name = row.get("tech_name") or ""
            if tech_name in TECH_NAME_IGNORE:
                n_tech_rows_ignored += 1
                continue

            tech_category = row.get("tech_category") or "unknown"
            has_version = bool(row.get("has_version"))

            n_tech_rows += 1
            origins_with_tech_leak.add(origin)
            origins_with_any_leak.add(origin)

            tech_name_counts[tech_name] += 1
            category_origin_sets[tech_category].add(origin)

            if has_version:
                origins_with_version_leak.add(origin)
                tech_name_version_counts[tech_name] += 1

        elif "language" in row:
            display_name = row.get("display_name") or row.get("language") or "unknown"
            if display_name in STACKTRACE_DISPLAY_IGNORE:
                n_stack_rows_ignored += 1
                continue

            language = row.get("language") or "unknown"

            n_stack_rows += 1
            origins_with_stacktrace.add(origin)
            origins_with_any_leak.add(origin)

            stack_display_counts[display_name] += 1
            stack_language_counts[language] += 1

    n_origins_with_tech_leak = len(origins_with_tech_leak)
    n_origins_with_version_leak = len(origins_with_version_leak)
    n_origins_with_stacktrace = len(origins_with_stacktrace)
    n_origins_with_any_leak = len(origins_with_any_leak)

    # Top N techs (including big platforms)
    top_tech_all = sorted(
        tech_name_counts.items(), key=lambda kv: kv[1], reverse=True
    )[:TOP_N_TECH]

    # Top N techs excluding WordPress / Cloudflare / Drupal and ignore list
    def is_big_platform(name: str) -> bool:
        return name in BIG_PLATFORM_TECH_NAMES

    filtered_items = [
        (name, count)
        for name, count in tech_name_counts.items()
        if not is_big_platform(name)
    ]
    top_tech_excl_big = sorted(
        filtered_items, key=lambda kv: kv[1], reverse=True
    )[:TOP_N_TECH]

    # Categories: count distinct origins per category
    category_origin_counts = {
        cat: len(origins) for cat, origins in category_origin_sets.items()
    }

    # Stack trace: top N display_names
    top_stack_display = sorted(
        stack_display_counts.items(), key=lambda kv: kv[1], reverse=True
    )[:TOP_N_STACKTRACE]

    summary = {
        "meta": {
            "n_scanned_origins": n_scanned_origins,
            "n_error_leak_rows_raw": len(rows),
            "n_tech_rows": n_tech_rows,
            "n_stack_rows": n_stack_rows,
            "n_tech_rows_ignored": n_tech_rows_ignored,
            "n_stack_rows_ignored": n_stack_rows_ignored,
            "tech_name_ignore_list": TECH_NAME_IGNORE,
            "stacktrace_display_ignore_list": STACKTRACE_DISPLAY_IGNORE,
            "big_platform_tech_names": BIG_PLATFORM_TECH_NAMES,
        },
        "tech_overview": {
            "n_origins_with_tech_leak": n_origins_with_tech_leak,
            "n_origins_with_version_leak": n_origins_with_version_leak,
            "n_origins_with_any_leak": n_origins_with_any_leak,
            "pct_origins_with_tech_leak": safe_pct(
                n_origins_with_tech_leak, n_scanned_origins
            ),
            "pct_origins_with_version_leak": safe_pct(
                n_origins_with_version_leak, n_scanned_origins
            ),
            "pct_origins_with_any_leak": safe_pct(
                n_origins_with_any_leak, n_scanned_origins
            ),
            "n_tech_rows": n_tech_rows,
            "n_unique_tech_names": len(tech_name_counts),
        },
        "tech_top": {
            "tech_name_counts": dict(tech_name_counts),
            "tech_name_version_counts": dict(tech_name_version_counts),
            "top_tech_all": top_tech_all,
            "top_tech_excluding_big_platforms": top_tech_excl_big,
        },
        "category_distribution": {
            "category_origin_counts": category_origin_counts,
        },
        "stacktrace_overview": {
            "n_origins_with_stacktrace": n_origins_with_stacktrace,
            "pct_origins_with_stacktrace": safe_pct(
                n_origins_with_stacktrace, n_scanned_origins
            ),
            "n_stack_rows": n_stack_rows,
            "n_stack_languages": len(stack_language_counts),
        },
        "stacktrace_top": {
            "stack_display_counts": dict(stack_display_counts),
            "stack_language_counts": dict(stack_language_counts),
            "top_stack_display": top_stack_display,
        },
    }

    return summary


def plot_error_leak_tech_top_all(summary: dict, out_path: Path) -> None:
    top_tech_all = summary["tech_top"]["top_tech_all"]
    if not top_tech_all:
        return

    labels = [name for name, _ in top_tech_all]
    values = [count for _, count in top_tech_all]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=45, ha="right")
    plt.ylabel("Number of origins")
    plt.title("Top technologies leaked in error pages (including WordPress/Cloudflare/Drupal)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_error_leak_tech_top_excl_big(summary: dict, out_path: Path) -> None:
    top_tech_excl = summary["tech_top"]["top_tech_excluding_big_platforms"]
    if not top_tech_excl:
        return

    labels = [name for name, _ in top_tech_excl]
    values = [count for _, count in top_tech_excl]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=45, ha="right")
    plt.ylabel("Number of origins")
    plt.title("Top technologies leaked in error pages (excluding WordPress/Cloudflare/Drupal)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_error_leak_category_distribution(summary: dict, out_path: Path) -> None:
    category_counts = summary["category_distribution"]["category_origin_counts"]
    if not category_counts:
        return

    labels = list(category_counts.keys())
    values = [category_counts[k] for k in labels]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.ylabel("Number of origins")
    plt.title("Error-page leaks by technology category")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_error_leak_stacktrace_top(summary: dict, out_path: Path) -> None:
    top_stack = summary["stacktrace_top"]["top_stack_display"]
    if not top_stack:
        return

    labels = [name for name, _ in top_stack]
    values = [count for _, count in top_stack]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.ylabel("Number of origins")
    plt.title("Top stack-trace languages leaked in error pages")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def build_metric_definitions() -> dict:
    return {
        "meta.n_scanned_origins":
            "Number of origins in origin_targets['all_origins'], i.e., sites that were in scope for the scan.",
        "meta.n_error_leak_rows_raw":
            "Total number of rows returned by modules['error_leak'] before any ignore filters are applied.",
        "meta.n_tech_rows":
            "Number of technology-leak rows kept after filtering out tech_name values in TECH_NAME_IGNORE.",
        "meta.n_stack_rows":
            "Number of stack-trace rows kept after filtering out display_name values in STACKTRACE_DISPLAY_IGNORE.",
        "meta.n_tech_rows_ignored":
            "Number of technology-leak rows that were discarded because their tech_name appears in TECH_NAME_IGNORE.",
        "meta.n_stack_rows_ignored":
            "Number of stack-trace rows that were discarded because their display_name appears in STACKTRACE_DISPLAY_IGNORE.",
        "meta.tech_name_ignore_list":
            "List of tech_name values that were treated as false positives and excluded from all statistics.",
        "meta.stacktrace_display_ignore_list":
            "List of stack-trace display_name values that were treated as false positives and excluded from all statistics.",
        "meta.big_platform_tech_names":
            "List of high-level platforms (e.g., WordPress, Cloudflare, Drupal) that are only excluded from the "
            "'no_wp_cf_drupal' plot but still counted everywhere else.",
        "tech_overview.n_origins_with_tech_leak":
            "Number of scanned origins that had at least one technology-leak row (after ignore filtering). Each origin "
            "is counted once even if it leaked multiple technologies.",
        "tech_overview.n_origins_with_version_leak":
            "Number of scanned origins that leaked at least one explicit version string (has_version=True) for any technology.",
        "tech_overview.n_origins_with_any_leak":
            "Number of scanned origins that had either a technology leak or a stack trace leak (union of both sets).",
        "tech_overview.pct_origins_with_tech_leak":
            "Percentage of scanned origins that leaked at least one technology, relative to n_scanned_origins.",
        "tech_overview.pct_origins_with_version_leak":
            "Percentage of scanned origins that leaked at least one explicit version string, relative to n_scanned_origins.",
        "tech_overview.pct_origins_with_any_leak":
            "Percentage of scanned origins that had any leak (technology or stack trace), relative to n_scanned_origins.",
        "tech_overview.n_tech_rows":
            "Number of technology-leak rows kept after ignore filtering (each row is one origin+signature match).",
        "tech_overview.n_unique_tech_names":
            "Number of distinct tech_name values appearing in technology-leak rows after ignore filtering.",
        "tech_top.tech_name_counts":
            "For each tech_name, the number of origins whose error page body matched that technology signature at least once "
            "(after ignore filtering). This is the underlying histogram used for the 'top N' plots.",
        "tech_top.tech_name_version_counts":
            "For each tech_name, the number of origins where has_version=True for that technology, i.e., where the "
            "error page appeared to leak an explicit version string.",
        "tech_top.top_tech_all":
            "List of the TOP_N_TECH technologies with the highest tech_name_counts, represented as [tech_name, count] pairs.",
        "tech_top.top_tech_excluding_big_platforms":
            "List of the TOP_N_TECH technologies with the highest counts after excluding any tech_name in "
            "BIG_PLATFORM_TECH_NAMES, represented as [tech_name, count] pairs.",
        "category_distribution.category_origin_counts":
            "For each tech_category (framework, database, cloud platform, etc.), the number of distinct origins that "
            "leaked at least one technology in that category.",
        "stacktrace_overview.n_origins_with_stacktrace":
            "Number of scanned origins that had at least one stack-trace row (after ignore filtering).",
        "stacktrace_overview.pct_origins_with_stacktrace":
            "Percentage of scanned origins that leaked a recognizable stack trace, relative to n_scanned_origins.",
        "stacktrace_overview.n_stack_rows":
            "Number of stack-trace rows kept after ignore filtering (each row is one origin+language-family match).",
        "stacktrace_overview.n_stack_languages":
            "Number of distinct programming-language families (stack_trace_signatures.language) for which at least "
            "one stack trace was observed.",
        "stacktrace_top.stack_display_counts":
            "For each stack-trace display_name (e.g., 'JavaScript / Node.js', 'Python'), the number of origins where an "
            "error page matched that language's stack-trace patterns.",
        "stacktrace_top.stack_language_counts":
            "For each underlying language tag (e.g., 'javascript', 'python'), the number of origins where a stack trace "
            "for that language was detected.",
        "stacktrace_top.top_stack_display":
            "List of the TOP_N_STACKTRACE display_name entries with the highest counts, represented as [display_name, count] pairs.",
    }

def main():
    parser = argparse.ArgumentParser(
        description="Summarise technology and stack-trace leaks from the error_leak module."
    )
    parser.add_argument(
        "results_json",
        type=Path,
        help="Path to full scan results JSON file produced by run_scan().",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory where error_leak_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)
    summary = compute_error_leak_blocks(results)

    # Plots
    plot_error_leak_tech_top_all(summary, out_dir / "error_leak_tech_topN_all.png")
    plot_error_leak_tech_top_excl_big(
        summary, out_dir / "error_leak_tech_topN_no_wp_cf_drupal.png"
    )
    plot_error_leak_category_distribution(
        summary, out_dir / "error_leak_category_distribution.png"
    )
    plot_error_leak_stacktrace_top(summary, out_dir / "error_leak_stacktrace_topN.png")

    # Add metric definitions and write JSON
    summary["metric_definitions"] = build_metric_definitions()

    out_path = out_dir / "error_leak_summary.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote error leak summary to {out_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

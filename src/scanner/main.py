#!/usr/bin/env python3
from __future__ import annotations

import sys
import argparse
import asyncio
from pathlib import Path
import json
import time

from scanner.definitions import init_rate_limiter_logger
from scanner.input_utils import load_domains_from_file, load_column_from_csv
from scanner.runner import run_scan


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Website security scanner for gov/authority sites"
    )
    ap.add_argument(
        "input",
        help="Input file path. If --csv-column is given, treated as CSV; otherwise plain text with one domain/URL per line.",
    )
    ap.add_argument(
        "--csv-column",
        help="Column name in the CSV that contains the URL/domain (e.g. 'url').",
    )
    ap.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Number of data rows to skip in the CSV before reading URLs (default: 0).",
    )
    ap.add_argument(
        "--max-concurrency",
        type=int,
        default=20,
        help="Maximum number of in-flight network/TLS operations (default: 20).",
    )
    ap.add_argument(
        "--max-hops",
        type=int,
        default=8,
        help="Maximum number of redirect hops to follow per URL (default: 8).",
    )
    ap.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP client timeout in seconds (default: 10).",
    )
    ap.add_argument(
        "--output-json",
        type=Path,
        help="Optional path to write full JSON results. If omitted, a brief summary is printed.",
    )
    ap.add_argument(
        "--row-limit",
        type=int,
        default=None,
        help="Max number of rows to read after --offset (default: no limit).",
    )
    return ap.parse_args(argv)


def _load_domains_from_args(args: argparse.Namespace) -> list[str]:
    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input file does not exist: {path}")

    if args.csv_column:
        domains = load_column_from_csv(path, column=args.csv_column, offset=args.offset, limit=args.row_limit)
    else:
        domains = load_domains_from_file(path)

    if not domains:
        raise SystemExit("No domains/URLs loaded from input file.")

    return domains


def main(argv: list[str] | None = None) -> None:
    start = time.perf_counter()
    args = parse_args(argv)
    try:
        domains = _load_domains_from_args(args)

        if args.output_json is not None:
            log_dir = args.output_json.parent
            init_rate_limiter_logger(log_dir)
            print(f"Logging rate limits to dir: {log_dir}")
        else:
            print(f"Logging rate limits to console only.")
            init_rate_limiter_logger(None)

        result = asyncio.run(
            run_scan(
                domains,
                max_concurrency=args.max_concurrency,
                http_timeout_s=args.timeout,
                redirect_max_hops=args.max_hops,
            )
        )

        scan_targets = result.get("scan_targets", {})
        origin_targets = result.get("origin_targets", {})
        n_input = len(scan_targets.get("uris", []))
        n_origins = len(origin_targets.get("all_origins", []))

        print(f"Scanned {n_input} input URLs across {n_origins} origins.")

        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(
                json.dumps(result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            print(f"Wrote full JSON results to {args.output_json}")

    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)
    finally:
        end = time.perf_counter()
        duration_ms = (end - start) * 1000
        print(f"Scan completed in : {duration_ms:.2f}ms")


if __name__ == "__main__":
    main()

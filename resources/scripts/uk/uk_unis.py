#!/usr/bin/env python3
"""
Parse Discover Uni's INSTITUTION.csv into:
name,url,abbreviation,source

- source is always "uk:edu"
- abbreviation left blank
- prefers FIRST_TRADING_NAME, falls back to LEGAL_NAME
- normalizes PROVURL (adds https:// if scheme missing)
- deduplicates by UKPRN (keeps first with non-empty URL)
- prints to stdout and writes to --out
"""

import argparse
import csv
import sys
from urllib.parse import urlparse

SOURCE_TAG = "uk:edu"

def normalize_url(u: str) -> str:
    if not u:
        return ""
    u = u.strip()
    if not u:
        return ""
    # If scheme missing, prepend https://
    parsed = urlparse(u)
    if not parsed.scheme:
        u = "https://" + u.lstrip("/")
        parsed = urlparse(u)
    # Very light validation: must have netloc (host)
    if not parsed.netloc:
        return ""
    return u

def choose_name(row) -> str:
    name = (row.get("FIRST_TRADING_NAME") or "").strip()
    if not name:
        name = (row.get("LEGAL_NAME") or "").strip()
    return name

def main():
    p = argparse.ArgumentParser(description="Convert Discover Uni INSTITUTION.csv to uk:edu sites CSV.")
    p.add_argument("--in", dest="in_path", required=True, help="Path to INSTITUTION.csv")
    p.add_argument("--out", dest="out_path", default="uk_edu_sites.csv", help="Output CSV path (default: uk_edu_sites.csv)")
    p.add_argument("--print-invalid", action="store_true", help="Report rows dropped due to missing/invalid URL")
    args = p.parse_args()

    fieldnames = ["name", "url", "abbreviation", "source"]

    # Writers
    out_fp = open(args.out_path, "w", newline="", encoding="utf-8")
    file_writer = csv.DictWriter(out_fp, fieldnames=fieldnames)
    stdout_writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)

    file_writer.writeheader()
    stdout_writer.writeheader()

    seen_ukprn = set()
    total, kept, skipped = 0, 0, 0

    with open(args.in_path, "r", newline="", encoding="utf-8-sig") as fp:
        reader = csv.DictReader(fp)
        # Basic header sanity
        required = {"LEGAL_NAME", "FIRST_TRADING_NAME", "PROVURL", "UKPRN"}
        missing = [c for c in required if c not in reader.fieldnames]
        if missing:
            print(f"# ERROR: Missing expected columns: {missing}", file=sys.stderr)
            sys.exit(2)

        for row in reader:
            total += 1

            ukprn = (row.get("UKPRN") or "").strip()
            name = choose_name(row)
            url = normalize_url(row.get("PROVURL") or "")

            if not name or not url:
                skipped += 1
                if args.print_invalid:
                    print(f"# drop: ukprn={ukprn!r} name={name!r} url={row.get('PROVURL')!r}", file=sys.stderr)
                continue

            if ukprn and ukprn in seen_ukprn:
                # Already captured this provider (keep first non-empty URL)
                continue
            if ukprn:
                seen_ukprn.add(ukprn)

            out_row = {
                "name": name,
                "url": url,
                "abbreviation": "",
                "source": SOURCE_TAG,
            }
            file_writer.writerow(out_row)
            stdout_writer.writerow(out_row)
            kept += 1

    out_fp.close()
    print(f"# Read {total} rows; kept {kept}; skipped {skipped}.", file=sys.stderr)
    print(f"# Wrote {args.out_path}", file=sys.stderr)

if __name__ == "__main__":
    main()

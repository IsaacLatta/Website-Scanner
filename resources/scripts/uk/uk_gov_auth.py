#!/usr/bin/env python3
"""
Fetch UK government organisations from GOV.UK Organisations API,
filter to live orgs, and output CSV (stdout + file).

Schema: name,url,abbreviation,source
source is always "uk:authorities"
"""

import argparse
import csv
import sys
import time
from typing import Iterator, Dict, Any

import requests
from requests.adapters import HTTPAdapter, Retry


API_ROOT = "https://www.gov.uk/api/organisations"
SOURCE_TAG = "uk:authorities"


def make_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    s.headers.update({
        "User-Agent": "CSA-UK-Collector/1.0 (+research; contact: your-email@example.com)"
    })
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


def fetch_page(session: requests.Session, page: int) -> Dict[str, Any]:
    resp = session.get(API_ROOT, params={"page": page}, timeout=20)
    resp.raise_for_status()
    return resp.json()


def iter_all_results(session: requests.Session, sleep_between: float = 0.0) -> Iterator[Dict[str, Any]]:
    """
    Iterate all 'results' across pages until an empty page is returned.
    We don't assume any specific 'pages' field; we stop when results == [].
    """
    page = 1
    while True:
        data = fetch_page(session, page)
        results = data.get("results", [])
        if not results:
            break
        for r in results:
            yield r
        page += 1
        if sleep_between:
            time.sleep(sleep_between)


def row_from_org(org: Dict[str, Any]) -> Dict[str, str]:
    title = org.get("title", "").strip()
    web_url = org.get("web_url", "").strip()
    details = org.get("details") or {}
    abbr = details.get("abbreviation") or ""
    return {
        "name": title,
        "url": web_url,
        "abbreviation": abbr,
        "source": SOURCE_TAG,
    }


def is_live(org: Dict[str, Any]) -> bool:
    details = org.get("details") or {}
    return (details.get("govuk_status") == "live")


def main():
    parser = argparse.ArgumentParser(description="Collect live UK authorities from GOV.UK Organisations API.")
    parser.add_argument("--out", default="uk_sites.csv", help="Output CSV file path (default: uk_sites.csv)")
    parser.add_argument("--throttle", type=float, default=0.0,
                        help="Seconds to sleep between page requests (default: 0)")
    args = parser.parse_args()

    session = make_session()

    # Prepare CSV writers: stdout and file
    fieldnames = ["name", "url", "abbreviation", "source"]
    out_fp = open(args.out, "w", newline="", encoding="utf-8")
    file_writer = csv.DictWriter(out_fp, fieldnames=fieldnames)
    stdout_writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)

    # Write headers
    file_writer.writeheader()
    stdout_writer.writeheader()

    total = 0
    kept = 0

    try:
        for org in iter_all_results(session, sleep_between=args.throttle):
            total += 1
            if not is_live(org):
                continue
            row = row_from_org(org)

            # Only keep rows that have at least a name and url
            if row["name"] and row["url"]:
                file_writer.writerow(row)
                stdout_writer.writerow(row)
                kept += 1
    finally:
        out_fp.close()

    print(f"# Fetched {total} organisations; kept {kept} live orgs.", file=sys.stderr)
    print(f"# CSV written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()

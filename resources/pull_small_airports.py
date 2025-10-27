#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parse Transport Canada's airports page HTML from stdin and output rows in the schema:
name<TAB>url<TAB>abbr<TAB>source

- Targets the "National Airports System" table (the one with rows like "Vancouver (YVR)" and the authority link in the 3rd column).
- abbr is left blank for airport authorities.
- source is set to "tc:airport-small-authorities".
- If --append FILE is provided, rows are appended to FILE without adding a header.
  Otherwise, rows are printed to stdout (also without a header, to match prior flow).
"""

import sys
import argparse
import csv
import re

from bs4 import BeautifulSoup

SOURCE = "tc:airport-small-authorities"

def find_nas_table(soup: BeautifulSoup):
    # Prefer the anchor id; fall back to heading text
    hdr = soup.find(id="National_Airports_System")
    if not hdr:
        hdr = soup.find(lambda t: t.name in ("h2", "h3") and "National Airports System" in t.get_text(strip=True))
    return hdr.find_next("table") if hdr else None

def extract_rows(html: str):
    soup = BeautifulSoup(html, "html.parser")
    table = find_nas_table(soup)
    if not table:
        return []

    out = []
    for tr in table.select("tbody > tr"):
        tds = tr.find_all("td")
        if len(tds) < 3:
            continue
        a = tds[2].find("a", href=True)
        if not a:
            # Skip rows without an external link in the "Operated by" column
            continue
        name = a.get_text(" ", strip=True)
        url = a["href"].strip()
        if not name or not url:
            continue
        out.append([name, url, "", SOURCE])
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--append", help="Path to TSV file to append rows (no header written)")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = extract_rows(html)

    if not rows:
        # Fail noisily so you know if the page shape changed
        print("No airport authority rows found in NAS table.", file=sys.stderr)
        sys.exit(1)

    if args.append:
        with open(args.append, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerows(rows)
    else:
        writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
        writer.writerows(rows)

if __name__ == "__main__":
    main()

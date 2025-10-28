#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parse the National Airports System (big airports) table from Transport Canada's page.

Output schema per row (TAB-separated, no header):
name    url    abbr    source

- Reads full HTML from stdin.
- Extracts the operator link (3rd column) from the NAS table.
- abbr is blank.
- source is 'tc:airport-nas-authorities'.
- If --append FILE is provided, appends rows to FILE; otherwise prints to stdout.
"""

import sys
import argparse
import csv
from bs4 import BeautifulSoup

SOURCE = "tc:airport-nas-authorities"

def find_nas_table(soup: BeautifulSoup):
    # Anchor id preferred; fall back to heading text
    hdr = soup.find(id="National_Airports_System")
    if not hdr:
        hdr = soup.find(lambda t: t.name in ("h2", "h3") and "National Airports System" in t.get_text(strip=True))
    return hdr.find_next("table") if hdr else None

def extract_rows(html: str):
    soup = BeautifulSoup(html, "html.parser")
    table = find_nas_table(soup)
    if not table:
        return []

    rows = []
    for tr in table.select("tbody > tr"):
        tds = tr.find_all("td")
        if len(tds) < 3:
            continue
        a = tds[2].find("a", href=True)
        if not a:
            continue
        name = a.get_text(" ", strip=True)
        url = a["href"].strip()
        if not name or not url:
            continue
        rows.append([name, url, "", SOURCE])
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--append", help="Path to TSV file to append rows (no header written)")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = extract_rows(html)
    if not rows:
        print("No rows found in National Airports System table.", file=sys.stderr)
        sys.exit(1)

    if args.append:
        with open(args.append, "a", newline="", encoding="utf-8") as f:
            csv.writer(f, delimiter="\t").writerows(rows)
    else:
        csv.writer(sys.stdout, delimiter="\t", lineterminator="\n").writerows(rows)

if __name__ == "__main__":
    main()

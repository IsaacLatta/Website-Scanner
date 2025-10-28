#!/usr/bin/env python3
import sys, csv, argparse
from urllib.parse import urljoin
from bs4 import BeautifulSoup

BASE = "https://www.canada.ca"
SOURCE = "tbs:info-source:list-institutions"

def extract_letter_sections(html):
    soup = BeautifulSoup(html, "html.parser")
    # Every letter header looks like: <h3 class="well well-sm" id="A">...</h3>
    letter_heads = soup.find_all("h3", class_="well well-sm")
    for h3 in letter_heads:
        letter = (h3.get("id") or "").strip()
        if not letter:
            continue
        # Walk forward until next h3.well well-sm; collect all <ul> blocks
        ul_blocks = []
        for sib in h3.next_siblings:
            # stop when we hit the next letter section
            if getattr(sib, "name", None) == "h3" and "well" in sib.get("class", []) and "well-sm" in sib.get("class", []):
                break
            if getattr(sib, "name", None) == "ul":
                ul_blocks.append(sib)

        # Extract links from each <ul>, including nested <ul>/<li> sub-bullets
        for ul in ul_blocks:
            for a in ul.find_all("a", href=True):
                name = " ".join(a.get_text(" ", strip=True).split())
                href = a["href"].strip()
                if not href or href.lower().startswith(("javascript:", "mailto:")):
                    continue
                url = href if href.lower().startswith(("http://","https://")) else urljoin(BASE, href)
                yield {
                    "name": name,
                    "url": url,
                    "letter": letter,
                    "source": SOURCE
                }

def main():
    ap = argparse.ArgumentParser(description="Extract institution URLs by letter from Info Source page HTML")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append to this CSV (creates if missing). If omitted, prints CSV to stdout.")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = list(extract_letter_sections(html))

    # Dedup by URL (case-insensitive)
    seen = set()
    deduped = []
    for r in rows:
        key = r["url"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    fieldnames = ["name","url","letter","source"]

    if args.append:
        # Append mode (create with header if file doesn't exist)
        try:
            # Check if file exists and non-empty
            with open(args.append, "r", newline="", encoding="utf-8") as f:
                has_header = f.readline().strip() != ""
        except FileNotFoundError:
            has_header = False

        with open(args.append, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            if not has_header:
                w.writeheader()
            for r in deduped:
                w.writerow(r)
    else:
        # Write to stdout
        w = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        w.writeheader()
        for r in deduped:
            w.writerow(r)

if __name__ == "__main__":
    main()

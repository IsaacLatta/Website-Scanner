#!/usr/bin/env python3
import sys, csv, argparse
from urllib.parse import urljoin
from bs4 import BeautifulSoup

BASE = "https://www.canada.ca"
SOURCE = "tbs:crown-corps:list"

def rows_from_crown_table(html):
    soup = BeautifulSoup(html, "html.parser")
    tbody = soup.find("tbody")
    if not tbody:
        return

    current_letter = None
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue

        # Letter divider row: <td id="A" class="... h2 bg-info" colspan="4">A</td>
        td0 = tds[0]
        classes = td0.get("class", [])
        if td0.has_attr("id") and ("h2" in classes and "bg-info" in classes):
            current_letter = td0.get("id", "").strip() or None
            continue

        # Skip utility “Top” rows (colspan + Top button)
        if td0.has_attr("colspan"):
            # These rows usually include a 'Top' button; ignore entirely
            continue

        # Find the first anchor in this row (robust to missing headers="who")
        a = tr.find("a", href=True)
        if not a:
            continue

        href = a["href"].strip()
        text = " ".join(a.get_text(" ", strip=True).split())

        # Skip non-organization anchors like 'Top' or footnote jumps
        if not href or href.lower().startswith(("mailto:", "javascript:")):
            continue
        if "wb-cont" in href or "#wb-cont" in href:
            continue

        url = href if href.lower().startswith(("http://", "https://")) else urljoin(BASE, href)

        yield {
            "name": text,
            "url": url,
            "letter": current_letter or "",
            "source": SOURCE,
        }

def main():
    ap = argparse.ArgumentParser(description="Extract Crown corporation URLs from TBS list HTML")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append to this CSV (creates if missing). If omitted, prints CSV to stdout.")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = list(rows_from_crown_table(html))

    # Deduplicate by URL (case-insensitive)
    seen = set()
    deduped = []
    for r in rows:
        key = r["url"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    fieldnames = ["name", "url", "letter", "source"]

    if args.append:
        # Detect whether we need to write a header
        try:
            with open(args.append, "r", encoding="utf-8") as f:
                has_any = f.read(1)
            write_header = not bool(has_any)
        except FileNotFoundError:
            write_header = True

        with open(args.append, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                w.writeheader()
            for r in deduped:
                w.writerow(r)
    else:
        w = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
        w.writeheader()
        for r in deduped:
            w.writerow(r)

if __name__ == "__main__":
    main()

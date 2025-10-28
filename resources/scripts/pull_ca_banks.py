#!/usr/bin/env python3
import sys
import argparse
import csv
from bs4 import BeautifulSoup

def detect_section_source(node):
    """
    Walk upward and leftward to find the nearest preceding <h2> that mentions Schedule I/II.
    Returns 'fin:ca-sch1', 'fin:ca-sch2', or None if not found.
    """
    # Try current and previous siblings upwards to find an h2
    cur = node
    while cur is not None:
        # Check current node if it's an h2
        if getattr(cur, "name", None) and cur.name.lower() == "h2":
            text = cur.get_text(" ", strip=True).lower()
            if "schedule i" in text:
                return "fin:ca-sch1"
            if "schedule ii" in text:
                return "fin:ca-sch2"
        # Then move to previous sibling if available; else climb to parent
        prev = cur.previous_sibling
        while prev is not None and getattr(prev, "name", None) is None:
            prev = prev.previous_sibling
        if prev is not None:
            cur = prev
            continue
        # climb
        cur = cur.parent
    return None

def parse_html(html, override_source=None):
    soup = BeautifulSoup(html, "html.parser")

    rows = []
    seen = set()  # de-dup (name,url)

    # Strategy:
    # - Prefer ULs that are adjacent to H2s mentioning Schedule I/II
    # - If no H2, still parse any UL > LI > A; source may come from override
    uls = soup.find_all("ul")
    for ul in uls:
        # find all <a> within <li>
        for a in ul.select("li a[href]"):
            name = a.get_text(" ", strip=True)
            url = (a.get("href") or "").strip()
            if not name or not url:
                continue
            # Infer source
            source = override_source or detect_section_source(ul)
            # If still unknown, skip (or fallback to sch1 if you prefer)
            if source is None:
                # Do not guess silently; skip to avoid mislabeling.
                continue

            key = (name, url, source)
            if key in seen:
                continue
            seen.add(key)

            # abbr is not available here; leave empty
            rows.append([name, url, "", source + ","])  # trailing comma as requested

    return rows

def write_rows_stdout(rows):
    writer = csv.writer(sys.stdout, lineterminator="\n")
    for row in rows:
        writer.writerow(row)

def append_rows_to_csv(rows, path):
    # Append rows to an existing CSV *without* writing a header
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        for row in rows:
            writer.writerow(row)

def main():
    ap = argparse.ArgumentParser(description="Parse CBA Schedule I/II bank lists (and similar ULs) into CSV rows.")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append parsed rows to an existing CSV (no header written).")
    ap.add_argument("--source", choices=["fin:ca-sch1", "fin:ca-sch2"],
                    help="Override source tag (useful if the HTML is just a <ul> without the <h2> headings).")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_html(html, override_source=args.source)

    if not rows:
        # Exit non-zero so the calling script knows nothing was parsed
        sys.stderr.write("No rows parsed (check that your HTML contains <ul><li><a ...> and that Schedule headers are present or --source is set).\n")
        sys.exit(2)

    if args.append:
        append_rows_to_csv(rows, args.append)
    else:
        write_rows_stdout(rows)

if __name__ == "__main__":
    main()

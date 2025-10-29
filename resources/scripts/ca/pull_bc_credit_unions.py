#!/usr/bin/env python3
import sys
import argparse
import csv
import re
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

DEFAULT_SOURCE = "fin:ca-cu-bc"

def norm_url(raw: str) -> str:
    """Normalize a URL:
    - Trim spaces
    - If it lacks a scheme, assume https://
    - Lowercase host
    """
    s = (raw or "").strip()
    if not s:
        return ""

    # If anchor text is like 'vanfirecu.com' or 'www.foo.com', add https://
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', s):
        s = "https://" + s.lstrip("/")

    try:
        p = urlparse(s)
        # If still no netloc (edge-case), bail
        if not p.netloc:
            return s
        # Lowercase hostname; keep path/query/fragment as-is
        netloc = p.netloc.lower()
        return urlunparse((p.scheme, netloc, p.path or "/", p.params, p.query, p.fragment))
    except Exception:
        return s

def parse_rows(html: str, source_tag: str):
    soup = BeautifulSoup(html, "html.parser")
    rows = []
    seen = set()

    for tr in soup.find_all("tr"):
        tds = tr.find_all("td")
        if not tds:
            continue

        # Name from first TD
        name = tds[0].get_text(" ", strip=True)
        if not name:
            continue

        # URL: first <a href> anywhere in the row
        a = tr.find("a", href=True)
        url = ""
        if a:
            url = a.get("href") or ""
            if not url.strip():
                # fallback to anchor text
                url = a.get_text(" ", strip=True)
        else:
            # Very rare: no <a>; try the last TD text as a domain
            url = tds[-1].get_text(" ", strip=True)

        url = norm_url(url)
        if not url:
            continue

        key = (name, url, source_tag)
        if key in seen:
            continue
        seen.add(key)
        rows.append([name, url, "", source_tag + ","])  # abbr empty; keep trailing comma

    return rows

def write_stdout(rows):
    w = csv.writer(sys.stdout, lineterminator="\n")
    for r in rows:
        w.writerow(r)

def append_csv(rows, path):
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Parse BC credit-union <tr> rows into CSV (name,url,abbr,source,).")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append rows to an existing CSV (no header).")
    ap.add_argument("--source", default=DEFAULT_SOURCE,
                    help=f"Override source tag (default: {DEFAULT_SOURCE})")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.source)

    if not rows:
        sys.stderr.write("No rows parsed. Ensure your HTML contains <tr><td>… and at least one <a href=…> per row.\n")
        sys.exit(2)

    if args.append:
        append_csv(rows, args.append)
    else:
        write_stdout(rows)

if __name__ == "__main__":
    main()

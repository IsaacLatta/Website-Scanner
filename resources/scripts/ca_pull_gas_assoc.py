#!/usr/bin/env python3
import sys
import argparse
import csv
import re
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

DEFAULT_SOURCE = "ci:ca-gas-assoc"

def fix_one_slash_scheme(s: str) -> str:
    # Normalize 'http:/' or 'https:/' to proper '://'
    return re.sub(r'^(https?):/([^/])', r'\1://\2', s.strip(), flags=re.IGNORECASE)

def norm_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    s = fix_one_slash_scheme(s)
    # Add scheme if missing
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', s):
        s = "https://" + s.lstrip("/")
    try:
        p = urlparse(s)
        if not p.netloc:
            # Handle cases like 'https:///example.com'
            if p.path and "." in p.path:
                host, *rest = p.path.split("/", 1)
                path = "/" + (rest[0] if rest else "")
                return urlunparse((p.scheme or "https", host.lower(), path or "/", "", "", ""))
            return s
        return urlunparse((p.scheme, p.netloc.lower(), p.path or "/", p.params, p.query, p.fragment))
    except Exception:
        return s

def parse_rows(html: str, source_tag: str):
    soup = BeautifulSoup(html, "html.parser")
    rows, seen = [], set()

    for a in soup.select("ul li a[href]"):
        name = a.get_text(" ", strip=True)
        href = (a.get("href") or "").strip()
        if not name or not href:
            continue
        url = norm_url(href)

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
    ap = argparse.ArgumentParser(description="Parse gas associations into CSV (name,url,abbr,source,).")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append rows to an existing CSV (no header).")
    ap.add_argument("--source", default=DEFAULT_SOURCE,
                    help=f"Override source tag (default: {DEFAULT_SOURCE})")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.source)

    if not rows:
        sys.stderr.write("No rows parsed. Ensure the HTML contains <ul> with <li><a href=...>...</a></li> entries.\n")
        sys.exit(2)

    if args.append:
        append_csv(rows, args.append)
    else:
        write_stdout(rows)

if __name__ == "__main__":
    main()

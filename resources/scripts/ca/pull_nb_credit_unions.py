#!/usr/bin/env python3
import sys
import argparse
import csv
import re
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

DEFAULT_SOURCE = "fin:ca-cu-nb"

def norm_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', s):
        s = "https://" + s.lstrip("/")
    try:
        p = urlparse(s)
        if not p.netloc:
            return s
        netloc = p.netloc.lower()
        path = p.path if p.path else "/"
        return urlunparse((p.scheme, netloc, path, p.params, p.query, p.fragment))
    except Exception:
        return s

def parse_rows(html: str, source_tag: str):
    soup = BeautifulSoup(html, "html.parser")
    rows = []
    seen = set()

    # Each institution lives under .protected-institution (article)
    for art in soup.select("article.protected-institution"):
        # Name from header
        header = art.select_one(".card-header")
        name = header.get_text(" ", strip=True) if header else ""
        if not name:
            continue

        # URL from Website field
        a = art.select_one(".protected-institution__field-website a[href]")
        url = ""
        if a:
            url = a.get("href") or ""
            if not url.strip():
                url = a.get_text(" ", strip=True)
        else:
            # Fallback: try any <a> in right column (very defensive)
            a_any = art.select_one("a[href]")
            if a_any:
                url = a_any.get("href") or a_any.get_text(" ", strip=True)

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
    ap = argparse.ArgumentParser(description="Parse NB credit-union cards into CSV (name,url,abbr,source,).")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append rows to an existing CSV (no header).")
    ap.add_argument("--source", default=DEFAULT_SOURCE,
                    help=f"Override source tag (default: {DEFAULT_SOURCE})")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.source)

    if not rows:
        sys.stderr.write("No rows parsed. Ensure the HTML contains 'article.protected-institution' cards with a Website link.\n")
        sys.exit(2)

    if args.append:
        append_csv(rows, args.append)
    else:
        write_stdout(rows)

if __name__ == "__main__":
    main()

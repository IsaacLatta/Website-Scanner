#!/usr/bin/env python3
import sys
import argparse
import csv
import re
from urllib.parse import urlparse, urlunparse
from bs4 import BeautifulSoup

DEFAULT_SOURCE = "ci:ca-gas-distributor"

def fix_one_slash_scheme(s: str) -> str:
    # Normalize 'http:/' or 'https:/' to 'http://' / 'https://'
    return re.sub(r'^(https?):/([^/])', r'\1://\2', s.strip(), flags=re.IGNORECASE)

def norm_url(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    s = fix_one_slash_scheme(s)
    # If still no scheme, prepend https://
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', s):
        s = "https://" + s.lstrip("/")
    try:
        p = urlparse(s)
        if not p.netloc:
            # Handle oddballs like 'https:///example.com'
            if p.path and "." in p.path:
                parts = p.path.split("/", 1)
                host = parts[0].lower()
                path = "/" + (parts[1] if len(parts) > 1 else "")
                return urlunparse((p.scheme or "https", host, path or "/", "", "", ""))
            return s
        netloc = p.netloc.lower()
        path = p.path or "/"
        return urlunparse((p.scheme, netloc, path, p.params, p.query, p.fragment))
    except Exception:
        return s

def extract_name(a_tag):
    # Prefer explicit entry title
    title_span = a_tag.select_one(".entry-title")
    if title_span:
        name = title_span.get_text(" ", strip=True)
        if name:
            return name
    # Fallback to logo alt text
    img = a_tag.find("img", alt=True)
    if img and img.get("alt"):
        name = img.get("alt").strip()
        if name:
            return name
    # Last resort: anchor text
    return a_tag.get_text(" ", strip=True)

def parse_rows(html: str, source_tag: str):
    soup = BeautifulSoup(html, "html.parser")
    rows, seen = [], set()

    # CGA layout: <ul class="viewList"> <li class="viewItem_*"> <h3> <a href=...> ... </a> </h3> </li>
    for li in soup.select("ul.viewList li.viewItem"):
        a = li.select_one("a[href]")
        if not a:
            continue

        name = extract_name(a)
        href = (a.get("href") or "").strip()
        if not name or not href:
            continue

        url = norm_url(href)
        if not url:
            continue

        key = (name, url, source_tag)
        if key in seen:
            continue
        seen.add(key)

        rows.append([name, url, "", source_tag + ","])  # abbr empty; trailing comma kept

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
    ap = argparse.ArgumentParser(description="Parse CGA natural gas distributors into CSV (name,url,abbr,source,).")
    ap.add_argument("--append", metavar="CSV_PATH", help="Append rows to an existing CSV (no header).")
    ap.add_argument("--source", default=DEFAULT_SOURCE,
                    help=f"Override source tag (default: {DEFAULT_SOURCE})")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.source)

    if not rows:
        sys.stderr.write("No rows parsed. Ensure the HTML contains <ul class='viewList'> with <a href=...> entries.\n")
        sys.exit(2)

    if args.append:
        append_csv(rows, args.append)
    else:
        write_stdout(rows)

if __name__ == "__main__":
    main()

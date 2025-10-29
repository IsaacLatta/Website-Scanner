#!/usr/bin/env python3
import sys
import argparse
import csv
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse, urljoin

DEFAULT_SOURCE = "ci:ca-pipelines"

NA_TOKENS = {"n/a", "na", "-", ""}

def fix_one_slash_scheme(s: str) -> str:
    # Normalize 'http:/' or 'https:/' to '://'
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
            # Handle accidental triple slashes or scheme-only with path
            if p.path and "." in p.path:
                host, *rest = p.path.split("/", 1)
                path = "/" + (rest[0] if rest else "")
                return urlunparse((p.scheme or "https", host.lower(), path or "/", "", "", ""))
            return s
        return urlunparse((p.scheme, p.netloc.lower(), p.path or "/", p.params, p.query, p.fragment))
    except Exception:
        return s

def clean_text(s: str) -> str:
    return re.sub(r'\s+', ' ', (s or '').replace('\xa0', ' ')).strip()

def maybe(s: str) -> str:
    t = clean_text(s).lower()
    return "" if t in NA_TOKENS else clean_text(s)

def parse_rows(html: str, source_tag: str, base: str | None):
    soup = BeautifulSoup(html, "html.parser")
    rows = []
    seen = set()

    for tr in soup.select("tbody tr"):
        tds = tr.find_all("td")
        if len(tds) < 5:
            continue

        name = clean_text(tds[0].get_text(" ", strip=True))
        group = clean_text(tds[1].get_text(" ", strip=True))

        # Company URL is in an <a>, or may be N/A text
        comp_a = tds[2].find("a")
        comp_url_raw = comp_a.get("href", "") if comp_a else tds[2].get_text(" ", strip=True)
        comp_url = norm_url(maybe(comp_url_raw))

        contact = clean_text(tds[3].get_text(" ", strip=True))
        contact = "" if contact.lower() in NA_TOKENS else contact

        prof_a = tds[4].find("a")
        prof_raw = prof_a.get("href", "") if prof_a else tds[4].get_text(" ", strip=True)
        prof_raw = "" if prof_raw.lower() in NA_TOKENS else prof_raw.strip()
        profile_url = urljoin(base, prof_raw) if (base and prof_raw) else prof_raw

        if not name:
            continue

        key = (name, comp_url, group, contact, profile_url, source_tag)
        if key in seen:
            continue
        seen.add(key)

        # CSV: name,company_url,abbr,source,group,contact,profile_url
        rows.append([name, comp_url, "", source_tag + ",", group, contact, profile_url])

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
    ap = argparse.ArgumentParser(
        description="Parse CER pipelines table into CSV (name,company_url,abbr,source,group,contact,profile_url)."
    )
    ap.add_argument("--append", metavar="CSV_PATH", help="Append rows to an existing CSV (no header).")
    ap.add_argument("--source", default=DEFAULT_SOURCE, help=f"Override source tag (default: {DEFAULT_SOURCE})")
    ap.add_argument("--base", default="", help="Base URL to resolve relative profile links (e.g., https://www.cer-rec.gc.ca/)")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.source, args.base.strip() or None)

    if not rows:
        sys.stderr.write("No rows parsed. Confirm the HTML <tbody><tr><td> structure matches the sample.\n")
        sys.exit(2)

    if args.append:
        append_csv(rows, args.append)
    else:
        write_stdout(rows)

if __name__ == "__main__":
    main()

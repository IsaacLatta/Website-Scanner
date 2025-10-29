#!/usr/bin/env python3
import sys
import csv
import argparse
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin

BASE = "https://www.usa.gov"

def normalize_ws(s: str) -> str:
    return " ".join(s.split()) if s else ""

def parse_accordion(soup):
    for acc in soup.select("div.usa-accordion"):
        headings = acc.select("h2.usa-accordion__heading > button.usa-accordion__button")
        contents = acc.select("div.usa-accordion__content")
        pairs = []
        try:
            for child in acc.children:
                if getattr(child, "name", None) is None:
                    continue
                if child.name == "h2" and child.select_one("button.usa-accordion__button"):
                    btn = child.select_one("button.usa-accordion__button")
                    pairs.append([btn, None])
                elif child.name == "div" and "usa-accordion__content" in child.get("class", []):
                    for p in reversed(pairs):
                        if p[1] is None:
                            p[1] = child
                            break
            if len([p for p in pairs if p[1] is not None]) < min(len(headings), len(contents)):
                pairs = [[h, contents[i] if i < len(contents) else None] for i, h in enumerate(headings)]
        except Exception:
            pairs = [[h, contents[i] if i < len(contents) else None] for i, h in enumerate(headings)]

        for btn, content in pairs:
            if not btn or content is None:
                continue
            fallback_name = normalize_ws(btn.get_text(strip=True))

            website_anchor = content.select_one("div.agency-first-field p.field--name-field-website a[href]")
            if not website_anchor:
                website_anchor = None
                for lab in content.find_all("p", class_="agency-index-label"):
                    if "Website" in lab.get_text():
                        next_a = lab.find_next("a", href=True)
                        if next_a and next_a.get("href"):
                            website_anchor = next_a
                            break
            if not website_anchor:
                continue

            url = website_anchor.get("href", "").strip()
            url = urljoin(BASE, url)
            name = normalize_ws(website_anchor.get_text(strip=True)) or fallback_name
            yield {
                "name": name,
                "url": url,
                "abbreviation": "",
                "source": ""
            }

def main():
    ap = argparse.ArgumentParser(description="Parse USA.gov A–Z accordion HTML from stdin into CSV rows (name,url,abbreviation,source).")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    ap.add_argument("--append", action="store_true", help="Append to CSV instead of overwriting. When set, header is not written unless file is empty.")
    ap.add_argument("--source", default="https://www.usa.gov/agency-index", help="Value for the 'source' column.")
    args = ap.parse_args()

    html = sys.stdin.read()
    if not html.strip():
        print("No HTML received on stdin.", file=sys.stderr)
        sys.exit(1)

    try:
        soup = BeautifulSoup(html, "html5lib")
    except Exception:
        # Fallback to lxml or built-in parser if html5lib isn't available
        parser = "lxml"
        try:
            soup = BeautifulSoup(html, parser)
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

    rows = list(parse_accordion(soup))
    if not rows:
        print("No rows parsed. Check that the input contains <div class='usa-accordion'> blocks.", file=sys.stderr)
        sys.exit(2)

    for r in rows:
        r["source"] = args.source

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["name", "url", "abbreviation", "source"]
    mode = "a" if args.append else "w"
    with open(out_path, mode, newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not args.append or (args.append and (not out_path.exists() or out_path.stat().st_size == 0)):
            writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}", file=sys.stderr)

if __name__ == "__main__":
    main()

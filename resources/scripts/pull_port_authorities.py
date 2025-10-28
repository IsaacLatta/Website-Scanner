#!/usr/bin/env python3
import sys, csv, argparse
from urllib.parse import urljoin
from bs4 import BeautifulSoup

BASE = "https://tc.canada.ca"
SOURCE = "tc:port-authorities"

def extract_ports(html):
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find("table")
    if not table:
        return

    current_province = ""
    # Skip the header row with “Province / Name of Port Authority”
    for tr in table.find_all("tr"):
        # Header row often has class "active"
        if "active" in tr.get("class", []):
            continue

        tds = tr.find_all("td")
        if not tds:
            continue

        # Province may be set in the first cell (with rowspan) for a block
        # Cells typically contain <p><strong>Province Name</strong></p>
        if len(tds) == 2:
            prov_cell = tds[0]
            prov_text = prov_cell.get_text(" ", strip=True)
            # Clean common formatting quirks
            prov_text = prov_text.replace("\xa0", " ").strip(" :")
            if prov_text:
                current_province = prov_text

            target_td = tds[1]
        else:
            # Continuation rows (no province cell)
            target_td = tds[0]

        a = target_td.find("a", href=True)
        if not a:
            continue

        name = " ".join(a.get_text(" ", strip=True).split())
        href = a["href"].strip()
        if not href or href.lower().startswith(("mailto:", "javascript:")):
            continue

        url = href if href.lower().startswith(("http://", "https://")) else urljoin(BASE, href)

        yield {
            "name": name,
            "url": url,
            # Keep schema consistent with prior files: put province into `letter`
            "letter": current_province,
            "source": SOURCE,
        }

def main():
    ap = argparse.ArgumentParser(description="Extract Canada Port Authorities from TC page HTML")
    ap.add_argument("--append", metavar="CSV_PATH",
                    help="Append to this CSV (creates if missing). If omitted, prints CSV to stdout.")
    args = ap.parse_args()

    html = sys.stdin.read()
    rows = list(extract_ports(html))

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

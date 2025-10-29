#!/usr/bin/env python3
import sys, csv, argparse, re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

PROV_MAP = {
    "british columbia": "bc",
    "manitoba": "mb",
    "new brunswick": "nb",
    "ontario": "on",
    "quebec": "qc",
    "québec": "qc",
    "saskatchewan": "sk",
    "alberta": "ab",
    "nova scotia": "ns",
    "newfoundland and labrador": "nl",
    "prince edward island": "pe",
    "yukon": "yt",
    "northwest territories": "nt",
    "nunavut": "nu",
}

def clean_text(t: str) -> str:
    if t is None:
        return ""
    # Collapse whitespace and unescape &nbsp; etc.
    t = t.replace("\xa0", " ")
    t = re.sub(r"\s+", " ", t).strip()
    return t

def parse_rows(html: str, base: str):
    soup = BeautifulSoup(html, "html.parser")
    rows_out = []

    # Find any <tbody>, else fallback to whole document
    tbodies = soup.find_all("tbody")
    roots = tbodies if tbodies else [soup]

    for root in roots:
        for tr in root.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) < 4:
                continue

            province_raw = clean_text(tds[0].get_text())
            prov_key = province_raw.lower()
            prov = PROV_MAP.get(prov_key, prov_key[:2].lower() if prov_key else "")

            # Facility cell (name + link)
            a = tds[1].find("a")
            name = clean_text(a.get_text() if a else tds[1].get_text())
            href = a.get("href") if a and a.has_attr("href") else ""
            url = urljoin(base, href) if base else href

            status = clean_text(tds[2].get_text())
            operator = clean_text(tds[3].get_text())

            # Tag format requested previously: ci:ca-nuclear:<prov>
            tag = f"ci:ca-nuclear:{prov}" if prov else "ci:ca-nuclear"

            # Columns: name, country, province, tag, status, operator, url
            rows_out.append([name, "ca", prov, tag, status, operator, url])
    return rows_out

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="")
    p.add_argument("--append", help="Append to existing CSV file instead of printing")
    args = p.parse_args()

    html = sys.stdin.read()
    rows = parse_rows(html, args.base)

    if not rows:
        sys.stderr.write("No rows parsed. Check HTML structure includes <tr><td>...\n")
        sys.exit(2)

    if args.append:
        with open(args.append, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f, lineterminator="\\n")
            w.writerows(rows)
    else:
        w = csv.writer(sys.stdout, lineterminator="\\n")
        w.writerows(rows)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import sys, argparse, csv, re
from bs4 import BeautifulSoup

# Map by domain → province slug
DOMAIN_TO_PROV = {
    "oag.ab.ca": "alberta",
    "bcauditor.com": "british-columbia",
    "oag.mb.ca": "manitoba",
    "agnb-vgnb.ca": "new-brunswick",
    "ag.gov.nl.ca": "newfoundland-and-labrador",
    "oag-ns.ca": "nova-scotia",
    "auditor.on.ca": "ontario",
    "vgq.qc.ca": "quebec",
    "auditor.sk.ca": "saskatchewan",
    # federal (exclude): "oag-bvg.gc.ca": "canada",
}

# Fallback: text → province slug
TEXT_TO_PROV = {
    "alberta": "alberta",
    "british columbia": "british-columbia",
    "manitoba": "manitoba",
    "new brunswick": "new-brunswick",
    "newfoundland and labrador": "newfoundland-and-labrador",
    "nova scotia": "nova-scotia",
    "ontario": "ontario",
    "quebec": "quebec",
    "québec": "quebec",
    "saskatchewan": "saskatchewan",
    # PEI page lists "other" offices only, so PEI isn't here.
}

def province_slug(name_text, href):
    # Try by domain first
    host = re.sub(r"^https?://", "", href).split("/")[0].lower()
    host = host.replace("www.", "")
    for dom, prov in DOMAIN_TO_PROV.items():
        if host.endswith(dom):
            return prov
    # Fallback by text
    t = name_text.lower()
    for key, prov in TEXT_TO_PROV.items():
        if key in t:
            return prov
    return None

def main():
    ap = argparse.ArgumentParser(description="Parse PEI 'Other Canadian Auditor General Offices' HTML and append CSV rows.")
    ap.add_argument("--append", required=True, help="Path to CSV file to append to.")
    args = ap.parse_args()

    html = sys.stdin.read()
    soup = BeautifulSoup(html, "html.parser")

    # Target the UL that contains the list; robust fallback to any UL with links to AGs
    candidates = soup.find_all("ul")
    rows = []

    for ul in candidates:
        for li in ul.find_all("li", recursive=False):
            a = li.find("a", href=True)
            if not a:
                continue
            href = a["href"].strip()
            # Skip federal OAG (we're focusing on provinces per instructions)
            if "oag-bvg.gc.ca" in href:
                continue

            # Get a clean full name from LI (handles split “Genera” + trailing “l” cases)
            name = " ".join(li.get_text(" ", strip=True).split())
            # If name contains a colon note (e.g., federal row), strip annotation after colon
            if ":" in name:
                name = name.split(":", 1)[0].strip()

            # Ensure the name ends with "Auditor General" in case the anchor text was split oddly
            # but avoid forcing it if it's already complete or is Québec's French title.
            if ("auditor genera" in name.lower()) and not name.lower().endswith("auditor general"):
                name = re.sub(r"(?i)auditor genera\b", "Auditor General", name)

            # Province slug for source tag
            prov = province_slug(name, href)
            if not prov:
                # If we can’t confidently map, skip to avoid bad source tags
                continue

            source = f"gov:auditor-{prov}"
            rows.append([name, href, "", source])

    # Deduplicate by (name, url)
    seen = set()
    deduped = []
    for r in rows:
        key = (r[0].lower(), r[1])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    # Append to CSV
    with open(args.append, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        for r in deduped:
            writer.writerow(r)

if __name__ == "__main__":
    main()

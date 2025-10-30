#!/usr/bin/env python3
import argparse
import csv
import io
import os
import re
import sys
import time
from typing import Iterable, Tuple, Optional, List
from pathlib import Path

try:
    import requests
except Exception:
    requests = None  # We'll error nicely if run without requests installed

PRA_BANKS_URL = "https://www.bankofengland.co.uk/-/media/boe/files/prudential-regulation/authorisations/which-firms-does-the-pra-regulate/2025/list-of-pra-regulated-banks.csv"
FCA_BASE = "https://register.fca.org.uk/services/V0.1"

EMAIL = "t00239008@mytru.ca"  # per request
ENV_KEY = "UK_FCA_API_KEY"

CUT_MARKER = "Banks incorporated outside the UK authorised to accept deposits through a branch in the UK"

def _fail(msg: str, rc: int = 2):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(rc)

def download_text(url: str, timeout: int = 30) -> str:
    if requests is None:
        _fail("The 'requests' package is required. Please: pip install requests")
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    r.encoding = r.apparent_encoding or "utf-8"
    return r.text

def load_pra_csv(text: str) -> Iterable[Tuple[str, str]]:
    """
    Returns (firm_name, frn) for the first UK-incorporated section only.
    Stops when it encounters the CUT_MARKER line.
    """
    # Trim at marker
    lines = text.splitlines()
    out_lines: List[str] = []
    for line in lines:
        if line.strip().startswith(CUT_MARKER):
            break
        out_lines.append(line)

    # Find header "Firm Name,FRN,LEI" and parse subsequent rows until a blank/section break
    csv_text = "\n".join(out_lines)
    reader = csv.reader(io.StringIO(csv_text))
    started = False
    for row in reader:
        if not row:
            continue
        if not started:
            if len(row) >= 2 and row[0].strip().lower() == "firm name" and row[1].strip().lower() == "frn":
                started = True
            continue
        # From here: rows should be firm rows until another empty/section line
        if len(row) < 2:
            continue
        firm = row[0].strip()
        frn = row[1].strip()
        if not firm or not frn or not frn.isdigit():
            # stop if we wander into footer noise
            continue
        yield (firm, frn)

def fca_get_ppob_website(frn: str, key: str, email: str, timeout: int = 20) -> Optional[str]:
    """
    Calls /Firm/{FRN}/Address?Type=PPOB and tries to return "Website Address".
    Falls back to scanning any returned addresses for Address Type=Principal Place of Business
    """
    if requests is None:
        _fail("The 'requests' package is required. Please: pip install requests")
    url = f"{FCA_BASE}/Firm/{frn}/Address"
    headers = {
        "x-auth-key": key,
        "x-auth-email": email,
        "Content-Type": "application/json",
    }
    params = {"Type": "PPOB"}
    r = requests.get(url, headers=headers, params=params, timeout=timeout)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    data = r.json()
    items = data.get("Data") or []

    # First try: items that already match PPOB (either by query or field)
    for it in items:
        if it.get("Address Type", "").lower().strip() in {"principal place of business", "ppob"}:
            website = (it.get("Website Address") or "").strip()
            if website:
                return website

    # Fallback: any item with a non-empty Website Address
    for it in items:
        website = (it.get("Website Address") or "").strip()
        if website:
            return website
    return None

def write_rows(rows: Iterable[Tuple[str, Optional[str]]], out_path: Path, append: bool, also_stdout: bool):
    mode = "a" if append and out_path.exists() else "w"
    with out_path.open(mode, newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if mode == "w":
            w.writerow(["name", "url", "abbr", "source"])
        for name, url in rows:
            row = [name, url or "", "", "uk:banks"]
            w.writerow(row)
            if also_stdout:
                print(",".join(row))

def main():
    ap = argparse.ArgumentParser(description="Build UK banks list (PRA) and enrich with FCA website URLs")
    ap.add_argument("--pra-csv-url", default=PRA_BANKS_URL, help="PRA banks CSV URL (default: %(default)s)")
    ap.add_argument("--input-file", help="Use a local CSV file instead of downloading from URL")
    ap.add_argument("--out", required=True, help="Output CSV path (columns: name,url,abbr,source)")
    ap.add_argument("--append", action="store_true", help="Append to output if file exists")
    ap.add_argument("--stdout", action="store_true", help="Also print results to stdout")
    ap.add_argument("--limit", type=int, default=0, help="Limit number of firms processed (0 = no limit)")
    ap.add_argument("--sleep", type=float, default=0.15, help="Sleep seconds between FCA API calls (default: %(default)s)")
    args = ap.parse_args()

    key = os.environ.get(ENV_KEY, "").strip()
    if not key:
        _fail(f"Environment variable {ENV_KEY} is not set")

    # Load PRA CSV text
    if args.input_file:
        text = Path(args.input_file).read_text(encoding="utf-8", errors="ignore")
    else:
        text = download_text(args.pra_csv_url)

    # Extract (name, frn) pairs
    pairs = list(load_pra_csv(text))
    if args.limit > 0:
        pairs = pairs[: args.limit]

    out_rows = []
    for name, frn in pairs:
        try:
            url = fca_get_ppob_website(frn, key, EMAIL)
        except Exception as e:
            # Be resilient; record empty URL if error
            url = None
        out_rows.append((name, url))
        if args.sleep > 0:
            time.sleep(args.sleep)

    out_path = Path(args.out)
    write_rows(out_rows, out_path, append=args.append, also_stdout=args.stdout)

if __name__ == "__main__":
    main()

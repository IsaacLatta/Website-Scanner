#!/usr/bin/env python3
# get_us_banks.py

import csv, time, argparse, requests

BASE = "https://api.fdic.gov/banks/institutions"
TOP10_STATES = ["CA","TX","FL","NY","PA","IL","OH","GA","NC","MI"]

def norm_url(u: str) -> str:
    if not u: return ""
    u = str(u).strip()
    if not u or u.upper() in {"N/A","NA","NONE"}: return ""
    if not u.lower().startswith(("http://","https://")):
        u = "https://" + u.lstrip("/")
    return u

def fetch_top_assets(state: str, limit: int = 10, api_key: str | None = None):
    params = {
        "filters": f"STALP:{state} AND ACTIVE:1",
        "fields": "NAME,WEBADDR,ASSET",
        "sort_by": "ASSET",
        "sort_order": "DESC",
        "limit": limit,
        "format": "json",
    }
    if api_key:
        params["api_key"] = api_key
    r = requests.get(BASE, params=params, timeout=30)
    r.raise_for_status()
    js = r.json()

    # Shape: {"data":[{"data": {...}, "score":0}, ...]}
    rows = []
    for item in js.get("data", []):
        rec = item.get("data", item) or {}
        name = rec.get("NAME") or ""
        url  = norm_url(rec.get("WEBADDR") or "")
        if name or url:
            rows.append((name, url))
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o","--out", default="us_banks_top10_by_state.csv")
    ap.add_argument("--states", nargs="*", default=TOP10_STATES)
    ap.add_argument("-n","--limit", type=int, default=10)
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    seen = set()  # (name,url) de-dupe across states
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name","url","abbr","source"])
        for st in args.states:
            try:
                rows = fetch_top_assets(st, args.limit, args.api_key)
            except Exception as e:
                print(f"[WARN] {st}: {e}")
                continue
            for name, url in rows:
                key = (name, url)
                if key in seen: 
                    continue
                seen.add(key)
                w.writerow([name, url, "", "us-banks"])
            if args.sleep: 
                time.sleep(args.sleep)
    print(f"Done → {args.out}")

if __name__ == "__main__":
    main()

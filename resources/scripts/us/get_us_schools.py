#!/usr/bin/env python3
import os, sys, csv, requests

BASE = "https://api.data.gov/ed/collegescorecard/v1/schools"
API_KEY = os.getenv("US_SCORECARD_API_KEY")

# Top 10 states by population (2024)
TOP10 = ["CA","TX","FL","NY","PA","IL","OH","GA","NC","MI"]

def norm_url(u: str | None) -> str:
    if not u:
        return ""
    u = u.strip()
    if not u:
        return ""
    if u.startswith(("http://", "https://")):
        return u
    # API often returns "www.example.edu/"; prefer https
    return "https://" + u.lstrip("/")

def fetch_top_by_size(state: str, top_n: int = 5):
    params = {
        "api_key": API_KEY,
        "school.state": state,
        # dotted keys are easiest to parse
        "fields": "id,school.name,school.school_url,latest.student.size",
        "sort": "latest.student.size:desc",
        "per_page": str(top_n),
        "page": "0",
    }
    r = requests.get(BASE, params=params, timeout=30)
    r.raise_for_status()
    js = r.json()
    # Defensive: results may be absent
    return js.get("results", [])

def main():
    if not API_KEY:
        print("ERROR: US_SCORECARD_API_KEY is not set in the environment.", file=sys.stderr)
        sys.exit(2)

    out_path = sys.argv[1] if len(sys.argv) > 1 else "us_edu_scorecard.csv"

    # Deduplicate on (name,url) across states (some multi-state systems appear in several states)
    seen = set()
    rows = []

    for st in TOP10:
        try:
            results = fetch_top_by_size(st, 5)
        except Exception as e:
            print(f"State {st}: request failed: {e}", file=sys.stderr)
            continue

        for rec in results:
            name = rec.get("school.name", "") or ""
            url  = norm_url(rec.get("school.school_url"))
            key  = (name, url)
            if key in seen:
                continue
            seen.add(key)
            rows.append([name, url, "", "us-edu-scorecard"])

    # Write CSV
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name","url","abbr","source"])
        w.writerows(rows)

    print(f"Done → {out_path}  (rows: {len(rows)})")

if __name__ == "__main__":
    main()

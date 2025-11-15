#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from collections import Counter

import matplotlib.pyplot as plt


def load_results(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den == 0:
        return 0.0
    return 100.0 * num / den


def compute_securitytxt_blocks(sec_results: dict) -> tuple[dict, dict, dict, dict, dict]:
    n_origins = len(sec_results)
    n_origin_offline = 0
    n_present = 0
    n_missing = 0
    n_timeouts = 0
    n_other_errors = 0

    field_combos = Counter()
    location_counts = Counter()

    n_present_has_expires = 0
    n_present_valid_expires = 0
    n_present_expired_expires = 0

    n_present_has_contact = 0
    n_present_has_canonical = 0
    n_present_multiple_contacts = 0

    for origin, row in sec_results.items():
        present = bool(row.get("present"))
        has_contact = bool(row.get("has_contact"))
        has_expires = bool(row.get("has_expires"))
        expires_valid = bool(row.get("expires_valid"))
        location = row.get("location") or ""
        error = row.get("error") or ""
        contacts = row.get("contacts") or ""
        canonical = row.get("canonical") or ""

        # High-level presence / errors
        if error == "origin offline":
            n_origin_offline += 1
        elif error.startswith("timeout:"):
            n_timeouts += 1
        elif error:
            n_other_errors += 1

        if present:
            n_present += 1
        else:
            # counted as "missing" if not present and not offline
            if error != "origin offline":
                n_missing += 1

        # Only consider present files for the rest
        if not present:
            continue

        # Field combinations
        if has_contact and has_expires:
            field_combos["contact_and_expires"] += 1
        elif has_contact and not has_expires:
            field_combos["contact_only"] += 1
        elif not has_contact and has_expires:
            field_combos["expires_only"] += 1
        else:
            field_combos["present_without_contact_or_expires"] += 1

        # Expires stats
        if has_expires:
            n_present_has_expires += 1
            if expires_valid:
                n_present_valid_expires += 1
            else:
                n_present_expired_expires += 1

        # Location stats
        if location:
            location_counts[location] += 1

        # Contact / canonical stats
        if has_contact:
            n_present_has_contact += 1
            # Split on commas to approximate number of contacts
            parts = [p.strip() for p in contacts.split(",") if p.strip()]
            if len(parts) > 1:
                n_present_multiple_contacts += 1

        if canonical:
            n_present_has_canonical += 1

    overview = {
        "n_origins": n_origins,
        "n_origin_offline_securitytxt": n_origin_offline,
        "n_present": n_present,
        "n_missing": n_missing,
        "n_timeouts": n_timeouts,
        "n_other_errors": n_other_errors,
    }

    # Expires block
    n_present_total = n_present
    n_no_expires = max(0, n_present_total - n_present_has_expires)
    expires_stats = {
        "n_present": n_present_total,
        "n_present_has_expires": n_present_has_expires,
        "n_present_valid_expires": n_present_valid_expires,
        "n_present_expired_expires": n_present_expired_expires,
        "n_present_no_expires": n_no_expires,
        "pct_valid_expires_among_expires": safe_pct(
            n_present_valid_expires, n_present_has_expires
        ),
        "pct_present_with_expires": safe_pct(
            n_present_has_expires, n_present_total
        ),
    }

    # Contact / canonical block
    contact_canonical = {
        "n_present": n_present_total,
        "n_present_has_contact": n_present_has_contact,
        "n_present_has_canonical": n_present_has_canonical,
        "n_present_multiple_contacts": n_present_multiple_contacts,
        "pct_present_with_contact": safe_pct(
            n_present_has_contact, n_present_total
        ),
        "pct_present_with_canonical": safe_pct(
            n_present_has_canonical, n_present_total
        ),
    }

    return (
        overview,
        dict(field_combos),
        expires_stats,
        dict(location_counts),
        contact_canonical,
    )


def plot_securitytxt_presence(overview: dict, out_path: Path) -> None:
    labels = ["has_securitytxt", "missing_securitytxt", "origin_offline"]
    values = [
        overview.get("n_present", 0),
        overview.get("n_missing", 0),
        overview.get("n_origin_offline_securitytxt", 0),
    ]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins")
    plt.title("security.txt presence per origin")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_securitytxt_field_combinations(field_combos: dict, out_path: Path) -> None:
    labels = ["contact_only", "expires_only", "contact_and_expires"]
    values = [field_combos.get(l, 0) for l in labels]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins (with security.txt)")
    plt.title("security.txt field combinations")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_securitytxt_expires(expires_stats: dict, out_path: Path) -> None:
    labels = ["valid_expires", "expired_expires", "no_expires"]
    values = [
        expires_stats.get("n_present_valid_expires", 0),
        expires_stats.get("n_present_expired_expires", 0),
        expires_stats.get("n_present_no_expires", 0),
    ]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins (with security.txt)")
    plt.title("security.txt Expires coverage and validity")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_securitytxt_locations(location_counts: dict, out_path: Path) -> None:
    if not location_counts:
        return

    labels = list(location_counts.keys())
    values = [location_counts[l] for l in labels]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=15, ha="right")
    plt.ylabel("Number of origins (with security.txt)")
    plt.title("security.txt locations")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_securitytxt_contact_canonical(contact_canonical: dict, out_path: Path) -> None:
    labels = ["has_contact", "has_canonical"]
    values = [
        contact_canonical.get("n_present_has_contact", 0),
        contact_canonical.get("n_present_has_canonical", 0),
    ]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins (with security.txt)")
    plt.title("security.txt contact and canonical coverage")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def build_metric_definitions() -> dict:
    return {
        "securitytxt_overview.n_origins":
            "Number of origins that appeared in the securitytxt module results.",
        "securitytxt_overview.n_origin_offline_securitytxt":
            "Number of origins where the securitytxt module recorded error='origin offline', "
            "indicating that the origin was treated as offline and security.txt was not probed.",
        "securitytxt_overview.n_present":
            "Number of origins where present=True, meaning at least one usable security.txt file "
            "was found at /.well-known/security.txt or /security.txt and contained a Contact or Expires field.",
        "securitytxt_overview.n_missing":
            "Number of origins that were probed (not origin offline) but did not yield any usable security.txt "
            "file (present=False).",
        "securitytxt_overview.n_timeouts":
            "Number of origins where the securitytxt module recorded an error starting with 'timeout:', "
            "indicating that the HTTPS request for security.txt did not complete before the timeout.",
        "securitytxt_overview.n_other_errors":
            "Number of origins where the securitytxt module recorded an error that was neither 'origin offline' "
            "nor a timeout, such as file_too_large or too_many_lines.",
        "field_combinations.contact_only":
            "Number of origins with present=True where security.txt contained at least one Contact field "
            "but no valid Expires field.",
        "field_combinations.expires_only":
            "Number of origins with present=True where security.txt contained a valid Expires field but no Contact field.",
        "field_combinations.contact_and_expires":
            "Number of origins with present=True where security.txt contained both at least one Contact field "
            "and a valid Expires field.",
        "field_combinations.present_without_contact_or_expires":
            "Number of origins with present=True but with neither Contact nor Expires fields detected. "
            "This should be zero in normal RFC 9116 files and is included as a sanity check.",
        "expires_stats.n_present":
            "Number of origins where security.txt was present (present=True).",
        "expires_stats.n_present_has_expires":
            "Number of present security.txt files that contained a validly parsed Expires field.",
        "expires_stats.n_present_valid_expires":
            "Number of present security.txt files where has_expires=True and expires_valid=True, "
            "i.e., the Expires timestamp was still in the future at scan time.",
        "expires_stats.n_present_expired_expires":
            "Number of present security.txt files where has_expires=True but expires_valid=False, "
            "meaning the advertised Expires timestamp was already in the past.",
        "expires_stats.n_present_no_expires":
            "Number of present security.txt files that did not include any Expires field.",
        "expires_stats.pct_valid_expires_among_expires":
            "Percentage of security.txt files with an Expires field where the Expires value was still valid "
            "at scan time (n_present_valid_expires / n_present_has_expires).",
        "expires_stats.pct_present_with_expires":
            "Percentage of present security.txt files that included an Expires field "
            "(n_present_has_expires / n_present).",
        "location_counts":
            "Histogram of locations where security.txt was successfully found among origins with present=True, "
            "typically '/.well-known/security.txt' and '/security.txt'.",
        "contact_canonical.n_present":
            "Number of origins where security.txt was present (present=True).",
        "contact_canonical.n_present_has_contact":
            "Number of present security.txt files that contained at least one Contact field.",
        "contact_canonical.n_present_has_canonical":
            "Number of present security.txt files that contained at least one Canonical field.",
        "contact_canonical.n_present_multiple_contacts":
            "Number of present security.txt files where the Contact field appeared more than once, "
            "i.e., after splitting the stored contacts string on commas there were multiple non-empty entries.",
        "contact_canonical.pct_present_with_contact":
            "Percentage of present security.txt files that included at least one Contact field.",
        "contact_canonical.pct_present_with_canonical":
            "Percentage of present security.txt files that included at least one Canonical field.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarise security.txt deployment from a scan results JSON."
    )
    parser.add_argument(
        "results_json",
        type=Path,
        help="Path to full scan results JSON file produced by run_scan().",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Directory where securitytxt_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)
    modules = results.get("modules", {})
    sec_results = modules.get("securitytxt", {})

    (
        overview,
        field_combos,
        expires_stats,
        location_counts,
        contact_canonical,
    ) = compute_securitytxt_blocks(sec_results)

    # Plots
    plot_securitytxt_presence(overview, out_dir / "securitytxt_presence.png")
    plot_securitytxt_field_combinations(
        field_combos, out_dir / "securitytxt_field_combinations.png"
    )
    plot_securitytxt_expires(expires_stats, out_dir / "securitytxt_expires_validity.png")
    plot_securitytxt_locations(
        location_counts, out_dir / "securitytxt_locations.png"
    )
    plot_securitytxt_contact_canonical(
        contact_canonical, out_dir / "securitytxt_contact_canonical.png"
    )

    summary = {
        "securitytxt_overview": overview,
        "field_combinations": field_combos,
        "expires_stats": expires_stats,
        "location_counts": location_counts,
        "contact_canonical": contact_canonical,
        "metric_definitions": build_metric_definitions(),
    }

    out_path = out_dir / "securitytxt_summary.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote security.txt summary to {out_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

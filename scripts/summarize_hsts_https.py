#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from collections import Counter
import math
import statistics

import matplotlib.pyplot as plt


def load_results(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den == 0:
        return 0.0
    return 100.0 * num / den


def describe_numeric(values):
    if not values:
        return {"count": 0, "mean": 0.0, "median": 0.0, "p95": 0.0, "max": 0}
    values_sorted = sorted(values)
    count = len(values_sorted)
    mean = statistics.fmean(values_sorted)
    median = statistics.median(values_sorted)
    p95_index = max(0, math.ceil(0.95 * count) - 1)
    p95 = values_sorted[p95_index]
    max_val = values_sorted[-1]
    return {
        "count": count,
        "mean": mean,
        "median": median,
        "p95": p95,
        "max": max_val,
    }


def build_origin_union(https_results: dict, hsts_results: dict) -> list[str]:
    origins = set()
    origins.update(https_results.keys())
    origins.update(hsts_results.keys())
    return sorted(origins)


def compute_https_connectivity_block(https_results: dict) -> dict:
    n_origins = len(https_results)
    n_https_success = 0
    n_https_error = 0
    n_https_non_https_final = 0

    status_family_counts_success = Counter()
    redirects_success = []

    for origin, row in https_results.items():
        success = bool(row.get("success"))
        status = row.get("status")
        final_scheme = row.get("final_scheme")
        redirects = row.get("redirects", 0)
        error = row.get("error", "")

        if success:
            n_https_success += 1
            if isinstance(status, int):
                if 200 <= status < 300:
                    status_family_counts_success["2xx"] += 1
                elif 300 <= status < 400:
                    status_family_counts_success["3xx"] += 1
                elif 400 <= status < 500:
                    status_family_counts_success["4xx"] += 1
                elif 500 <= status < 600:
                    status_family_counts_success["5xx"] += 1
            redirects_success.append(int(redirects))
        else:
            if error:
                n_https_error += 1
            elif final_scheme and final_scheme != "https":
                n_https_non_https_final += 1

    redirects_stats_success = describe_numeric(redirects_success)

    return {
        "n_origins": n_origins,
        "n_https_success": n_https_success,
        "n_https_error": n_https_error,
        "n_https_non_https_final": n_https_non_https_final,
        "status_family_counts_success": dict(status_family_counts_success),
        "redirects_stats_success": redirects_stats_success,
    }


def classify_http_to_https(hsts_results: dict) -> dict:
    """
    Compute high-level HTTP->HTTPS behaviour buckets.
    """
    n_http_probe_ok = 0
    n_http_redirect_to_https = 0
    n_http_redirect_not_to_https = 0
    n_http_no_redirect = 0
    n_http_probe_error = 0

    redirect_code_counts = Counter()

    for origin, row in hsts_results.items():
        status = row.get("redirect_status")
        redirected_to_https = bool(row.get("redirected_to_https"))

        if status is None:
            # No HTTP status recorded: treat as HTTP probe error
            n_http_probe_error += 1
            continue

        n_http_probe_ok += 1

        if 300 <= status < 400:
            redirect_code_counts[status] += 1
            if redirected_to_https:
                n_http_redirect_to_https += 1
            else:
                n_http_redirect_not_to_https += 1
        else:
            n_http_no_redirect += 1

    return {
        "n_http_probe_ok": n_http_probe_ok,
        "n_http_redirect_to_https": n_http_redirect_to_https,
        "n_http_redirect_not_to_https": n_http_redirect_not_to_https,
        "n_http_no_redirect": n_http_no_redirect,
        "n_http_probe_error": n_http_probe_error,
        "redirect_code_counts": dict(redirect_code_counts),
    }


def compute_hsts_block(hsts_results: dict) -> dict:
    """
    Summarise HSTS presence and quality among HTTPS-capable origins.
    """
    n_https_ok = 0
    n_has_hsts = 0
    n_hsts_maxage_1yr = 0
    n_hsts_include_subdomains = 0
    n_hsts_preload_flag = 0
    n_hsts_strong = 0

    for origin, row in hsts_results.items():
        https_ok = bool(row.get("https_ok"))
        if not https_ok:
            continue
        n_https_ok += 1

        has_hsts = bool(row.get("has_hsts"))
        if not has_hsts:
            continue

        n_has_hsts += 1

        max_age_ge_1yr = bool(row.get("max_age_ge_1yr"))
        include_subdomains = bool(row.get("include_subdomains"))
        preload_flag = bool(row.get("preload"))

        if max_age_ge_1yr:
            n_hsts_maxage_1yr += 1
        if include_subdomains:
            n_hsts_include_subdomains += 1
        if preload_flag:
            n_hsts_preload_flag += 1
        if max_age_ge_1yr and include_subdomains:
            n_hsts_strong += 1

    # Conditional fractions
    frac_has_hsts_among_https_ok = safe_pct(n_has_hsts, n_https_ok)
    frac_hsts_strong_among_hsts = safe_pct(n_hsts_strong, n_has_hsts)
    frac_preload_among_hsts = safe_pct(n_hsts_preload_flag, n_has_hsts)
    frac_maxage_1yr_among_hsts = safe_pct(n_hsts_maxage_1yr, n_has_hsts)
    frac_include_subdomains_among_hsts = safe_pct(
        n_hsts_include_subdomains, n_has_hsts
    )

    return {
        "n_https_ok": n_https_ok,
        "n_has_hsts": n_has_hsts,
        "n_hsts_maxage_1yr": n_hsts_maxage_1yr,
        "n_hsts_include_subdomains": n_hsts_include_subdomains,
        "n_hsts_preload_flag": n_hsts_preload_flag,
        "n_hsts_strong": n_hsts_strong,
        "fractions": {
            "pct_has_hsts_among_https_ok": frac_has_hsts_among_https_ok,
            "pct_hsts_strong_among_hsts": frac_hsts_strong_among_hsts,
            "pct_preload_among_hsts": frac_preload_among_hsts,
            "pct_maxage_1yr_among_hsts": frac_maxage_1yr_among_hsts,
            "pct_include_subdomains_among_hsts": frac_include_subdomains_among_hsts,
        },
    }


def compute_enforcement_counts(https_results: dict, hsts_results: dict) -> dict:
    """
    Compute counts for categories used in PNG #1, plus core aggregates.
    """
    origins = build_origin_union(https_results, hsts_results)

    count_https_unreachable = 0
    count_no_redirect = 0
    count_redirect_to_https = 0
    count_redirect_to_https_no_hsts = 0
    count_redirect_to_https_hsts_weak = 0
    count_redirect_to_https_hsts_strong = 0

    for origin in origins:
        https_row = https_results.get(origin)
        hsts_row = hsts_results.get(origin)

        # Does HTTPS work at all for this origin?
        https_works = False
        if https_row and https_row.get("success"):
            https_works = True
        elif hsts_row and hsts_row.get("https_ok"):
            https_works = True

        if not https_works:
            count_https_unreachable += 1

        # HTTP behaviour via HSTS module
        if hsts_row:
            status = hsts_row.get("redirect_status")
            redirected_to_https = bool(hsts_row.get("redirected_to_https"))
            has_hsts = bool(hsts_row.get("has_hsts"))
            max_age_ge_1yr = bool(hsts_row.get("max_age_ge_1yr"))
            include_subdomains = bool(hsts_row.get("include_subdomains"))
            https_ok = bool(hsts_row.get("https_ok"))

            if status is not None:
                # HTTP responded
                if 300 <= status < 400:
                    if redirected_to_https:
                        count_redirect_to_https += 1
                        if https_ok and not has_hsts:
                            count_redirect_to_https_no_hsts += 1
                        if https_ok and has_hsts:
                            if max_age_ge_1yr and include_subdomains:
                                count_redirect_to_https_hsts_strong += 1
                            else:
                                count_redirect_to_https_hsts_weak += 1
                    # non-HTTPS 3xx redirects do not affect the other counts
                else:
                    # HTTP returned a non-3xx status
                    count_no_redirect += 1

    return {
        "https_unreachable": count_https_unreachable,
        "no_redirect": count_no_redirect,
        "redirect_to_https": count_redirect_to_https,
        "redirect_to_https_no_hsts": count_redirect_to_https_no_hsts,
        "redirect_to_https_hsts_weak": count_redirect_to_https_hsts_weak,
        "redirect_to_https_hsts_strong": count_redirect_to_https_hsts_strong,
    }


# ---- Plotting helpers ----


def plot_enforcement_overview(counts: dict, out_path: Path) -> None:
    labels = [
        "https_unreachable",
        "no_redirect",
        "redirect_to_https",
        "redirect_to_https_no_hsts",
        "redirect_to_https_hsts_weak",
        "redirect_to_https_hsts_strong",
    ]
    values = [counts.get(label, 0) for label in labels]

    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=45, ha="right")
    plt.ylabel("Number of origins")
    plt.title("HTTPS enforcement overview")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_https_reachability(https_block: dict, out_path: Path) -> None:
    labels = ["https_success", "https_error", "https_non_https_final"]
    values = [
        https_block.get("n_https_success", 0),
        https_block.get("n_https_error", 0),
        https_block.get("n_https_non_https_final", 0),
    ]
    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins")
    plt.title("HTTPS reachability")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_http_to_https(http_block: dict, out_path: Path) -> None:
    labels = [
        "redirect_to_https",
        "redirect_3xx_other",
        "no_redirect",
        "http_probe_error",
    ]
    values = [
        http_block.get("n_http_redirect_to_https", 0),
        http_block.get("n_http_redirect_not_to_https", 0),
        http_block.get("n_http_no_redirect", 0),
        http_block.get("n_http_probe_error", 0),
    ]

    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins")
    plt.title("HTTP to HTTPS behaviour")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_hsts_flags_among_hsts(hsts_block: dict, out_path: Path) -> None:
    # Only consider sites with HSTS enabled
    n_has_hsts = hsts_block.get("n_has_hsts", 0)
    if n_has_hsts == 0:
        return

    labels = ["max_age_ge_1yr", "include_subdomains", "preload_flag"]
    values = [
        hsts_block.get("n_hsts_maxage_1yr", 0),
        hsts_block.get("n_hsts_include_subdomains", 0),
        hsts_block.get("n_hsts_preload_flag", 0),
    ]

    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins (HSTS-enabled)")
    plt.title("HSTS configuration flags (among HSTS-enabled sites)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_hsts_presence(hsts_block: dict, out_path: Path) -> None:
    n_https_ok = hsts_block.get("n_https_ok", 0)
    n_has_hsts = hsts_block.get("n_has_hsts", 0)
    n_hsts_strong = hsts_block.get("n_hsts_strong", 0)

    if n_https_ok == 0:
        return

    n_no_hsts = n_https_ok - n_has_hsts

    labels = ["no_hsts", "hsts_any", "hsts_strong"]
    values = [n_no_hsts, n_has_hsts, n_hsts_strong]

    plt.figure()
    x = range(len(labels))
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins (HTTPS working)")
    plt.title("HSTS presence and strength")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def build_metric_definitions() -> dict:
    """
    Mapping of metric paths to human-readable descriptions.
    This gets embedded in the JSON so you can paste into the paper later.
    """
    return {
        "https_connectivity.n_origins":
            "Number of origins that appeared in the https_connectivity module results.",
        "https_connectivity.n_https_success":
            "Number of origins where the https_connectivity module marked success=True "
            "and the final_scheme was HTTPS.",
        "https_connectivity.n_https_error":
            "Number of origins where HTTPS was attempted but the https_connectivity row "
            "contains a non-empty error string (timeout, client error, etc.) and success=False.",
        "https_connectivity.n_https_non_https_final":
            "Number of origins where HTTPS was attempted and no explicit error was recorded, "
            "but the final_scheme reported by https_connectivity was not 'https'.",
        "https_connectivity.status_family_counts_success":
            "For origins with HTTPS success, counts of HTTP status families (2xx, 3xx, 4xx, 5xx) "
            "based on the final status code in the https_connectivity results.",
        "https_connectivity.redirects_stats_success":
            "Descriptive statistics (count, mean, median, 95th percentile, max) of the number "
            "of redirects followed on the HTTPS path, computed only for origins where "
            "https_connectivity.success is True.",
        "http_to_https.n_http_probe_ok":
            "Number of origins for which the HSTS module recorded an HTTP status code when "
            "probing http://origin/ (i.e., the HTTP probe returned some response).",
        "http_to_https.n_http_redirect_to_https":
            "Number of origins where the HTTP probe status was 3xx and the HSTS module marked "
            "redirected_to_https=True (Location header pointed to an HTTPS URL).",
        "http_to_https.n_http_redirect_not_to_https":
            "Number of origins where the HTTP probe status was 3xx but redirected_to_https=False, "
            "indicating a redirect that did not target HTTPS.",
        "http_to_https.n_http_no_redirect":
            "Number of origins where the HTTP probe succeeded but the status code was not in the "
            "3xx range, meaning the site served a non-redirect response over HTTP.",
        "http_to_https.n_http_probe_error":
            "Number of origins where the HSTS module did not record any HTTP status code for the "
            "HTTP probe (redirect_status is None), typically because the origin was offline or "
            "the HTTP request errored or timed out before a response.",
        "http_to_https.redirect_code_counts":
            "Histogram of concrete 3xx status codes (e.g., 301, 302, 307, 308) returned by the "
            "HTTP probe when redirect_status was in the 3xx range.",
        "hsts.n_https_ok":
            "Number of origins where the HSTS module successfully completed the follow-up HTTPS "
            "request and recorded https_ok=True (final status in the 200–599 range).",
        "hsts.n_has_hsts":
            "Number of origins with https_ok=True whose HTTPS response included a Strict-Transport-Security header.",
        "hsts.n_hsts_maxage_1yr":
            "Number of HSTS-enabled origins (has_hsts=True) where the parsed max-age directive "
            "was at least 31,536,000 seconds (one year).",
        "hsts.n_hsts_include_subdomains":
            "Number of HSTS-enabled origins (has_hsts=True) whose HSTS header included the "
            "includeSubDomains directive.",
        "hsts.n_hsts_preload_flag":
            "Number of HSTS-enabled origins (has_hsts=True) whose HSTS header included the "
            "preload directive. Note that this only checks the header flag, not actual presence "
            "on the browser preload list.",
        "hsts.n_hsts_strong":
            "Number of HSTS-enabled origins (has_hsts=True) that simultaneously configured "
            "max-age >= 1 year and includeSubDomains=True (our definition of 'strong HSTS').",
        "hsts.fractions.pct_has_hsts_among_https_ok":
            "Percentage of HTTPS-working origins (n_https_ok) that set any HSTS header.",
        "hsts.fractions.pct_hsts_strong_among_hsts":
            "Percentage of HSTS-enabled origins that meet the 'strong HSTS' criteria "
            "(max-age >= 1 year and includeSubDomains).",
        "hsts.fractions.pct_preload_among_hsts":
            "Percentage of HSTS-enabled origins whose HSTS header contains the preload directive.",
        "hsts.fractions.pct_maxage_1yr_among_hsts":
            "Percentage of HSTS-enabled origins that configured max-age >= 1 year.",
        "hsts.fractions.pct_include_subdomains_among_hsts":
            "Percentage of HSTS-enabled origins whose HSTS header includes the includeSubDomains directive.",
        "enforcement_counts.https_unreachable":
            "Number of origins for which neither the https_connectivity module nor the HSTS module "
            "reported a successful HTTPS response (https_connectivity.success is False and "
            "HSTS.https_ok is False or missing). These are effectively HTTPS-unreachable for our scanner.",
        "enforcement_counts.no_redirect":
            "Number of origins where the HSTS HTTP probe recorded a non-3xx status code for "
            "http://origin/ (redirect_status not in the 300–399 range), meaning that HTTP was served "
            "without an HTTP->HTTPS redirect.",
        "enforcement_counts.redirect_to_https":
            "Number of origins where the HSTS HTTP probe recorded a 3xx status code and "
            "redirected_to_https=True, meaning that http://origin/ redirected directly to an HTTPS URL.",
        "enforcement_counts.redirect_to_https_no_hsts":
            "Number of origins where http://origin/ redirected to HTTPS (redirected_to_https=True), "
            "the HSTS module marked https_ok=True, but the HTTPS response did not include any "
            "Strict-Transport-Security header (has_hsts=False).",
        "enforcement_counts.redirect_to_https_hsts_weak":
            "Number of origins where http://origin/ redirected to HTTPS and the HTTPS response "
            "included HSTS (has_hsts=True), but the configuration did not meet the 'strong HSTS' "
            "definition (i.e., max-age < 1 year or includeSubDomains=False).",
        "enforcement_counts.redirect_to_https_hsts_strong":
            "Number of origins where http://origin/ redirected to HTTPS and the HTTPS response "
            "included 'strong HSTS' (has_hsts=True, max-age >= 1 year, includeSubDomains=True).",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarise HTTPS enforcement and HSTS stats from a scan results JSON."
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
        help="Directory where https_hsts_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)
    modules = results.get("modules", {})

    https_results = modules.get("https_connectivity", {})
    hsts_results = modules.get("hsts", {})

    https_block = compute_https_connectivity_block(https_results)
    http_block = classify_http_to_https(hsts_results)
    hsts_block = compute_hsts_block(hsts_results)
    enforcement_counts = compute_enforcement_counts(https_results, hsts_results)

    # Generate plots
    plot_enforcement_overview(
        enforcement_counts, out_dir / "https_enforcement_overview.png"
    )
    plot_https_reachability(https_block, out_dir / "https_reachability.png")
    plot_http_to_https(http_block, out_dir / "http_to_https_behaviour.png")
    plot_hsts_flags_among_hsts(hsts_block, out_dir / "hsts_flags_among_hsts_sites.png")
    plot_hsts_presence(hsts_block, out_dir / "hsts_presence_and_strength.png")

    summary = {
        "https_connectivity": https_block,
        "http_to_https": http_block,
        "hsts": hsts_block,
        "enforcement_counts": enforcement_counts,
        "metric_definitions": build_metric_definitions(),
    }

    summary_path = out_dir / "https_hsts_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote HTTPS/HSTS summary to {summary_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

    #!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from collections import Counter

import matplotlib.pyplot as plt

HeaderRating = str

SECURITY_RULES = [
    "referrer_policy",
    "csp_frame_ancestors",
    "x_frame_options",
    "x_content_type_options",
    "permissions_policy",
]

COOKIE_RULE = "cookies"

TOP_N_REVEALING = 20

def load_results(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den == 0:
        return 0.0
    return 100.0 * num / den


def summarise_headers(results: dict) -> dict:
    modules = results.get("modules", {})
    header_module = modules.get("headers", {}) or {}

    n_sites = len(header_module)

    baseline_enabled_counts = Counter()
    baseline_all_enabled = 0

    posture_counts = Counter()

    security_rating_counts: dict[str, Counter] = {
        name: Counter() for name in SECURITY_RULES
    }
    security_presence_counts: Counter[str] = Counter()

    cookie_rating_counts: Counter[str] = Counter()
    cookie_flag_counts: Counter[str] = Counter()
    n_sites_with_cookies = 0

    revealing_presence_counts: Counter[str] = Counter()
    revealing_count_distribution: Counter[str] = Counter()
    n_sites_with_any_revealing = 0

    for url, results_list in header_module.items():
        security_results: dict[str, dict] = {}
        cookie_result = None
        revealing_results = []

        for r in results_list:
            name = r.get("name")
            category = r.get("category", "security")
            if category == "revealing":
                revealing_results.append(r)
            else:
                if name == COOKIE_RULE:
                    cookie_result = r
                else:
                    security_results[name] = r

        enabled_count = 0
        insecure_or_obsolete = False

        for rule in SECURITY_RULES:
            r = security_results.get(rule)
            if not r:
                continue
            rating: HeaderRating = r.get("rating", "unknown")
            present = bool(r.get("present", False))

            security_rating_counts[rule][rating] += 1
            if present:
                security_presence_counts[rule] += 1

            # Treat both "recommended" and "sufficient" as "enabled" for baseline
            if rating in ("recommended", "sufficient"):
                enabled_count += 1
            if rating in ("insecure", "obsolete"):
                insecure_or_obsolete = True

        baseline_enabled_counts[enabled_count] += 1
        if enabled_count == len(SECURITY_RULES):
            baseline_all_enabled += 1

        if enabled_count == 0:
            posture = "weak"
        elif enabled_count >= 3 and not insecure_or_obsolete:
            posture = "strong"
        else:
            posture = "mixed"
        posture_counts[posture] += 1

        if cookie_result and cookie_result.get("present", False):
            n_sites_with_cookies += 1
            rating = cookie_result.get("rating", "unknown")
            cookie_rating_counts[rating] += 1

            extra = cookie_result.get("additional_fields") or {}
            if extra.get("has_secure"):
                cookie_flag_counts["secure"] += 1
            if extra.get("has_httponly"):
                cookie_flag_counts["httponly"] += 1

            samesite = (extra.get("samesite") or "").strip().lower()
            if samesite == "strict":
                cookie_flag_counts["samesite_strict"] += 1
            elif samesite == "lax":
                cookie_flag_counts["samesite_lax"] += 1
            elif samesite == "none":
                cookie_flag_counts["samesite_none"] += 1
            else:
                cookie_flag_counts["samesite_missing_or_other"] += 1

            if extra.get("has_max_age") or extra.get("has_expires"):
                cookie_flag_counts["has_lifetime"] += 1

        present_revealing = 0
        for r in revealing_results:
            display_name = r.get("name")
            if r.get("present", False):
                present_revealing += 1
                revealing_presence_counts[display_name] += 1

        if present_revealing == 0:
            revealing_count_distribution["0"] += 1
        elif present_revealing == 1:
            revealing_count_distribution["1"] += 1
        elif present_revealing == 2:
            revealing_count_distribution["2"] += 1
        else:
            revealing_count_distribution["3+"] += 1

        if present_revealing > 0:
            n_sites_with_any_revealing += 1

    baseline_histogram = {
        "0": baseline_enabled_counts.get(0, 0),
        "1-2": sum(baseline_enabled_counts[k] for k in (1, 2)),
        "3-4": sum(baseline_enabled_counts[k] for k in (3, 4)),
        "5_all": baseline_enabled_counts.get(len(SECURITY_RULES), 0),
    }

    security_rules_summary = {}
    for rule in SECURITY_RULES:
        ratings = security_rating_counts[rule]
        security_rules_summary[rule] = {
            "ratings": dict(ratings),
            "n_present": security_presence_counts.get(rule, 0),
        }

    top_revealing = sorted(
        revealing_presence_counts.items(),
        key=lambda kv: kv[1],
        reverse=True,
    )[:TOP_N_REVEALING]

    summary = {
        "meta": {
            "n_sites": n_sites,
        },
        "baseline_overview": {
            "security_rules": SECURITY_RULES,
            "baseline_enabled_histogram": baseline_histogram,
            "n_sites_with_any_baseline": n_sites - baseline_enabled_counts.get(0, 0),
            "pct_sites_with_any_baseline": safe_pct(
                n_sites - baseline_enabled_counts.get(0, 0), n_sites
            ),
            "n_sites_with_all_baseline": baseline_all_enabled,
            "pct_sites_with_all_baseline": safe_pct(
                baseline_all_enabled, n_sites
            ),
            "posture_counts": dict(posture_counts),
        },
        "security_rules": security_rules_summary,
        "cookies": {
            "n_sites_with_cookies": n_sites_with_cookies,
            "pct_sites_with_cookies": safe_pct(n_sites_with_cookies, n_sites),
            "rating_counts": dict(cookie_rating_counts),
            "flag_counts": dict(cookie_flag_counts),
        },
        "revealing_headers": {
            "n_sites_with_any_revealing": n_sites_with_any_revealing,
            "pct_sites_with_any_revealing": safe_pct(
                n_sites_with_any_revealing, n_sites
            ),
            "presence_counts": dict(revealing_presence_counts),
            "count_distribution": dict(revealing_count_distribution),
            "top_revealing": top_revealing,
        },
    }

    return summary

def plot_baseline_histogram(summary: dict, out_path: Path) -> None:
    hist = summary["baseline_overview"]["baseline_enabled_histogram"]
    labels = ["0", "1-2", "3-4", "5_all"]
    values = [hist.get(k, 0) for k in labels]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, ["0", "1–2", "3–4", "5 (all)"])
    plt.ylabel("Number of sites")
    plt.title("Number of baseline security headers enabled per site")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_posture_buckets(summary: dict, out_path: Path) -> None:
    posture = summary["baseline_overview"]["posture_counts"]
    labels = ["strong", "mixed", "weak"]
    values = [posture.get(k, 0) for k in labels]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of sites")
    plt.title("Overall security-header posture per site")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_security_rule_ratings(summary: dict, out_path: Path) -> None:
    rules = summary["security_rules"]
    ratings_order = ["recommended", "sufficient", "insecure", "obsolete", "unknown"]
    labels = SECURITY_RULES
    x = range(len(labels))

    bottom = [0] * len(labels)
    plt.figure()
    for rating in ratings_order:
        values = [rules[name]["ratings"].get(rating, 0) for name in labels]
        plt.bar(x, values, bottom=bottom, label=rating)
        bottom = [bottom[i] + values[i] for i in range(len(values))]

    plt.xticks(x, labels, rotation=30, ha="right")
    plt.ylabel("Number of sites")
    plt.title("Rating outcomes for core security headers")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_security_header_presence(summary: dict, out_path: Path) -> None:
    rules = summary["security_rules"]
    labels = SECURITY_RULES
    values = [rules[name]["n_present"] for name in labels]
    y = range(len(labels))
    plt.figure()
    plt.barh(y, values)
    plt.yticks(y, labels)
    plt.xlabel("Number of sites")
    plt.title("Sites that explicitly send each core security header")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_revealing_any(summary: dict, out_path: Path) -> None:
    rev = summary["revealing_headers"]
    n_sites = summary["meta"]["n_sites"]
    with_any = rev["n_sites_with_any_revealing"]
    without = n_sites - with_any
    labels = ["At least one revealing header", "No revealing headers"]
    values = [with_any, without]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=20, ha="right")
    plt.ylabel("Number of sites")
    plt.title("Sites exposing OWASP 'revealing' headers")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_revealing_top(summary: dict, out_path: Path) -> None:
    top = summary["revealing_headers"]["top_revealing"]
    if not top:
        return
    labels = [name for name, _ in top]
    values = [count for _, count in top]
    y = range(len(labels))
    plt.figure()
    plt.barh(y, values)
    plt.yticks(y, labels)
    plt.xlabel("Number of sites")
    plt.title("Most common revealing headers")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_revealing_distribution(summary: dict, out_path: Path) -> None:
    dist = summary["revealing_headers"]["count_distribution"]
    labels = ["0", "1", "2", "3+"]
    values = [dist.get(k, 0) for k in labels]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of sites")
    plt.title("Number of different revealing headers per site")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_cookie_flags(summary: dict, out_path: Path) -> None:
    cookies = summary["cookies"]
    flag_counts = cookies["flag_counts"]
    labels = [
        "secure",
        "httponly",
        "samesite_strict",
        "samesite_lax",
        "samesite_none",
        "samesite_missing_or_other",
        "has_lifetime",
    ]
    values = [flag_counts.get(k, 0) for k in labels]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=30, ha="right")
    plt.ylabel("Number of cookie-setting sites")
    plt.title("Cookie flags observed on sample Set-Cookie headers")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_cookie_ratings(summary: dict, out_path: Path) -> None:
    cookies = summary["cookies"]
    rating_counts = cookies["rating_counts"]
    ratings_order = ["recommended", "sufficient", "insecure", "obsolete", "unknown"]
    labels = ratings_order
    values = [rating_counts.get(k, 0) for k in ratings_order]
    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of cookie-setting sites")
    plt.title("Classifier outcomes for sample Set-Cookie headers")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def build_metric_definitions() -> dict:
    return {
        "meta.n_sites":
            "Number of input URLs for which the headers module produced results. "
            "Each entry corresponds to one final HTTP response after redirects.",

        "baseline_overview.security_rules":
            "List of core browser-side security header rules considered in the baseline: "
            "referrer policy, CSP frame-ancestors, X-Frame-Options, X-Content-Type-Options, "
            "and Permissions-Policy. Cookies are handled separately.",

        "baseline_overview.baseline_enabled_histogram":
            "Histogram of how many core security headers each site enabled with a rating of "
            "either 'recommended' or 'sufficient'. Bucket '0' counts sites with no such headers; "
            "'1-2' counts sites with one or two; '3-4' counts sites with three or four; "
            "'5_all' counts sites where all five baseline headers were rated 'recommended' or 'sufficient'.",

        "baseline_overview.n_sites_with_any_baseline":
            "Number of sites that enabled at least one core security header with rating "
            "'recommended' or 'sufficient' (i.e., not in the 0 bucket).",

        "baseline_overview.pct_sites_with_any_baseline":
            "Percentage of sites that enabled at least one core security header with rating "
            "'recommended' or 'sufficient'.",

        "baseline_overview.n_sites_with_all_baseline":
            "Number of sites where all five baseline headers were classified as either "
            "'recommended' or 'sufficient'.",

        "baseline_overview.pct_sites_with_all_baseline":
            "Percentage of sites where all five baseline headers were classified as either "
            "'recommended' or 'sufficient'.",

        "baseline_overview.posture_counts":
            "Counts of sites in each coarse-grained posture bucket: "
            "'strong' = three or more baseline headers rated recommended/sufficient and none rated insecure/obsolete; "
            "'mixed' = at least one baseline header enabled but some headers rated insecure/obsolete; "
            "'weak' = no baseline headers rated recommended/sufficient.",

        "security_rules":
            "For each core security rule, an object containing a ratings histogram and the number of "
            "sites that explicitly sent that header.",

        "security_rules.<rule>.ratings":
            "For a given rule (e.g., 'referrer_policy', 'x_content_type_options'), counts of sites whose "
            "final response was classified with that rating: 'recommended', 'sufficient', 'insecure', "
            "'obsolete', or 'unknown'. Ratings are computed by the per-header classifier in headers.py.",

        "security_rules.<rule>.n_present":
            "Number of sites where the corresponding header name was explicitly present in the HTTP response "
            "(present=True). Missing headers still have a rating via on_missing_class, but are not counted here.",

        "cookies.n_sites_with_cookies":
            "Number of sites where at least one Set-Cookie header was seen on the final response "
            "(present=True for the 'cookies' rule).",

        "cookies.pct_sites_with_cookies":
            "Percentage of sites that set at least one cookie, relative to meta.n_sites.",

        "cookies.rating_counts":
            "Counts of cookie-setting sites for each classifier outcome on the sample Set-Cookie header: "
            "'recommended' (Secure+HttpOnly+SameSite=Strict), 'sufficient' (Secure+HttpOnly+SameSite=Lax), "
            "or 'insecure'/other.",

        "cookies.flag_counts":
            "For cookie-setting sites only, counts of how many sites had each attribute flagged on the sample "
            "Set-Cookie header: 'secure', 'httponly', 'samesite_strict', 'samesite_lax', 'samesite_none', "
            "'samesite_missing_or_other', and 'has_lifetime' (true if either Max-Age or Expires was present).",

        "revealing_headers.n_sites_with_any_revealing":
            "Number of sites where at least one OWASP 'revealing' header (for example, Server, X-Powered-By, "
            "X-Generator) was present in the final response.",

        "revealing_headers.pct_sites_with_any_revealing":
            "Percentage of sites where at least one revealing header was present, relative to meta.n_sites.",

        "revealing_headers.presence_counts":
            "For each revealing header display name (for example, 'server', 'x_powered_by'), the number of sites "
            "whose final response included that header.",

        "revealing_headers.count_distribution":
            "Distribution over sites of the number of distinct revealing headers that were present at all. "
            "Bucket '0' counts sites with none of these headers; '1' with exactly one; '2' with two; '3+' with three or more.",

        "revealing_headers.top_revealing":
            "List of the TOP_N_REVEALING most common revealing headers, represented as [header_name, site_count] "
            "pairs. This is used to identify which banners (for example, Server or X-Powered-By) appear most frequently.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarise security and revealing headers from the headers module."
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
        help="Directory where headers_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)
    summary = summarise_headers(results)
    summary["metric_definitions"] = build_metric_definitions()

    plot_baseline_histogram(summary, out_dir / "headers_baseline_coverage.png")
    plot_posture_buckets(summary, out_dir / "headers_posture_bucket.png")
    plot_security_rule_ratings(summary, out_dir / "headers_security_rule_ratings.png")
    plot_security_header_presence(summary, out_dir / "headers_security_header_presence.png")
    plot_revealing_any(summary, out_dir / "headers_revealing_any.png")
    plot_revealing_top(summary, out_dir / "headers_revealing_topN.png")
    plot_revealing_distribution(
        summary, out_dir / "headers_revealing_count_distribution.png"
    )
    plot_cookie_flags(summary, out_dir / "headers_cookies_flags.png")
    plot_cookie_ratings(summary, out_dir / "headers_cookies_ratings.png")

    out_path = out_dir / "headers_summary.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote headers summary to {out_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

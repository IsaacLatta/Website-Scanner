#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from collections import Counter, defaultdict
import statistics
import math

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


def classify_resolution(res: dict) -> str:
    """
    Classify a single resolution outcome for high-level stats.

    Categories:
      - ok_final_2xx / 3xx / 4xx_non_block / 5xx
      - blocked_403_503
      - redirect_error (max hops / loop)
      - timeout_error
      - other_error
    """
    error = res.get("error")
    entry_status = res.get("entry_status")
    final_status = res.get("final_status")

    has_block_status = False
    for status in (entry_status, final_status):
        if status in (403, 503):
            has_block_status = True
            break

    if error:
        if error == "timeout":
            return "timeout_error"
        if error in ("max_hops_exceeded", "redirect_loop"):
            return "redirect_error"
        return "other_error"

    if has_block_status:
        return "blocked_403_503"

    if final_status is None:
        return "other_error"

    if 200 <= final_status < 300:
        return "ok_final_2xx"
    if 300 <= final_status < 400:
        return "ok_final_3xx"
    if 400 <= final_status < 500:
        # we already excluded 403 above
        return "ok_final_4xx_non_block"
    if 500 <= final_status < 600:
        return "ok_final_5xx"
    return "other_error"


def compute_inputs_block(results: dict) -> dict:
    scan_targets = results.get("scan_targets", {})
    origin_targets = results.get("origin_targets", {})

    input_uris = scan_targets.get("uris", [])
    input_origins = scan_targets.get("origins", [])
    entry_origins = origin_targets.get("entry_origins", [])
    final_origins = origin_targets.get("final_origins", [])
    all_origins = origin_targets.get("all_origins", [])

    origin_to_uri_count = Counter()
    resolutions = results.get("resolutions", {})
    for url, res in resolutions.items():
        entry_origin = res.get("entry_origin")
        if entry_origin:
            origin_to_uri_count[entry_origin] += 1

    uris_per_origin_stats = describe_numeric(list(origin_to_uri_count.values()))

    n_final_only = len(set(final_origins) - set(entry_origins))

    return {
        "n_input_uris": len(input_uris),
        "n_input_origins": len(input_origins),
        "n_entry_origins": len(entry_origins),
        "n_final_origins": len(final_origins),
        "n_all_origins": len(all_origins),
        "uris_per_entry_origin": uris_per_origin_stats,
        "n_final_only_origins": n_final_only,
    }


def compute_redirect_block(results: dict, out_dir: Path) -> dict:
    resolutions = results.get("resolutions", {})
    n_resolutions = len(resolutions)

    hop_counts_all_success = []
    hop_counts_success_non_block = []

    outcome_counter = Counter()
    entry_status_counter = Counter()
    final_status_counter = Counter()

    url_outcomes = {}

    for url, res in resolutions.items():
        hops = res.get("hops") or []
        entry_status = res.get("entry_status")
        final_status = res.get("final_status")

        if entry_status is not None:
            entry_status_counter[entry_status] += 1
        if final_status is not None:
            final_status_counter[final_status] += 1

        outcome = classify_resolution(res)
        outcome_counter[outcome] += 1
        url_outcomes[url] = outcome

        error = res.get("error")
        has_block_status = any(
            status in (403, 503) for status in (entry_status, final_status)
        )

        has_final = res.get("final_url") is not None
        if error is None and has_final:
            hop_count = len(hops)
            hop_counts_all_success.append(hop_count)
            if not has_block_status:
                hop_counts_success_non_block.append(hop_count)

    hop_stats_all = describe_numeric(hop_counts_all_success)
    hop_stats_non_block = describe_numeric(hop_counts_success_non_block)

    def bucket_hops(values):
        buckets = Counter()
        for h in values:
            if h == 0:
                buckets["0"] += 1
            elif h == 1:
                buckets["1"] += 1
            elif h == 2:
                buckets["2"] += 1
            else:
                buckets["3_plus"] += 1
        return dict(buckets)

    hop_buckets_all = bucket_hops(hop_counts_all_success)
    hop_buckets_non_block = bucket_hops(hop_counts_success_non_block)

    if hop_counts_all_success:
        plt.figure()
        plt.hist(
            hop_counts_all_success,
            bins=range(0, max(hop_counts_all_success) + 2),
        )
        plt.xlabel("Redirect hop count")
        plt.ylabel("Number of input URLs")
        plt.title("Redirect hop distribution (all successful resolutions)")
        plt.tight_layout()
        plt.savefig(out_dir / "hop_distribution_all_success.png")
        plt.close()

    if hop_counts_success_non_block:
        plt.figure()
        plt.hist(
            hop_counts_success_non_block,
            bins=range(0, max(hop_counts_success_non_block) + 2),
        )
        plt.xlabel("Redirect hop count")
        plt.ylabel("Number of input URLs")
        plt.title("Redirect hop distribution (successful, non-403/503)")
        plt.tight_layout()
        plt.savefig(out_dir / "hop_distribution_non_block.png")
        plt.close()

    if outcome_counter:
        plt.figure()
        labels = list(outcome_counter.keys())
        counts = [outcome_counter[label] for label in labels]
        plt.bar(labels, counts)
        plt.xticks(rotation=45, ha="right")
        plt.ylabel("Number of input URLs")
        plt.title("Resolution outcomes")
        plt.tight_layout()
        plt.savefig(out_dir / "resolution_outcomes.png")
        plt.close()

    def plot_status_counter(counter: Counter, title: str, filename: str):
        if not counter:
            return
        plt.figure()
        codes = sorted(counter.keys())
        counts = [counter[c] for c in codes]
        plt.bar([str(c) for c in codes], counts)
        plt.xlabel("HTTP status code")
        plt.ylabel("Number of input URLs")
        plt.title(title)
        plt.tight_layout()
        plt.savefig(out_dir / filename)
        plt.close()

    plot_status_counter(
        entry_status_counter,
        "Entry status distribution",
        "entry_status_distribution.png",
    )
    plot_status_counter(
        final_status_counter,
        "Final status distribution",
        "final_status_distribution.png",
    )

    n_blocked = outcome_counter.get("blocked_403_503", 0)
    n_timeout_err = outcome_counter.get("timeout_error", 0)

    blocked_fraction = safe_pct(n_blocked, n_resolutions)
    timeout_fraction = safe_pct(n_timeout_err, n_resolutions)

    def family_buckets(counter: Counter):
        fam = Counter()
        for code, count in counter.items():
            if 200 <= code < 300:
                fam["2xx"] += count
            elif 300 <= code < 400:
                fam["3xx"] += count
            elif 400 <= code < 500:
                fam["4xx"] += count
            elif 500 <= code < 600:
                fam["5xx"] += count
        return dict(fam)

    entry_families = family_buckets(entry_status_counter)
    final_families = family_buckets(final_status_counter)

    return {
        "n_resolutions": n_resolutions,
        "hop_counts_all_success": hop_stats_all,
        "hop_counts_success_non_block": hop_stats_non_block,
        "hop_buckets_all_success": hop_buckets_all,
        "hop_buckets_success_non_block": hop_buckets_non_block,
        "outcome_counts": dict(outcome_counter),
        "n_blocked_403_503": n_blocked,
        "blocked_403_503_fraction": blocked_fraction,
        "n_timeout_error": n_timeout_err,
        "timeout_error_fraction": timeout_fraction,
        "entry_status_counts": dict(entry_status_counter),
        "final_status_counts": dict(final_status_counter),
        "entry_status_family_counts": entry_families,
        "final_status_family_counts": final_families,
        "url_outcomes": url_outcomes,
    }


def compute_origin_health_block(results: dict, url_outcomes: dict, out_dir: Path) -> dict:
    origin_health = results.get("origin_health", {})
    resolutions = results.get("resolutions", {})

    origin_to_urls = defaultdict(list)
    for url, res in resolutions.items():
        origin = res.get("entry_origin")
        if origin:
            origin_to_urls[origin].append(url)

    unreachable_labels = {
        "blocked_403_503",
        "timeout_error",
        "redirect_error",
        "other_error",
    }

    n_origins = len(origin_health) if origin_health else len(origin_to_urls)

    origins_all_unreachable = []
    for origin, urls in origin_to_urls.items():
        if not urls:
            continue
        if all(url_outcomes.get(u) in unreachable_labels for u in urls):
            origins_all_unreachable.append(origin)

    http_forbidden_count = 0
    http_dead_count = 0
    tls_dead_count = 0
    any_timeout_count = 0

    http_timeout_values = []
    tls_timeout_values = []

    http_statuses_for_forbidden = Counter()

    for key, h in origin_health.items():
        http_forbidden = h.get("http_forbidden", False)
        http_timeout_count = h.get("http_timeout_count", 0)
        tls_timeout_count = h.get("tls_timeout_count", 0)
        http_statuses = h.get("http_statuses") or []

        if http_forbidden:
            http_forbidden_count += 1
            for code in http_statuses:
                if code in (403, 503):
                    http_statuses_for_forbidden[code] += 1
                else:
                    http_statuses_for_forbidden["other"] += 1

        if http_timeout_count >= 3:
            http_dead_count += 1
        if tls_timeout_count >= 2:
            tls_dead_count += 1
        if http_timeout_count > 0 or tls_timeout_count > 0:
            any_timeout_count += 1

        http_timeout_values.append(http_timeout_count)
        tls_timeout_values.append(tls_timeout_count)

    http_timeout_buckets = Counter()
    for v in http_timeout_values:
        if v == 0:
            http_timeout_buckets["0"] += 1
        elif v == 1:
            http_timeout_buckets["1"] += 1
        elif v == 2:
            http_timeout_buckets["2"] += 1
        else:
            http_timeout_buckets["3_plus"] += 1

    tls_timeout_buckets = Counter()
    for v in tls_timeout_values:
        if v == 0:
            tls_timeout_buckets["0"] += 1
        elif v == 1:
            tls_timeout_buckets["1"] += 1
        else:
            tls_timeout_buckets["2_plus"] += 1

    if http_timeout_buckets:
        plt.figure()
        labels = ["0", "1", "2", "3_plus"]
        counts = [http_timeout_buckets.get(l, 0) for l in labels]
        plt.bar(labels, counts)
        plt.xlabel("HTTP timeout count bucket")
        plt.ylabel("Number of origins")
        plt.title("HTTP timeout counts per origin")
        plt.tight_layout()
        plt.savefig(out_dir / "origin_http_timeout_buckets.png")
        plt.close()

    if tls_timeout_buckets:
        plt.figure()
        labels = ["0", "1", "2_plus"]
        counts = [tls_timeout_buckets.get(l, 0) for l in labels]
        plt.bar(labels, counts)
        plt.xlabel("TLS timeout count bucket")
        plt.ylabel("Number of origins")
        plt.title("TLS timeout counts per origin")
        plt.tight_layout()
        plt.savefig(out_dir / "origin_tls_timeout_buckets.png")
        plt.close()

    if http_statuses_for_forbidden:
        plt.figure()
        labels = list(http_statuses_for_forbidden.keys())   # [403, 503, "other"]
        counts = [http_statuses_for_forbidden[l] for l in labels]
        x = range(len(labels))
        plt.bar(x, counts)
        plt.xticks(x, [str(l) for l in labels])
        plt.xlabel("HTTP status code for forbidden origins")
        plt.ylabel("Number of origins")
        plt.title("HTTP block statuses recorded for origins")
        plt.tight_layout()
        plt.savefig(out_dir / "origin_http_forbidden_statuses.png")
        plt.close()

    return {
        "n_origins": n_origins,
        "n_origins_all_inputs_unreachable": len(origins_all_unreachable),
        "origins_all_inputs_unreachable": origins_all_unreachable,
        "n_origins_http_forbidden": http_forbidden_count,
        "n_origins_http_dead": http_dead_count,
        "n_origins_tls_dead": tls_dead_count,
        "n_origins_any_timeout": any_timeout_count,
        "http_timeout_buckets": dict(http_timeout_buckets),
        "tls_timeout_buckets": dict(tls_timeout_buckets),
        "http_statuses_for_forbidden": dict(http_statuses_for_forbidden),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Summarise redirect/origin health stats from a scan results JSON."
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
        help="Directory where redirect_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)

    inputs_block = compute_inputs_block(results)
    redirect_block = compute_redirect_block(results, out_dir)
    origin_block = compute_origin_health_block(
        results, redirect_block["url_outcomes"], out_dir
    )

    # Remove url_outcomes from redirect_block before writing summary, to keep it compact
    redirect_block_compact = dict(redirect_block)
    redirect_block_compact.pop("url_outcomes", None)

    summary = {
        "inputs": inputs_block,
        "redirects": redirect_block_compact,
        "origin_health": origin_block,
    }

    summary_path = out_dir / "redirect_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote redirect summary to {summary_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

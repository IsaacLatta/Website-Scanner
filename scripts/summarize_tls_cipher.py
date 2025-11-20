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

def compute_tls_block(tls_results: dict) -> dict:
    n_origins = len(tls_results)
    n_origin_offline_tls = 0

    support_counts = {
        "tls1_3": 0,
        "tls1_2": 0,
        "tls1_1": 0,
        "tls1_0": 0,
        "sslv3": 0,
    }
    tested_counts = {
        "tls1_3": 0,
        "tls1_2": 0,
        "tls1_1": 0,
        "tls1_0": 0,
        "sslv3": 0,
    }

    n_any_modern_tls = 0
    n_any_legacy_tls = 0
    n_modern_no_legacy = 0

    for origin, row in tls_results.items():
        err = row.get("error", "") or ""
        if "origin offline" in err:
            n_origin_offline_tls += 1

        t13 = row.get("tls13")
        t12 = row.get("tls12")
        t11 = row.get("tls11")
        t10 = row.get("tls10")
        ssl_legacy = row.get("ssl_legacy")

        # Per-version counts
        if t13 is not None:
            tested_counts["tls1_3"] += 1
            if t13:
                support_counts["tls1_3"] += 1
        if t12 is not None:
            tested_counts["tls1_2"] += 1
            if t12:
                support_counts["tls1_2"] += 1
        if t11 is not None:
            tested_counts["tls1_1"] += 1
            if t11:
                support_counts["tls1_1"] += 1
        if t10 is not None:
            tested_counts["tls1_0"] += 1
            if t10:
                support_counts["tls1_0"] += 1
        if ssl_legacy is not None:
            tested_counts["sslv3"] += 1
            if ssl_legacy:
                support_counts["sslv3"] += 1

        any_modern = bool(t13) or bool(t12)
        any_legacy = bool(t11) or bool(t10) or bool(ssl_legacy)
        if any_modern:
            n_any_modern_tls += 1
        if any_legacy:
            n_any_legacy_tls += 1
        if any_modern and not any_legacy:
            n_modern_no_legacy += 1

    return {
        "n_origins": n_origins,
        "n_origin_offline_tls": n_origin_offline_tls,
        "support_counts": support_counts,
        "tested_counts": tested_counts,
        "n_any_modern_tls": n_any_modern_tls,
        "n_any_legacy_tls": n_any_legacy_tls,
        "n_modern_no_legacy": n_modern_no_legacy,
    }


def compute_negotiated_versions(cipher_results: dict) -> dict:
    version_counts = Counter()
    n_with_version = 0

    for origin, row in cipher_results.items():
        ver = (row.get("negotiated_version") or "").strip()
        if not ver:
            continue
        n_with_version += 1
        if ver in ("TLSv1.3", "TLSv1.2"):
            version_counts[ver] += 1
        else:
            version_counts["other"] += 1

    return {
        "n_with_version": n_with_version,
        "version_counts": dict(version_counts),
    }


def compute_tls13_cipher_categories(cipher_results: dict) -> dict:
    category_counts = Counter()
    n_tls13_forced_attempted = 0

    for origin, row in cipher_results.items():
        cipher = row.get("tls13_forced_cipher")
        category = row.get("tls13_forced_category")
        if cipher is None:
            continue
        n_tls13_forced_attempted += 1
        cat = category or "unknown"
        category_counts[cat] += 1

    return {
        "n_tls13_forced_attempted": n_tls13_forced_attempted,
        "category_counts": dict(category_counts),
    }


def compute_tls12_cipher_categories(cipher_results: dict) -> dict:
    category_counts = Counter()
    n_tls12_forced_attempted = 0

    for origin, row in cipher_results.items():
        cipher = row.get("tls12_forced_cipher")
        category = row.get("tls12_forced_category")
        if cipher is None:
            continue
        n_tls12_forced_attempted += 1
        cat = category or "unknown"
        category_counts[cat] += 1

    return {
        "n_tls12_forced_attempted": n_tls12_forced_attempted,
        "category_counts": dict(category_counts),
    }


def compute_tls12_weaknesses(cipher_results: dict) -> dict:
    n_tls12_weak_probeable = 0
    n_accepts_insecure_true = 0
    n_accepts_insecure_false = 0
    n_allows_sha1_true = 0
    n_allows_sha1_false = 0
    n_allows_cbc_true = 0
    n_allows_cbc_false = 0
    n_tls12_good_policy = 0

    for origin, row in cipher_results.items():
        ai = row.get("accepts_insecure_tls12")
        sh = row.get("allows_sha1_tls12")
        cb = row.get("allows_cbc_tls12")

        if ai is not None or sh is not None or cb is not None:
            n_tls12_weak_probeable += 1

        if ai is True:
            n_accepts_insecure_true += 1
        elif ai is False:
            n_accepts_insecure_false += 1

        if sh is True:
            n_allows_sha1_true += 1
        elif sh is False:
            n_allows_sha1_false += 1

        if cb is True:
            n_allows_cbc_true += 1
        elif cb is False:
            n_allows_cbc_false += 1

        # Good policy: all probed flags explicitly False (and at least one probed)
        probed_flags = [v for v in (ai, sh, cb) if v is not None]
        if probed_flags and all(v is False for v in probed_flags):
            n_tls12_good_policy += 1

    pct_tls12_good_policy = safe_pct(n_tls12_good_policy, n_tls12_weak_probeable)

    return {
        "n_tls12_weak_probeable": n_tls12_weak_probeable,
        "n_accepts_insecure_tls12_true": n_accepts_insecure_true,
        "n_accepts_insecure_tls12_false": n_accepts_insecure_false,
        "n_allows_sha1_tls12_true": n_allows_sha1_true,
        "n_allows_sha1_tls12_false": n_allows_sha1_false,
        "n_allows_cbc_tls12_true": n_allows_cbc_true,
        "n_allows_cbc_tls12_false": n_allows_cbc_false,
        "n_tls12_good_policy": n_tls12_good_policy,
        "pct_tls12_good_policy": pct_tls12_good_policy,
    }


def plot_tls_protocol_support(tls_block: dict, out_path: Path) -> None:
    labels = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSLv3"]
    keys = ["tls1_3", "tls1_2", "tls1_1", "tls1_0", "sslv3"]
    values = [tls_block["support_counts"].get(k, 0) for k in keys]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of origins")
    plt.title("Supported TLS protocol versions")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_legacy_protocol_exposure(tls_block: dict, out_path: Path) -> None:
    n_any_legacy = tls_block.get("n_any_legacy_tls", 0)
    n_any_modern = tls_block.get("n_any_modern_tls", 0)
    n_no_legacy = max(0, n_any_modern - n_any_legacy)

    labels = ["no_legacy_protocols", "any_legacy_protocols"]
    values = [n_no_legacy, n_any_legacy]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=0)
    plt.ylabel("Number of origins")
    plt.title("Legacy TLS protocol exposure")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_negotiated_versions(neg_block: dict, out_path: Path) -> None:
    vc = neg_block.get("version_counts", {})
    labels = ["TLSv1.3", "TLSv1.2", "other"]
    values = [vc.get("TLSv1.3", 0), vc.get("TLSv1.2", 0), vc.get("other", 0)]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of origins")
    plt.title("Negotiated TLS versions (natural handshake)")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_tls13_cipher_categories(t13_block: dict, out_path: Path) -> None:
    cc = t13_block.get("category_counts", {})
    if not cc:
        return
    labels = ["recommended", "sufficient", "unknown"]
    values = [cc.get("recommended", 0), cc.get("sufficient", 0), cc.get("unknown", 0)]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of origins")
    plt.title("Forced TLS 1.3 cipher suite categories")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_tls12_cipher_categories(t12_block: dict, out_path: Path) -> None:
    cc = t12_block.get("category_counts", {})
    if not cc:
        return
    labels = ["recommended", "sufficient", "insecure", "unknown", "phase_out"]
    values = [
        cc.get("recommended", 0),
        cc.get("sufficient", 0),
        cc.get("insecure", 0),
        cc.get("unknown", 0),
        cc.get("phase_out", 0)
    ]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels)
    plt.ylabel("Number of origins")
    plt.title("Forced TLS 1.2 cipher suite categories")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_tls12_weak_features(weak_block: dict, out_path: Path) -> None:
    labels = ["accepts_insecure_tls12", "allows_sha1_tls12", "allows_cbc_tls12"]
    values = [
        weak_block.get("n_accepts_insecure_tls12_true", 0),
        weak_block.get("n_allows_sha1_tls12_true", 0),
        weak_block.get("n_allows_cbc_tls12_true", 0),
    ]

    x = range(len(labels))
    plt.figure()
    plt.bar(x, values)
    plt.xticks(x, labels, rotation=20, ha="right")
    plt.ylabel("Number of origins")
    plt.title("TLS 1.2 weak cipher features accepted")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def build_metric_definitions() -> dict:
    """
    Human-readable descriptions of each metric in the summary JSON.
    """
    return {
        "tls_overview.n_origins":
            "Number of origins that appeared in the TLS module results.",
        "tls_overview.n_origin_offline_tls":
            "Number of origins where the TLS module recorded an error string containing "
            "'origin offline', indicating that TLS probing was skipped because the origin "
            "was already considered offline/unreachable.",
        "tls_overview.support_counts":
            "For each protocol version (TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSLv3), the number "
            "of origins where the corresponding boolean field (tls13, tls12, tls11, tls10, "
            "ssl_legacy) was True, meaning that a handshake using exactly that version succeeded.",
        "tls_overview.tested_counts":
            "For each protocol version, the number of origins where the corresponding boolean "
            "field was not None, i.e., where the client had the capability to probe that version "
            "and the scan attempted it (True = supported, False = not supported).",
        "tls_overview.n_any_modern_tls":
            "Number of origins that supported at least one modern TLS version (tls13=True or tls12=True).",
        "tls_overview.n_any_legacy_tls":
            "Number of origins that supported any legacy protocol version (tls11=True, tls10=True, or ssl_legacy=True).",
        "tls_overview.n_modern_no_legacy":
            "Number of origins that supported at least one modern TLS version (TLS 1.2 or 1.3) and did not "
            "support any legacy versions (TLS 1.1, TLS 1.0, SSLv3 all False).",
        "negotiated_versions.n_with_version":
            "Number of origins in the cipher module results whose natural TLS handshake reported a non-empty negotiated_version value.",
        "negotiated_versions.version_counts":
            "Counts of negotiated TLS protocol versions for the natural handshake with the cipher module's client, "
            "grouped into 'TLSv1.3', 'TLSv1.2', and 'other'.",
        "tls13_cipher_categories.n_tls13_forced_attempted":
            "Number of origins where the cipher module successfully forced a TLS 1.3 handshake and recorded a tls13_forced_cipher.",
        "tls13_cipher_categories.category_counts":
            "For origins where a forced TLS 1.3 handshake succeeded, counts of tls13_forced_category values: "
            "'recommended' (in the CCCS recommended list), 'sufficient' (acceptable but not top-tier), "
            "and 'unknown' (not in either list).",
        "tls12_cipher_categories.n_tls12_forced_attempted":
            "Number of origins where the cipher module successfully forced a TLS 1.2 handshake and recorded a tls12_forced_cipher.",
        "tls12_cipher_categories.category_counts":
            "For origins where a forced TLS 1.2 handshake succeeded, counts of tls12_forced_category values: "
            "'recommended' (modern AEAD/ECDHE suites), 'sufficient', 'insecure' (RC4/3DES/SHA-1/CBC families), "
            "and 'unknown'.",
        "tls12_weaknesses.n_tls12_weak_probeable":
            "Number of origins where at least one of the TLS 1.2 weakness probes was attempted "
            "(accepts_insecure_tls12, allows_sha1_tls12, allows_cbc_tls12 not all None).",
        "tls12_weaknesses.n_accepts_insecure_tls12_true":
            "Number of origins where the cipher module successfully negotiated a TLS 1.2 connection using the "
            "INSECURE_CIPHER_STRING_TLS12 bundle (e.g., NULL/EXPORT/RC4/3DES/SHA-1), indicating that the server "
            "is willing to accept clearly insecure TLS 1.2 cipher suites.",
        "tls12_weaknesses.n_accepts_insecure_tls12_false":
            "Number of origins where the INSECURE_CIPHER_STRING_TLS12 probe was attempted and no TLS 1.2 handshake "
            "could be completed using those insecure cipher suites.",
        "tls12_weaknesses.n_allows_sha1_tls12_true":
            "Number of origins where the cipher module successfully completed a TLS 1.2 handshake when restricted "
            "to SHA-1-based cipher suites (allows_sha1_tls12=True).",
        "tls12_weaknesses.n_allows_sha1_tls12_false":
            "Number of origins where the SHA-1-only TLS 1.2 probe was attempted and failed (allows_sha1_tls12=False).",
        "tls12_weaknesses.n_allows_cbc_tls12_true":
            "Number of origins where the cipher module successfully completed a TLS 1.2 handshake when restricted "
            "to CBC-mode cipher suites (allows_cbc_tls12=True).",
        "tls12_weaknesses.n_allows_cbc_tls12_false":
            "Number of origins where the CBC-only TLS 1.2 probe was attempted and failed (allows_cbc_tls12=False).",
        "tls12_weaknesses.n_tls12_good_policy":
            "Number of origins where all attempted TLS 1.2 weakness probes (insecure bundle, SHA-1-only, CBC-only) "
            "returned False, i.e., every probed weak cipher set was refused.",
        "tls12_weaknesses.pct_tls12_good_policy":
            "Percentage of TLS 1.2–probeable origins (n_tls12_weak_probeable) that refused all probed weak cipher "
            "sets (n_tls12_good_policy).",
    }

def main():
    parser = argparse.ArgumentParser(
        description="Summarise TLS protocol and cipher-suite stats from a scan results JSON."
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
        help="Directory where tls_cipher_summary.json and PNG plots will be written.",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results = load_results(args.results_json)
    modules = results.get("modules", {})

    tls_results = modules.get("tls", {})
    cipher_results = modules.get("cipher") or modules.get("ciphers", {})

    tls_block = compute_tls_block(tls_results)
    neg_block = compute_negotiated_versions(cipher_results)
    t13_block = compute_tls13_cipher_categories(cipher_results)
    t12_block = compute_tls12_cipher_categories(cipher_results)
    weak_block = compute_tls12_weaknesses(cipher_results)

    # Plots
    plot_tls_protocol_support(tls_block, out_dir / "tls_protocol_support.png")
    plot_legacy_protocol_exposure(tls_block, out_dir / "legacy_protocol_exposure.png")
    plot_negotiated_versions(neg_block, out_dir / "negotiated_tls_versions.png")
    plot_tls13_cipher_categories(t13_block, out_dir / "tls13_cipher_categories.png")
    plot_tls12_cipher_categories(t12_block, out_dir / "tls12_cipher_categories.png")
    plot_tls12_weak_features(weak_block, out_dir / "tls12_weak_features.png")

    summary = {
        "tls_overview": tls_block,
        "negotiated_versions": neg_block,
        "tls13_cipher_categories": t13_block,
        "tls12_cipher_categories": t12_block,
        "tls12_weaknesses": weak_block,
        "metric_definitions": build_metric_definitions(),
    }

    out_path = out_dir / "tls_cipher_summary.json"
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)

    print(f"Wrote TLS/cipher summary to {out_path}")
    print(f"PNG plots written to {out_dir}")


if __name__ == "__main__":
    main()

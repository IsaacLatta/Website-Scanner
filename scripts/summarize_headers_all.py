#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple, List

import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "headers"

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

BASELINE_COUNTRY = "ca"
BASELINE_SECTOR = "auth"
BASELINE_LABEL = "CA Auth"

SECURITY_HEADER_RULES: List[Tuple[str, str]] = [
    ("referrer_policy", "Referrer-Policy"),
    ("x_content_type_options", "X-Content-Type-Options"),
    ("x_frame_options", "X-Frame-Options"),
    ("csp_frame_ancestors", "CSP frame-ancestors"),
    ("permissions_policy", "Permissions-Policy"),
]


def load_summary(country: str, sector: str) -> Dict:
    """
    Load headers_summary.json for a given (country, sector) pair.

    Expected path:
      ../results/<country>/<sector>/headers/headers_summary.json
    """
    path = RESULTS_DIR / country / sector / "headers" / "headers_summary.json"
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_pct(num: int, den: int) -> float:
    if den <= 0:
        return 0.0
    return (num / den) * 100.0


def ensure_outdir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def bar_positions(n_bars: int, n_series: int) -> List[List[float]]:
    """
    Compute grouped bar positions for clustered bar charts.

    Returns:
      positions[series_index][i] = x-position for that series's bar in group i.
    """
    x = list(range(n_bars))
    if n_series <= 0:
        return [[] for _ in range(n_series)]

    width = 0.8 / n_series  # keep the whole cluster narrower than 1.0
    offsets = [(-0.4 + width / 2) + s * width for s in range(n_series)]
    return [[xi + offsets[s] for xi in x] for s in range(n_series)]


def build_sector_variants(sector_code: str) -> Dict[str, Dict]:
    """
    For a sector (auth, edu, fin, energy), build a mapping:

        variant_label -> headers_summary_dict

    Variants always include:
      - CA Auth (baseline), label "CA Auth"

    And, if present:
      - CA <SectorLabel>        (for sector != 'auth')
      - US <SectorLabel>
      - UK <SectorLabel>

    Examples:
      sector_code = 'fin'  ->  CA Auth, CA Finance, US Finance, UK Finance (if present)
      sector_code = 'auth' ->  CA Auth, US Authorities, UK Authorities
    """
    variants: Dict[str, Dict] = {}

    # Baseline: CA authorities
    baseline_summary = load_summary(BASELINE_COUNTRY, BASELINE_SECTOR)
    variants[BASELINE_LABEL] = baseline_summary

    sector_path, sector_label = SECTORS[sector_code]

    # CA sector variant (skip duplicate for 'auth')
    if sector_code != "auth":
        try:
            ca_summary = load_summary("ca", sector_path)
            variants[f"CA {sector_label}"] = ca_summary
        except FileNotFoundError:
            pass

    # US sector
    try:
        us_summary = load_summary("us", sector_path)
        variants[f"US {sector_label}"] = us_summary
    except FileNotFoundError:
        pass

    # UK sector
    try:
        uk_summary = load_summary("uk", sector_path)
        variants[f"UK {sector_label}"] = uk_summary
    except FileNotFoundError:
        pass

    return variants


def plot_revealing_headers_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare revealing header counts across:

        CA Auth, CA <Sector>, US <Sector>, UK <Sector> (where available)

    For each dataset, we use:
      revealing_headers.count_distribution["0" | "1" | "2" | "3+"]

    Plot: one stacked bar per variant, with segments for 0 / 1 / 2 / 3+.
    """
    if len(variants) < 2:
        return

    categories = ["0", "1", "2", "3+"]
    cat_labels = ["0", "1", "2", "3+"]

    variant_names = list(variants.keys())
    n_variants = len(variant_names)

    # percent of sites in each bucket, per variant
    pct_per_variant: Dict[str, List[float]] = {}
    for name in variant_names:
        summary = variants[name]
        meta = summary.get("meta", {})
        n_sites = meta.get("n_sites", 0)
        dist = summary.get("revealing_headers", {}).get("count_distribution", {})
        vals = [safe_pct(dist.get(cat, 0), n_sites) for cat in categories]
        pct_per_variant[name] = vals

    # If literally everything is zero, skip plotting
    if all(all(v == 0.0 for v in vals) for vals in pct_per_variant.values()):
        return

    x = list(range(n_variants))
    bottoms = [0.0] * n_variants

    plt.figure()
    for idx_cat, cat in enumerate(categories):
        heights = [pct_per_variant[name][idx_cat] for name in variant_names]
        plt.bar(x, heights, bottom=bottoms, label=cat_labels[idx_cat])
        bottoms = [b + h for b, h in zip(bottoms, heights)]

    plt.xticks(x, variant_names, rotation=20)
    plt.ylabel("Share of sites (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"Revealing headers per site – {sector_label} vs CA authorities")
    plt.legend(title="# revealing headers per site")
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def plot_security_headers_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare presence of individual security headers:

      Referrer-Policy
      X-Content-Type-Options
      X-Frame-Options
      CSP frame-ancestors
      Permissions-Policy

    For each dataset we compute:

      % of sites where that header is present at all.
    """
    if len(variants) < 2:
        return

    header_labels = [label for _, label in SECURITY_HEADER_RULES]

    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(header_labels)

    vals_per_variant: Dict[str, List[float]] = {}

    for name in variant_names:
        summary = variants[name]
        meta = summary.get("meta", {})
        n_sites = meta.get("n_sites", 0)
        rules = summary.get("security_rules", {})

        vals: List[float] = []
        for rule_key, _ in SECURITY_HEADER_RULES:
            r = rules.get(rule_key, {})
            n_present = r.get("n_present", 0)
            vals.append(safe_pct(n_present, n_sites))
        vals_per_variant[name] = vals

    if all(all(v == 0.0 for v in vals) for vals in vals_per_variant.values()):
        return

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), header_labels, rotation=20)
    plt.ylabel("Share of sites with header (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"Security header presence – {sector_label} vs CA authorities")
    plt.legend()
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def plot_cookies_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare cookie hardening among sites that set cookies.

    For each dataset (variant):

      - % of cookie-setting sites with Secure cookies
      - % with HttpOnly cookies
      - % with SameSite Lax or Strict
      - % with Recommended or Sufficient cookie rating
    """
    if len(variants) < 2:
        return

    categories = [
        "Secure",
        "HttpOnly",
        "SameSite ≥ Lax",
        "Recommended/Sufficient",
    ]

    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(categories)

    vals_per_variant: Dict[str, List[float]] = {}
    any_cookies = False

    for name in variant_names:
        summary = variants[name]
        cookies = summary.get("cookies", {})
        n_c = cookies.get("n_sites_with_cookies", 0)
        flags = cookies.get("flag_counts", {})
        ratings = cookies.get("rating_counts", {})

        if n_c > 0:
            any_cookies = True

        secure_pct = safe_pct(flags.get("secure", 0), n_c)
        httponly_pct = safe_pct(flags.get("httponly", 0), n_c)
        samesite_ge_lax_ct = flags.get("samesite_lax", 0) + flags.get("samesite_strict", 0)
        samesite_ge_lax_pct = safe_pct(samesite_ge_lax_ct, n_c)
        rec_suff_ct = ratings.get("recommended", 0) + ratings.get("sufficient", 0)
        rec_suff_pct = safe_pct(rec_suff_ct, n_c)

        vals_per_variant[name] = [
            secure_pct,
            httponly_pct,
            samesite_ge_lax_pct,
            rec_suff_pct,
        ]

    if not any_cookies:
        return

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), categories, rotation=20)
    plt.ylabel("Share of cookie-setting sites (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"Cookie security flags – {sector_label} vs CA authorities")
    plt.legend()
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    _ = load_summary(BASELINE_COUNTRY, BASELINE_SECTOR)

    for sector_code in SECTORS.keys():
        variants = build_sector_variants(sector_code)
        if len(variants) < 2:
            continue

        _, sector_label = SECTORS[sector_code]
        sector_slug = sector_label.lower().replace(" ", "_")

        out_reveal = OUT_DIR / f"revealing_headers_vs_ca_auth_{sector_slug}.png"
        plot_revealing_headers_sector(sector_code, variants, out_reveal)

        out_sec = OUT_DIR / f"security_headers_vs_ca_auth_{sector_slug}.png"
        plot_security_headers_sector(sector_code, variants, out_sec)

        out_cookies = OUT_DIR / f"cookies_vs_ca_auth_{sector_slug}.png"
        plot_cookies_sector(sector_code, variants, out_cookies)


if __name__ == "__main__":
    main()

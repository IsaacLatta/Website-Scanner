#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple, List

import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "https_hsts"

SECTORS: Dict[str, Tuple[str, str]] = {
    "auth": ("auth", "Authorities"),
    "edu": ("edu", "Education"),
    "fin": ("fin", "Finance"),
    "energy": ("energy", "Energy"),
}

BASELINE_COUNTRY = "ca"
BASELINE_SECTOR = "auth"
BASELINE_LABEL = "CA Auth"


def load_summary(country: str, sector: str) -> Dict:
    """
    Load https_hsts_summary.json for a given (country, sector) pair.

    Expected path:
      ../results/<country>/<sector>/https_hsts/https_hsts_summary.json
    """
    path = RESULTS_DIR / country / sector / "hsts_https" / "https_hsts_summary.json"
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
    For a sector (auth, edu, fin, energy), build:

        variant_label -> summary_dict

    Variants always include:
      - CA Auth (baseline), label "CA Auth"

    And, if present:
      - CA <SectorLabel>        (for sector != 'auth')
      - US <SectorLabel>
      - UK <SectorLabel>

    Examples:
      sector_code = 'fin'  ->  CA Auth, CA Finance, US Finance, UK Finance (if they exist)
      sector_code = 'auth' ->  CA Auth, US Authorities, UK Authorities
    """
    variants: Dict[str, Dict] = {}

    # Baseline: CA authorities
    baseline_summary = load_summary(BASELINE_COUNTRY, BASELINE_SECTOR)
    variants[BASELINE_LABEL] = baseline_summary

    sector_path, sector_label = SECTORS[sector_code]

    if sector_code != "auth":
        try:
            ca_summary = load_summary("ca", sector_path)
            variants[f"CA {sector_label}"] = ca_summary
        except FileNotFoundError:
            pass

    try:
        us_summary = load_summary("us", sector_path)
        variants[f"US {sector_label}"] = us_summary
    except FileNotFoundError:
        pass

    try:
        uk_summary = load_summary("uk", sector_path)
        variants[f"UK {sector_label}"] = uk_summary
    except FileNotFoundError:
        pass

    return variants


def plot_enforcement_sector(sector_code: str, variants: Dict[str, Dict], out_path: Path) -> None:
    """
    For a given sector, compare HTTPS/HSTS enforcement categories across:

        CA Auth, CA <Sector>, US <Sector>, UK <Sector> (where available)

    Categories (percent of all origins in that dataset):
      - HTTPS unreachable
      - HTTP no redirect
      - Redirect→HTTPS, no HSTS
      - Redirect→HTTPS, weak HSTS
      - Redirect→HTTPS, strong HSTS
    """
    if len(variants) < 2:
        return

    categories = [
        ("https_unreachable", "HTTPS unreachable"),
        ("no_redirect", "HTTP no redirect"),
        ("redirect_to_https_no_hsts", "Redirect→HTTPS, no HSTS"),
        ("redirect_to_https_hsts_weak", "Redirect→HTTPS, weak HSTS"),
        ("redirect_to_https_hsts_strong", "Redirect→HTTPS, strong HSTS"),
    ]

    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(categories)

    vals_per_variant: Dict[str, List[float]] = {}

    for name in variant_names:
        summary = variants[name]
        counts = summary.get("enforcement_counts", {})
        n_origins = summary.get("https_connectivity", {}).get("n_origins", 0)
        vals = [safe_pct(counts.get(key, 0), n_origins) for key, _ in categories]
        vals_per_variant[name] = vals

    if all(all(v == 0.0 for v in vals) for vals in vals_per_variant.values()):
        return

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), [label for _, label in categories], rotation=20)
    plt.ylabel("Share of origins (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"HTTPS/HSTS enforcement – {sector_label} vs CA authorities")
    plt.legend()
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def plot_hsts_quality_sector(sector_code: str, variants: Dict[str, Dict], out_path: Path) -> None:
    """
    For a given sector, compare HSTS configuration quality across variants.

    For each dataset we look only at HSTS-enabled origins and plot:
      - % with max-age ≥ 1 year
      - % with includeSubDomains
      - % with preload flag
      - % that meet the 'strong HSTS' definition (max-age ≥ 1 year + includeSubDomains)
    """
    if len(variants) < 2:
        return

    categories = [
        ("maxage", "max-age ≥ 1 year"),
        ("subdomains", "includeSubDomains"),
        ("preload", "preload flag"),
        ("strong", "strong HSTS"),
    ]

    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(categories)

    vals_per_variant: Dict[str, List[float]] = {}

    for name in variant_names:
        h = variants[name].get("hsts", {})
        n_has = h.get("n_has_hsts", 0)
        vals = [
            safe_pct(h.get("n_hsts_maxage_1yr", 0), n_has),
            safe_pct(h.get("n_hsts_include_subdomains", 0), n_has),
            safe_pct(h.get("n_hsts_preload_flag", 0), n_has),
            safe_pct(h.get("n_hsts_strong", 0), n_has),
        ]
        vals_per_variant[name] = vals

    # If every variant has zero HSTS usage, nothing to plot
    if all(all(v == 0.0 for v in vals) for vals in vals_per_variant.values()):
        return

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), [label for _, label in categories], rotation=20)
    plt.ylabel("Share of HSTS-enabled origins (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"HSTS configuration quality – {sector_label} vs CA authorities")
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
            # If we only have CA Auth and nothing else for this sector, skip
            continue

        _, sector_label = SECTORS[sector_code]
        sector_slug = sector_label.lower().replace(" ", "_")

        out_enforce = OUT_DIR / f"https_enforcement_vs_ca_auth_{sector_slug}.png"
        plot_enforcement_sector(sector_code, variants, out_enforce)

        out_hsts = OUT_DIR / f"hsts_quality_vs_ca_auth_{sector_slug}.png"
        plot_hsts_quality_sector(sector_code, variants, out_hsts)


if __name__ == "__main__":
    main()

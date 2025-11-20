#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple, List

import matplotlib.pyplot as plt


SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = SCRIPT_DIR.parent / "results"
OUT_DIR = RESULTS_DIR / "comparison" / "tls_cipher"

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
    Load tls_cipher_summary.json for a given (country, sector) pair.

    Expected path:
      ../results/<country>/<sector>/tls_cipher/tls_cipher_summary.json
    """
    path = RESULTS_DIR / country / sector / "tls_cipher" / "tls_cipher_summary.json"
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
    Compute grouped bar positions:
      - n_bars: number of x-axis groups (e.g., TLS versions)
      - n_series: number of bars per group (e.g., variants like CA Auth, CA Fin, US Fin)

    Returns:
      positions[series_index][i] = x-position for that series's bar in group i.
    """
    x = list(range(n_bars))
    if n_series <= 0:
        return [[] for _ in range(n_series)]

    width = 0.8 / n_series  # total cluster width < 1.0
    offsets = [(-0.4 + width / 2) + s * width for s in range(n_series)]
    return [[xi + offsets[s] for xi in x] for s in range(n_series)]


def build_sector_variants(sector_code: str) -> Dict[str, Dict]:
    """
    For a sector (auth, edu, fin, energy), build a mapping:

        variant_label -> summary_dict

    Variants always include:
      - CA Auth (baseline), label "CA Auth"
    And, if present:
      - CA <SectorLabel>        (except when sector_code == 'auth')
      - US <SectorLabel>
      - UK <SectorLabel>

    Examples:
      sector_code = 'fin'  ->  CA Auth, CA Finance, US Finance, UK Finance (if they exist)
      sector_code = 'auth' ->  CA Auth, US Authorities, UK Authorities
    """
    variants: Dict[str, Dict] = {}

    baseline_summary = load_summary(BASELINE_COUNTRY, BASELINE_SECTOR)
    variants[BASELINE_LABEL] = baseline_summary

    sector_path, sector_label = SECTORS[sector_code]

    # CA sector variant (skip duplicate for 'auth', since that's the baseline)
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


def plot_tls_support_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare TLS protocol support across variants:

        CA Auth, CA <Sector>, US <Sector>, UK <Sector> (where available)

    Uses:
      tls_overview.support_counts, n_origins
    Versions: TLS 1.3, 1.2, 1.1, 1.0 (SSL completely omitted).
    """
    if len(variants) < 2:
        return

    labels = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"]
    keys = ["tls1_3", "tls1_2", "tls1_1", "tls1_0"]

    # Keep insertion order so CA Auth is first
    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(labels)

    vals_per_variant: Dict[str, List[float]] = {}
    for name in variant_names:
        block = variants[name]["tls_overview"]
        n_origins = block.get("n_origins", 0)
        sc = block.get("support_counts", {})
        vals = [safe_pct(sc.get(k, 0), n_origins) for k in keys]
        vals_per_variant[name] = vals

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), labels)
    plt.ylabel("Share of origins supporting version (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"TLS protocol support – {sector_label} vs CA authorities")
    plt.legend()
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def plot_negotiated_versions_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare negotiated TLS versions (natural handshake)
    across variants:

        CA Auth, CA <Sector>, US <Sector>, UK <Sector> (where available)

    Uses:
      negotiated_versions.version_counts, n_with_version
    Categories: TLSv1.3, TLSv1.2, other
    """
    if len(variants) < 2:
        return

    labels = ["TLSv1.3", "TLSv1.2", "other"]
    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(labels)

    vals_per_variant: Dict[str, List[float]] = {}

    for name in variant_names:
        block = variants[name].get("negotiated_versions", {})
        n = block.get("n_with_version", 0)
        vc = block.get("version_counts", {})

        v13 = vc.get("TLSv1.3", 0)
        v12 = vc.get("TLSv1.2", 0)
        other = max(0, n - v13 - v12)

        vals = [
            safe_pct(v13, n),
            safe_pct(v12, n),
            safe_pct(other, n),
        ]
        vals_per_variant[name] = vals

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), labels)
    plt.ylabel("Share of origins (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"Negotiated TLS versions (natural handshake) – {sector_label} vs CA authorities")
    plt.legend()
    plt.tight_layout()
    ensure_outdir(out_path)
    plt.savefig(out_path)
    plt.close()


def plot_tls12_categories_sector(
    sector_code: str,
    variants: Dict[str, Dict],
    out_path: Path,
) -> None:
    """
    For a given sector, compare forced TLS 1.2 cipher categories (CCCS/NSA
    buckets) across variants:

        CA Auth, CA <Sector>, US <Sector>, UK <Sector> (where available)

    Uses:
      tls12_cipher_categories.category_counts, n_tls12_forced_attempted
    Categories: recommended, sufficient, phase_out, insecure, unknown
    """
    if len(variants) < 2:
        return

    categories = ["recommended", "sufficient", "phase_out", "insecure", "unknown"]
    variant_names = list(variants.keys())
    n_series = len(variant_names)
    n_bars = len(categories)

    vals_per_variant: Dict[str, List[float]] = {}

    for name in variant_names:
        block = variants[name].get("tls12_cipher_categories", {})
        n = block.get("n_tls12_forced_attempted", 0)
        cc = block.get("category_counts", {})

        vals = [
            safe_pct(cc.get("recommended", 0), n),
            safe_pct(cc.get("sufficient", 0), n),
            safe_pct(cc.get("phase_out", 0), n),
            safe_pct(cc.get("insecure", 0), n),
            safe_pct(cc.get("unknown", 0), n),
        ]
        vals_per_variant[name] = vals

    if all(all(v == 0.0 for v in vals) for vals in vals_per_variant.values()):
        return

    positions = bar_positions(n_bars, n_series)

    plt.figure()
    for idx, name in enumerate(variant_names):
        vals = vals_per_variant[name]
        plt.bar(positions[idx], vals, label=name)

    plt.xticks(range(n_bars), categories, rotation=15)
    plt.ylabel("Share of TLS 1.2–probeable origins (%)")

    _, sector_label = SECTORS[sector_code]
    plt.title(f"Forced TLS 1.2 cipher categories – {sector_label} vs CA authorities")
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

        out_tls_support = OUT_DIR / f"tls_support_vs_ca_auth_{sector_slug}.png"
        plot_tls_support_sector(sector_code, variants, out_tls_support)

        out_neg = OUT_DIR / f"negotiated_versions_vs_ca_auth_{sector_slug}.png"
        plot_negotiated_versions_sector(sector_code, variants, out_neg)

        out_tls12 = OUT_DIR / f"tls12_categories_vs_ca_auth_{sector_slug}.png"
        plot_tls12_categories_sector(sector_code, variants, out_tls12)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import csv
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


def load_full_results(country: str, sector: str) -> Dict | None:
    """
    Load full scan results to get consistent n_input_origins from scan_targets.
    Expected path: ../results/<country>/<sector>/<country>_<sector>.json
    """
    filename = f"{country}_{sector}.json"
    path = RESULTS_DIR / country / sector / filename
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_redirect_summary(country: str, sector: str) -> Dict | None:
    """
    Load redirect summary to get n_input_origins (ground truth).
    Expected path: ../results/<country>/<sector>/redirects/redirects_summary.json
    """
    path = RESULTS_DIR / country / sector / "redirects" / "redirects_summary.json"
    if not path.is_file():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_true_origin_count(country: str, sector: str) -> int:
    """
    Get the true n_input_origins from redirect resolution.
    This is the ground truth that all other modules should use.
    Returns 0 if redirect summary not found.
    """
    redirect_summary = load_redirect_summary(country, sector)
    if not redirect_summary:
        return 0
    uri_origin_overview = redirect_summary.get("uri_origin_overview", {})
    return uri_origin_overview.get("n_input_origins", 0)


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


def generate_csv_summary(all_variants: Dict[str, Dict[str, Dict]], out_path: Path) -> None:
    """
    Generate a CSV summary of TLS support, negotiated versions, and TLS 1.2 categories
    for all sector variants.
    
    Args:
        all_variants: Dict mapping sector_code -> (variant_name -> summary_dict)
        out_path: Output path for CSV file
    """
    rows = []
    
    for sector_code, variants in all_variants.items():
        _, sector_label = SECTORS[sector_code]
        
        for variant_name in sorted(variants.keys()):
            summary = variants[variant_name]
            
            # Parse variant_name to extract country and sector
            # E.g., "CA Auth" -> ("CA", "Authorities")
            parts = variant_name.split(maxsplit=1)
            country_code = parts[0].lower() if len(parts) > 0 else ""
            sector = parts[1] if len(parts) > 1 else ""
            
            # Map sector label back to sector folder
            sector_path = None
            for scode, (spath, slabel) in SECTORS.items():
                if slabel == sector:
                    sector_path = spath
                    break
            
            # Get TRUE origin count from redirect summary
            n_origins = 0
            if sector_path and country_code:
                n_origins = get_true_origin_count(country_code, sector_path)
            
            # Fallback to TLS summary if redirect not available
            if n_origins == 0:
                tls_overview = summary.get("tls_overview", {})
                n_origins = tls_overview.get("n_origins", 0)
            else:
                tls_overview = summary.get("tls_overview", {})
            
            support_counts = tls_overview.get("support_counts", {})
            
            pct_tls13_support = safe_pct(support_counts.get("tls1_3", 0), n_origins)
            pct_tls12_support = safe_pct(support_counts.get("tls1_2", 0), n_origins)
            pct_tls11_support = safe_pct(support_counts.get("tls1_1", 0), n_origins)
            pct_tls10_support = safe_pct(support_counts.get("tls1_0", 0), n_origins)
            
            # Negotiated versions
            neg_block = summary.get("negotiated_versions", {})
            n_with_version = neg_block.get("n_with_version", 0)
            version_counts = neg_block.get("version_counts", {})
            
            v13_neg = version_counts.get("TLSv1.3", 0)
            v12_neg = version_counts.get("TLSv1.2", 0)
            other_neg = max(0, n_with_version - v13_neg - v12_neg)
            
            pct_tls13_neg = safe_pct(v13_neg, n_with_version)
            pct_tls12_neg = safe_pct(v12_neg, n_with_version)
            pct_other_neg = safe_pct(other_neg, n_with_version)
            
            # TLS 1.2 cipher categories
            tls12_block = summary.get("tls12_cipher_categories", {})
            n_tls12 = tls12_block.get("n_tls12_forced_attempted", 0)
            category_counts = tls12_block.get("category_counts", {})
            
            pct_recommended = safe_pct(category_counts.get("recommended", 0), n_tls12)
            pct_sufficient = safe_pct(category_counts.get("sufficient", 0), n_tls12)
            pct_phase_out = safe_pct(category_counts.get("phase_out", 0), n_tls12)
            pct_insecure = safe_pct(category_counts.get("insecure", 0), n_tls12)
            pct_unknown = safe_pct(category_counts.get("unknown", 0), n_tls12)
            
            rows.append({
                "country": parts[0] if len(parts) > 0 else "",
                "sector": sector,
                "n_origins": n_origins,
                "pct_tls13_support": f"{pct_tls13_support:.1f}",
                "pct_tls12_support": f"{pct_tls12_support:.1f}",
                "pct_tls11_support": f"{pct_tls11_support:.1f}",
                "pct_tls10_support": f"{pct_tls10_support:.1f}",
                "n_with_version": n_with_version,
                "pct_tls13_neg": f"{pct_tls13_neg:.1f}",
                "pct_tls12_neg": f"{pct_tls12_neg:.1f}",
                "pct_other_neg": f"{pct_other_neg:.1f}",
                "n_tls12_forced": n_tls12,
                "pct_recommended": f"{pct_recommended:.1f}",
                "pct_sufficient": f"{pct_sufficient:.1f}",
                "pct_phase_out": f"{pct_phase_out:.1f}",
                "pct_insecure": f"{pct_insecure:.1f}",
                "pct_unknown": f"{pct_unknown:.1f}",
            })
    
    ensure_outdir(out_path)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "country", "sector", "n_origins",
            "pct_tls13_support", "pct_tls12_support", "pct_tls11_support", "pct_tls10_support",
            "n_with_version", "pct_tls13_neg", "pct_tls12_neg", "pct_other_neg",
            "n_tls12_forced", "pct_recommended", "pct_sufficient", "pct_phase_out",
            "pct_insecure", "pct_unknown",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def generate_latex_table(csv_path: Path, out_path: Path) -> None:
    """
    Generate a LaTeX table using csvsimple that reads from the CSV file.
    
    Args:
        csv_path: Path to the CSV file
        out_path: Output path for the .tex file
    """
    latex_content = r"""\begin{inlinecap}
\captionof{table}{TLS protocol support, negotiated versions, and cipher categories by country and sector.}
\label{tab:tls_cipher_summary}
\centering
\tiny
\setlength{\tabcolsep}{1.5pt}
\resizebox{\textwidth}{!}{%
  \csvreader[
    tabular=llrrrrrrrrrrrrrr,
    table head=\toprule
      Country & Sector & $n$ origins &
      \multicolumn{4}{c}{TLS Support (\%)} &
      \multicolumn{3}{c}{Negotiated (\%)} &
      \multicolumn{5}{c}{TLS 1.2 Cipher Categories (\%)} \\
      \cmidrule(lr){4-7} \cmidrule(lr){8-10} \cmidrule(lr){11-15}
      & & & 1.3 & 1.2 & 1.1 & 1.0 & 1.3 & 1.2 & Other & Rec. & Suff. & Phase & Insec. & Unk. \\\midrule,
    late after line=\\,
    late after last line=\\\bottomrule
  ]{""" + str(csv_path.relative_to(csv_path.parent.parent.parent)) + r"""}{%
    country=\Country,
    sector=\Sector,
    n_origins=\Norigins,
    pct_tls13_support=\TLSa,
    pct_tls12_support=\TLSb,
    pct_tls11_support=\TLSc,
    pct_tls10_support=\TLSd,
    n_with_version=\Nwv,
    pct_tls13_neg=\Nega,
    pct_tls12_neg=\Negb,
    pct_other_neg=\Negc,
    n_tls12_forced=\Ntf,
    pct_recommended=\Crec,
    pct_sufficient=\Csuf,
    pct_phase_out=\Cphs,
    pct_insecure=\Cins,
    pct_unknown=\Cunk
  }{%
    \Country & \Sector & \Norigins &
    \TLSa & \TLSb & \TLSc & \TLSd &
    \Nega & \Negb & \Negc &
    \Crec & \Csuf & \Cphs & \Cins & \Cunk
  }%
}%
\end{inlinecap}
"""
    
    ensure_outdir(out_path)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(latex_content)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    _ = load_summary(BASELINE_COUNTRY, BASELINE_SECTOR)

    # Collect all variants for CSV generation
    all_variants: Dict[str, Dict[str, Dict]] = {}

    for sector_code in SECTORS.keys():
        variants = build_sector_variants(sector_code)
        if len(variants) < 2:
            continue

        all_variants[sector_code] = variants

        _, sector_label = SECTORS[sector_code]
        sector_slug = sector_label.lower().replace(" ", "_")

        out_tls_support = OUT_DIR / f"tls_support_vs_ca_auth_{sector_slug}.png"
        plot_tls_support_sector(sector_code, variants, out_tls_support)

        out_neg = OUT_DIR / f"negotiated_versions_vs_ca_auth_{sector_slug}.png"
        plot_negotiated_versions_sector(sector_code, variants, out_neg)

        out_tls12 = OUT_DIR / f"tls12_categories_vs_ca_auth_{sector_slug}.png"
        plot_tls12_categories_sector(sector_code, variants, out_tls12)

    # Generate CSV summary
    csv_path = OUT_DIR / "tls_cipher_summary.csv"
    generate_csv_summary(all_variants, csv_path)
    print(f"Generated CSV: {csv_path}")

    # Generate LaTeX table
    tex_path = OUT_DIR / "tls_cipher_summary_table.tex"
    generate_latex_table(csv_path, tex_path)
    print(f"Generated LaTeX: {tex_path}")


if __name__ == "__main__":
    main()
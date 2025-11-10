# scanner/origins.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Set
from urllib.parse import urlparse

from scanner.targets import ScanTargets, _normalize_origin
from scanner.redirects import ResolutionResult


@dataclass
class OriginTargets:
    entry_origins: List[str]
    final_origins: List[str]
    all_origins: List[str]


def build_origin_targets(
    targets: ScanTargets,
    resolutions: Dict[str, ResolutionResult],
) -> OriginTargets:
    """
    Build sets of entry and final origins from the entry targets
    """
    entry_set: Set[str] = set(targets.origins)
    final_set: Set[str] = set()

    for res in resolutions.values():
        if res.final_origin:
            final_set.add(res.final_origin)

    all_set = entry_set | final_set

    return OriginTargets(
        entry_origins=sorted(entry_set),
        final_origins=sorted(final_set),
        all_origins=sorted(all_set),
    )

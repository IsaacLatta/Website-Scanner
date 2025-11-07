# tests/test_targets.py
import pytest

from scanner.targets import (
    ScanTargets,
    build_scan_targets,
    clean_domains,
    _normalize_origin,
)


def test_clean_domains_strips_whitespace_and_control_chars():
    domains = [
        "  example.com  ",
        "foo.com\n",
        "bar.com\r\n",
        " exa mple.org ",  # internal spaces too
        "",
        "   ",
    ]

    cleaned = clean_domains(domains)

    # Empty / whitespace-only entries become empty strings, which build_scan_targets ignores.
    assert cleaned == [
        "example.com",
        "foo.com",
        "bar.com",
        "example.org",
        "",
        "",
    ]


@pytest.mark.parametrize(
    "host,scheme,port,expected",
    [
        ("example.com", "https", None, "example.com"),
        ("example.com", "http", None, "example.com"),
        ("example.com", "https", 443, "example.com"),
        ("example.com", "http", 80, "example.com"),
        ("example.com", "https", 444, "example.com:444"),
        ("example.com", "http", 8080, "example.com:8080"),
    ],
)
def test_normalize_origin(host, scheme, port, expected):
    assert _normalize_origin(host, scheme, port) == expected


def test_build_scan_targets_basic_domain_defaults_to_https():
    targets = build_scan_targets(["example.com"])

    assert isinstance(targets, ScanTargets)
    assert targets.origins == ["example.com"]
    assert targets.uris == ["https://example.com"]


def test_build_scan_targets_trims_and_ignores_empty():
    raw = [
        "  example.com  ",
        "\nfoo.com\r\n",
        "   ",
        "",
    ]

    targets = build_scan_targets(raw)

    assert "example.com" in targets.origins
    assert "foo.com" in targets.origins
    assert len(targets.origins) == 2

    assert "https://example.com" in targets.uris
    assert "https://foo.com" in targets.uris
    assert len(targets.uris) == 2


def test_build_scan_targets_deduplicates_domains_case_insensitively_by_host():
    raw = [
        "example.com",
        "EXAMPLE.com",
        "https://example.com",
        "https://EXAMPLE.com",
    ]

    targets = build_scan_targets(raw)

    assert targets.origins == ["example.com"]

    assert targets.uris == ["https://example.com"]


def test_build_scan_targets_handles_explicit_ports():
    raw = [
        "example.com:8443",
        "https://example.org:443/path",
        "http://example.net:80",
        "http://example.net:8080",
    ]

    targets = build_scan_targets(raw)

    assert "example.com:8443" in targets.origins
    assert "example.org" in targets.origins
    assert "example.net" in targets.origins
    assert "example.net:8080" in targets.origins

    assert "https://example.com:8443" in targets.uris
    assert "https://example.org:443/path" in targets.uris
    assert "http://example.net:80" in targets.uris
    assert "http://example.net:8080" in targets.uris


def test_build_scan_targets_sorts_outputs_deterministically():
    raw = [
        "b-example.com",
        "a-example.com",
        "c-example.com",
    ]

    targets = build_scan_targets(raw)

    assert targets.origins == [
        "a-example.com",
        "b-example.com",
        "c-example.com",
    ]
    assert targets.uris == [
        "https://a-example.com",
        "https://b-example.com",
        "https://c-example.com",
    ]


def test_build_scan_targets_ignores_entries_without_hostname():
    raw = [
        "https://",         # invalid
        "   ",              # invalid
        "valid.com",        # valid
    ]

    targets = build_scan_targets(raw)

    assert targets.origins == ["valid.com"]
    assert targets.uris == ["https://valid.com"]

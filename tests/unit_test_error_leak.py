# tests/test_error_leaks.py

import pytest

from scanner.modules.error.error_leak import (
    Signature,
    VERSION_REGEX,
    _is_textual_content_type,
    _detect_tech_leaks_for_body,
    _compile_alias_pattern,
)


def test_is_textual_content_type_basic():
    assert _is_textual_content_type("text/html") is True
    assert _is_textual_content_type("text/html; charset=utf-8") is True
    assert _is_textual_content_type("text/plain") is True
    assert _is_textual_content_type("application/json") is True
    assert _is_textual_content_type("application/problem+json") is True
    assert _is_textual_content_type("image/png") is False
    assert _is_textual_content_type("") is False
    assert _is_textual_content_type("   ") is False
    assert _is_textual_content_type("application/octet-stream") is False


def test_version_regex_matches_common_patterns():
    m1 = VERSION_REGEX.search("Django 4.2 error")
    assert m1
    assert m1.group(1) == "4.2"

    m2 = VERSION_REGEX.search("PostgreSQL 16.2.1: FATAL error")
    assert m2
    assert m2.group(1) == "16.2.1"

    m3 = VERSION_REGEX.search("Next.js v14.1.0 encountered an error")
    assert m3
    assert m3.group(1) == "14.1.0"

    m4 = VERSION_REGEX.search("Apache Tomcat/9.0.85 - error page")
    assert m4
    assert m4.group(1) == "9.0.85"


def test_detects_framework_with_version_near_alias():
    sig = Signature(
        display_name="Django",
        category="framework_backend",
        aliases=["django"],
    )
    body = """
    <!doctype html>
    <html>
      <body>
        <h1>Server Error (500)</h1>
        <p>Django 4.2.5</p>
      </body>
    </html>
    """

    compiled_aliases = {a: _compile_alias_pattern(a) for a in sig.aliases}

    rows = _detect_tech_leaks_for_body(
        origin="example.com",
        body=body,
        signatures=[sig],
        compiled_aliases=compiled_aliases,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.origin == "example.com"
    assert row.signature.display_name == "Django"
    assert row.alias == "django"
    assert row.has_version is True
    assert row.version == "4.2.5"
    assert "Django" in row.version_context


def test_detects_framework_without_version():
    sig = Signature(
        display_name="Django",
        category="framework_backend",
        aliases=["django"],
    )
    body = "Oops, a Django application error occurred."

    compiled_aliases = {a: _compile_alias_pattern(a) for a in sig.aliases}

    rows = _detect_tech_leaks_for_body(
        origin="example.com",
        body=body,
        signatures=[sig],
        compiled_aliases=compiled_aliases,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.signature.display_name == "Django"
    assert row.has_version is False
    assert row.version is None


def test_detects_database_with_version():
    sig = Signature(
        display_name="PostgreSQL",
        category="db_relational",
        aliases=["postgresql", "postgres"],
    )
    body = "FATAL: password authentication failed for user \"app\" (PostgreSQL 16.2)"

    compiled_aliases = {a: _compile_alias_pattern(a) for a in sig.aliases}

    rows = _detect_tech_leaks_for_body(
        origin="db.example.com",
        body=body,
        signatures=[sig],
        compiled_aliases=compiled_aliases,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.signature.display_name == "PostgreSQL"
    assert row.has_version is True
    assert row.version == "16.2"
    assert "PostgreSQL" in row.version_context


def test_detects_cloud_platform_name_only():
    sig = Signature(
        display_name="Heroku",
        category="cloud_paas",
        aliases=["heroku", "herokuapp.com"],
    )
    body = "Application Error - Heroku\nAn error occurred in the application."

    compiled_aliases = {a: _compile_alias_pattern(a) for a in sig.aliases}

    rows = _detect_tech_leaks_for_body(
        origin="myapp.herokuapp.com",
        body=body,
        signatures=[sig],
        compiled_aliases=compiled_aliases,
    )

    assert len(rows) == 1
    row = rows[0]
    assert row.signature.display_name == "Heroku"
    assert row.has_version is False
    assert row.version is None


def test_word_boundaries_prevent_false_positive():
    # Alias is "next". The text contains "next" as part of another word but
    # not as a standalone word.
    sig = Signature(
        display_name="Next.js",
        category="framework_fullstack",
        aliases=["next"],
    )
    body = "The nextdoor neighbor is not related to Next.js at all."

    compiled_aliases = {a: _compile_alias_pattern(a) for a in sig.aliases}

    rows = _detect_tech_leaks_for_body(
        origin="example.com",
        body=body,
        signatures=[sig],
        compiled_aliases=compiled_aliases,
    )

    # We do expect a hit because "Next.js" is present, but we want to check
    # that the plain "nextdoor" part did not cause any spurious matches.
    assert len(rows) == 1
    assert "Next.js" in rows[0].version_context

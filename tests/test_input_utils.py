from pathlib import Path

from scanner.input_utils import load_domains_from_file, load_column_from_csv

def test_load_domains_from_file_strips_and_skips_empty(tmp_path):
    p = tmp_path / "domains.txt"
    p.write_text(
        "example.com\n"
        "\n"
        "   https://foo.example.org/path  \r\n"
        "   \n"
        "bar.gov\n",
        encoding="utf-8",
    )

    domains = load_domains_from_file(p)

    assert domains == [
        "example.com",
        "https://foo.example.org/path",
        "bar.gov",
    ]


def test_load_column_from_csv_with_offset():
    csv_path = Path("tests/res/test_domains.csv")
    assert csv_path.exists(), "test_domains.csv is missing"

    urls_all = load_column_from_csv(csv_path, column="url", offset=0)
    assert len(urls_all) == 9
    assert urls_all[0] == "https://www.canada.ca/en/administrative-tribunals-support-service.html"
    assert urls_all[-1] == "https://www.bdc.ca/en"

    urls_offset = load_column_from_csv(csv_path, column="url", offset=3)
    assert urls_offset == urls_all[3:]


def test_load_column_from_csv_missing_column_raises():
    csv_path = Path("tests/res/test_domains.csv")
    assert csv_path.exists(), "test_domains.csv is missing"

    try:
        load_column_from_csv(csv_path, column="nonexistent_column", offset=0)
        assert False, "Expected ValueError for missing column"
    except ValueError as e:
        pass
        # assert "not found in CSV header" in str(e)

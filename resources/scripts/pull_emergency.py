#!/usr/bin/env python3
import sys, argparse, csv, re
from html.parser import HTMLParser

class EMOHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = []               # (province, agency_name, url)
        self._in_p = False
        self._in_strong = False
        self._cur_province = None
        self._cur_link_href = None
        self._cur_link_text = None
        self._in_a = False

    def handle_starttag(self, tag, attrs):
        if tag == "p":
            self._in_p = True
            # reset per-<p>
            self._cur_province = None
            self._cur_link_href = None
            self._cur_link_text = None
            self._in_a = False
            self._in_strong = False
        elif self._in_p and tag == "strong":
            self._in_strong = True
        elif self._in_p and tag == "a":
            self._in_a = True
            href = dict(attrs).get("href", "")
            self._cur_link_href = href

    def handle_endtag(self, tag):
        if tag == "strong":
            self._in_strong = False
        elif tag == "a":
            self._in_a = False
        elif tag == "p" and self._in_p:
            # finalize this paragraph
            if self._cur_province and self._cur_link_href and self._cur_link_text:
                self.rows.append((
                    self._cur_province.strip(),
                    self._cur_link_text.strip(),
                    self._cur_link_href.strip()
                ))
            # clear p state
            self._in_p = False
            self._cur_province = None
            self._cur_link_href = None
            self._cur_link_text = None
            self._in_a = False
            self._in_strong = False

    def handle_data(self, data):
        if self._in_p and self._in_strong:
            # Province names are in <strong>...</strong>
            text = data.strip()
            if text:
                # Some pages might include trailing punctuation/newlines; keep clean
                self._cur_province = text
        elif self._in_p and self._in_a:
            # Link text is the agency name
            t = data.strip()
            if t:
                # Accumulate in case link text arrives in chunks
                self._cur_link_text = (self._cur_link_text or "") + (t if not self._cur_link_text else " " + t)

# province → slug for source tag
def slugify_province(name: str) -> str:
    # Normalize common variants
    normalized = name.strip()
    replacements = {
        "Québec": "Quebec",
        "Quebec": "Quebec",
        "Newfoundland & Labrador": "Newfoundland and Labrador",
        "Newfoundland and Labrador": "Newfoundland and Labrador",
        "Northwest Territories": "Northwest Territories",
        "Prince Edward Island": "Prince Edward Island",
        "British Columbia": "British Columbia",
        "Nova Scotia": "Nova Scotia",
        "New Brunswick": "New Brunswick",
        "Yukon": "Yukon",
        "Nunavut": "Nunavut",
        "Ontario": "Ontario",
        "Manitoba": "Manitoba",
        "Saskatchewan": "Saskatchewan",
        "Alberta": "Alberta",
    }
    normalized = replacements.get(normalized, normalized)
    slug = normalized.lower()
    slug = re.sub(r"&", " and ", slug)
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug

def main():
    ap = argparse.ArgumentParser(description="Parse Canada.ca EMO list HTML to CSV rows: name,url,<empty>,source")
    ap.add_argument("--append", help="Append to existing CSV file (otherwise prints to stdout)")
    args = ap.parse_args()

    html = sys.stdin.read()

    parser = EMOHTMLParser()
    parser.feed(html)

    # Deduplicate (province, url)
    seen = set()
    rows_out = []
    for prov, agency, url in parser.rows:
        key = (prov, url)
        if key in seen:
            continue
        seen.add(key)
        source = f"gov:emergency-{slugify_province(prov)}"
        name = f"{agency}"
        rows_out.append([name, url, "", source])

    # If nothing parsed, fail loudly to avoid writing empty lines
    if not rows_out:
        sys.stderr.write("No EMO rows found. Check that the HTML structure matches the expected Canada.ca format.\n")
        sys.exit(1)

    if args.append:
        with open(args.append, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_out)
    else:
        w = csv.writer(sys.stdout)
        w.writerows(rows_out)

if __name__ == "__main__":
    main()

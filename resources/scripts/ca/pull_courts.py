#!/usr/bin/env python3
import sys, re, argparse, unicodedata

def slugify(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = s.encode("ascii", "ignore").decode("ascii")
    s = s.strip().lower()
    s = re.sub(r"&", " and ", s)
    s = re.sub(r"['’]", "", s)                 # drop apostrophes
    s = re.sub(r"[^a-z0-9]+", "-", s)          # non-alnum -> dash
    s = re.sub(r"-+", "-", s).strip("-")
    return s

def normalize_level(level: str) -> str:
    # Keep display name as-is (minus trailing colon), slug separately for source
    return level.strip().rstrip(":")

def iter_province_blocks(html: str):
    # Find each <h3>Province</h3> and the content until the next <h3>
    h3_iter = list(re.finditer(r"<h3>\s*([^<]+?)\s*</h3>", html, re.IGNORECASE))
    for i, m in enumerate(h3_iter):
        prov = m.group(1).strip()
        start = m.end()
        end = h3_iter[i+1].start() if i+1 < len(h3_iter) else len(html)
        chunk = html[start:end]
        yield prov, chunk

def extract_links_from_chunk(chunk: str):
    # Match paragraphs like:
    # <p><span>Supreme Court: </span><a href="https://..."> ... </a></p>
    # Skip any where the span contains "CanLII"
    p_iter = re.finditer(
        r"<p[^>]*>\s*<span>\s*([^<]+?)\s*</span>\s*"
        r"(?:</?span[^>]*>\s*)?"                    # tolerate extra span close/open
        r"<a\s+href=\"([^\"]+)\"[^>]*>.*?</a>.*?</p>",
        chunk, re.IGNORECASE | re.DOTALL
    )
    for pm in p_iter:
        label = pm.group(1)
        href = pm.group(2)
        if re.search(r"canlii", label, re.IGNORECASE):
            continue
        # Exclude empty anchors or fragment-only links
        if not href or href.strip() in ("#",):
            continue
        yield normalize_level(label), href.strip()

def main():
    ap = argparse.ArgumentParser(description="Parse DOJ courts hyperlinks page into authorities TSV/CSV")
    ap.add_argument("--append", required=True, help="Path to output file to append")
    ap.add_argument("--delimiter", default="\t", help="Field delimiter (default: TAB)")
    args = ap.parse_args()

    html = sys.stdin.read()

    rows = []
    for province, chunk in iter_province_blocks(html):
        prov_slug = slugify(province)
        for level, url in extract_links_from_chunk(chunk):
            name = f"{province} {level}"
            level_slug = slugify(level)
            source = f"gov:courts-{prov_slug}-{level_slug}"
            # Skip obvious non-court aggregators if any slipped through
            rows.append((name, url, "", source))

    # Append to file
    delim = args.delimiter
    with open(args.append, "a", encoding="utf-8", newline="") as f:
        for name, url, abbr, source in rows:
            f.write(f"{name}{delim}{url}{delim}{abbr}{delim}{source}\n")

if __name__ == "__main__":
    main()

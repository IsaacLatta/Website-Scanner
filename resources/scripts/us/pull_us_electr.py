#!/usr/bin/env python3
import argparse, csv, sys, os
from pypdf import PdfReader
import pdfplumber

def iter_links(pdf_path):
    r = PdfReader(pdf_path)
    with pdfplumber.open(pdf_path) as pl:
        for i, page in enumerate(r.pages):
            pl_page = pl.pages[i]
            annots = page.get("/Annots") or []
            for annot_ref in annots:
                annot = annot_ref.get_object()
                if annot.get("/Subtype") != "/Link":
                    continue
                a = annot.get("/A")
                if not (a and a.get("/URI")):
                    continue
                uri = a.get("/URI")
                # Rect is [x0, y0, x1, y1] with origin bottom-left
                x0, y0, x1, y1 = [float(v) for v in annot.get("/Rect")]
                # Try to read text inside/near the link bbox
                pad = 2
                bbox = (x0 - pad, y0 - pad, x1 + pad, y1 + pad)
                name = ""
                try:
                    cropped = pl_page.crop(bbox)
                    txt = (cropped.extract_text() or "").strip()
                    if txt:
                        name = txt
                except Exception:
                    pass
                if not name:
                    # Fallback: collect words whose centers fall inside a slightly expanded bbox
                    words = pl_page.extract_words() or []
                    near = []
                    X0, Y0, X1, Y1 = x0 - 4, y0 - 4, x1 + 4, y1 + 4
                    for w in words:
                        cx = (float(w["x0"]) + float(w["x1"])) / 2
                        cy = (float(w["top"]) + float(w["bottom"])) / 2
                        if X0 <= cx <= X1 and Y0 <= cy <= Y1:
                            near.append(w["text"])
                    name = " ".join(near).strip()
                yield name, uri

def main():
    ap = argparse.ArgumentParser(description="Extract PDF hyperlinks to CSV rows: name,url,<empty>,source")
    ap.add_argument("pdf", help="Input PDF file")
    ap.add_argument("--source", default="us-energy-io-utilities", help="Source column value")
    ap.add_argument("--stdout", action="store_true", help="Print CSV rows to stdout instead of writing a file")
    ap.add_argument("--out", help="Output CSV path (created if missing)")
    ap.add_argument("--append", action="store_true", help="Append to --out if it exists (write header if new)")
    ap.add_argument("--unique", action="store_true", help="De-duplicate rows by (name,url)")
    args = ap.parse_args()

    rows = [(name, url, "", args.source) for name, url in iter_links(args.pdf)]
    if args.unique:
        seen, dedup = set(), []
        for r in rows:
            key = (r[0].strip().lower(), r[1].strip().lower())
            if key not in seen:
                seen.add(key)
                dedup.append(r)
        rows = dedup

    header = ["name", "url", "", "source"]

    if args.stdout or not args.out:
        # Dump to stdout (with header first)
        w = csv.writer(sys.stdout)
        w.writerow(header)
        for r in rows:
            w.writerow(r)
        return

    # File output path supplied
    exists = os.path.exists(args.out)
    mode = "a" if args.append and exists else "w"
    with open(args.out, mode, newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        # Write header if creating or overwriting, or if appending to a new file
        if mode == "w" or (mode == "a" and not exists):
            w.writerow(header)
        for r in rows:
            w.writerow(r)
    print(f"Wrote {len(rows)} rows -> {args.out} ({'append' if mode=='a' else 'overwrite'})")

if __name__ == "__main__":
    main()

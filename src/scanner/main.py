#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path
from scanner.runner import SecurityScanner

import scanner.config as cfg
from scanner.plotter import PlotGenerator

def clean_domains(domains: list[str]) -> list[str]:
    return [d.strip().replace(' ', '').replace('\n', '').replace('\r', '')  for d in domains]

def main():
    ap = argparse.ArgumentParser(description="Website security scanner with concurrent testing")
    ap.add_argument("input", nargs="?", help="Input file with one domain per line")
    ap.add_argument("-d", "--domains", nargs="+", help="Scan these domain names instead of a file")
    ap.add_argument("-o", "--output-dir", default=".", help="Directory for PNGs and CSV")
    ap.add_argument("--csv-out", default="results.csv", help="CSV filename")
    ap.add_argument("-w", "--workers", type=int, default=10, help="Max concurrent workers")
    ap.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    ap.add_argument("--verify-cert", action="store_true", help="Verify SSL certificates")
    # ap.add_argument("-m", "--missing-headers", default=None, help="Check for required headers")
    # ap.add_argument("-r", "--regex-headers", default=None, help="Validate headers against regex")
    
    args = ap.parse_args()

    if not args.input and not args.domains:
        print("ERROR: provide an input file or --domains ...")
        sys.exit(1)

    domains = None
    if args.domains:
        domains = args.domains
    else:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

    if not domains:
        print("ERROR: No domains to scan")
        sys.exit(1)

    domains = clean_domains(domains)

    config = cfg.Config()
    config.OUTPUT_DIR = Path(args.output_dir)
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    config.CSV_FILENAME = args.csv_out
    config.MAX_TIMEOUT = args.timeout
    config.VERIFY_CERTIFICATE = args.verify_cert
    cfg.download_headers(config, config.MAX_TIMEOUT)
    scanner = SecurityScanner(config, max_workers=args.workers)

    try:
        print(f"Starting scan of {len(domains)} domains...")
        results = scanner.scan_domains(domains)
        print(f"Scanned {len(domains)} domains in {scanner.duration():.2f} seconds.")

        print(f"Generating results ...")
        plotter = PlotGenerator(args.output_dir)
        plotter.generate_reports(results, len(domains))
        print(f"Results saved to {args.output_dir}.")

    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
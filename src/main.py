#!/usr/bin/env python3
"""
Web Security Scanner - Main Entry Point
"""
import sys
import argparse
from pathlib import Path
from runner import SecurityScanner

def main():
    ap = argparse.ArgumentParser(description="Website security scanner with concurrent testing")
    ap.add_argument("input", nargs="?", help="Input file with one domain per line")
    ap.add_argument("-d", "--domains", nargs="+", help="Scan these domain names instead of a file")
    ap.add_argument("-o", "--output-dir", default=".", help="Directory for PNGs and CSV")
    ap.add_argument("--csv-out", default="results.csv", help="CSV filename")
    ap.add_argument("-w", "--workers", type=int, default=10, help="Max concurrent workers")
    ap.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    ap.add_argument("--verify-cert", action="store_true", help="Verify SSL certificates")
    ap.add_argument("-m", "--missing-headers", default=None, help="Check for required headers")
    ap.add_argument("-r", "--regex-headers", default=None, help="Validate headers against regex")
    
    args = ap.parse_args()

    if not args.input and not args.domains:
        print("ERROR: provide an input file or --domains ...")
        sys.exit(1)

    # Get list of domains
    if args.domains:
        domains = args.domains
    else:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    
    if not domains:
        print("ERROR: No domains to scan")
        sys.exit(1)
    
    # Create scanner instance
    scanner = SecurityScanner(
        output_dir=args.output_dir,
        csv_filename=args.csv_out,
        max_workers=args.workers,
        timeout=args.timeout,
        verify_certificates=args.verify_cert,
        missing_headers_file=args.missing_headers,
        regex_headers_file=args.regex_headers
    )
    
    # Run the scan
    try:
        scanner.scan_domains(domains)
        print(f"\nScan complete! Results saved to {args.output_dir}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
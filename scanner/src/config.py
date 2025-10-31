#!/usr/bin/env python3
from pathlib import Path
import requests

class Config:
    OUTPUT_DIR = Path(".")
    CSV_FILENAME: str = "results.csv" # should append the date
    MAX_TIMEOUT = 10
    VERIFY_CERTIFICATE = False
    CIPHERSUITES = []
    REVEALING_HEADERS = []
    REVEALING_HEADERS_LOWER = []
    USER_AGENT = "Mozilla/5.0"

def download_headers(cfg: Config, timeout_s: int = 10):
        try:
            r = requests.get("https://ciphersuite.info/api/cs", timeout=timeout_s).json()
            cfg.CIPHERSUITES = r['ciphersuites']
        except Exception as e:
            print(f"WARNING: Could not load cipher suite data: {e}")
            cfg.CIPHERSUITES = []
        
        try:
            r = requests.get("https://owasp.org/www-project-secure-headers/ci/headers_remove.json", 
                           timeout_s).json()
            cfg.REVEALING_HEADERS = r['headers']
            cfg.REVEALING_HEADERS_LOWER = [h.lower() for h in r['headers']]
        except Exception as e:
            print(f"WARNING: Could not load revealing headers data: {e}")
            cfg.REVEALING_HEADERS = []
            cfg.REVEALING_HEADERS_LOWER = []

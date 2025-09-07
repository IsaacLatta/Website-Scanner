#!/usr/bin/env python3
from pathlib import Path

class Config:
    OUTPUT_DIR = Path(".")
    MAX_TIMEOUT = 10
    VERIFY_CERTIFICATE = False
    CIPHERSUITES = []
    REVEALING_HEADERS = []
    
    USER_AGENT = "Mozilla/5.0 (Security Scanner 1.0)"